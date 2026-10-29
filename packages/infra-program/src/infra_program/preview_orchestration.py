"""Explicit read-only collection and existing-stack preview; no deployment authority."""

import argparse
import hashlib
import json
import os
import tomllib
from pathlib import Path
from typing import Any

from infra_core.backend import validate_receipt
from infra_core.backend_posture import capture_posture, validate_posture_evidence
from infra_core.cutover import repository_state
from infra_core.foundation import load_foundation
from infra_core.governance.contracts import number, timestamp
from infra_core.inventory.cloudflare import collect_zone
from infra_core.inventory.oci import OCIReader, collect
from infra_core.inventory.oci_usage import collect_usage
from infra_core.inventory.supabase import collect_management
from infra_core.inventory_evidence import capture_inventory
from infra_core.oci.config import parse_config
from infra_core.preview_contracts import describe_preview
from infra_core.service_evidence import capture_cloudflare_evidence, capture_supabase_evidence

from infra_program.preview_driver import Context, run_preview
from infra_program.preview_program import (
    NetworkPreviewContext,
    OkePreviewContext,
    ServicePreviewContext,
)

MESSAGE = "PREVIEW006: preview orchestration rejected; inspect private inputs and prerequisites"
COMMON = {
    "schema_version",
    "configuration",
    "encrypted_configuration",
    "qualification",
    "cli_archive",
    "provider_home",
    "backend_account_id",
    "backend_oci_config",
    "output",
}
EXTRA = {
    "cloudflare-edge": {"review"},
    "supabase-database": {"supplement", "organizations"},
    "oci-network": {"account", "usage", "usage_cutoff", "oci_config"},
    "oci-oke": {"account", "usage", "usage_cutoff", "oci_config", "dependency_outputs"},
}


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError(MESSAGE)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    _require(len(dict(pairs)) == len(pairs))
    return dict(pairs)


def _json(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw, object_pairs_hook=_unique)
    json.dumps(value, allow_nan=False)
    _require(type(value) is dict)
    assert isinstance(value, dict)
    return value


def _private(root: Path, value: str | Path) -> Path:
    path = root / value
    # Check unresolved ancestors as well as the resolved destination.
    _require(path.is_absolute() and path.is_relative_to(root / ".infra"))
    _require(not any(p.is_symlink() for p in (path, *path.parents)))
    _require(path.resolve().is_relative_to(root / ".infra") and path.resolve() != root / ".infra")
    return path.resolve()


def execute(root: Path, args: argparse.Namespace) -> None:
    """Fail closed before collection; only a new sanitized receipt is persisted.

    Source review/environment approvals, IAM and credential custody are external
    prerequisites. An enabled tracked flag is necessary, not operational authority.
    """
    try:
        _execute(root.resolve(), args)
    except Exception:
        raise ValueError(MESSAGE) from None


def _execute(root: Path, args: argparse.Namespace) -> None:
    foundation = load_foundation(root)
    contract = describe_preview(foundation, args.unit, args.commit)
    _require(contract.preview_enabled and repository_state(root) == (args.commit, True))
    _require(args.request is not None)
    captured: dict[Path, bytes] = {}

    def read(value: str | Path) -> bytes:
        path = _private(root, value)
        if path not in captured:
            with path.open("rb") as stream:
                raw = stream.read(1024 * 1024 + 1)
            _require(0 < len(raw) <= 1024 * 1024)
            captured[path] = raw
        return captured[path]

    request_raw = read(args.request)
    request = _json(request_raw)
    _require(set(request) == COMMON | EXTRA[args.unit])
    _require(type(request["schema_version"]) is int and request["schema_version"] == 1)
    destination = _private(root, request["output"])
    _require(not destination.exists())
    cli_archive = _private(root, request["cli_archive"])
    provider_home = _private(root, request["provider_home"])
    # Capture every small reviewed input before the first remote observation.
    for key in {
        "configuration",
        "encrypted_configuration",
        "qualification",
        "backend_oci_config",
    } | (EXTRA[args.unit] - {"organizations", "usage_cutoff"}):
        read(request[key])
    configuration = (
        tomllib.loads(read(request["configuration"]).decode())
        if args.unit.startswith("oci-")
        else _json(read(request["configuration"]))
    )
    profiles_raw = (root / "config/quotas/profiles.toml").read_bytes()
    profiles = tomllib.loads(profiles_raw.decode())["profiles"]
    qualification = _json(read(request["qualification"]))
    validate_receipt(foundation, qualification)
    credentials = {
        key: os.environ[key]
        for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "PULUMI_CONFIG_PASSPHRASE")
    }
    _require(all(credentials.values()) and len(credentials["PULUMI_CONFIG_PASSPHRASE"]) >= 20)
    if "AWS_SESSION_TOKEN" in os.environ:
        credentials["AWS_SESSION_TOKEN"] = os.environ["AWS_SESSION_TOKEN"]
    token = ""
    if not args.unit.startswith("oci-"):
        token = os.environ[
            ("CLOUDFLARE" if args.unit == "cloudflare-edge" else "SUPABASE") + "_API_TOKEN"
        ]
        _require(bool(token))
    backend_reader = OCIReader(
        str(_private(root, request["backend_oci_config"])), "DEFAULT", request["backend_account_id"]
    )
    posture, envelope = capture_posture(
        foundation,
        backend_reader.backend_posture(foundation),
        account_id=request["backend_account_id"],
        commit=args.commit,
    )
    validate_posture_evidence(
        foundation,
        posture,
        envelope,
        account_id=request["backend_account_id"],
        commit=args.commit,
    )
    context: Context
    dependency = None
    if args.unit.startswith("oci-"):
        cfg = parse_config(configuration)
        account = tomllib.loads(read(request["account"]).decode())
        profile = profiles[account["profile"]]
        reader = OCIReader(
            str(_private(root, request["oci_config"])), "DEFAULT", account["account_id"]
        )
        cutoff = timestamp(request["usage_cutoff"], "usage cutoff")
        usage = _json(read(request["usage"]))
        _require(account["account_id"] == usage["account_id"] and usage["provider"] == "oci")
        _require(cutoff <= timestamp(usage["covered_through"], "independent coverage"))
        observed = collect_usage(
            reader, account["account_id"], account["home_region"], cutoff=cutoff
        )
        _require(observed.covered_through is None and bool(observed.observations))
        for metric, value in observed.totals:
            _require(
                value is not None
                and number(usage["values"][metric], metric) >= number(value, metric)
            )
        # Preserve the independent watermark and source clocks, never promote query completion.
        usage["source"] += (
            "; supplemental-usage-sha256="
            + hashlib.sha256(read(request["usage"])).hexdigest()
            + "; usage-observations-sha256="
            + hashlib.sha256(
                json.dumps(
                    [(o.request_sha256, o.response_sha256) for o in observed.observations]
                ).encode()
            ).hexdigest()
        )
        inventory, sidecar = capture_inventory(
            account,
            profile,
            collect(reader, account["account_id"], account["home_region"], usage=usage),
            commit=args.commit,
        )
        cls = OkePreviewContext if args.unit == "oci-oke" else NetworkPreviewContext
        context = cls(foundation, contract, args.commit, cfg, account, profile, inventory, sidecar)
        if args.unit == "oci-oke":
            dependency = read(request["dependency_outputs"])
        _require(not reader.config.get("pass_phrase") and not reader.config.get("key_content"))
        credentials.update(
            {
                "OCI_USER_OCID": reader.config["user"],
                "OCI_FINGERPRINT": reader.config["fingerprint"],
                "OCI_PRIVATE_KEY_PATH": str(Path(reader.config["key_file"]).resolve()),
            }
        )
    else:
        provider = "cloudflare" if args.unit == "cloudflare-edge" else "supabase"
        _require(configuration["provider"] == provider and configuration["unit"] == args.unit)
        profile = profiles[provider + "-free"]
        if provider == "cloudflare":
            review = _json(read(request["review"]))
            zone = collect_zone(
                configuration["account_id"],
                configuration["scope_id"],
                review["scope_name"],
                token=token,
            )
            payload, sidecar = capture_cloudflare_evidence(
                configuration, profile, zone, review, commit=args.commit
            )
        else:
            organizations = request["organizations"]
            _require(
                isinstance(organizations, list) and all(isinstance(x, str) for x in organizations)
            )
            management = collect_management(
                configuration["account_id"], tuple(organizations), token=token
            )
            payload, sidecar = capture_supabase_evidence(
                configuration,
                profile,
                management,
                read(request["supplement"]),
                commit=args.commit,
            )
        context = ServicePreviewContext(
            foundation, contract, args.commit, configuration, profile, payload, sidecar
        )

    def recheck() -> None:
        _require(
            repository_state(root) == (args.commit, True) and load_foundation(root) == foundation
        )
        _require((root / "config/quotas/profiles.toml").read_bytes() == profiles_raw)
        for path, original in captured.items():
            with _private(root, path).open("rb") as stream:
                _require(stream.read(len(original) + 1) == original)
        validate_receipt(foundation, qualification)
        validate_posture_evidence(
            foundation,
            posture,
            envelope,
            account_id=request["backend_account_id"],
            commit=args.commit,
        )

    recheck()
    receipt = run_preview(
        root,
        context,
        cli_archive=cli_archive,
        provider_home=provider_home,
        encrypted_configuration=read(request["encrypted_configuration"]),
        credentials=credentials,
        dependency_outputs=dependency,
    )
    recheck()
    report = json.dumps(
        {
            "schema_version": 1,
            "kind": "preview-orchestration",
            "preview_result": _json(receipt),
            "request_sha256": hashlib.sha256(request_raw).hexdigest(),
            "qualification_sha256": hashlib.sha256(read(request["qualification"])).hexdigest(),
            "posture_sha256": hashlib.sha256(posture).hexdigest(),
            "posture_envelope_sha256": hashlib.sha256(envelope).hexdigest(),
            "deployment_authorized": False,
            "cutover_authorized": False,
        },
        sort_keys=True,
        allow_nan=False,
    ).encode()
    _require(len(report) <= 65536)
    _private(root, destination).parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(report)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    print("PASS: preview receipt saved; deployment and cutover remain disabled")
