"""Owned existing-stack preview executor; protected operational admission remains external."""

import hashlib
import json
import os
import sys
import tempfile
import time
import tomllib
from copy import deepcopy
from dataclasses import asdict, fields, replace
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

import infra_core
import pulumi_supabase
from infra_core.cutover import repository_state
from infra_core.evidence import MAX_TOTAL_BYTES
from infra_core.foundation import load_foundation
from infra_core.oci.config import FoundationConfig as OciConfig
from infra_core.oci.config import ImageEvidence
from infra_core.oci.graph import NETWORK_UNIT, OKE_UNIT, network_graph, oke_graph, proposal
from infra_core.preview_contracts import PreviewContract, describe_preview
from infra_core.preview_results import create_preview_result, preview_input_digests
from infra_core.provider_tools import (
    materialize_home,
    verified_environment,
    verified_supabase_environment,
)
from infra_core.service_evidence import validate_service_evidence
from pulumi import automation as auto

from infra_program.governance import preflight
from infra_program.oci.dependencies import network_digest, validate_network
from infra_program.preview_program import (
    NetworkPreviewContext,
    OkePreviewContext,
    ServicePreviewContext,
    dispatch_preview,
)
from infra_program.preview_runtime import MESSAGE, Command, Stack, cli_runtime, require

Context = ServicePreviewContext | NetworkPreviewContext | OkePreviewContext
REQUEST_LIMIT = 2 * MAX_TOTAL_BYTES + 65536
SOURCES = (
    "policies/__main__.py",
    "policies/PulumiPolicy.yaml",
    "packages/infra-program/src/infra_program/governance.py",
    "uv.lock",
    ".python-version",
    "packages/infra-program/src/infra_program/preview_driver.py",
    "packages/infra-program/src/infra_program/preview_runtime.py",
)


def _encoded(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    require(len(dict(pairs)) == len(pairs))
    return dict(pairs)


def _invalid(value: str) -> Any:
    raise RuntimeError(MESSAGE)


def _json(content: bytes, limit: int) -> dict[str, Any]:
    require(type(content) is bytes and 0 < len(content) <= limit)
    value = json.loads(content, object_pairs_hook=_unique, parse_constant=_invalid)
    require(type(value) is dict)
    assert isinstance(value, dict)
    return value


def _read(path: Path, limit: int) -> bytes:
    require(not path.is_symlink() and not path.is_junction())
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    require(len(value) <= limit)
    return value


def _checkout(root: Path) -> None:
    require(
        Path(__file__).resolve().parents[4] == root
        and Path(infra_core.__file__ or "")
        .resolve()
        .is_relative_to(root / "packages/infra-core/src")
        and Path(pulumi_supabase.__file__ or "").resolve().is_relative_to(root / "sdks/supabase")
        and Path(sys.prefix).resolve() == (root / ".venv").resolve()
    )
    require(
        ".".join(map(str, sys.version_info[:3])) == (root / ".python-version").read_text().strip()
    )


def _contract(root: Path, context: Context) -> None:
    require(type(context) in {ServicePreviewContext, NetworkPreviewContext, OkePreviewContext})
    expected = (
        OkePreviewContext
        if context.contract.unit == OKE_UNIT
        else NetworkPreviewContext
        if context.contract.unit == NETWORK_UNIT
        else ServicePreviewContext
    )
    require(type(context) is expected)
    foundation = load_foundation(root)
    require(
        foundation == context.foundation
        and context.contract.preview_enabled is True
        and describe_preview(foundation, context.contract.unit, context.expected_commit)
        == context.contract
    )


def _stack_config(context: Context, content: bytes) -> dict[str, Any]:
    value = _json(content, 1024 * 1024)
    require(
        set(value) == {"encryptionsalt", "config"}
        and type(value["encryptionsalt"]) is str
        and value["encryptionsalt"].startswith("v1:")
        and len(value["encryptionsalt"]) > 3
    )
    keys: set[str] = set()
    if isinstance(context, ServicePreviewContext):
        keys.add(context.contract.unit + ":token")
        if context.contract.unit == "supabase-database":
            keys.update(
                context.contract.unit + ":databasePassword-" + r["key"]
                for r in context.proposal["resources"]
            )
    require(type(value["config"]) is dict and set(value["config"]) == keys)
    for secret in value["config"].values():
        require(
            type(secret) is dict
            and set(secret) == {"secure"}
            and type(secret["secure"]) is str
            and secret["secure"].startswith("v1:")
            and len(secret["secure"]) > 3
        )
    return value


def _prepare(
    root: Path, context: Context, ciphertext: bytes, dependency: bytes | None
) -> tuple[Context, dict[str, bytes], dict[str, Any]]:
    artifacts = {"profile": _encoded(context.profile), "envelope": context.envelope}
    if isinstance(context, ServicePreviewContext):
        require(
            context.proposal.get("unit") == context.contract.unit
            and context.proposal.get("provider")
            == ("supabase" if context.contract.unit == "supabase-database" else "cloudflare")
        )
        validate_service_evidence(
            context.proposal,
            context.profile,
            context.evidence,
            context.envelope,
            commit=context.expected_commit,
        )
        configuration = context.proposal
        artifacts["evidence"] = context.evidence
    else:
        cfg = context.configuration
        graph = oke_graph(cfg) if type(context) is OkePreviewContext else network_graph(cfg)
        unit = OKE_UNIT if type(context) is OkePreviewContext else NETWORK_UNIT
        preflight(
            context.account,
            context.profile,
            context.inventory,
            proposal(graph, context.account["account_id"], cfg.region, units=(unit,)),
            lambda: None,
            envelope=context.envelope,
            commit=context.expected_commit,
        )
        configuration = asdict(cfg)
        artifacts.update(account=_encoded(context.account), evidence=context.inventory)
        if type(context) is OkePreviewContext:
            require(type(dependency) is bytes)
            assert dependency is not None
            observed = _json(dependency, 65536)
            validate_network(observed, cfg, context.account["account_id"])
            digest = network_digest(observed)
            require(context.expected_network_sha256 in (None, digest))
            context = replace(context, expected_network_sha256=digest)
            artifacts["dependency_outputs"] = dependency
    require((dependency is not None) == (type(context) is OkePreviewContext))
    settings = _stack_config(context, ciphertext)
    artifacts["proposal"] = _encoded(
        {"configuration": configuration, "stack_configuration": settings}
    )
    for key in ("toolchain", "provider_toolchain"):
        artifacts[key] = _read(root / "config" / (key.replace("_", "-") + ".json"), 65536)
    artifacts["policy"] = _encoded(
        {p: hashlib.sha256(_read(root / p, MAX_TOTAL_BYTES)).hexdigest() for p in SOURCES}
    )
    preview_input_digests(context.contract, artifacts)
    return context, artifacts, settings


def _request(
    root: Path, context: Context, artifacts: dict[str, bytes], dependency: bytes | None
) -> bytes:
    payload = asdict(context)
    payload.pop("foundation")
    for key in ("evidence", "inventory", "envelope"):
        if key in payload:
            payload[key] = payload[key].hex()
    result = _encoded(
        {
            "root": str(root),
            "context": payload,
            "input_digests": preview_input_digests(context.contract, artifacts),
            "dependency_hex": dependency.hex() if dependency is not None else None,
        }
    )
    require(len(result) <= REQUEST_LIMIT)
    return result


def _versions(root: Path, context: Context, artifacts: dict[str, bytes]) -> None:
    pins = json.loads(artifacts["provider_toolchain"])
    lock = tomllib.loads(_read(root / "uv.lock", MAX_TOTAL_BYTES).decode())
    expected = {
        "pulumi": context.foundation.pulumi_version,
        "pulumi-oci": pins["providers"]["oci"]["version"],
        "pulumi-cloudflare": pins["providers"]["cloudflare"]["version"],
        "pulumi-supabase": pins["downstream"]["version"],
        "pulumi-policy": next(
            p["version"] for p in lock["package"] if p["name"] == "pulumi-policy"
        ),
    }
    require(
        json.loads(artifacts["toolchain"])["tools"]["pulumi"]["version"] == expected["pulumi"]
        and all(version(p) == v for p, v in expected.items())
    )


def program_from_request() -> None:
    """Owned local-program entry point; no arbitrary callable, pickle or sys.path modification."""
    try:
        request = _json(_read(Path("context.json"), REQUEST_LIMIT), REQUEST_LIMIT)
        require(set(request) == {"root", "context", "input_digests", "dependency_hex"})
        root, payload = Path(request["root"]), request["context"]
        _checkout(root)
        contract = payload["contract"]
        contract["dependency_stacks"] = tuple(contract["dependency_stacks"])
        contract = PreviewContract(**contract)
        cls: type[Context] = (
            OkePreviewContext
            if contract.unit == OKE_UNIT
            else NetworkPreviewContext
            if contract.unit == NETWORK_UNIT
            else ServicePreviewContext
        )
        require(set(payload) == {f.name for f in fields(cls)} - {"foundation"})
        payload["contract"] = contract
        for key in ("evidence", "inventory", "envelope"):
            if key in payload:
                payload[key] = bytes.fromhex(payload[key])
        if cls is not ServicePreviewContext:
            values = payload["configuration"]
            values["image"] = ImageEvidence(**values["image"])
            for key in ("administrator_cidrs", "availability_domains", "supported_versions"):
                values[key] = tuple(values[key])
            payload["configuration"] = OciConfig(**values)
        context = cls(foundation=load_foundation(root), **payload)
        _contract(root, context)
        dependency = (
            bytes.fromhex(request["dependency_hex"])
            if request["dependency_hex"] is not None
            else None
        )
        context, artifacts, _ = _prepare(
            root, context, _read(Path("stack.yaml"), 1024 * 1024), dependency
        )
        require(preview_input_digests(contract, artifacts) == request["input_digests"])
        _versions(root, context, artifacts)
        dispatch_preview(context)
    except Exception:
        raise RuntimeError(MESSAGE) from None


def run_preview(
    root: Path,
    context: Context,
    *,
    cli_archive: Path,
    provider_home: Path,
    encrypted_configuration: bytes,
    credentials: dict[str, str],
    dependency_outputs: bytes | None = None,
) -> bytes:
    """Library only: callers must separately establish protected operational admission."""
    started, deadline = datetime.now(UTC).isoformat(), time.monotonic() + 300
    try:
        return _run(
            root.resolve(),
            deepcopy(context),
            cli_archive,
            provider_home,
            encrypted_configuration,
            dict(credentials),
            dependency_outputs,
            started,
            deadline,
        )
    except Exception:
        raise RuntimeError(MESSAGE) from None


def _run(
    root: Path,
    context: Context,
    cli_archive: Path,
    provider_home: Path,
    ciphertext: bytes,
    credentials: dict[str, str],
    dependency: bytes | None,
    started: str,
    deadline: float,
) -> bytes:
    _checkout(root)
    _contract(root, context)
    require(repository_state(root) == (context.expected_commit, True))
    context, artifacts, settings = _prepare(root, context, ciphertext, dependency)
    _versions(root, context, artifacts)
    required = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "PULUMI_CONFIG_PASSPHRASE"}
    if context.contract.unit.startswith("oci-"):
        required |= {"OCI_USER_OCID", "OCI_FINGERPRINT", "OCI_PRIVATE_KEY_PATH"}
        require(
            Path(credentials.get("OCI_PRIVATE_KEY_PATH", "")).is_absolute()
            and Path(credentials["OCI_PRIVATE_KEY_PATH"]).is_file()
        )
    require(
        required <= set(credentials) <= required | {"AWS_SESSION_TOKEN"}
        and all(type(v) is str and 0 < len(v) <= 65536 for v in credentials.values())
    )
    require(len(credentials["PULUMI_CONFIG_PASSPHRASE"]) >= 20)
    parent = root / ".infra"
    require(not parent.is_symlink() and not parent.is_junction())
    parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="preview-", dir=parent) as directory:
        work = Path(directory)
        require(work.is_absolute() and work.resolve().is_relative_to(parent.resolve()))
        runtime = cli_runtime(root, cli_archive, work / "bin")
        supabase = context.contract.unit == "supabase-database"
        environment = materialize_home(root, provider_home, work / "home", supabase=supabase)
        environment.update(credentials)
        for key in ("SystemRoot", "WINDIR"):
            if key in os.environ:
                environment[key] = os.environ[key]
        environment.update(
            HOME=str(work),
            USERPROFILE=str(work),
            TMP=str(work),
            TEMP=str(work),
            TMPDIR=str(work),
            PATH=os.pathsep.join((str(Path(sys.executable).parent), str(runtime.binary.parent))),
            PULUMI_BACKEND_URL=context.foundation.backend.url(),
            PULUMI_SKIP_UPDATE_CHECK="true",
            PULUMI_DEBUG_COMMANDS="true",
            AWS_EC2_METADATA_DISABLED="true",
        )
        request, config = _request(root, context, artifacts, dependency), _encoded(settings)
        owned = {
            "context.json": request,
            "stack.yaml": config,
            "Pulumi.yaml": _encoded(
                {
                    "name": context.foundation.project,
                    "runtime": {"name": "python", "options": {"virtualenv": sys.prefix}},
                }
            ),
            "__main__.py": (
                b"from infra_program.preview_driver import program_from_request\n"
                b"program_from_request()\n"
            ),
        }
        for name, content in owned.items():
            (work / name).write_bytes(content)
        adapter = Command(
            runtime, work, environment, context.contract.stack_identity, root / "policies"
        )
        adapter.deadline = deadline
        require(time.monotonic() < deadline)
        require(repository_state(root) == (context.expected_commit, True))
        workspace = auto.LocalWorkspace(
            work_dir=str(work), pulumi_home=environment["PULUMI_HOME"], pulumi_command=adapter
        )
        stack = Stack.select(context.contract.stack_identity, workspace)
        stack.preview(
            policy_packs=[str(root / "policies")],
            parallel=1,
            color="never",
            suppress_outputs=True,
            suppress_progress=True,
            refresh=False,
            config_file=str(work / "stack.yaml"),
        )
        runtime.verify()
        (verified_supabase_environment if supabase else verified_environment)(root, work / "home")
        require(all(_read(work / name, len(content)) == content for name, content in owned.items()))
        require(repository_state(root) == (context.expected_commit, True))
        _, after, _ = _prepare(root, context, config, dependency)
        _versions(root, context, after)
        require(
            preview_input_digests(context.contract, artifacts)
            == preview_input_digests(context.contract, after)
        )
        return create_preview_result(
            context.contract,
            artifacts,
            stack.wire.records,
            exit_code=0,
            started_at=started,
            completed_at=datetime.now(UTC).isoformat(),
            now=datetime.now(UTC),
        )
