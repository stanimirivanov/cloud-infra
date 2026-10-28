"""CLI admission, collector handoff and no stale/secret output; no cloud or CLI runs."""

import json
import subprocess
import sys
import tomllib
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_backend
import test_cloudflare_collection as cf
import test_oci
import test_supabase_collection as sb
from infra_core import cli as core_cli
from infra_core.foundation import load_foundation
from infra_core.inventory.oci_usage import UsageCollection
from infra_core.inventory_evidence import validate_inventory_evidence
from infra_core.provider_evidence import record_observation
from infra_core.service_evidence import validate_service_evidence
from infra_program import cli
from infra_program import preview_orchestration as op
from infra_program.preview_program import OkePreviewContext, ServicePreviewContext
from test_cloudflare_collection import network as cf_network  # noqa: F401
from test_supabase_collection import network as sb_network  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "c" * 40


def toml(values):
    return "\n".join(f"{key} = {json.dumps(value)}" for key, value in values.items())


@pytest.fixture(params=list(op.EXTRA))
def case(request, tmp_path, monkeypatch):
    request.getfixturevalue("cf_network")
    request.getfixturevalue("sb_network")
    unit = request.param
    root = tmp_path
    (root / ".infra").mkdir()
    (root / "config/quotas").mkdir(parents=True)
    profiles = (ROOT / "config/quotas/profiles.toml").read_bytes()
    (root / "config/quotas/profiles.toml").write_bytes(profiles)
    foundation = load_foundation(ROOT)
    foundation = replace(
        foundation, units=tuple(replace(u, preview_enabled=True) for u in foundation.units)
    )
    monkeypatch.setattr(op, "load_foundation", lambda root: foundation)
    monkeypatch.setattr(op, "repository_state", lambda root: (COMMIT, True))
    state = SimpleNamespace(root=root, unit=unit, calls=[], fault=None, context=None, settings=None)

    def save(name, value):
        path = root / ".infra" / name
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        return str(path)

    inputs = {
        key: save(key + ".json", {})
        for key in op.COMMON - {"schema_version", "backend_account_id", "provider_home", "output"}
    }
    inputs.update(
        schema_version=1,
        backend_account_id="backend-tenancy",
        provider_home=".infra/home",
        output=".infra/result.json",
    )
    inputs["qualification"] = save("qualification.json", test_backend.receipt(foundation))
    if unit == "cloudflare-edge":
        proposal, _, review = cf.reviewed.__wrapped__()
        inputs["review"] = save("review.json", review)
    elif unit == "supabase-database":
        proposal, _, supplement = sb.supplement.__wrapped__()
        inputs.update(
            supplement=save("supplement.json", supplement), organizations=[sb.ORG, "paid-org"]
        )
    else:
        cfg = test_oci.config.__wrapped__()
        values = asdict(cfg)
        image = values.pop("image")
        proposal = b"[foundation]\n" + toml(values).encode() + b"\n[image]\n" + toml(image).encode()
        account, _, inventory = test_oci.evidence()
        inputs.update(
            account=save("account.toml", toml(account).encode()),
            usage=save("usage.json", inventory["usage"]),
            usage_cutoff=inventory["usage"]["covered_through"],
            oci_config=save("oci-config", b"synthetic"),
        )
        if unit == "oci-oke":
            inputs["dependency_outputs"] = save("dependency.json", {"captured": True})
    inputs["configuration"] = save("configuration", proposal)
    state.inputs, state.request_path = inputs, root / ".infra/request.json"
    state.request_path.write_text(json.dumps(inputs))
    for key in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "PULUMI_CONFIG_PASSPHRASE",
        "CLOUDFLARE_API_TOKEN",
        "SUPABASE_API_TOKEN",
    ):
        monkeypatch.setenv(
            key, "synthetic-token" if key.endswith("API_TOKEN") else "synthetic-credential-value"
        )
    monkeypatch.setenv("PULUMI_DEBUG_COMMANDS", "must-not-forward")

    class Reader:
        def __init__(self, path, profile, tenancy):
            state.calls.append("reader")
            assert profile == "DEFAULT"
            self.config = dict(
                user="user",
                fingerprint="fingerprint",
                key_file=inputs["oci_config"] if unit.startswith("oci-") else "unused",
            )

        def backend_posture(self, config):
            state.calls.append("posture")
            if state.fault == "collect":
                raise RuntimeError("private-source-token")
            clock = datetime.now(UTC).isoformat()
            return dict(
                schema_version=1,
                configuration_sha256=config.digest,
                account_id="backend-tenancy",
                namespace=config.backend.endpoint.split("//")[1].split(".")[0],
                bucket=config.backend.bucket,
                region=config.backend.region,
                collection_started_at=clock,
                collection_completed_at=clock,
                public_access_type="NoPublicAccess",
                versioning="Disabled" if state.fault == "posture" else "Enabled",
                storage_tier="Standard",
                is_read_only=False,
                lifecycle_policy_etag=None,
                retention_rule_count=0,
                preauthenticated_request_count=0,
            )

        def list(self, operation, **kwargs):
            if operation == "regions":
                return [dict(region_name="eu-frankfurt-1", status="READY", is_home_region=True)]
            if operation == "ads":
                return [dict(name="synthetic-ad")]
            return []

    def usage(reader, account, region, *, cutoff):
        state.calls.append("usage")
        clock = datetime.now(UTC)
        observation = record_observation(
            "oci", b"query", b"response", started=clock, finished=clock
        )
        return UsageCollection(
            account,
            cutoff,
            cutoff,
            (observation,),
            tuple(
                (
                    metric,
                    None
                    if state.fault == "unknown"
                    else "1"
                    if state.fault == "understated"
                    else "0",
                )
                for metric in inventory["usage"]["values"]
            ),
        )

    def preview(root, context, **kwargs):
        state.calls.append("preview")
        state.context, state.settings = context, kwargs
        if isinstance(context, ServicePreviewContext):
            validate_service_evidence(
                context.proposal, context.profile, context.evidence, context.envelope, commit=COMMIT
            )
        else:
            data = validate_inventory_evidence(
                context.account, context.profile, context.inventory, context.envelope, commit=COMMIT
            )
            assert data["usage"]["covered_through"] == inventory["usage"]["covered_through"]
            assert "supplemental-usage-sha256=" in data["usage"]["source"]
        assert "PULUMI_DEBUG_COMMANDS" not in kwargs["credentials"]
        if state.fault == "runtime":
            raise RuntimeError("private-runtime-token")
        if state.fault == "changed":
            Path(inputs["configuration"]).write_text("changed")
        return b'{"deployment_authorized":false,"cutover_authorized":false}'

    monkeypatch.setattr(op, "OCIReader", Reader)
    monkeypatch.setattr(op, "collect_usage", usage)
    monkeypatch.setattr(op, "run_preview", preview)
    return state


def invoke(case):
    return cli.main(
        [
            "--root",
            str(case.root),
            "preview",
            "--unit",
            case.unit,
            "--commit",
            COMMIT,
            "--request",
            str(case.request_path),
        ]
    )


def test_four_unit_cli_handoff_and_private_receipt(case, monkeypatch, capsys):
    monkeypatch.setattr(core_cli, "find_repository", lambda root: case.root)
    assert invoke(case) == 0
    output = capsys.readouterr()
    assert output.err == "" and "PASS:" in output.out and "synthetic-credential" not in output.out
    report = json.loads((case.root / ".infra/result.json").read_bytes())
    assert report["deployment_authorized"] is report["cutover_authorized"] is False
    assert case.calls.index("posture") < case.calls.index("preview")
    assert isinstance(case.context, OkePreviewContext) == (case.unit == "oci-oke")
    assert (case.settings["dependency_outputs"] is not None) == (case.unit == "oci-oke")
    # Exclusive destination: a retry neither collects nor overwrites old success.
    case.calls.clear()
    assert invoke(case) == 1 and case.calls == []


@pytest.mark.parametrize(
    "fault",
    [
        "disabled",
        "dirty",
        "commit",
        "qualification",
        "posture",
        "collect",
        "runtime",
        "changed",
        "unknown-field",
        "missing-file",
        "oversize",
        "escape",
        "coverage",
        "credentials",
        "duplicate",
        "changed-before",
        "unknown",
        "understated",
    ],
)
def test_failures_never_publish_success_or_raw_diagnostics(case, fault, monkeypatch, capsys):
    monkeypatch.setattr(core_cli, "find_repository", lambda root: case.root)
    case.fault = fault
    if fault == "disabled":
        monkeypatch.setattr(op, "load_foundation", lambda root: load_foundation(ROOT))
    elif fault in ("dirty", "commit"):
        monkeypatch.setattr(
            op,
            "repository_state",
            lambda root: ("d" * 40 if fault == "commit" else COMMIT, fault != "dirty"),
        )
    elif fault == "qualification":
        Path(case.inputs["qualification"]).write_text("{}")
    elif fault == "missing-file":
        Path(case.inputs["configuration"]).unlink()
    elif fault == "oversize":
        Path(case.inputs["configuration"]).write_bytes(b"x" * (1024 * 1024 + 1))
    elif fault in ("escape", "unknown-field"):
        case.inputs["configuration" if fault == "escape" else "extra"] = "../outside.json"
        case.request_path.write_text(json.dumps(case.inputs))
    elif fault == "duplicate":
        case.request_path.write_text('{"schema_version":1,"schema_version":1}')
    elif fault == "credentials":
        monkeypatch.delenv("AWS_ACCESS_KEY_ID")
    elif fault == "changed-before":
        original = op.capture_posture

        def change(*args, **kwargs):
            result = original(*args, **kwargs)
            Path(case.inputs["configuration"]).write_text("changed")
            return result

        monkeypatch.setattr(op, "capture_posture", change)
    elif fault == "coverage":
        key = (
            "usage"
            if case.unit.startswith("oci-")
            else "review"
            if case.unit == "cloudflare-edge"
            else "supplement"
        )
        Path(case.inputs[key]).write_text("{}")
    elif fault in ("unknown", "understated") and not case.unit.startswith("oci-"):
        pytest.skip("OCI-only metric fault")
    assert invoke(case) == 1
    output = capsys.readouterr()
    assert output.out == "" and output.err.strip() == "FAIL: " + op.MESSAGE
    assert not (case.root / ".infra/result.json").exists()
    if fault in (
        "disabled",
        "dirty",
        "commit",
        "qualification",
        "unknown-field",
        "missing-file",
        "oversize",
        "escape",
        "duplicate",
        "credentials",
    ):
        assert case.calls == []


def test_core_without_composition_still_denies_preview(capsys):
    assert core_cli.main(["--root", str(ROOT), "preview", "--unit", "cloudflare-edge"]) == 1
    assert "disabled" in capsys.readouterr().err


def test_normal_composition_cannot_activate_tracked_units(monkeypatch, capsys):
    monkeypatch.setattr(op, "OCIReader", lambda *args: pytest.fail("unexpected collection"))
    monkeypatch.setattr(op, "run_preview", lambda *args: pytest.fail("unexpected preview"))
    assert (
        cli.main(["--root", str(ROOT), "preview", "--unit", "cloudflare-edge", "--commit", COMMIT])
        == 1
    )
    assert capsys.readouterr().err.strip() == "FAIL: " + op.MESSAGE


def test_console_composition_is_owned_by_program_package():
    core = tomllib.loads((ROOT / "packages/infra-core/pyproject.toml").read_text())
    program = tomllib.loads((ROOT / "packages/infra-program/pyproject.toml").read_text())
    assert "scripts" not in core["project"]
    assert program["project"]["scripts"]["infra"] == "infra_program.cli:main"


def test_offline_composition_keeps_pulumi_unloaded():
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from infra_program.cli import main; "
            "assert main(['backend','inspect']) == 0; assert 'pulumi' not in sys.modules",
        ],
        cwd=ROOT,
        capture_output=True,
        check=True,
        timeout=30,
    )
