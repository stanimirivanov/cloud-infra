"""Backend trust boundaries, state isolation and qualification failure regressions."""

import hashlib
import json
import os
import subprocess
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from importlib.metadata import version
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml
from evidence_helpers import recovery_metrics
from infra_core import backend, cli
from infra_core.foundation import deny_deployment, load_foundation

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def config():
    return load_foundation(ROOT)


@pytest.mark.parametrize(
    "change",
    [
        {"prefix": "01-infrastructure"},
        {"prefix": "pulumi/../terraform"},
        {"bucket": "other/path"},
        {"region": "eu-frankfurt-2"},
        {"endpoint": "http://frx.compat.objectstorage.eu-frankfurt-1.oraclecloud.com"},
        {
            "endpoint": "https://user:password@frx.compat.objectstorage.eu-frankfurt-1.oraclecloud.com"
        },
        {"endpoint": "https://attacker.example"},
        {"endpoint": "https://frx.compat.objectstorage.eu-frankfurt-1.oraclecloud.com?secret=x"},
    ],
)
def test_backend_rejects_unsafe_namespace_or_endpoint(config, change):
    with pytest.raises(ValueError):
        replace(config.backend, **change)


def test_qualification_namespace_is_unique_and_https_path_style(config):
    url = urlsplit(config.backend.url("a" * 32))
    assert url.path == "/pulumi/qualification/" + "a" * 32
    assert parse_qs(url.query)["s3ForcePathStyle"] == ["true"]
    with pytest.raises(ValueError):
        config.backend.url("../escape")
    assert config.pulumi_version == version("pulumi")


@pytest.mark.parametrize("unit", ["oci-network", "oci-oke", "cloudflare-edge", "supabase-database"])
def test_units_are_disabled_even_without_external_tools(config, unit):
    with pytest.raises(RuntimeError, match="disabled"):
        deny_deployment(config, unit)


@pytest.mark.parametrize("operation", ["preview", "deploy"])
def test_cli_cannot_start_resource_operations(monkeypatch, capsys, operation):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("unexpected process"))
    assert cli.main(["--root", str(ROOT), operation, "--unit", "oci-network"]) == 1
    assert "disabled" in capsys.readouterr().err


def test_no_write_flag_preserves_existing_evidence(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config/pulumi.toml").write_bytes((ROOT / "config/pulumi.toml").read_bytes())
    (tmp_path / "pyproject.toml").write_text('[project]\nname="oci-oke-infrastructure"\n')
    (tmp_path / ".infra").mkdir()
    evidence = tmp_path / ".infra/qualification.json"
    evidence.write_text("existing")
    assert cli.main(["--root", str(tmp_path), "backend", "qualify"]) == 1
    assert evidence.read_text() == "existing"


def test_explicit_write_consent_required(config):
    with pytest.raises(backend.QualificationError, match="allow-backend-writes"):
        backend.qualify(config, local=True, allow_writes=False)


def test_remote_credentials_are_required_without_ambient_fallback(tmp_path):
    with pytest.raises(backend.QualificationError, match="AWS_ACCESS_KEY_ID"):
        backend.qualification_environment({}, tmp_path, local=False)
    source = {
        "AWS_ACCESS_KEY_ID": "hmac-id",
        "AWS_SECRET_ACCESS_KEY": "hmac-secret",
        "PULUMI_CONFIG_PASSPHRASE": "x" * 30,
        "OCI_CLI_KEY_CONTENT": "real-key",
        "PULUMI_BACKEND_URL": "https://unexpected",
        "AWS_PROFILE": "ambient",
        "PULUMI_CONFIG_PASSPHRASE_FILE": "unexpected",
        "BACKEND_POSTURE_JSON": "private evidence",
        "BACKEND_POSTURE_ENVELOPE_JSON": "private sidecar",
        "PATH": "tools",
    }
    env = backend.qualification_environment(source, tmp_path, local=False)
    assert env["PULUMI_HOME"] == str(tmp_path)
    assert env["AWS_ACCESS_KEY_ID"] == "hmac-id"
    assert env["AWS_EC2_METADATA_DISABLED"] == "true"
    assert all(
        key not in env
        for key in (
            "OCI_CLI_KEY_CONTENT",
            "PULUMI_BACKEND_URL",
            "AWS_PROFILE",
            "PULUMI_CONFIG_PASSPHRASE_FILE",
            "BACKEND_POSTURE_JSON",
            "BACKEND_POSTURE_ENVELOPE_JSON",
        )
    )


def test_raw_cli_output_is_never_returned_on_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a[0], 1, stdout="SECRET_VALUE", stderr="SECRET_VALUE"
        ),
    )
    with pytest.raises(backend.QualificationError, match="raw output withheld") as failure:
        backend.PulumiSession(tmp_path, {}).run("readback", ["stack", "output"])
    assert "SECRET_VALUE" not in str(failure.value)


def receipt(config):
    return {
        "schema_version": 3,
        "run_id": "a" * 32,
        "recovery": recovery_metrics(),
        "kind": "oci-s3",
        "configuration_sha256": config.digest,
        "pulumi_version": config.pulumi_version,
        "completed_at": datetime.now(UTC).isoformat(),
        "checks": [
            "encrypted-config",
            "encrypted-checkpoint",
            "lock-contention",
            "restore-readback",
            "independent-recovery",
            "wrong-passphrase-rejected",
        ],
        "deployment_authorized": False,
    }


@pytest.mark.parametrize(
    "change",
    [
        {"kind": "local"},
        {"configuration_sha256": "different"},
        {"pulumi_version": "0.0.0"},
        {"checks": []},
        {"deployment_authorized": True},
        {"completed_at": (datetime.now(UTC) - timedelta(days=2)).isoformat()},
        {"completed_at": (datetime.now(UTC) + timedelta(days=1)).isoformat()},
    ],
)
def test_receipt_rejects_local_stale_or_mismatched_evidence(config, change):
    with pytest.raises((ValueError, backend.QualificationError)):
        backend.validate_receipt(config, receipt(config) | change)


def test_receipt_binding_is_not_resource_authorization(config):
    backend.validate_receipt(config, receipt(config))
    with pytest.raises(RuntimeError):
        deny_deployment(config, "oci-network")


@pytest.mark.parametrize(
    "bad_phase",
    [
        "preview",
        "checkpoint",
        "simulate-loss",
        "recovery-login",
        "recovery-initialize",
        "restore",
        "wrong-passphrase-login",
        "wrong-passphrase-check",
        "readback",
        "cleanup",
    ],
)
def test_failed_qualification_never_returns_success_and_cleans_own_stack(
    config, monkeypatch, bad_phase
):
    events = []

    class FakeSession:
        sentinel = None

        def __init__(self, cwd, env):
            self.cwd, self.env = cwd, env

        def run(self, phase, args):
            events.append((phase, args))
            if phase == bad_phase:
                raise backend.QualificationError("synthetic phase failure")
            if phase == "version":
                return "v" + config.pulumi_version
            if phase == "initialize":
                assert args[-2:] == ["--secrets-provider", config.secrets_provider]
                (self.cwd / f"Pulumi.{args[2]}.yaml").write_text("encrypted")
            if phase == "configure":
                FakeSession.sentinel = args[3]
            if phase == "export":
                return json.dumps(
                    {
                        "deployment": {
                            "resources": [
                                {
                                    "type": "pulumi:pulumi:Stack",
                                    "outputs": {"sentinel": {"ciphertext": "x"}},
                                }
                            ]
                        }
                    }
                )
            if phase == "readback":
                return json.dumps(FakeSession.sentinel)
            return ""

        def check_decryption_rejected(self, stack, sentinel):
            events.append(("wrong-passphrase-check", [stack]))
            if bad_phase == "wrong-passphrase-check":
                raise backend.QualificationError("synthetic rejection failure")

        def check_lock(self, stack, marker):
            events.append(("locking", [stack]))

    monkeypatch.setattr(backend, "PulumiSession", FakeSession)
    with pytest.raises(backend.QualificationError):
        backend.qualify(config, local=True, allow_writes=True)
    cleanup = [args for phase, args in events if phase == "cleanup"]
    assert len(cleanup) == 1
    assert cleanup[0][2].startswith("qualification-")
    assert "--force" not in cleanup[0]


def test_protected_workflow_has_no_pr_trigger_or_resource_credentials(config):
    text = (ROOT / ".github/workflows/pulumi.yml").read_text()
    workflow = yaml.load(text, Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"]["cancel-in-progress"] == "false"
    job = workflow["jobs"]["foundation"]
    assert job["needs"] == "verify"
    assert job["environment"] == "pulumi-backend-qualification"
    assert "refs/heads/main" in job["if"] and "github.repository_owner" in job["if"]
    steps = job["steps"]
    setup = next(step for step in steps if step.get("name") == "Install checksum-verified tools")
    assert setup["run"] == "./.github/scripts/install-tools.ps1"
    assert setup["shell"] == "pwsh"
    assert not any(
        name in text for name in ("OCI_CLI_KEY_CONTENT", "PULUMI_ACCESS_TOKEN", "state push")
    )
    secret_steps = [step for step in steps if "secrets." in str(step)]
    assert len(secret_steps) == 2
    assert secret_steps[0]["if"] == "inputs.operation == 'audit' || inputs.operation == 'qualify'"
    assert secret_steps[1]["if"] == "inputs.operation == 'qualify'"
    artifact = next(
        step for step in steps if step.get("uses", "").startswith("actions/upload-artifact")
    )
    assert artifact["with"]["path"] == ".infra/qualification.json"


@pytest.mark.backend_integration
@pytest.mark.skipif(
    os.environ.get("RUN_PULUMI_LOCAL_QUALIFICATION") != "1", reason="explicit local-backend opt-in"
)
def test_real_local_backend_encryption_lock_and_recovery(config):
    evidence = backend.qualify(config, local=True, allow_writes=True)
    assert evidence["schema_version"] == 3
    assert evidence["recovery"]["restore_seconds"] > 0
    assert evidence["recovery"]["backup_age_seconds"] >= 0
    assert "independent-recovery" in evidence["checks"]
    assert "wrong-passphrase-rejected" in evidence["checks"]
    assert evidence["kind"] == "local"
    assert evidence["deployment_authorized"] is False
    with pytest.raises(backend.QualificationError):
        backend.validate_receipt(config, evidence)


@pytest.mark.parametrize("replacement", ["enabled = true", 'enabled = "false"'])
def test_configuration_cannot_enable_units(tmp_path, replacement):
    (tmp_path / "config").mkdir()
    text = (ROOT / "config/pulumi.toml").read_text().replace("enabled = false", replacement)
    (tmp_path / "config/pulumi.toml").write_text(text)
    with pytest.raises(ValueError, match="disabled"):
        load_foundation(tmp_path)


def test_failed_cli_retry_removes_stale_success_without_emitting_receipt(tmp_path, monkeypatch):
    (tmp_path / "config").mkdir()
    (tmp_path / "config/pulumi.toml").write_bytes((ROOT / "config/pulumi.toml").read_bytes())
    (tmp_path / "pyproject.toml").write_text('[project]\nname="oci-oke-infrastructure"\n')
    (tmp_path / ".infra").mkdir()
    evidence = tmp_path / ".infra/qualification.json"
    evidence.write_text("stale-success")

    def fail(*args, **kwargs):
        raise backend.QualificationError("deliberate failure")

    monkeypatch.setattr(cli, "qualify", fail)
    assert cli.main(["--root", str(tmp_path), "backend", "qualify", "--allow-backend-writes"]) == 1
    assert not evidence.exists()


def test_cli_rejects_receipt_path_escape_before_backend_call(monkeypatch):
    monkeypatch.setattr(cli, "qualify", lambda *a, **kw: pytest.fail("unexpected backend call"))
    assert (
        cli.main(
            [
                "--root",
                str(ROOT),
                "backend",
                "qualify",
                "--allow-backend-writes",
                "--receipt",
                "../escape.json",
            ]
        )
        == 1
    )


def test_inspection_needs_no_credentials_or_cli(monkeypatch, capsys):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("unexpected process"))
    assert cli.main(["--root", str(ROOT), "backend", "inspect"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["deployment_enabled"] is False
    assert output["backend"].startswith("s3://kishu-tf-state/pulumi?")


@pytest.mark.parametrize(
    "change",
    [
        ("schema_version = 3", "schema_version = 2"),
        ('secrets_provider = "passphrase"', ""),
        ('secrets_provider = "passphrase"', 'secrets_provider = "default"'),
        ('secrets_provider = "passphrase"', 'secrets_provider = "awskms://key"'),
        ('secrets_provider = "passphrase"', "secrets_provider = true"),
        ('secrets_provider = "passphrase"', 'secrets_provider = "passphrase"\nextra = "field"'),
    ],
)
def test_foundation_requires_closed_explicit_encryption_policy(tmp_path, change):
    (tmp_path / "config").mkdir()
    source = (ROOT / "config/pulumi.toml").read_text(encoding="utf-8")
    (tmp_path / "config/pulumi.toml").write_text(source.replace(*change), encoding="utf-8")
    with pytest.raises(ValueError):
        load_foundation(tmp_path)


def test_encryption_policy_is_bound_to_receipts_and_cannot_be_replaced(config):
    assert config.secrets_provider == "passphrase"
    old_configuration = asdict(config)
    del old_configuration["secrets_provider"]
    old_digest = hashlib.sha256(json.dumps(old_configuration, sort_keys=True).encode()).hexdigest()
    assert config.digest != old_digest
    with pytest.raises(backend.QualificationError):
        backend.validate_receipt(config, receipt(config) | {"configuration_sha256": old_digest})
    with pytest.raises(ValueError, match="SECRET001"):
        replace(config, secrets_provider="default")
