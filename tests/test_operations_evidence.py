"""Backend posture, measured receipts and independent synthetic recovery contracts."""

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from infra_core import backend
from infra_core.backend_posture import validate_posture
from infra_core.foundation import load_foundation
from infra_core.governance.contracts import GovernanceError
from test_backend import receipt

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def config():
    return load_foundation(ROOT)


@pytest.fixture
def posture(config):
    now = datetime.now(UTC).isoformat()
    return {
        "schema_version": 1,
        "configuration_sha256": config.digest,
        "account_id": "synthetic-tenancy",
        "namespace": config.backend.endpoint.split("//")[1].split(".")[0],
        "bucket": config.backend.bucket,
        "region": config.backend.region,
        "collection_started_at": now,
        "collection_completed_at": now,
        "public_access_type": "NoPublicAccess",
        "versioning": "Enabled",
        "storage_tier": "Standard",
        "is_read_only": False,
        "lifecycle_policy_etag": None,
        "retention_rule_count": 0,
        "preauthenticated_request_count": 0,
    }


def test_valid_posture_is_diagnostic_only(config, posture):
    assert validate_posture(config, posture)["deployment_authorized"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"namespace": "other"},
        {"bucket": "other"},
        {"configuration_sha256": "stale"},
        {"versioning": "Disabled"},
        {"versioning": "Suspended"},
        {"public_access_type": "ObjectRead"},
        {"storage_tier": "Archive"},
        {"is_read_only": True},
        {"is_read_only": None},
        {"lifecycle_policy_etag": "unreviewed"},
        {"retention_rule_count": 1},
        {"preauthenticated_request_count": 1},
        {"retention_rule_count": False},
        {"collection_started_at": (datetime.now(UTC) - timedelta(hours=2)).isoformat()},
        {"collection_completed_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat()},
    ],
)
def test_unsafe_stale_or_mismatched_posture_fails(config, posture, change):
    with pytest.raises(GovernanceError, match="BACKEND"):
        validate_posture(config, posture | change)


def test_remote_qualification_requires_posture_before_any_process(config, monkeypatch):
    monkeypatch.setattr(
        backend, "PulumiSession", lambda *a: pytest.fail("unexpected backend process")
    )
    with pytest.raises(backend.QualificationError, match="posture"):
        backend.qualify(config, local=False, allow_writes=True)


@pytest.mark.parametrize(
    "change", [{"schema_version": 1}, {"recovery": None}, {"run_id": "invalid"}]
)
def test_old_or_unmeasured_receipts_fail(config, change):
    with pytest.raises(backend.QualificationError):
        backend.validate_receipt(config, receipt(config) | change)


@pytest.mark.parametrize(
    "key,value",
    [
        ("restore_seconds", 0),
        ("restore_seconds", float("inf")),
        ("backup_age_seconds", -1),
        ("checkpoint_bytes", True),
        ("checkpoint_bytes", 1024 * 1024 + 1),
        ("checkpoint_sha256", "invalid"),
    ],
)
def test_receipt_measurements_are_bounded_known_numbers(config, key, value):
    evidence = receipt(config)
    evidence["recovery"][key] = value
    with pytest.raises(backend.QualificationError, match="recovery"):
        backend.validate_receipt(config, evidence)


def test_recovery_uses_fresh_session_and_only_generated_stack(tmp_path, monkeypatch, config):
    stack = "qualification-" + "a" * 32
    for name in ("Pulumi.yaml", "__main__.py", f"Pulumi.{stack}.yaml"):
        (tmp_path / name).write_text("encrypted fixture")
    backup = tmp_path / "backup.json"
    backup.write_text("encrypted checkpoint")
    sessions, events = [], []

    class Session:
        def __init__(self, cwd, env):
            self.cwd, self.env = cwd, env
            sessions.append(self)

        def run(self, phase, args):
            events.append((phase, args))
            return json.dumps("synthetic-secret") if phase == "readback" else ""

    monkeypatch.setattr(backend, "PulumiSession", Session)
    env = {"PULUMI_HOME": str(tmp_path / "old-home")}
    original = Session(tmp_path, env)
    metrics = backend._rehearse_recovery(
        original,
        tmp_path,
        env,
        "file://synthetic",
        stack,
        backup,
        "synthetic-secret",
        time.perf_counter(),
        config=config,
    )
    assert (
        sessions[1].cwd != original.cwd
        and sessions[1].env["PULUMI_HOME"] != original.env["PULUMI_HOME"]
    )
    assert [phase for phase, _ in events] == [
        "simulate-loss",
        "recovery-login",
        "recovery-initialize",
        "restore",
        "readback",
    ]
    assert events[2][1][-2:] == ["--secrets-provider", config.secrets_provider]
    assert metrics["checkpoint_bytes"] == backup.stat().st_size
    assert metrics["restore_seconds"] > 0
    with pytest.raises(backend.QualificationError, match="generated"):
        backend._rehearse_recovery(
            original,
            tmp_path,
            env,
            "file://synthetic",
            "production",
            backup,
            "secret",
            0,
            config=config,
        )


def test_cli_posture_failures_invalidate_old_evidence_without_raw_errors(
    tmp_path, monkeypatch, capsys
):
    import infra_core.inventory.oci as inventory_oci
    from infra_core import cli

    (tmp_path / "config").mkdir()
    (tmp_path / "config/pulumi.toml").write_bytes((ROOT / "config/pulumi.toml").read_bytes())
    (tmp_path / "pyproject.toml").write_text('[project]\nname="oci-oke-infrastructure"\n')
    (tmp_path / ".infra").mkdir()
    output = tmp_path / ".infra/backend-posture.json"
    output.write_text("stale success")

    def fail(*args):
        raise RuntimeError("SECRET_CONFIG_MUST_NOT_ESCAPE")

    monkeypatch.setattr(inventory_oci, "OCIReader", fail)
    assert (
        cli.main(
            [
                "--root",
                str(tmp_path),
                "backend",
                "collect-posture",
                "--account-id",
                "synthetic",
                "--oci-config",
                "unused",
            ]
        )
        == 1
    )
    assert not output.exists()
    assert "SECRET_CONFIG" not in capsys.readouterr().err
