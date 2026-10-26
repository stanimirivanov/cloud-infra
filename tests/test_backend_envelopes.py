"""Backend consumers bind captured bytes and independently expected scope before operations."""

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_operations_evidence as fixtures
import yaml
from infra_core import backend, cli, cutover
from infra_core import backend_posture as bp
from infra_core.evidence import EvidenceError
from infra_core.governance.contracts import GovernanceError

config = fixtures.config
posture = fixtures.posture

COMMIT = "a" * 40
ACCOUNT = "synthetic-tenancy"


def capture(config, posture):
    return bp.capture_posture(config, posture, account_id=ACCOUNT, commit=COMMIT)


def check(config, payload, envelope, **kwargs):
    return bp.validate_posture_evidence(
        config,
        payload,
        envelope,
        account_id=kwargs.get("account_id", ACCOUNT),
        commit=kwargs.get("commit", COMMIT),
    )


def test_capture_preserves_original_clocks_and_remains_diagnostic(config, posture):
    payload, envelope = capture(config, posture)
    assert json.loads(payload) == posture
    assert check(config, payload, envelope)["deployment_authorized"] is False
    predicate = json.loads(envelope)["predicate"]
    assert predicate["collection_started_at"] == posture["collection_started_at"]
    assert predicate["scope"]["unit"] == "backend"


@pytest.mark.parametrize(
    "mutation", ["bytes", "account", "region", "unit", "commit", "config", "clock", "stale", "kind"]
)
def test_consumer_rejects_tampering_and_wrong_expectations(config, posture, mutation):
    payload, envelope = capture(config, posture)
    data = json.loads(envelope)
    if mutation == "bytes":
        payload += b" "  # Equivalent JSON is still different captured evidence.
    elif mutation == "account":
        with pytest.raises(EvidenceError, match="EVID003"):
            check(config, payload, envelope, account_id="other")
        return
    elif mutation == "commit":
        with pytest.raises(EvidenceError, match="EVID003"):
            check(config, payload, envelope, commit="b" * 40)
        return
    elif mutation in ("region", "unit", "config"):
        key = "configuration_sha256" if mutation == "config" else mutation
        data["predicate"]["scope"][key] = "f" * 64 if mutation == "config" else "other"
    elif mutation in ("clock", "stale"):
        age = timedelta(minutes=1) if mutation == "clock" else timedelta(hours=2)
        data["predicate"]["collection_started_at"] = (datetime.now(UTC) - age).isoformat()
    else:
        data["predicateType"] = "other"
    with pytest.raises((EvidenceError, GovernanceError)):
        check(config, payload, json.dumps(data).encode())


@pytest.mark.parametrize(
    "payload", [b"[]", b'{"secret":', b"\xff", b'{"schema_version":1,"schema_version":1}']
)
def test_correct_hash_cannot_upgrade_invalid_payload(config, posture, payload):
    _, envelope = capture(config, posture)
    import hashlib

    data = json.loads(envelope)
    data["subject"][0]["digest"]["sha256"] = hashlib.sha256(payload).hexdigest()
    with pytest.raises((EvidenceError, GovernanceError)) as error:
        check(config, payload, json.dumps(data).encode())
    assert "secret" not in str(error.value)


def test_capture_rejects_another_account_and_unsafe_observations(config, posture):
    for change in ({"account_id": "other"}, {"versioning": "Disabled"}):
        with pytest.raises(GovernanceError, match="BACKEND"):
            capture(config, posture | change)


@pytest.mark.parametrize("missing", ["payload", "envelope", "oversized"])
def test_file_capture_requires_bounded_pair(tmp_path, monkeypatch, missing):
    path = tmp_path / "posture.json"
    if missing != "payload":
        path.write_bytes(b"{}")
    if missing != "envelope":
        bp.envelope_path(path).write_bytes(b"{}")
    if missing == "oversized":
        monkeypatch.setattr(bp, "MAX_ENVELOPE_BYTES", 1)
    with pytest.raises(EvidenceError, match="BACKEND006"):
        bp.read_posture_pair(path)


@pytest.mark.parametrize("bad", [True, False])
def test_remote_guard_runs_before_pulumi_or_temporary_state(config, posture, monkeypatch, bad):
    payload, envelope = capture(config, posture)
    events = []

    def version(*args):
        events.append("preflight-passed")
        raise RuntimeError("stop-before-cli")

    monkeypatch.setattr(backend, "version", version)
    monkeypatch.setattr(backend.tempfile, "TemporaryDirectory", lambda **kw: pytest.fail("state"))
    with pytest.raises(EvidenceError if bad else RuntimeError):
        backend.qualify(
            config,
            local=False,
            allow_writes=True,
            posture=payload,
            posture_envelope=envelope + b"invalid" if bad else envelope,
            account_id=ACCOUNT,
            commit=COMMIT,
        )
    assert events == ([] if bad else ["preflight-passed"])


def test_checkout_identity_must_be_clean_and_errors_are_sanitized(monkeypatch, tmp_path):
    monkeypatch.setattr(cutover, "repository_state", lambda root: (COMMIT, False))
    with pytest.raises(ValueError, match="clean"):
        cli._posture_commit(tmp_path)

    def fail(root):
        raise subprocess.CalledProcessError(1, "git", stderr="PRIVATE")

    monkeypatch.setattr(cutover, "repository_state", fail)
    with pytest.raises(ValueError, match="BACKEND006") as error:
        cli._posture_commit(tmp_path)
    assert "PRIVATE" not in str(error.value)


def test_cli_roundtrip_and_changed_checkout_invalidate_outputs(
    config, posture, tmp_path, monkeypatch, capsys
):
    import infra_core.inventory.oci as oci

    (tmp_path / "config").mkdir()
    root = Path(__file__).resolve().parents[1]
    (tmp_path / "config/pulumi.toml").write_bytes((root / "config/pulumi.toml").read_bytes())
    (tmp_path / "pyproject.toml").write_text('[project]\nname="oci-oke-infrastructure"\n')
    monkeypatch.setattr(cli, "_posture_commit", lambda root: COMMIT)
    monkeypatch.setattr(
        oci, "OCIReader", lambda *args: SimpleNamespace(backend_posture=lambda config: posture)
    )
    common = ["--root", str(tmp_path), "backend"]
    collect = [*common, "collect-posture", "--account-id", ACCOUNT, "--oci-config", "unused"]
    assert cli.main(collect) == 0
    path = tmp_path / ".infra/backend-posture.json"
    assert check(config, *bp.read_posture_pair(path))["deployment_authorized"] is False
    assert cli.main([*common, "check-posture", "--account-id", ACCOUNT]) == 0
    assert cli.main([*common, "check-posture", "--account-id", "other"]) == 1
    original_write = Path.write_bytes

    def fail_sidecar(self, content):
        if self == bp.envelope_path(path):
            raise OSError("PRIVATE publication failure")
        return original_write(self, content)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "write_bytes", fail_sidecar)
        assert cli.main(collect) == 1
    assert not path.exists() and not bp.envelope_path(path).exists()
    captured = capsys.readouterr()
    assert "PRIVATE" not in captured.err
    assert "deployment_authorized" in captured.out
    assert cli.main(collect) == 0
    commits = iter([COMMIT, "b" * 40])
    monkeypatch.setattr(cli, "_posture_commit", lambda root: next(commits))
    assert cli.main(collect) == 1
    assert not path.exists() and not bp.envelope_path(path).exists()


def test_workflow_handoff_supplies_independent_account_and_exact_byte_pair():
    root = Path(__file__).resolve().parents[1]
    document = yaml.load(
        (root / ".github/workflows/pulumi.yml").read_text(), Loader=yaml.BaseLoader
    )
    step = next(
        step
        for step in document["jobs"]["foundation"]["steps"]
        if "BACKEND_POSTURE_JSON" in step.get("env", {})
    )
    assert step["env"]["BACKEND_POSTURE_ACCOUNT_ID"] == "${{ vars.BACKEND_POSTURE_ACCOUNT_ID }}"
    assert "secrets.BACKEND_POSTURE_ENVELOPE_JSON" in step["env"]["BACKEND_POSTURE_ENVELOPE_JSON"]
    assert (
        'qualify --account-id "$BACKEND_POSTURE_ACCOUNT_ID" --allow-backend-writes' in step["run"]
    )
    assert step["run"].count("write_bytes") == 2
    assert "backend-posture.json.envelope.json" in step["run"]


@pytest.mark.parametrize("missing", ["posture_envelope", "account_id", "commit"])
def test_remote_api_has_no_legacy_or_self_scoped_fallback(config, posture, monkeypatch, missing):
    payload, envelope = capture(config, posture)
    arguments = dict(posture=payload, posture_envelope=envelope, account_id=ACCOUNT, commit=COMMIT)
    arguments[missing] = None
    monkeypatch.setattr(
        backend, "version", lambda *args: pytest.fail("unexpected process preflight")
    )
    with pytest.raises(backend.QualificationError, match="posture"):
        backend.qualify(config, local=False, allow_writes=True, **arguments)


@pytest.mark.parametrize(
    "change",
    [
        {"account_id": "other"},
        {"bucket": "other"},
        {"versioning": "Disabled"},
        {"retention_rule_count": 1},
    ],
)
def test_recomputed_subject_digest_cannot_bypass_payload_semantics(config, posture, change):
    import hashlib

    _, envelope = capture(config, posture)
    payload = json.dumps(posture | change).encode()
    data = json.loads(envelope)
    data["subject"][0]["digest"]["sha256"] = hashlib.sha256(payload).hexdigest()
    with pytest.raises(GovernanceError, match="BACKEND"):
        check(config, payload, json.dumps(data).encode())
