"""Authenticated assertions and local bindings, never live acceptance or permission."""

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infra_core import cli, operations
from infra_core import readiness as r
from infra_core.review_signatures import preauth

NOW = datetime(2026, 10, 30, tzinfo=UTC)
COMMIT = "a" * 40


@pytest.fixture(params=sorted(r.UNITS))
def bundle(tmp_path, monkeypatch, request):
    root = tmp_path
    (root / ".infra").mkdir()
    (root / "config").mkdir()
    keys = {role: Ed25519PrivateKey.generate() for role in ("operator", "approver")}
    policy = dict(
        schema_version=1,
        enabled=True,
        repository="example/infra",
        repository_id=123,
        max_approval_age_seconds=900,
        max_backup_age_seconds=3600,
        environments={"apply/" + request.param: request.param + "-apply"},
        reviewers=[
            dict(
                principal=role,
                roles=[role],
                public_key=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
            )
            for role, key in keys.items()
        ],
    )
    (root / "config/operations-policy.json").write_bytes(operations.encoded(policy))
    config = b'{"synthetic":"PRIVATE-config"}'
    (root / ".infra/config.json").write_bytes(config)
    record = dict(
        schema_version=1,
        unit=request.param,
        commit=COMMIT,
        actor="requester",
        configuration_sha256=r.digest(config),
        policy_sha256=r.digest(operations.encoded(policy)),
        gates=[],
    )
    for gate, stage in r.GATES.items():
        path = ".infra/" + gate + ".json"
        data = operations.encoded(dict(unit=request.param, synthetic="PRIVATE-evidence"))
        (root / path).write_bytes(data)
        record["gates"].append(
            dict(
                gate=gate,
                stage=stage,
                observed_at=NOW.isoformat(),
                reviewed_at=NOW.isoformat(),
                expires_at=(NOW + timedelta(minutes=5)).isoformat(),
                reviewer="approver",
                outcome="accepted",
                evidence=[dict(path=path, sha256=r.digest(data))],
            )
        )
    index = dict(
        schema_version=1,
        record=".infra/record.json",
        operator=".infra/operator.json",
        approver=".infra/approver.json",
        configuration=".infra/config.json",
    )
    (root / ".infra/index.json").write_bytes(operations.encoded(index))
    monkeypatch.setattr(r, "repository_state", lambda root: (COMMIT, True))

    def sign():
        payload = operations.encoded(record)
        (root / index["record"]).write_bytes(payload)
        for role, key in keys.items():
            proof = dict(
                payloadType=r.PAYLOAD_TYPE,
                payload=base64.b64encode(payload).decode(),
                signatures=[
                    dict(sig=base64.b64encode(key.sign(preauth(payload, r.PAYLOAD_TYPE))).decode())
                ],
            )
            (root / index[role]).write_bytes(operations.encoded(proof))

    sign()
    return root, record, index, sign


def check(bundle, **kw):
    root, record, _, _ = bundle
    return r.check(root, Path(".infra/index.json"), unit=record["unit"], now=kw.get("now", NOW))


def test_complete_signed_report_has_no_authority_or_private_output(bundle):
    root, _, _, _ = bundle
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    report = check(bundle)
    assert report["status"] == "accepted" and len(report["gates"]) == 10
    assert all(row["status"] == "accepted" for row in report["gates"])
    assert (
        report["execution_authorized"]
        is report["activation_authorized"]
        is report["live_controls_verified"]
        is False
    )
    assert "PRIVATE" not in json.dumps(report) and ".infra" not in json.dumps(report)
    assert before == {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize(
    "fault,expected",
    [
        ("empty", "missing"),
        ("missing", "missing"),
        ("changed", "stale"),
        ("expired", "stale"),
        ("future", "stale"),
        ("configuration", "stale"),
        ("policy", "stale"),
        ("failed", "failed"),
        ("forged", "failed"),
        ("wrong-role", "failed"),
        ("disabled", "failed"),
        ("reviewer", "failed"),
        ("actor", "failed"),
        ("payload-type", "failed"),
    ],
)
def test_gate_outcomes_never_turn_missing_stale_or_forged_into_acceptance(bundle, fault, expected):
    root, record, index, sign = bundle
    row = record["gates"][0]
    if fault == "empty":
        record["gates"] = []
    elif fault == "missing":
        (root / row["evidence"][0]["path"]).unlink()
    elif fault == "changed":
        (root / row["evidence"][0]["path"]).write_bytes(b"changed")
    elif fault == "expired":
        row["observed_at"] = row["reviewed_at"] = (NOW - timedelta(minutes=1)).isoformat()
        row["expires_at"] = NOW.isoformat()
    elif fault == "future":
        row["reviewed_at"] = (NOW + timedelta(seconds=1)).isoformat()
    elif fault == "configuration":
        (root / index["configuration"]).write_bytes(b"changed")
    elif fault in {"disabled", "policy"}:
        path = root / "config/operations-policy.json"
        policy = json.loads(path.read_bytes())
        policy["enabled" if fault == "disabled" else "repository_id"] = (
            False if fault == "disabled" else 456
        )
        path.write_bytes(operations.encoded(policy))
    elif fault == "failed":
        row["outcome"] = "failed"
    elif fault == "reviewer":
        row["reviewer"] = "untrusted"
    elif fault == "actor":
        record["actor"] = "OPERATOR"
    sign()
    if fault == "forged":
        record["commit"] = "b" * 40
        (root / index["record"]).write_bytes(operations.encoded(record))
    elif fault == "wrong-role":
        (root / index["approver"]).write_bytes((root / index["operator"]).read_bytes())
    elif fault == "payload-type":
        path = root / index["operator"]
        value = json.loads(path.read_bytes())
        value["payloadType"] = "application/vnd.in-toto+json"
        path.write_bytes(operations.encoded(value))
    result = check(bundle)
    assert result["status"] == "incomplete" and result["gates"][0]["status"] == expected


@pytest.mark.parametrize(
    "fault",
    [
        "duplicate",
        "unknown",
        "stage",
        "authority",
        "clock",
        "traversal",
        "absolute",
        "hash",
        "duplicate-evidence",
    ],
)
def test_closed_record_rejects_ambiguity_even_when_signed(bundle, fault):
    root, value, _, sign = bundle
    row = value["gates"][0]
    if fault == "duplicate":
        value["gates"][-1] = row
    elif fault == "unknown":
        row["gate"] = "PRIVATE"
    elif fault == "stage":
        row["stage"] = "activation"
    elif fault == "authority":
        value["execution_authorized"] = True
    elif fault == "clock":
        row["observed_at"] = (NOW + timedelta(seconds=1)).isoformat()
    elif fault in {"traversal", "absolute"}:
        row["evidence"][0]["path"] = (
            ".infra/../PRIVATE.json" if fault == "traversal" else str(root / ".infra/PRIVATE.json")
        )
    elif fault == "hash":
        row["evidence"][0]["sha256"] = "bad"
    else:
        row["evidence"].append(row["evidence"][0])
    sign()
    with pytest.raises(ValueError, match="READY001"):
        check(bundle)


def test_wrong_unit_and_changed_checkout(bundle, monkeypatch):
    root, value, _, _ = bundle
    other = next(u for u in r.UNITS if u != value["unit"])
    with pytest.raises(ValueError, match="READY001"):
        r.check(root, Path(".infra/index.json"), unit=other, now=NOW)
    for state in (("b" * 40, True), (COMMIT, False)):
        monkeypatch.setattr(r, "repository_state", lambda root, state=state: state)
        assert all(row["status"] == "stale" for row in check(bundle)["gates"])


@pytest.mark.parametrize("fault", ["oversize", "duplicate-json", "symlink", "during-read"])
def test_bounded_inputs_and_concurrent_change_fail_closed(bundle, monkeypatch, fault):
    root, value, index, _ = bundle
    path = root / index["record"]
    if fault == "oversize":
        path.write_bytes(b" " * (operations.MAX_BYTES + 1))
    elif fault == "duplicate-json":
        path.write_bytes(b'{"schema_version":1,"schema_version":1}')
    elif fault == "symlink":
        path.unlink()
        path.symlink_to(root / index["configuration"])
    else:
        real = r.repository_state
        count = 0

        def change(root):
            nonlocal count
            count += 1
            if count == 2:
                (root / value["gates"][0]["evidence"][0]["path"]).write_bytes(b"changed")
            return real(root)

        monkeypatch.setattr(r, "repository_state", change)
    with pytest.raises(ValueError, match="READY001"):
        check(bundle)


def test_cli_exit_status_redaction_and_no_execution_callbacks(bundle, monkeypatch, capsys):
    root, value, _, _ = bundle
    monkeypatch.setattr(cli, "find_repository", lambda _: root)
    original = r.check
    monkeypatch.setattr(r, "check", lambda *a, **kw: original(*a, **kw, now=NOW))
    args = ["readiness", "--unit", value["unit"], "--evidence", ".infra/index.json"]
    assert cli.main(args, apply=lambda *a: pytest.fail("execution")) == 0
    assert json.loads(capsys.readouterr().out)["execution_authorized"] is False
    (root / value["gates"][0]["evidence"][0]["path"]).unlink()
    assert cli.main(args) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "incomplete"
    assert cli.main(args[:-1] + [".infra/PRIVATE-missing.json"]) == 1
    error = capsys.readouterr().err
    assert "READY001" in error and "PRIVATE" not in error


def test_signed_cross_unit_evidence_is_not_accepted(bundle):
    root, value, _, sign = bundle
    item = value["gates"][0]["evidence"][0]
    payload = operations.encoded(dict(unit="foreign"))
    (root / item["path"]).write_bytes(payload)
    item["sha256"] = r.digest(payload)
    sign()
    result = check(bundle)
    assert result["gates"][0]["reason"] == "evidence_scope_mismatch"


def test_missing_evidence_created_during_evaluation_rejects_report(bundle, monkeypatch):
    root, value, _, _ = bundle
    path = root / value["gates"][0]["evidence"][0]["path"]
    payload = path.read_bytes()
    path.unlink()
    count = 0

    def state(root):
        nonlocal count
        count += 1
        if count == 2:
            path.write_bytes(payload)
        return COMMIT, True

    monkeypatch.setattr(r, "repository_state", state)
    with pytest.raises(ValueError, match="READY001"):
        check(bundle)


@pytest.mark.parametrize("fault", ["alias", "directory", "empty", "naive-clock"])
def test_control_and_clock_boundaries(bundle, fault):
    root, value, index, sign = bundle
    if fault == "alias":
        index["approver"] = index["operator"]
        (root / ".infra/index.json").write_bytes(operations.encoded(index))
    elif fault == "directory":
        path = root / index["record"]
        path.unlink()
        path.mkdir()
    elif fault == "empty":
        (root / index["record"]).write_bytes(b"")
    else:
        value["gates"][0]["observed_at"] = "2026-10-30T00:00:00"
        sign()
    with pytest.raises(ValueError, match="READY001"):
        check(bundle)


def test_total_evidence_budget_is_bounded(bundle):
    root, value, _, sign = bundle
    payload = operations.encoded(dict(padding="x" * (operations.MAX_BYTES - 100)))
    refs = []
    for number in range(13):
        path = f".infra/large-{number}.json"
        (root / path).write_bytes(payload)
        refs.append(dict(path=path, sha256=r.digest(payload)))
    value["gates"][0]["evidence"] = refs[:8]
    value["gates"][1]["evidence"] = refs[8:]
    sign()
    with pytest.raises(ValueError, match="READY001"):
        check(bundle)
