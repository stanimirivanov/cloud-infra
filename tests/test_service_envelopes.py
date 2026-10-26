"""Service CLI transport rejects replay/tampering without changing the pure domain."""

import hashlib
import json
import subprocess
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
import test_services as fixtures
from infra_core import cli
from infra_core import service_evidence as se
from infra_core.evidence import EvidenceError
from infra_core.governance.contracts import GovernanceError

service = fixtures.service
COMMIT = "a" * 40


def pair(service):
    config, evidence, profile = service
    payload = json.dumps(evidence, indent=2).encode()
    return payload, se.capture_service_evidence(config, profile, payload, commit=COMMIT)


def check(service, payload, envelope, **kwargs):
    config, _, profile = service
    return se.validate_service_evidence(
        config, profile, payload, envelope, commit=kwargs.pop("commit", COMMIT), **kwargs
    )


def rehash(envelope, payload):
    data = json.loads(envelope)
    data["subject"][0]["digest"]["sha256"] = hashlib.sha256(payload).hexdigest()
    return json.dumps(data).encode()


def test_preserves_bytes_clocks_and_inputs(service):
    original = deepcopy(service)
    payload, envelope = pair(service)
    assert check(service, payload, envelope)["deployment_authorized"] is False
    predicate = json.loads(envelope)["predicate"]
    assert predicate["scope"]["region"] == "global"
    assert predicate["scope"]["account_id"] == service[0]["account_id"]
    assert predicate["collection_started_at"] == service[1]["collection_started_at"]
    assert predicate["collection_completed_at"] == service[1]["collection_completed_at"]
    assert service == original
    with pytest.raises(EvidenceError, match="EVID002"):
        check(service, payload + b" ", envelope)


def test_configuration_digest_ignores_object_order_but_binds_resource_properties(service):
    payload, envelope = pair(service)
    config, _, profile = service
    se.validate_service_evidence(
        dict(reversed(list(config.items()))),
        dict(reversed(list(profile.items()))),
        payload,
        envelope,
        commit=COMMIT,
    )
    config["resources"][0]["props"]["name"] = "other.example.com"
    with pytest.raises(EvidenceError, match="EVID003"):
        check(service, payload, envelope)


@pytest.mark.parametrize("mutation", ["account", "scope", "unit", "growth", "profile", "commit"])
def test_independent_expectations_reject_replay(service, mutation):
    payload, envelope = pair(service)
    config, _, profile = service
    if mutation in ("account", "scope", "unit"):
        config[mutation + "_id" if mutation != "unit" else "unit"] = "other"
    elif mutation == "growth":
        config["growth"] = {"different": 1}
    elif mutation == "profile":
        profile["revision"] += 1
    with pytest.raises(EvidenceError, match="EVID003"):
        check(service, payload, envelope, commit="b" * 40 if mutation == "commit" else COMMIT)


@pytest.mark.parametrize("mutation", ["kind", "region", "clock", "stale"])
def test_envelope_contract_and_original_clock_equality(service, mutation):
    payload, envelope = pair(service)
    data = json.loads(envelope)
    if mutation == "kind":
        data["predicateType"] = "other"
    elif mutation == "region":
        data["predicate"]["scope"]["region"] = "eu-central-1"
    else:
        age = timedelta(hours=1) if mutation == "stale" else timedelta(seconds=1)
        data["predicate"]["collection_started_at"] = (datetime.now(UTC) - age).isoformat()
    with pytest.raises((EvidenceError, GovernanceError), match="EVID|EXT023"):
        check(service, payload, json.dumps(data).encode())


@pytest.mark.parametrize(
    "payload", [b"[]", b'{"PRIVATE":', b"\xff", b'{"complete":true,"complete":true}', b'{"x":NaN}']
)
def test_recomputed_hash_cannot_upgrade_invalid_json(service, payload):
    _, envelope = pair(service)
    with pytest.raises((EvidenceError, GovernanceError), match="EXT023") as error:
        check(service, payload, rehash(envelope, payload))
    assert "PRIVATE" not in str(error.value)


def test_recomputed_hash_cannot_upgrade_domain_or_legacy_evidence(service):
    _, envelope = pair(service)
    for change in ({"complete": False}, {"schema_version": 1}):
        payload = json.dumps(service[1] | change).encode()
        with pytest.raises(GovernanceError):
            check(service, payload, rehash(envelope, payload))
        with pytest.raises(GovernanceError):
            se.capture_service_evidence(service[0], service[2], payload, commit=COMMIT)


@pytest.mark.parametrize("missing", ["payload", "envelope", "payload-size", "envelope-size"])
def test_read_pair_is_bounded_and_requires_both_files(tmp_path, monkeypatch, missing):
    path = tmp_path / "evidence.json"
    sidecar = path.with_name(path.name + ".envelope.json")
    if missing != "payload":
        path.write_bytes(b"{}")
    if missing != "envelope":
        sidecar.write_bytes(b"{}")
    if missing.endswith("-size"):
        monkeypatch.setattr(
            se, "MAX_ARTIFACT_BYTES" if missing == "payload-size" else "MAX_ENVELOPE_BYTES", 1
        )
    with pytest.raises((EvidenceError, GovernanceError), match="EXT023") as error:
        se.read_service_pair(path)
    assert str(tmp_path) not in str(error.value)


def test_checkout_identity_is_clean_and_errors_are_safe(tmp_path, monkeypatch):
    monkeypatch.setattr(se, "repository_state", lambda root: (COMMIT, False))
    with pytest.raises(GovernanceError, match="EXT023"):
        se.reviewed_commit(tmp_path)

    def fail(root):
        raise subprocess.CalledProcessError(1, "git", stderr="PRIVATE")

    monkeypatch.setattr(se, "repository_state", fail)
    with pytest.raises(EvidenceError, match="EXT023") as error:
        se.reviewed_commit(tmp_path)
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("changed", [False, True])
def test_cli_requires_pair_and_stable_commit(service, tmp_path, monkeypatch, capsys, changed):
    payload, envelope = pair(service)
    config = tmp_path / "proposal.json"
    path = tmp_path / "usage.json"
    config.write_text(json.dumps(service[0]))
    path.write_bytes(payload)
    sidecar = path.with_name(path.name + ".envelope.json")
    sidecar.write_bytes(envelope)
    commits = iter([COMMIT, "b" * 40 if changed else COMMIT])
    monkeypatch.setattr(se, "reviewed_commit", lambda root: next(commits))
    args = [
        "--root",
        str(fixtures.ROOT),
        "services",
        "audit",
        "--config",
        str(config),
        "--evidence",
        str(path),
    ]
    assert cli.main(args) == (1 if changed else 0)
    output = capsys.readouterr()
    assert ("EXT023" in output.err and not output.out) if changed else output.out
    sidecar.unlink()
    monkeypatch.setattr(se, "reviewed_commit", lambda root: COMMIT)
    assert cli.main(args) == 1
    assert "EXT023" in capsys.readouterr().err
