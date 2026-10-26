"""OCI transport binding, offline audit handoff and failed pair publication."""

import hashlib
import json
import subprocess
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_governance as fixtures
from infra_core import cli
from infra_core import inventory_evidence as ie
from infra_core.evidence import EvidenceError
from infra_core.governance.audit import audit
from infra_core.governance.contracts import GovernanceError

evidence = fixtures.evidence
COMMIT = "a" * 40
NOW = fixtures.NOW


def pair(evidence):
    account, profile, inventory, _ = evidence
    return ie.capture_inventory(account, profile, inventory, commit=COMMIT, now=NOW)


def check(evidence, payload, envelope, commit=COMMIT):
    return ie.validate_inventory_evidence(*evidence[:2], payload, envelope, commit=commit, now=NOW)


def rehash(payload, envelope):
    data = json.loads(envelope)
    data["subject"][0]["digest"]["sha256"] = hashlib.sha256(payload).hexdigest()
    return json.dumps(data).encode()


def test_preserves_observations_and_binds_semantic_configuration(evidence):
    original = deepcopy(evidence)
    payload, envelope = pair(evidence)
    inventory = check(evidence, payload, envelope)
    assert inventory == evidence[2]
    assert evidence == original
    predicate = json.loads(envelope)["predicate"]
    assert predicate["scope"]["unit"] == "oci-account"
    assert predicate["collection_started_at"] == inventory["observed_at"]
    assert predicate["collection_completed_at"] == inventory["collection_completed_at"]
    assert audit(*evidence[:2], inventory, evidence[3], now=NOW)["deployment_authorized"] is False
    reordered = (dict(reversed(list(evidence[0].items()))), evidence[1])
    assert (
        ie.validate_inventory_evidence(*reordered, payload, envelope, commit=COMMIT, now=NOW)
        == inventory
    )


@pytest.mark.parametrize(
    "mutation",
    ["bytes", "account", "region", "config", "profile", "commit", "unit", "kind", "clock", "stale"],
)
def test_rejects_tampering_and_replay(evidence, mutation):
    payload, envelope = pair(evidence)
    data = json.loads(envelope)
    commit = COMMIT
    if mutation == "bytes":
        payload += b" "
    elif mutation in ("account", "region"):
        evidence[0]["account_id" if mutation == "account" else "home_region"] = "other"
    elif mutation == "config":
        evidence[0]["reservations"]["ocpus"] = 1
    elif mutation == "profile":
        evidence[1]["revision"] += 1
    elif mutation == "commit":
        commit = "b" * 40
    elif mutation == "unit":
        data["predicate"]["scope"]["unit"] = "oci-oke"
    elif mutation == "kind":
        data["predicateType"] = "other"
    else:
        age = timedelta(hours=1) if mutation == "stale" else timedelta(seconds=1)
        data["predicate"]["collection_started_at"] = (NOW - age).isoformat()
    with pytest.raises((EvidenceError, GovernanceError), match="EVID|GOV043"):
        check(evidence, payload, json.dumps(data).encode(), commit=commit)


@pytest.mark.parametrize(
    "payload", [b"[]", b'{"PRIVATE":', b"\xff", b'{"complete":true,"complete":true}', b'{"x":NaN}']
)
def test_recomputed_hash_cannot_upgrade_invalid_json(evidence, payload):
    _, envelope = pair(evidence)
    with pytest.raises((EvidenceError, GovernanceError), match="GOV003|GOV043") as error:
        check(evidence, payload, rehash(payload, envelope))
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("fault", ["query", "legacy", "scope", "incomplete", "record", "usage"])
def test_binding_cannot_replace_coverage_or_billing_audit(evidence, fault):
    _, envelope = pair(evidence)
    inventory = evidence[2]
    if fault == "query":
        inventory["coverage"]["queries"].pop()
    elif fault == "legacy":
        inventory["schema_version"] = 1
    elif fault == "scope":
        inventory["account_id"] = "other"
    elif fault == "incomplete":
        inventory["all_compartments"] = False
    elif fault == "record":
        inventory["resources"] = [{}]
    else:
        inventory["usage"] = None
    payload = json.dumps(inventory).encode()
    if fault == "usage":
        assert check(evidence, payload, rehash(payload, envelope))["usage"] is None
        with pytest.raises(GovernanceError):
            audit(*evidence, now=NOW)
    else:
        with pytest.raises(GovernanceError, match="GOV003|GOV042|GOV043"):
            check(evidence, payload, rehash(payload, envelope))
        with pytest.raises(GovernanceError):
            pair(evidence)


@pytest.mark.parametrize("fault", ["payload", "envelope", "payload-size", "envelope-size"])
def test_read_pair_requires_bounded_files(tmp_path, monkeypatch, fault):
    path = tmp_path / "inventory.json"
    if fault != "payload":
        path.write_bytes(b"{}")
    if fault != "envelope":
        path.with_name(path.name + ".envelope.json").write_bytes(b"{}")
    if fault.endswith("-size"):
        monkeypatch.setattr(
            ie, "MAX_ARTIFACT_BYTES" if fault == "payload-size" else "MAX_ENVELOPE_BYTES", 1
        )
    with pytest.raises((EvidenceError, GovernanceError), match="GOV043"):
        ie.read_inventory_pair(path)


def setup_cli(evidence, tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="oci-oke-infrastructure"\n')
    (tmp_path / "config/quotas").mkdir(parents=True)
    source = Path(__file__).resolve().parents[1] / "config/quotas/profiles.toml"
    (tmp_path / "config/quotas/profiles.toml").write_bytes(source.read_bytes())
    (tmp_path / "account.toml").write_text(
        "\n".join(
            f"{key} = {json.dumps(value)}"
            for key, value in evidence[0].items()
            if key != "reservations"
        )
        + "\n[reservations]\n"
    )
    (tmp_path / "plan.json").write_text(json.dumps(evidence[3]))
    (tmp_path / "usage.json").write_text(json.dumps(evidence[2]["usage"]))
    monkeypatch.setattr(ie, "reviewed_commit", lambda root: COMMIT)
    monkeypatch.setattr(ie, "datetime", SimpleNamespace(now=lambda tz: NOW))
    monkeypatch.setattr("infra_core.governance.audit.audit", lambda *args: audit(*args, now=NOW))
    monkeypatch.setattr("infra_core.inventory.oci.OCIReader", lambda *args: object())
    monkeypatch.setattr(
        "infra_core.inventory.oci.collect",
        lambda *a, usage=None: deepcopy(evidence[2]) | {"usage": usage},
    )
    base = ["--root", str(tmp_path), "governance"]
    collect = base + ["inventory", "--account", "account.toml", "--oci-config", "unused"]
    check = base + [
        "audit",
        "--account",
        "account.toml",
        "--inventory",
        ".infra/inventory.json",
        "--plan",
        "plan.json",
    ]
    path = tmp_path / ".infra/inventory.json"
    return collect, check, path, path.with_name(path.name + ".envelope.json")


def test_cli_collects_pair_and_requires_binding_before_audit(
    evidence, tmp_path, monkeypatch, capsys
):
    collect, check, path, sidecar = setup_cli(evidence, tmp_path, monkeypatch)
    assert cli.main(collect + ["--usage", "usage.json"]) == 0
    assert sidecar.exists()
    capsys.readouterr()
    assert cli.main(check) == 0
    assert json.loads(capsys.readouterr().out)["deployment_authorized"] is False
    path.write_bytes(path.read_bytes() + b" ")
    assert cli.main(check) == 1
    assert "EVID002" in capsys.readouterr().err
    sidecar.unlink()
    assert cli.main(check) == 1
    assert "GOV043" in capsys.readouterr().err


@pytest.mark.parametrize("fault", ["sdk", "dirty", "changed", "payload", "envelope", "profile"])
def test_failed_collection_never_leaves_a_usable_pair(
    evidence, tmp_path, monkeypatch, capsys, fault
):
    collect, _, path, sidecar = setup_cli(evidence, tmp_path, monkeypatch)
    path.parent.mkdir()
    path.write_bytes(b"old payload")
    sidecar.write_bytes(b"old sidecar")

    def fail(*args):
        raise RuntimeError("PRIVATE")

    if fault == "sdk":
        monkeypatch.setattr("infra_core.inventory.oci.OCIReader", fail)
    elif fault == "dirty":
        monkeypatch.setattr(ie, "reviewed_commit", fail)
    elif fault == "changed":
        commits = iter([COMMIT, "b" * 40])
        monkeypatch.setattr(ie, "reviewed_commit", lambda root: next(commits))
    elif fault == "profile":
        (tmp_path / "config/quotas/profiles.toml").unlink()
    else:
        write = Path.write_bytes
        target = path if fault == "payload" else sidecar

        def fail_write(self, content):
            if self == target:
                raise OSError("PRIVATE")
            return write(self, content)

        monkeypatch.setattr(Path, "write_bytes", fail_write)
    assert cli.main(collect) == 1
    assert not path.exists() and not sidecar.exists()
    output = capsys.readouterr()
    assert "GOV040" in output.err and "PRIVATE" not in output.err


def test_cli_missing_usage_and_changed_audit_commit_fail(evidence, tmp_path, monkeypatch, capsys):
    collect, check, _, _ = setup_cli(evidence, tmp_path, monkeypatch)
    assert cli.main(collect) == 0
    capsys.readouterr()
    assert cli.main(check) == 1  # A complete resource listing is not billing evidence.
    capsys.readouterr()
    assert cli.main(collect + ["--usage", "usage.json"]) == 0
    capsys.readouterr()
    commits = iter([COMMIT, "b" * 40])
    monkeypatch.setattr(ie, "reviewed_commit", lambda root: next(commits))
    assert cli.main(check) == 1
    output = capsys.readouterr()
    assert "GOV043" in output.err and not output.out


def test_reviewed_checkout_identity_is_clean_and_errors_are_safe(tmp_path, monkeypatch):
    monkeypatch.setattr(ie, "repository_state", lambda root: (COMMIT, False))
    with pytest.raises(GovernanceError, match="GOV043"):
        ie.reviewed_commit(tmp_path)

    def fail(root):
        raise subprocess.CalledProcessError(1, "git", stderr="PRIVATE")

    monkeypatch.setattr(ie, "repository_state", fail)
    with pytest.raises(EvidenceError, match="GOV043") as error:
        ie.reviewed_commit(tmp_path)
    assert "PRIVATE" not in str(error.value)
