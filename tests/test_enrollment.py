"""Enrollment checks remain offline and pending even with consistent observations."""

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from evidence_helpers import administration_responses
from infra_core import administration, cli
from infra_core import enrollment as e

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
NOW = datetime(2026, 10, 30, tzinfo=UTC)


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    (tmp_path / "config").mkdir()
    (tmp_path / ".infra").mkdir()
    for name in (administration.POLICY, administration.KEYS, "config/operations-policy.json"):
        (tmp_path / name).write_bytes((ROOT / name).read_bytes())
    monkeypatch.setattr(e, "repository_state", lambda root: (COMMIT, True))
    index = {"schema_version": 1, "administration": None, "environments": {}}
    return tmp_path, index


def write(root, index):
    path = Path(".infra/enrollment.json")
    (root / path).write_text(json.dumps(index))
    return path


def observation(root, name):
    policy = json.loads((root / administration.POLICY).read_bytes())
    policy["environment"] = name
    responses = administration_responses(policy, COMMIT)
    responses["environment"]["can_admins_bypass"] = False
    return dict(
        schema_version=1,
        commit=COMMIT,
        started_at=NOW.isoformat(),
        completed_at=NOW.isoformat(),
        responses={
            key: responses[key] for key in ("repository", "branch", "environment", "branches")
        },
    )


def test_empty_enrollment_is_pending_and_does_not_call_github(bundle, monkeypatch):
    root, _ = bundle
    monkeypatch.setattr(administration, "_get", lambda *args: pytest.fail("network call"))
    result = e.check(root, now=NOW)
    assert result["status"] == result["operation_trust"] == result["administration"] == "pending"
    assert set(result["environments"]) == e.ENVIRONMENTS
    assert set(result["environments"].values()) == {"pending"}
    assert not any(
        result[key]
        for key in (
            "enrollment_complete",
            "execution_authorized",
            "activation_authorized",
            "live_controls_verified",
        )
    )
    assert set(result["runner_custody"]) == {"service-operations", "recovery"}


def test_all_environment_observations_still_require_independent_enrollment(bundle):
    root, index = bundle
    for number, name in enumerate(sorted(e.ENVIRONMENTS)):
        path = f".infra/environment-{number}.json"
        (root / path).write_text(json.dumps(observation(root, name)))
        index["environments"][name] = path
    result = e.check(root, write(root, index), now=NOW)
    assert set(result["environments"].values()) == {"observed-controls-consistent"}
    assert result["status"] == "pending"
    assert result["enrollment_complete"] is False


@pytest.mark.parametrize(
    "change",
    [
        "stale",
        "future",
        "commit",
        "repository",
        "bypass",
        "reviewers",
        "branch",
        "duplicate",
        "unknown",
    ],
)
def test_invalid_environment_observations_are_not_pending_or_success(bundle, change):
    root, index = bundle
    name = "oci-network-apply"
    data = observation(root, name)
    if change == "stale":
        data["started_at"] = (NOW - timedelta(minutes=16)).isoformat()
        data["completed_at"] = data["started_at"]
    elif change == "future":
        data["completed_at"] = (NOW + timedelta(seconds=1)).isoformat()
    elif change == "commit":
        data["commit"] = "b" * 40
    elif change == "repository":
        data["responses"]["repository"]["id"] = 12
    elif change == "bypass":
        del data["responses"]["environment"]["can_admins_bypass"]
    elif change == "reviewers":
        data["responses"]["environment"]["protection_rules"] = []
    elif change == "branch":
        data["responses"]["branches"]["branch_policies"][0]["name"] = "*"
    elif change == "duplicate":
        index["environments"]["oci-oke-apply"] = ".infra/env.json"
    else:
        name = "cloudflare-edge-import"
    (root / ".infra/env.json").write_text(json.dumps(data))
    index["environments"][name] = ".infra/env.json"
    with pytest.raises(ValueError, match="ENROLL001"):
        e.check(root, write(root, index), now=NOW)


def test_administration_reuses_complete_validator(bundle):
    root, index = bundle
    policy = (root / administration.POLICY).read_bytes()
    keys = (root / administration.KEYS).read_bytes()
    data = dict(
        schema_version=5,
        commit=COMMIT,
        started_at=NOW.isoformat(),
        completed_at=NOW.isoformat(),
        policy_sha256={
            name: hashlib.sha256(raw).hexdigest()
            for name, raw in ((administration.POLICY, policy), (administration.KEYS, keys))
        },
        responses=administration_responses(json.loads(policy), COMMIT),
    )
    index["administration"] = ".infra/admin.json"
    path = root / index["administration"]
    path.write_text(json.dumps(data))
    assert (
        e.check(root, write(root, index), now=NOW)["administration"]
        == "observed-controls-consistent"
    )
    data["responses"]["protection"]["enforce_admins"]["enabled"] = False
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="ENROLL001"):
        e.check(root, write(root, index), now=NOW)


@pytest.mark.parametrize(
    "change", [None, "same-key", "same-principal", "missing-role", "wrong-id", "wrong-environment"]
)
def test_enabled_policy_needs_distinct_role_coverage(bundle, change):
    root, _ = bundle
    path = root / "config/operations-policy.json"
    policy = json.loads(path.read_bytes())
    policy.update(
        enabled=True,
        max_approval_age_seconds=300,
        max_backup_age_seconds=3600,
        reviewers=[
            dict(
                principal=role, roles=[role], public_key=base64.b64encode(bytes([n]) * 32).decode()
            )
            for n, role in enumerate(("operator", "approver"), 1)
        ],
    )
    if change == "same-key":
        policy["reviewers"][1]["public_key"] = policy["reviewers"][0]["public_key"]
    elif change == "same-principal":
        policy["reviewers"][1]["principal"] = "OPERATOR"
    elif change == "missing-role":
        policy["reviewers"][1]["roles"] = ["operator"]
    elif change == "wrong-id":
        policy["repository_id"] = 12
    elif change == "wrong-environment":
        policy["environments"]["apply/oci-network"] = "other"
    path.write_text(json.dumps(policy))
    if change:
        with pytest.raises(ValueError, match="ENROLL001"):
            e.check(root, now=NOW)
    else:
        result = e.check(root, now=NOW)
        assert result["operation_trust"] == "configuration-consistent"
        assert result["enrollment_complete"] is False


@pytest.mark.parametrize(
    "path",
    [
        "../private.json",
        "/tmp/private.json",
        "config/administration.json",
        ".infra/../private.json",
        ".infra/missing.json",
    ],
)
def test_paths_fail_redacted(bundle, path):
    root, index = bundle
    index["administration"] = path
    with pytest.raises(
        ValueError, match="^ENROLL001: enrollment input rejected; private diagnostics withheld$"
    ):
        e.check(root, write(root, index), now=NOW)


def test_symlink_duplicate_json_and_dirty_checkout(bundle, monkeypatch):
    root, index = bundle
    path = write(root, index)
    (root / ".infra/link.json").symlink_to(root / path)
    with pytest.raises(ValueError, match="ENROLL001"):
        e.check(root, Path(".infra/link.json"), now=NOW)
    (root / path).write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError, match="ENROLL001"):
        e.check(root, path, now=NOW)
    monkeypatch.setattr(e, "repository_state", lambda root: (COMMIT, False))
    with pytest.raises(ValueError, match="ENROLL001"):
        e.check(root, now=NOW)


def test_cli_pending_has_nonzero_exit_and_no_writes(bundle, monkeypatch, capsys):
    root, _ = bundle
    monkeypatch.setattr(cli, "find_repository", lambda arg: root)
    before = sorted(root.rglob("*"))
    assert cli.main(["security", "check-enrollment"]) == 1
    assert json.loads(capsys.readouterr().out)["enrollment_complete"] is False
    assert sorted(root.rglob("*")) == before


def test_workflow_environment_and_runner_contract_coverage():
    environments = {"oci-handoff"}  # Signed library admission, no workflow.
    groups = set()
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        workflow = yaml.safe_load(path.read_text())
        for job in workflow["jobs"].values():
            if "environment" in job:
                name = job["environment"]
                if "${{ inputs.unit }}" in name or "${{ matrix.unit }}" in name:
                    units = e.UNITS
                    if path.stem in ("oci-apply", "oci-preview", "resource-import"):
                        units = e.UNITS[:2]
                    elif path.stem in ("service-apply", "service-preview"):
                        units = e.UNITS[2:]
                    environments.update(
                        name.replace("${{ inputs.unit }}", u).replace("${{ matrix.unit }}", u)
                        for u in units
                    )
                else:
                    environments.add(name)
            runner = job.get("runs-on")
            if isinstance(runner, dict):
                groups.add(runner["group"])
                assert runner["labels"] == ["self-hosted", "linux", "x64"]
    assert environments == e.ENVIRONMENTS
    assert groups == set(e.RUNNER_GATES)


@pytest.mark.parametrize(
    "field,value",
    [("schema_version", True), ("administration", 7), ("environments", []), ("extra", False)],
)
def test_closed_index_contract(bundle, field, value):
    root, index = bundle
    index[field] = value
    with pytest.raises(ValueError, match="ENROLL001"):
        e.check(root, write(root, index), now=NOW)


@pytest.mark.parametrize("change", ["commit", "policy", "evidence"])
def test_changes_during_validation_fail_closed(bundle, monkeypatch, change):
    root, index = bundle
    index_path = write(root, index)
    calls = 0

    def state(root):
        nonlocal calls
        calls += 1
        if calls == 2:
            if change == "commit":
                return "b" * 40, True
            path = root / ("config/operations-policy.json" if change == "policy" else index_path)
            path.write_bytes(path.read_bytes() + b" ")
        return COMMIT, True

    monkeypatch.setattr(e, "repository_state", state)
    with pytest.raises(ValueError, match="ENROLL001"):
        e.check(root, index_path, now=NOW)


def test_oversized_index_is_rejected(bundle):
    root, _ = bundle
    path = Path(".infra/large.json")
    (root / path).write_bytes(b" " * (administration.MAX_BYTES + 1))
    with pytest.raises(ValueError, match="ENROLL001"):
        e.check(root, path, now=NOW)
