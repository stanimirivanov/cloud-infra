"""Synthetic REST observations exercise administrative sensors without credentials."""

import json
import subprocess
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import yaml
from evidence_helpers import administration_responses
from infra_core import administration as admin
from infra_core import cli

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40


@pytest.fixture
def observation(tmp_path, monkeypatch):
    (tmp_path / "config").mkdir()
    for name in (admin.POLICY, admin.KEYS):
        (tmp_path / name).write_bytes((ROOT / name).read_bytes())
    monkeypatch.setattr(admin, "repository_state", lambda root: (COMMIT, True))
    policy = json.loads((tmp_path / admin.POLICY).read_bytes())
    responses = administration_responses(policy, COMMIT)
    calls = []

    def query(endpoint):
        calls.append(endpoint)
        if len(calls) <= 5:
            return deepcopy(responses[list(responses)[len(calls) - 1]])
        if len(calls) <= 5 + len(policy["required_checks"]):
            return deepcopy(
                responses["checks"][policy["required_checks"][len(calls) - 6]["context"]]
            )
        return deepcopy(
            responses[{8: "workflow_runs", 9: "pull_requests", 10: "pull_request"}[len(calls)]]
        )

    payload = admin.collect(tmp_path, query=query)
    return tmp_path, json.loads(payload), calls


def encoded(document):
    return json.dumps(document).encode()


def test_collection_and_offline_revalidation_preserve_disabled_authority(observation):
    root, document, calls = observation
    assert len(calls) == 10
    policy = json.loads((root / admin.POLICY).read_bytes())
    base = "repos/" + policy["repository"] + "/environments/" + policy["environment"]
    assert calls[3:5] == [base, base + "/deployment-branch-policies?per_page=100&page=1"]
    assert "check_name=Credential-free%20verification%20%28ubuntu-24.04%29" in calls[5]
    assert calls[7].endswith("/actions/runs?check_suite_id=21&per_page=100&page=1")
    assert calls[8].endswith("/commits/" + COMMIT + "/pulls?per_page=100&page=1")
    assert calls[9].endswith("/pulls/31")
    result = admin.check(root, encoded(document))
    assert result["status"] == "observed-controls-consistent"
    assert result["deployment_authorized"] is result["cutover_authorized"] is False
    assert "environment administrator bypass independently verified" in result["remaining_gates"]


@pytest.mark.parametrize(
    "section,path,value",
    [
        ("repository", "id", True),
        ("repository", "full_name", "other/repo"),
        ("repository", "default_branch", "other"),
        ("branch", "protected", False),
        ("branch", "commit.sha", "b" * 40),
        ("protection", "url", "https://other/PRIVATE"),
        ("protection", "enforce_admins.enabled", False),
        ("protection", "allow_force_pushes.enabled", True),
        ("protection", "allow_deletions.enabled", True),
        ("protection", "required_status_checks.strict", False),
        ("protection", "required_status_checks.checks", []),
        ("protection", "required_pull_request_reviews.required_approving_review_count", 0),
        ("protection", "required_pull_request_reviews.required_approving_review_count", True),
        ("protection", "required_pull_request_reviews.dismiss_stale_reviews", False),
        ("protection", "required_pull_request_reviews.require_last_push_approval", False),
        (
            "protection",
            "required_pull_request_reviews.bypass_pull_request_allowances",
            {"users": [{"id": 1}]},
        ),
    ],
)
def test_unsafe_or_incomplete_controls_fail_closed(observation, section, path, value):
    root, document, _ = observation
    target = document["responses"][section]
    parts = path.split(".")
    for key in parts[:-1]:
        target = target[key]
    target[parts[-1]] = value
    with pytest.raises(ValueError, match="ADMIN002|ADMIN003|GOV003") as error:
        admin.check(root, encoded(document))
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize(
    "fault", ["unknown-app", "any-app", "duplicate-check", "conflicting-check"]
)
def test_check_app_identities_are_explicit(observation, fault):
    root, document, _ = observation
    checks = document["responses"]["protection"]["required_status_checks"]["checks"]
    if fault in {"unknown-app", "any-app"}:
        checks[0]["app_id"] = -1 if fault == "any-app" else None
    elif fault == "duplicate-check":
        checks.append(deepcopy(checks[0]))
    else:
        checks.append({"context": checks[0]["context"], "app_id": -1})
    with pytest.raises(ValueError, match="ADMIN003"):
        admin.check(root, encoded(document))


@pytest.mark.parametrize(
    "fault",
    [
        "commit",
        "policy",
        "keys",
        "stale",
        "future",
        "reversed",
        "long-collection",
        "dirty",
        "version",
        "duplicate",
        "oversize",
    ],
)
def test_binding_clock_and_input_boundaries(observation, monkeypatch, fault):
    root, document, _ = observation
    now = datetime.fromisoformat(document["completed_at"]) + timedelta(seconds=1)
    if fault == "commit":
        document["commit"] = "b" * 40
    elif fault in {"policy", "keys"}:
        path = root / (admin.POLICY if fault == "policy" else admin.KEYS)
        path.write_bytes(path.read_bytes() + b"\n")
    elif fault == "stale":
        now += timedelta(minutes=16)
    elif fault == "future":
        now -= timedelta(minutes=1)
    elif fault == "reversed":
        document["started_at"] = now.isoformat()
    elif fault == "long-collection":
        document["started_at"] = (now - timedelta(minutes=6)).isoformat()
    elif fault == "dirty":
        monkeypatch.setattr(admin, "repository_state", lambda root: (COMMIT, False))
    elif fault == "version":
        document["schema_version"] = True
    payload = encoded(document)
    if fault == "duplicate":
        payload = b'{"commit":"PRIVATE",' + payload[1:]
    elif fault == "oversize":
        payload = b" " * (admin.MAX_BYTES + 1)
    with pytest.raises(ValueError, match="ADMIN001|ADMIN002") as error:
        admin.check(root, payload, now=now)
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize(
    "failure", ["denied", "timeout", "missing-tool", "invalid-json", "oversize"]
)
def test_get_is_read_only_and_suppresses_raw_failures(tmp_path, monkeypatch, failure):
    def run(args, **kwargs):
        assert args[:7] == ["gh", "api", "--hostname", "github.com", "--method", "GET", "-H"]
        assert kwargs["timeout"] == 30 and kwargs["cwd"] == tmp_path
        if failure == "timeout":
            raise subprocess.TimeoutExpired("PRIVATE", 30)
        if failure == "missing-tool":
            raise OSError("PRIVATE")
        payload = b"PRIVATE" if failure != "oversize" else b" " * (admin.MAX_BYTES + 1)
        return subprocess.CompletedProcess(
            args, 1 if failure == "denied" else 0, payload, b"PRIVATE"
        )

    monkeypatch.setattr(admin.subprocess, "run", run)
    with pytest.raises(ValueError, match="ADMIN001|ADMIN004") as error:
        admin._get(tmp_path, "repos/owner/repo")
    assert "PRIVATE" not in str(error.value)


def test_cli_private_collection_offline_check_and_no_overwrite(observation, monkeypatch, capsys):
    root, document, _ = observation
    monkeypatch.setattr(cli, "find_repository", lambda start: root)
    monkeypatch.setattr(admin, "collect", lambda root: encoded(document))
    monkeypatch.setattr(admin, "_get", lambda *args: pytest.fail("offline check made a request"))
    assert cli.main(["security", "collect-administration"]) == 0
    assert (
        cli.main(["security", "check-administration", "--evidence", ".infra/administration.json"])
        == 0
    )
    assert '"cutover_authorized": false' in capsys.readouterr().out
    assert cli.main(["security", "collect-administration"]) == 1
    assert cli.main(["security", "collect-administration", "--output", "config/public.json"]) == 1
    assert not (root / "config/public.json").exists()


@pytest.mark.parametrize(
    "fault",
    ["version", "repository", "traversal", "id", "checks", "app", "duplicate"],
)
def test_public_policy_is_closed_and_explicit(observation, fault):
    root, document, _ = observation
    path = root / admin.POLICY
    policy = json.loads(path.read_bytes())
    if fault == "version":
        policy["schema_version"] = True
    elif fault == "repository":
        policy["repository"] = "https://PRIVATE/other"
    elif fault == "traversal":
        policy["repository"] = "owner/.."
    elif fault == "id":
        policy["repository_id"] = True
    elif fault == "checks":
        policy["required_checks"] = []
    elif fault == "app":
        policy["required_checks"][0]["app_id"] = -1
    else:
        policy["required_checks"].append(deepcopy(policy["required_checks"][0]))
    path.write_bytes(encoded(policy))
    with pytest.raises(ValueError, match="ADMIN001") as error:
        admin.check(root, encoded(document))
    assert "PRIVATE" not in str(error.value)


def test_collection_rejects_head_changed_during_observation(observation):
    root, document, calls = observation
    position = 0

    def query(endpoint):
        nonlocal position
        assert endpoint == calls[position]
        name = ["repository", "branch", "protection", "environment", "branches"][position]
        response = deepcopy(document["responses"][name])
        position += 1
        if name == "branch":
            response["commit"]["sha"] = "b" * 40
        return response

    with pytest.raises(ValueError, match="ADMIN002"):
        admin.collect(root, query=query)


def test_get_parses_a_successful_fixed_host_get(tmp_path, monkeypatch):
    monkeypatch.setattr(
        admin.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, b'{"id": 7}', b""),
    )
    assert admin._get(tmp_path, "repos/owner/repo") == {"id": 7}


@pytest.mark.parametrize("mutable", [None, "payload", "policy", "reviewer_policy"])
def test_rootless_validator_uses_only_supplied_immutable_bytes(observation, monkeypatch, mutable):
    root, document, _ = observation
    inputs = {
        "payload": encoded(document),
        "policy": (root / admin.POLICY).read_bytes(),
        "reviewer_policy": (root / admin.KEYS).read_bytes(),
    }
    if mutable:
        inputs[mutable] = bytearray(inputs[mutable])

    def unavailable(*args, **kwargs):
        pytest.fail("rootless validation attempted external access")

    with monkeypatch.context() as isolated:
        for name in ("_context", "_get", "repository_state"):
            isolated.setattr(admin, name, unavailable)
        isolated.setattr(Path, "open", unavailable)
        if mutable:
            with pytest.raises(ValueError, match="ADMIN001"):
                admin.validate_snapshot(
                    **inputs, commit=COMMIT, now=datetime.fromisoformat(document["completed_at"])
                )
        else:
            assert (
                admin.validate_snapshot(
                    **inputs, commit=COMMIT, now=datetime.fromisoformat(document["completed_at"])
                )["cutover_authorized"]
                is False
            )


def test_policy_check_names_match_both_workflow_matrix_jobs():
    policy = json.loads((ROOT / admin.POLICY).read_bytes())
    workflow = yaml.load(
        (ROOT / ".github/workflows/verify.yml").read_text(), Loader=yaml.BaseLoader
    )
    job = workflow["jobs"]["verify"]
    assert {check["context"] for check in policy["required_checks"]} == {
        job["name"].replace("${{ matrix.os }}", os) for os in job["strategy"]["matrix"]["os"]
    }
    foundation = yaml.load(
        (ROOT / ".github/workflows/pulumi.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert foundation["jobs"]["foundation"]["environment"] == policy["environment"]
    assert policy["workflow"]["path"] == ".github/workflows/verify.yml"


@pytest.mark.parametrize(
    "section,path,value",
    [
        ("environment", "name", "PRIVATE"),
        ("environment", "url", "https://other/PRIVATE"),
        ("environment", "id", True),
        ("environment", "protection_rules", []),
        ("environment", "can_admins_bypass", True),
        ("environment", "can_admins_bypass", None),
        ("environment", "protection_rules.0.prevent_self_review", False),
        ("environment", "protection_rules.0.reviewers", []),
        ("environment", "protection_rules.0.reviewers.0.type", "Bot"),
        ("environment", "protection_rules.0.reviewers.0.type", []),
        ("environment", "protection_rules.0.reviewers.0.reviewer.id", True),
        ("environment", "protection_rules.0.reviewers.0.reviewer.id", -1),
        ("environment", "deployment_branch_policy", None),
        ("environment", "deployment_branch_policy.protected_branches", True),
        ("environment", "deployment_branch_policy.custom_branch_policies", False),
        ("branches", "total_count", 2),
        ("branches", "total_count", True),
        ("branches", "branch_policies", []),
        ("branches", "branch_policies.0.name", "*"),
        ("branches", "branch_policies.0.type", "tag"),
    ],
)
def test_environment_settings_fail_closed(observation, section, path, value):
    root, document, _ = observation
    target = document["responses"][section]
    keys = path.split(".")
    for key in keys[:-1]:
        target = target[int(key)] if isinstance(target, list) else target[key]
    target[keys[-1]] = value
    with pytest.raises(ValueError, match="ADMIN002|ADMIN003|GOV003") as error:
        admin.check(root, encoded(document))
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize(
    "fault",
    [
        "duplicate-rule",
        "duplicate-reviewer",
        "too-many-reviewers",
        "extra-policy",
        "missing-type",
        "missing-count",
        "missing-self-review",
    ],
)
def test_ambiguous_or_incomplete_environment_evidence_fails(observation, fault):
    root, document, _ = observation
    environment = document["responses"]["environment"]
    branches = document["responses"]["branches"]
    rule = environment["protection_rules"][0]
    if fault == "duplicate-rule":
        environment["protection_rules"].append(deepcopy(rule))
    elif fault == "duplicate-reviewer":
        rule["reviewers"].append(deepcopy(rule["reviewers"][0]))
    elif fault == "too-many-reviewers":
        rule["reviewers"] = [{"type": "User", "reviewer": {"id": i}} for i in range(1, 8)]
    elif fault == "extra-policy":
        branches["branch_policies"].append({"name": "release/*", "type": "branch"})
    elif fault == "missing-type":
        branches["branch_policies"][0].pop("type")
    elif fault == "missing-count":
        branches.pop("total_count")
    else:
        rule.pop("prevent_self_review")
    with pytest.raises(ValueError, match="ADMIN003"):
        admin.check(root, encoded(document))


def test_team_review_and_additional_restrictive_rules_leave_unproven_gates(observation):
    root, document, _ = observation
    environment = document["responses"]["environment"]
    environment["protection_rules"][0]["reviewers"][0]["type"] = "Team"
    environment["protection_rules"].append({"type": "wait_timer", "wait_timer": 30})
    environment["can_admins_bypass"] = False
    result = admin.check(root, encoded(document))
    assert result["cutover_authorized"] is result["deployment_authorized"] is False
    assert "environment administrator bypass independently verified" in result["remaining_gates"]


@pytest.mark.parametrize("fault", ["old-snapshot", "main-only", "old-policy", "policy-environment"])
def test_incomplete_or_legacy_evidence_cannot_satisfy_current_schema(observation, fault):
    root, document, _ = observation
    if fault == "old-snapshot":
        document["schema_version"] = 1
    elif fault == "main-only":
        document["responses"].pop("environment")
        document["responses"].pop("branches")
    else:
        path = root / admin.POLICY
        policy = json.loads(path.read_bytes())
        if fault == "old-policy":
            policy["schema_version"] = 1
            policy.pop("environment")
        else:
            policy["environment"] = "../PRIVATE"
        path.write_bytes(encoded(policy))
    with pytest.raises(ValueError, match="ADMIN001|ADMIN002|GOV003") as error:
        admin.check(root, encoded(document))
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("fault", ["denied", "unsafe"])
def test_environment_collection_failure_does_not_write_a_successful_snapshot(
    observation, monkeypatch, capsys, fault
):
    root, document, calls = observation
    position = 0

    def get(root, endpoint):
        nonlocal position
        assert endpoint == calls[position]
        name = ["repository", "branch", "protection", "environment", "branches"][position]
        position += 1
        if name == "environment" and fault == "denied":
            raise ValueError("ADMIN004: denied or unavailable")
        response = deepcopy(document["responses"][name])
        if name == "environment":
            response["protection_rules"][0]["prevent_self_review"] = False
        return response

    monkeypatch.setattr(admin, "_get", get)
    monkeypatch.setattr(cli, "find_repository", lambda start: root)
    assert cli.main(["security", "collect-administration"]) == 1
    assert "FAIL:" in capsys.readouterr().err
    assert not (root / ".infra/administration.json").exists()
