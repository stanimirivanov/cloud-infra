"""Synthetic REST observations exercise administrative sensors without credentials."""

import json
import subprocess
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import yaml
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
    base = "https://api.github.com/repos/" + policy["repository"]
    responses = {
        "repository": {
            "id": policy["repository_id"],
            "full_name": policy["repository"],
            "default_branch": "main",
        },
        "branch": {"name": "main", "protected": True, "commit": {"sha": COMMIT}},
        "protection": {
            "url": base + "/branches/main/protection",
            "enforce_admins": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
            "required_status_checks": {
                "strict": True,
                "checks": deepcopy(policy["required_checks"]),
            },
            "required_pull_request_reviews": {
                "required_approving_review_count": 1,
                "dismiss_stale_reviews": True,
                "require_last_push_approval": True,
            },
        },
    }
    calls = []

    def query(endpoint):
        calls.append(endpoint)
        return deepcopy(responses[list(responses)[len(calls) - 1]])

    payload = admin.collect(tmp_path, query=query)
    return tmp_path, json.loads(payload), calls


def encoded(document):
    return json.dumps(document).encode()


def test_collection_and_offline_revalidation_preserve_disabled_authority(observation):
    root, document, calls = observation
    assert len(calls) == 3
    assert calls[-1].endswith("/branches/main/protection")
    result = admin.check(root, encoded(document))
    assert result["status"] == "observed-controls-consistent"
    assert result["deployment_authorized"] is result["cutover_authorized"] is False
    assert (
        "environment approval, branch restrictions and administrator bypass verified"
        in result["remaining_gates"]
    )


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
        name = ["repository", "branch", "protection"][position]
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


def test_policy_check_names_match_both_workflow_matrix_jobs():
    policy = json.loads((ROOT / admin.POLICY).read_bytes())
    workflow = yaml.load(
        (ROOT / ".github/workflows/verify.yml").read_text(), Loader=yaml.BaseLoader
    )
    job = workflow["jobs"]["verify"]
    assert {check["context"] for check in policy["required_checks"]} == {
        job["name"].replace("${{ matrix.os }}", os) for os in job["strategy"]["matrix"]["os"]
    }
