"""Successful check names alone cannot substitute for the pinned workflow's execution."""

import json
from copy import deepcopy
from datetime import datetime, timedelta

import pytest
import test_administration as administrative
import test_cutover as cutover_fixtures
from infra_core import administration, cli, cutover

observation = administrative.observation
review = cutover_fixtures.review


def execution(document):
    responses = document["responses"]
    checks = list(responses["checks"].values())
    return checks, checks[0]["check_runs"][0], responses["workflow_runs"]["workflow_runs"][0]


@pytest.mark.parametrize(
    "kind,path,value",
    [
        ("check", "name", "PRIVATE"),
        ("check", "head_sha", "b" * 40),
        ("check", "status", "in_progress"),
        ("check", "conclusion", "failure"),
        ("check", "conclusion", "skipped"),
        ("check", "conclusion", "neutral"),
        ("check", "id", True),
        ("check", "app.id", -1),
        ("check", "app.id", True),
        ("check", "check_suite.id", 0),
        ("workflow", "id", True),
        ("workflow", "workflow_id", 1),
        ("workflow", "path", ".github/workflows/other.yml"),
        ("workflow", "head_sha", "b" * 40),
        ("workflow", "head_branch", "other"),
        ("workflow", "event", "pull_request"),
        ("workflow", "event", "workflow_dispatch"),
        ("workflow", "conclusion", "failure"),
        ("workflow", "status", "queued"),
        ("workflow", "check_suite_id", 23),
        ("workflow", "repository.id", 1),
        ("workflow", "head_repository.id", True),
        ("workflow", "run_started_at", "2026-01-01T00:00:02Z"),
        ("check", "completed_at", "2026-01-01T00:00:00Z"),
    ],
)
def test_mismatched_execution_cannot_be_reported_as_success(observation, kind, path, value):
    root, document, _ = observation
    _, check, workflow = execution(document)
    target = check if kind == "check" else workflow
    keys = path.split(".")
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    with pytest.raises(ValueError, match="ADMIN005") as error:
        administration.check(root, json.dumps(document).encode())
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize(
    "fault",
    [
        "count",
        "missing",
        "duplicate",
        "suite",
        "identity",
        "extra-context",
        "run-count",
        "duplicate-run",
        "future",
        "legacy",
        "missing-execution",
    ],
)
def test_execution_pages_are_complete_and_bound_to_one_suite(observation, fault):
    root, document, _ = observation
    checks, first, workflow = execution(document)
    code = "ADMIN005"
    if fault == "count":
        checks[0]["total_count"] = True
    elif fault == "missing":
        checks[0]["check_runs"] = []
    elif fault == "duplicate":
        checks[0]["check_runs"].append(deepcopy(first))
    elif fault == "suite":
        checks[1]["check_runs"][0]["check_suite"]["id"] = 99
    elif fault == "identity":
        checks[1]["check_runs"][0]["id"] = first["id"]
    elif fault == "extra-context":
        document["responses"]["checks"]["other"] = checks[0]
        code = "GOV003"
    elif fault == "run-count":
        document["responses"]["workflow_runs"]["total_count"] = 2
    elif fault == "duplicate-run":
        document["responses"]["workflow_runs"]["workflow_runs"].append(deepcopy(workflow))
    elif fault == "future":
        workflow["updated_at"] = (
            datetime.fromisoformat(document["completed_at"]) + timedelta(seconds=1)
        ).isoformat()
    elif fault == "legacy":
        document["schema_version"] = 2
        code = "ADMIN002"
    else:
        document["responses"].pop("checks")
        code = "GOV003"
    with pytest.raises(ValueError, match=code):
        administration.check(root, json.dumps(document).encode())


@pytest.mark.parametrize("field,value", [("id", True), ("path", "../PRIVATE.yml")])
def test_workflow_policy_identity_is_closed_and_explicit(observation, field, value):
    root, document, _ = observation
    path = root / administration.POLICY
    policy = json.loads(path.read_bytes())
    policy["workflow"][field] = value
    path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(ValueError, match="ADMIN001"):
        administration.check(root, json.dumps(document).encode())


@pytest.mark.parametrize("fault", ["failed-check", "other-workflow", "legacy"])
def test_valid_cutover_signatures_cannot_upgrade_execution_failures(review, fault):
    root, document, artifacts, write = review
    observation = artifacts["administration"]
    _, check, workflow = execution(observation)
    if fault == "failed-check":
        check["conclusion"] = "failure"
    elif fault == "other-workflow":
        workflow["workflow_id"] += 1
    else:
        observation["schema_version"] = 2
    write("administration", observation)
    with pytest.raises(ValueError, match="ADMIN002|ADMIN005"):
        cutover.check(root, document)


def test_failed_check_collection_never_fetches_a_run_or_writes_success(
    observation, monkeypatch, capsys
):
    root, document, calls = observation
    responses = document["responses"]
    by_endpoint = dict(
        zip(
            calls[:5],
            (
                responses[name]
                for name in ("repository", "branch", "protection", "environment", "branches")
            ),
            strict=True,
        )
    )
    by_endpoint.update(zip(calls[5:7], responses["checks"].values(), strict=True))
    first = next(iter(responses["checks"].values()))["check_runs"][0]
    first["conclusion"] = "failure"

    def get(root, endpoint):
        assert endpoint != calls[-1], "failed checks must not select a workflow run"
        return by_endpoint[endpoint]

    monkeypatch.setattr(administration, "_get", get)
    monkeypatch.setattr(cli, "find_repository", lambda start: root)
    assert cli.main(["security", "collect-administration"]) == 1
    assert "ADMIN005" in capsys.readouterr().err
    assert not (root / ".infra/administration.json").exists()


def test_legacy_environment_only_policy_requires_migration(observation):
    root, document, _ = observation
    path = root / administration.POLICY
    policy = json.loads(path.read_bytes())
    policy["schema_version"] = 2
    policy.pop("workflow")
    path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(ValueError, match="ADMIN001|GOV003"):
        administration.check(root, json.dumps(document).encode())
