"""Merged-PR observations supply a boundary, never independent approval or authority."""

import json
import subprocess
from copy import deepcopy

import pytest
import test_administration as administrative
import test_cutover as cutover_fixtures
from infra_core import administration, cli, cutover

observation = administrative.observation
review = cutover_fixtures.review


@pytest.mark.parametrize(
    "path,value",
    [
        ("id", True),
        ("id", 99),
        ("number", 99),
        ("number", 0),
        ("state", "open"),
        ("merged", False),
        ("merged", 1),
        ("merge_commit_sha", "b" * 40),
        ("base.ref", "release"),
        ("base.repo.id", True),
        ("base.repo.id", 1),
        ("base.repo.full_name", "PRIVATE/other"),
        ("head.sha", "c" * 40),
        ("head.sha", "PRIVATE"),
        ("user.id", True),
        ("user.type", "Team"),
        ("merged_by.id", 0),
        ("merged_by.type", "Team"),
        ("created_at", "2026-01-01T00:00:00Z"),
        ("merged_at", "2026-01-01T00:00:01Z"),
        ("closed_at", "2025-12-31T23:58:00Z"),
        ("closed_at", "2099-01-01T00:00:00Z"),
        ("merged_at", None),
    ],
)
def test_canonical_pull_request_must_match_the_observed_merge(observation, path, value):
    root, document, _ = observation
    target = document["responses"]["pull_request"]
    keys = path.split(".")
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    with pytest.raises(ValueError, match="ADMIN006|GOV002") as error:
        administration.check(root, json.dumps(document).encode())
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("fault", ["none", "multiple", "number", "base", "missing", "legacy"])
def test_commit_association_is_mandatory_and_unambiguous(observation, fault):
    root, document, _ = observation
    items = document["responses"]["pull_requests"]["items"]
    if fault == "none":
        items.clear()
    elif fault == "multiple":
        items.append(deepcopy(items[0]))
    elif fault == "number":
        items[0]["number"] = "https://PRIVATE"
    elif fault == "base":
        items[0]["base"]["ref"] = "other"
    elif fault == "missing":
        document["responses"].pop("pull_requests")
    else:
        document["schema_version"] = 3
    with pytest.raises(ValueError, match="ADMIN002|ADMIN006|GOV003"):
        administration.check(root, json.dumps(document).encode())


@pytest.mark.parametrize("fault", ["none", "invalid-number", "denied", "invalid-detail"])
def test_collection_rejects_bad_provenance_without_writing_success(
    observation, monkeypatch, capsys, fault
):
    root, document, calls = observation
    responses = document["responses"]
    pages = [
        responses[name]
        for name in ("repository", "branch", "protection", "environment", "branches")
    ]
    pages.extend(responses["checks"].values())
    pages.extend(responses[name] for name in ("workflow_runs", "pull_requests", "pull_request"))
    if fault == "none":
        pages[8]["items"] = []
    elif fault == "invalid-number":
        pages[8]["items"][0]["number"] = "https://PRIVATE"
    elif fault == "invalid-detail":
        pages[9]["merged"] = False
    observed = []

    def get(root, endpoint):
        index = len(observed)
        assert endpoint == calls[index]
        observed.append(endpoint)
        if fault == "denied" and index == 8:
            raise ValueError("ADMIN004: denied or unavailable")
        return pages[index]

    monkeypatch.setattr(administration, "_get", get)
    monkeypatch.setattr(cli, "find_repository", lambda start: root)
    assert cli.main(["security", "collect-administration"]) == 1
    error = capsys.readouterr().err
    assert ("ADMIN004" if fault == "denied" else "ADMIN006") in error
    assert len(observed) == (10 if fault == "invalid-detail" else 9)
    assert not (root / ".infra/administration.json").exists()


@pytest.mark.parametrize("payload", [b"[]", b"[{},{}]", b'[{"id":1,"id":2}]', b"{}"])
def test_get_normalizes_only_the_association_array(tmp_path, monkeypatch, payload):
    def run(args, **kwargs):
        assert args[args.index("--method") + 1] == "GET"
        assert kwargs["cwd"] == tmp_path and kwargs["timeout"] == 30
        return subprocess.CompletedProcess(args, 0, payload, b"PRIVATE")

    monkeypatch.setattr(administration.subprocess, "run", run)
    endpoint = "repos/owner/repo/commits/" + "a" * 40 + "/pulls?per_page=100&page=1"
    if payload in (b"[]", b"[{},{}]"):
        assert administration._get(tmp_path, endpoint) == {"items": json.loads(payload)}
        with pytest.raises(ValueError, match="ADMIN001"):
            administration._get(tmp_path, "repos/owner/repo")
    else:
        with pytest.raises(ValueError, match="ADMIN001"):
            administration._get(tmp_path, endpoint)


@pytest.mark.parametrize("fault", ["wrong-merge", "unmerged", "legacy"])
def test_fresh_cutover_signatures_cannot_upgrade_invalid_provenance(review, fault):
    root, document, artifacts, write = review
    snapshot = artifacts["administration"]
    if fault == "wrong-merge":
        snapshot["responses"]["pull_request"]["merge_commit_sha"] = "b" * 40
    elif fault == "unmerged":
        snapshot["responses"]["pull_request"]["merged"] = False
    else:
        snapshot["schema_version"] = 3
    write("administration", snapshot)
    with pytest.raises(ValueError, match="ADMIN002|ADMIN006"):
        cutover.check(root, document)


def test_observed_merged_pull_does_not_claim_review_or_historical_enforcement(observation):
    root, document, _ = observation
    result = administration.check(root, json.dumps(document).encode())
    assert result["deployment_authorized"] is result["cutover_authorized"] is False
    assert any("last-push reviewer independence" in gate for gate in result["remaining_gates"])
    # Actor identity structure is not an independent-human approval policy.
    document["responses"]["pull_request"]["merged_by"] = {"id": 32, "type": "Bot"}
    administration.check(root, json.dumps(document).encode())
