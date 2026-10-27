"""Final-head review observations never imply last-push or operational approval."""

import json
import subprocess
from copy import deepcopy

import pytest
import test_administration as administrative
import test_cutover as cutover_fixtures
from infra_core import administration, cli, cutover

observation = administrative.observation
review = cutover_fixtures.review


def check(root, document):
    return administration.check(root, json.dumps(document).encode())


def items(document):
    return document["responses"]["reviews"]["items"]


@pytest.mark.parametrize(
    "path,value",
    [
        ("id", True),
        ("id", 0),
        ("user.id", True),
        ("user.id", 32),
        ("user.type", "Bot"),
        ("user.type", "Team"),
        ("state", "PENDING"),
        ("state", "PRIVATE"),
        ("state", "DISMISSED"),
        ("state", "CHANGES_REQUESTED"),
        ("state", "COMMENTED"),
        ("commit_id", "c" * 40),
        ("commit_id", "PRIVATE"),
        ("pull_request_url", "https://PRIVATE/pulls/31"),
        ("author_association", "CONTRIBUTOR"),
        ("author_association", None),
        ("submitted_at", "2025-12-31T23:57:59Z"),
        ("submitted_at", "2025-12-31T23:59:01Z"),
        ("submitted_at", "2099-01-01T00:00:00Z"),
        ("submitted_at", None),
    ],
)
def test_invalid_or_ineligible_approval_never_counts(observation, path, value):
    root, document, _ = observation
    target = items(document)[0]
    keys = path.split(".")
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    with pytest.raises(ValueError, match="ADMIN007|GOV002") as error:
        check(root, document)
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize(
    "fault", ["missing", "empty", "full-page", "duplicate", "unordered", "tie", "legacy"]
)
def test_review_coverage_and_order_fail_closed(observation, fault):
    root, document, _ = observation
    reviews = items(document)
    if fault == "missing":
        document["responses"].pop("reviews")
    elif fault == "empty":
        reviews.clear()
    elif fault == "full-page":
        reviews.extend(deepcopy(reviews[0]) for _ in range(99))
    elif fault == "duplicate":
        reviews.append(deepcopy(reviews[0]))
    elif fault in ("unordered", "tie"):
        later = deepcopy(reviews[0])
        later["id"] += 1
        if fault == "unordered":
            later["submitted_at"] = "2025-12-31T23:58:29Z"
        reviews.append(later)
    else:
        document["schema_version"] = 4
    with pytest.raises(ValueError, match="ADMIN002|ADMIN007|GOV003"):
        check(root, document)


@pytest.mark.parametrize(
    "state", ["CHANGES_REQUESTED", "DISMISSED", "APPROVED", "COMMENTED", "stale-head"]
)
def test_only_latest_decision_counts_and_comments_do_not_erase_it(observation, state):
    root, document, _ = observation
    later = deepcopy(items(document)[0])
    later.update(id=41, state=state, submitted_at="2025-12-31T23:58:40Z")
    if state == "stale-head":
        later.update(state="APPROVED", commit_id="c" * 40)
    items(document).append(later)
    if state in ("APPROVED", "COMMENTED"):
        check(root, document)
    else:
        with pytest.raises(ValueError, match="ADMIN007"):
            check(root, document)


@pytest.mark.parametrize("state", ["CHANGES_REQUESTED", "DISMISSED"])
def test_other_users_change_request_blocks_despite_enough_approvals(observation, state):
    root, document, _ = observation
    other = deepcopy(items(document)[0])
    other.update(id=41, state=state, submitted_at="2025-12-31T23:58:40Z")
    other["user"]["id"] = 35
    items(document).append(other)
    if state == "CHANGES_REQUESTED":
        with pytest.raises(ValueError, match="unresolved change requests"):
            check(root, document)
    else:
        check(root, document)  # Another user's dismissed verdict cannot revoke this approval.


def test_distinct_users_meet_count_and_resolved_changes_are_supported(observation):
    root, document, _ = observation
    document["responses"]["protection"]["required_pull_request_reviews"][
        "required_approving_review_count"
    ] = 2
    second = deepcopy(items(document)[0])
    second.update(id=41, submitted_at="2025-12-31T23:58:40Z")
    items(document).append(second)
    with pytest.raises(ValueError, match="ADMIN007"):
        check(root, document)  # Two decisions by one user cannot meet a count of two.
    second["user"]["id"] = 35
    second["author_association"] = "MEMBER"
    check(root, document)
    first = items(document)[0]
    first["state"] = "CHANGES_REQUESTED"
    with pytest.raises(ValueError, match="ADMIN007"):
        check(root, document)
    resolution = deepcopy(first)
    resolution.update(id=42, state="APPROVED", submitted_at="2025-12-31T23:58:50Z")
    items(document).append(resolution)
    check(root, document)


@pytest.mark.parametrize("fault", ["denied", "invalid"])
def test_review_collection_failure_writes_no_success(observation, monkeypatch, capsys, fault):
    root, document, calls = observation
    responses = document["responses"]
    pages = [
        responses[name]
        for name in ("repository", "branch", "protection", "environment", "branches")
    ]
    pages.extend(responses["checks"].values())
    pages.extend(
        responses[name] for name in ("workflow_runs", "pull_requests", "pull_request", "reviews")
    )
    observed = []

    def get(root, endpoint):
        index = len(observed)
        assert endpoint == calls[index]
        observed.append(endpoint)
        if index == 10:
            if fault == "denied":
                raise ValueError("ADMIN004: denied")
            return {"items": []}
        return pages[index]

    monkeypatch.setattr(administration, "_get", get)
    monkeypatch.setattr(cli, "find_repository", lambda start: root)
    assert cli.main(["security", "collect-administration"]) == 1
    assert ("ADMIN004" if fault == "denied" else "ADMIN007") in capsys.readouterr().err
    assert len(observed) == 11
    assert not (root / ".infra/administration.json").exists()


def test_review_array_adapter_uses_fixed_get_without_following_urls(tmp_path, monkeypatch):
    endpoint = "repos/owner/repo/pulls/31/reviews?per_page=100&page=1"

    def run(args, **kwargs):
        assert args[-1] == endpoint and args[args.index("--method") + 1] == "GET"
        assert kwargs["cwd"] == tmp_path and kwargs["timeout"] == 30
        return subprocess.CompletedProcess(args, 0, b'[{"url":"https://PRIVATE"}]', b"")

    monkeypatch.setattr(administration.subprocess, "run", run)
    assert administration._get(tmp_path, endpoint) == {"items": [{"url": "https://PRIVATE"}]}


@pytest.mark.parametrize("fault", ["stale-head", "dismissed", "legacy"])
def test_new_cutover_signatures_cannot_upgrade_invalid_review_observations(review, fault):
    root, document, artifacts, write = review
    snapshot = artifacts["administration"]
    if fault == "stale-head":
        items(snapshot)[0]["commit_id"] = "c" * 40
    elif fault == "dismissed":
        items(snapshot)[0]["state"] = "DISMISSED"
    else:
        snapshot["schema_version"] = 4
    write("administration", snapshot)
    with pytest.raises(ValueError, match="ADMIN002|ADMIN007"):
        cutover.check(root, document)


def test_review_observations_leave_last_push_and_custody_gates(observation):
    root, document, _ = observation
    result = check(root, document)
    assert result["deployment_authorized"] is result["cutover_authorized"] is False
    assert any("last-push reviewer independence" in gate for gate in result["remaining_gates"])
