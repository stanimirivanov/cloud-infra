"""Read-only GitHub settings observations; never administrative or deployment authority."""

import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

from infra_core.cutover import repository_state
from infra_core.governance.contracts import fields, mapping, records, require, timestamp

MAX_BYTES = 1024 * 1024
POLICY = "config/administration.json"
KEYS = "config/cutover-reviewers.toml"


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "ADMIN001", "duplicate JSON field")
        result[key] = value
    return result


def _json(payload: bytes, *, array: bool = False) -> dict[str, Any]:
    require(len(payload) <= MAX_BYTES, "ADMIN001", "administrative input exceeds size limit")
    try:
        value = json.loads(payload, object_pairs_hook=_object)
        if array:
            return {"items": records(value, "GitHub array")}
        return mapping(value, "administrative input")
    except (ValueError, TypeError, RecursionError):
        raise ValueError("ADMIN001: invalid administrative JSON") from None


def _context(root: Path) -> tuple[dict[str, Any], str, dict[str, bytes]]:
    commit, clean = repository_state(root)
    require(
        clean and re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit) is not None,
        "ADMIN002",
        "administrative evidence requires a clean committed checkout",
    )
    snapshots = {}
    for name in (POLICY, KEYS):
        with (root / name).open("rb") as stream:
            payload = stream.read(MAX_BYTES + 1)
        require(len(payload) <= MAX_BYTES, "ADMIN001", "policy exceeds size limit")
        snapshots[name] = payload
    return _policy(snapshots[POLICY]), commit, snapshots


def _policy(payload: bytes) -> dict[str, Any]:
    policy = fields(
        _json(payload),
        {
            "schema_version",
            "repository",
            "repository_id",
            "environment",
            "workflow",
            "required_checks",
        },
        "administrative policy",
    )
    require(
        type(policy["schema_version"]) is int
        and policy["schema_version"] == 3
        and isinstance(policy["repository"], str)
        and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}", policy["repository"]
        )
        is not None
        and policy["repository"].split("/")[1] not in {".", ".."}
        and type(policy["repository_id"]) is int
        and policy["repository_id"] > 0
        and isinstance(policy["environment"], str)
        and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", policy["environment"]) is not None,
        "ADMIN001",
        "unsupported administrative policy identity",
    )
    workflow = fields(policy["workflow"], {"id", "path"}, "verification workflow")
    require(
        type(workflow["id"]) is int
        and workflow["id"] > 0
        and isinstance(workflow["path"], str)
        and re.fullmatch(r"\.github/workflows/[A-Za-z0-9_-]+\.ya?ml", workflow["path"]) is not None,
        "ADMIN001",
        "verification workflow identity must be explicit",
    )
    checks = records(policy["required_checks"], "required checks")
    require(1 <= len(checks) <= 16, "ADMIN001", "required checks must be explicit")
    seen = set()
    for check in checks:
        fields(check, {"context", "app_id"}, "required check")
        require(
            isinstance(check["context"], str)
            and 1 <= len(check["context"]) <= 256
            and check["context"] not in seen
            and type(check["app_id"]) is int
            and check["app_id"] > 0,
            "ADMIN001",
            "required check identity must be unique and app-bound",
        )
        seen.add(check["context"])
    return policy


def _bindings(policy: bytes, reviewer_policy: bytes) -> dict[str, str]:
    return {
        POLICY: hashlib.sha256(policy).hexdigest(),
        KEYS: hashlib.sha256(reviewer_policy).hexdigest(),
    }


def _get(root: Path, endpoint: str) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [
                "gh",
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
                "-H",
                "Accept: application/vnd.github+json",
                "-H",
                "X-GitHub-Api-Version: 2022-11-28",
                endpoint,
            ],
            cwd=root,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError("ADMIN004: GitHub GET unavailable; raw diagnostics suppressed") from None
    require(result.returncode == 0, "ADMIN004", "GitHub GET denied or unavailable; no evidence")
    return _json(
        result.stdout,
        array=("/commits/" in endpoint and endpoint.endswith("/pulls?per_page=100&page=1"))
        or ("/pulls/" in endpoint and endpoint.endswith("/reviews?per_page=100&page=1")),
    )


def _controls(policy: dict[str, Any], responses: dict[str, Any], commit: str) -> None:
    repo, branch, protection = (
        mapping(responses[name], "GitHub response")
        for name in ("repository", "branch", "protection")
    )
    api = "https://api.github.com/repos/" + policy["repository"]
    require(
        type(repo.get("id")) is int
        and repo["id"] == policy["repository_id"]
        and repo.get("full_name") == policy["repository"]
        and repo.get("default_branch") == "main"
        and branch.get("name") == "main"
        and branch.get("protected") is True
        and mapping(branch.get("commit"), "branch commit").get("sha") == commit
        and protection.get("url") == api + "/branches/main/protection",
        "ADMIN002",
        "repository/main identity differs from reviewed checkout",
    )
    for name, enabled in (
        ("enforce_admins", True),
        ("allow_force_pushes", False),
        ("allow_deletions", False),
    ):
        require(
            mapping(protection.get(name), "branch control").get("enabled") is enabled,
            "ADMIN003",
            "main administrator/force-push/deletion control is unsafe",
        )
    checks = mapping(protection.get("required_status_checks"), "required status checks")
    actual = records(checks.get("checks"), "app-bound checks")
    require(
        checks.get("strict") is True
        and all(
            sum(item.get("context") == expected["context"] for item in actual) == 1
            and sum(
                item.get("context") == expected["context"]
                and type(item.get("app_id")) is int
                and item["app_id"] == expected["app_id"]
                for item in actual
            )
            == 1
            for expected in policy["required_checks"]
        ),
        "ADMIN003",
        "strict required harness checks must match their trusted app",
    )
    reviews = mapping(protection.get("required_pull_request_reviews"), "PR review control")
    count = reviews.get("required_approving_review_count")
    bypass = mapping(reviews.get("bypass_pull_request_allowances", {}), "PR bypass")
    require(
        type(count) is int
        and 1 <= count <= 6
        and reviews.get("dismiss_stale_reviews") is True
        and reviews.get("require_last_push_approval") is True
        and set(bypass) <= {"users", "teams", "apps"}
        and all(bypass.get(kind, []) == [] for kind in ("users", "teams", "apps")),
        "ADMIN003",
        "independent current PR review with no explicit bypass is required",
    )


def _environment(policy: dict[str, Any], responses: dict[str, Any]) -> None:
    environment = mapping(responses["environment"], "environment observation")
    branches = mapping(responses["branches"], "environment branch observations")
    require(
        environment.get("name") == policy["environment"]
        and environment.get("url")
        == "https://api.github.com/repos/"
        + policy["repository"]
        + "/environments/"
        + policy["environment"]
        and type(environment.get("id")) is int
        and environment["id"] > 0,
        "ADMIN002",
        "environment identity differs from reviewed policy",
    )
    rules = records(environment.get("protection_rules"), "environment rules")
    reviewers = [rule for rule in rules if rule.get("type") == "required_reviewers"]
    require(
        len(reviewers) == 1
        and reviewers[0].get("prevent_self_review") is True
        and environment.get("can_admins_bypass", False) is False,
        "ADMIN003",
        "environment requires self-review prevention and no observed admin bypass",
    )
    people = records(reviewers[0].get("reviewers"), "environment reviewers")
    identities = [(p.get("type"), mapping(p.get("reviewer"), "reviewer").get("id")) for p in people]
    require(
        1 <= len(people) <= 6
        and all(
            kind in ("User", "Team") and type(identity) is int and identity > 0
            for kind, identity in identities
        )
        and len(set(identities)) == len(identities),
        "ADMIN003",
        "environment reviewer identities must be explicit and unique",
    )
    selection = mapping(environment.get("deployment_branch_policy"), "environment selection")
    policies = records(branches.get("branch_policies"), "environment branch policies")
    require(
        selection.get("protected_branches") is False
        and selection.get("custom_branch_policies") is True
        and type(branches.get("total_count")) is int
        and branches["total_count"] == 1
        and len(policies) == 1
        and policies[0].get("name") == "main"
        and policies[0].get("type") == "branch",
        "ADMIN003",
        "environment must select only main branch; incomplete lists/tags unsupported",
    )


def _successful(value: dict[str, Any], commit: str) -> bool:
    return (
        value.get("head_sha") == commit
        and value.get("status") == "completed"
        and value.get("conclusion") == "success"
    )


def _check_suite(
    policy: dict[str, Any], value: object, commit: str
) -> tuple[int, list[dict[str, Any]]]:
    checks = fields(
        value, {item["context"] for item in policy["required_checks"]}, "check observations"
    )
    suite_id = None
    observed = []
    ids = set()
    for expected in policy["required_checks"]:
        response = mapping(checks[expected["context"]], "check-run page")
        runs = records(response.get("check_runs"), "check runs")
        require(
            type(response.get("total_count")) is int
            and response["total_count"] == 1
            and len(runs) == 1,
            "ADMIN005",
            "one complete unambiguous latest required check is needed",
        )
        run = runs[0]
        app = mapping(run.get("app"), "check app")
        suite = mapping(run.get("check_suite"), "check suite").get("id")
        identity = run.get("id")
        require(
            type(identity) is int
            and identity > 0
            and identity not in ids
            and type(suite) is int
            and suite > 0
            and (suite_id is None or suite_id == suite)
            and run.get("name") == expected["context"]
            and type(app.get("id")) is int
            and app["id"] == expected["app_id"]
            and _successful(run, commit),
            "ADMIN005",
            "required checks must succeed at the expected commit/app in one suite",
        )
        ids.add(identity)
        suite_id = suite
        observed.append(run)
    assert isinstance(suite_id, int)
    return suite_id, observed


def _execution(
    policy: dict[str, Any], responses: dict[str, Any], commit: str, end: datetime
) -> None:
    suite, checks = _check_suite(policy, responses["checks"], commit)
    page = mapping(responses["workflow_runs"], "workflow-run page")
    runs = records(page.get("workflow_runs"), "workflow runs")
    require(
        type(page.get("total_count")) is int and page["total_count"] == 1 and len(runs) == 1,
        "ADMIN005",
        "one complete workflow run must correspond to the check suite",
    )
    run = runs[0]
    require(
        _successful(run, commit)
        and type(run.get("id")) is int
        and run["id"] > 0
        and type(run.get("workflow_id")) is int
        and run["workflow_id"] == policy["workflow"]["id"]
        and run.get("path") == policy["workflow"]["path"]
        and run.get("event") == "push"
        and run.get("head_branch") == "main"
        and type(run.get("check_suite_id")) is int
        and run["check_suite_id"] == suite
        and all(
            type(mapping(run.get(name), "run repository").get("id")) is int
            and run[name]["id"] == policy["repository_id"]
            for name in ("repository", "head_repository")
        ),
        "ADMIN005",
        "successful execution must belong to the pinned workflow and main repository",
    )
    created, started, updated = (
        timestamp(run.get(name), "workflow execution")
        for name in ("created_at", "run_started_at", "updated_at")
    )
    require(
        created <= started <= updated <= end,
        "ADMIN005",
        "workflow clocks are inconsistent or future",
    )
    for check in checks:
        first, last = (
            timestamp(check.get(name), "check execution") for name in ("started_at", "completed_at")
        )
        require(
            started <= first <= last <= updated,
            "ADMIN005",
            "check clocks differ from workflow execution",
        )


def _associated_pull(policy: dict[str, Any], value: object, commit: str) -> dict[str, Any]:
    page = fields(value, {"items"}, "associated pull requests")
    items = records(page["items"], "associated pull requests")
    # A single result on a 100-record page cannot silently omit another page.
    require(len(items) == 1, "ADMIN006", "one unambiguous introducing pull request is required")
    pull = items[0]
    _pull_identity(policy, pull, commit)
    return pull


def _pull_identity(policy: dict[str, Any], pull: dict[str, Any], commit: str) -> None:
    base = mapping(pull.get("base"), "pull request base")
    repo = mapping(base.get("repo"), "pull request repository")
    require(
        all(type(pull.get(name)) is int and pull[name] > 0 for name in ("id", "number"))
        and pull.get("state") == "closed"
        and pull.get("merge_commit_sha") == commit
        and base.get("ref") == "main"
        and type(repo.get("id")) is int
        and repo["id"] == policy["repository_id"]
        and repo.get("full_name") == policy["repository"],
        "ADMIN006",
        "introducing pull request must match the expected merge commit and repository/main",
    )


def _provenance(
    policy: dict[str, Any], responses: dict[str, Any], commit: str, end: datetime
) -> None:
    associated = _associated_pull(policy, responses["pull_requests"], commit)
    pull = mapping(responses["pull_request"], "canonical pull request")
    _pull_identity(policy, pull, commit)
    head = mapping(pull.get("head"), "pull request head")
    require(
        pull["id"] == associated["id"]
        and pull["number"] == associated["number"]
        and pull.get("merged") is True
        and isinstance(head.get("sha"), str)
        and re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", head["sha"]) is not None
        and head.get("sha") == mapping(associated.get("head"), "associated head").get("sha"),
        "ADMIN006",
        "canonical merged pull request must match its association and reviewed head",
    )
    for name in ("user", "merged_by"):
        actor = mapping(pull.get(name), "pull request actor")
        require(
            type(actor.get("id")) is int
            and actor["id"] > 0
            and actor.get("type") in ("User", "Bot"),
            "ADMIN006",
            "pull request actors require explicit numeric identities",
        )
    created, merged, closed = (
        timestamp(pull.get(name), "pull request clock")
        for name in ("created_at", "merged_at", "closed_at")
    )
    execution = responses["workflow_runs"]["workflow_runs"][0]
    require(
        created <= merged <= closed <= end
        and merged <= timestamp(execution["created_at"], "workflow creation"),
        "ADMIN006",
        "merge clocks must precede main execution and observation",
    )


def _review_approvals(policy: dict[str, Any], responses: dict[str, Any], end: datetime) -> None:
    pull = responses["pull_request"]  # Canonical identity/head/clocks validated first.
    page = fields(responses["reviews"], {"items"}, "PR reviews")
    reviews = records(page["items"], "PR reviews")
    require(1 <= len(reviews) < 100, "ADMIN007", "review page empty or potentially truncated")
    created = timestamp(pull["created_at"], "PR creation")
    merged = timestamp(pull["merged_at"], "PR merge")
    previous = created
    ids = set()
    decisions: dict[int, tuple[datetime, dict[str, Any]]] = {}
    for review in reviews:
        actor = mapping(review.get("user"), "review actor")
        identity = review.get("id")
        state = review.get("state")
        require(
            type(identity) is int
            and identity > 0
            and identity not in ids
            and type(actor.get("id")) is int
            and actor["id"] > 0
            and actor.get("type") in ("User", "Bot")
            and state in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED", "COMMENTED")
            and review.get("pull_request_url")
            == "https://api.github.com/repos/"
            + policy["repository"]
            + "/pulls/"
            + str(pull["number"])
            and isinstance(review.get("commit_id"), str)
            and re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", review["commit_id"]) is not None,
            "ADMIN007",
            "review must have unique identities, a known submitted state and matching PR",
        )
        submitted = timestamp(review.get("submitted_at"), "review submission")
        require(previous <= submitted <= end, "ADMIN007", "review clocks unordered or future")
        previous = submitted
        ids.add(identity)
        if state != "COMMENTED":
            prior = decisions.get(actor["id"])
            require(
                prior is None or prior[0] < submitted,
                "ADMIN007",
                "same-user decision clocks are ambiguous",
            )
            decisions[actor["id"]] = (submitted, review)
    require(
        all(review["state"] != "CHANGES_REQUESTED" for _, review in decisions.values()),
        "ADMIN007",
        "unresolved change requests block approval evidence",
    )
    approvals = sum(
        review["state"] == "APPROVED"
        and identity != pull["user"]["id"]
        and review["user"]["type"] == "User"
        and review.get("author_association") in ("OWNER", "MEMBER", "COLLABORATOR")
        and review["commit_id"] == pull["head"]["sha"]
        and submitted <= merged
        for identity, (submitted, review) in decisions.items()
    )
    required = responses["protection"]["required_pull_request_reviews"][
        "required_approving_review_count"
    ]
    require(
        approvals >= required, "ADMIN007", "insufficient distinct non-author final-head approvals"
    )


def validate_snapshot(
    payload: bytes, *, policy: bytes, reviewer_policy: bytes, commit: str, now: datetime
) -> dict[str, Any]:
    """Validate captured immutable inputs only; no Git, filesystem or network access."""
    require(
        all(
            type(value) is bytes and len(value) <= MAX_BYTES
            for value in (payload, policy, reviewer_policy)
        ),
        "ADMIN001",
        "administrative inputs require bounded immutable bytes",
    )
    require(
        isinstance(commit, str) and re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit) is not None,
        "ADMIN002",
        "expected commit must be explicit",
    )
    bindings = _bindings(policy, reviewer_policy)
    expected = _policy(policy)
    data = fields(
        _json(payload),
        {"schema_version", "commit", "policy_sha256", "started_at", "completed_at", "responses"},
        "administrative snapshot",
    )
    require(
        type(data["schema_version"]) is int
        and data["schema_version"] == 5
        and data["commit"] == commit
        and data["policy_sha256"] == bindings,
        "ADMIN002",
        "administrative snapshot commit/policy binding differs",
    )
    clock = now
    require(clock.tzinfo is not None, "ADMIN002", "clock requires timezone")
    start, end = (
        timestamp(data["started_at"], "collection start"),
        timestamp(data["completed_at"], "collection end"),
    )
    require(
        start <= end <= clock
        and end - start <= timedelta(minutes=5)
        and clock - start <= timedelta(minutes=15),
        "ADMIN002",
        "administrative observations stale or collection incomplete",
    )
    responses = fields(
        data["responses"],
        {
            "repository",
            "branch",
            "protection",
            "environment",
            "branches",
            "checks",
            "workflow_runs",
            "pull_requests",
            "pull_request",
            "reviews",
        },
        "GitHub observations",
    )
    _controls(expected, responses, commit)
    _environment(expected, responses)
    _execution(expected, responses, commit, end)
    _provenance(expected, responses, commit, end)
    _review_approvals(expected, responses, end)
    return {
        "status": "observed-controls-consistent",
        "deployment_authorized": False,
        "cutover_authorized": False,
        "remaining_gates": [
            "environment administrator bypass independently verified",
            "last-push reviewer independence, key enrollment/custody and historical protection",
            "cutover evidence consumption and explicit operational approval",
        ],
    }


def check(root: Path, payload: bytes, *, now: datetime | None = None) -> dict[str, Any]:
    _, commit, snapshots = _context(root)
    result = validate_snapshot(
        payload,
        policy=snapshots[POLICY],
        reviewer_policy=snapshots[KEYS],
        commit=commit,
        now=now or datetime.now(UTC),
    )
    require(
        repository_state(root) == (commit, True), "ADMIN002", "checkout changed during validation"
    )
    return result


def collect(root: Path, *, query: Callable[[str], dict[str, Any]] | None = None) -> bytes:
    policy, commit, snapshots = _context(root)
    start = datetime.now(UTC)
    base = "repos/" + policy["repository"]
    environment = base + "/environments/" + policy["environment"]
    endpoints = {
        "repository": base,
        "branch": base + "/branches/main",
        "protection": base + "/branches/main/protection",
        "environment": environment,
        "branches": environment + "/deployment-branch-policies?per_page=100&page=1",
    }
    fetch = query or (lambda endpoint: _get(root, endpoint))
    responses = {name: fetch(endpoint) for name, endpoint in endpoints.items()}
    # Reject unsafe base settings before spending requests on execution observations.
    _controls(policy, responses, commit)
    _environment(policy, responses)
    responses["checks"] = {
        item["context"]: fetch(
            base
            + "/commits/"
            + commit
            + "/check-runs?check_name="
            + quote(item["context"], safe="")
            + "&filter=latest&per_page=100&page=1"
        )
        for item in policy["required_checks"]
    }
    suite, _ = _check_suite(policy, responses["checks"], commit)
    responses["workflow_runs"] = fetch(
        base + "/actions/runs?check_suite_id=" + str(suite) + "&per_page=100&page=1"
    )
    _execution(policy, responses, commit, datetime.now(UTC))
    responses["pull_requests"] = fetch(base + "/commits/" + commit + "/pulls?per_page=100&page=1")
    pull = _associated_pull(policy, responses["pull_requests"], commit)
    responses["pull_request"] = fetch(base + "/pulls/" + str(pull["number"]))
    _provenance(policy, responses, commit, datetime.now(UTC))
    responses["reviews"] = fetch(
        base + "/pulls/" + str(pull["number"]) + "/reviews?per_page=100&page=1"
    )
    payload = json.dumps(
        {
            "schema_version": 5,
            "commit": commit,
            "policy_sha256": _bindings(snapshots[POLICY], snapshots[KEYS]),
            "started_at": start.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
            "responses": responses,
        },
        sort_keys=True,
    ).encode()
    check(root, payload)
    return payload


def private_path(root: Path, path: Path) -> Path:
    destination = (root / path).resolve()
    require(
        destination.is_relative_to(root.resolve() / ".infra") and destination.suffix == ".json",
        "ADMIN001",
        "administrative evidence must be private JSON under checkout .infra",
    )
    return destination
