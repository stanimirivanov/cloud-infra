"""Read-only GitHub settings observations; never administrative or deployment authority."""

import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

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


def _json(payload: bytes) -> dict[str, Any]:
    require(len(payload) <= MAX_BYTES, "ADMIN001", "administrative input exceeds size limit")
    try:
        return mapping(json.loads(payload, object_pairs_hook=_object), "administrative input")
    except (ValueError, TypeError, RecursionError):
        raise ValueError("ADMIN001: invalid administrative JSON") from None


def _context(root: Path) -> tuple[dict[str, Any], str, dict[str, str]]:
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
    policy = fields(
        _json(snapshots[POLICY]),
        {"schema_version", "repository", "repository_id", "required_checks"},
        "administrative policy",
    )
    require(
        type(policy["schema_version"]) is int
        and policy["schema_version"] == 1
        and isinstance(policy["repository"], str)
        and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}", policy["repository"]
        )
        is not None
        and policy["repository"].split("/")[1] not in {".", ".."}
        and type(policy["repository_id"]) is int
        and policy["repository_id"] > 0,
        "ADMIN001",
        "unsupported administrative policy identity",
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
    return (
        policy,
        commit,
        {name: hashlib.sha256(data).hexdigest() for name, data in snapshots.items()},
    )


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
    return _json(result.stdout)


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


def check(root: Path, payload: bytes, *, now: datetime | None = None) -> dict[str, Any]:
    policy, commit, bindings = _context(root)
    data = fields(
        _json(payload),
        {"schema_version", "commit", "policy_sha256", "started_at", "completed_at", "responses"},
        "administrative snapshot",
    )
    require(
        type(data["schema_version"]) is int
        and data["schema_version"] == 1
        and data["commit"] == commit
        and data["policy_sha256"] == bindings,
        "ADMIN002",
        "administrative snapshot commit/policy binding differs",
    )
    clock = now or datetime.now(UTC)
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
        {"repository", "branch", "protection"},
        "GitHub observations",
    )
    _controls(policy, responses, commit)
    require(
        repository_state(root) == (commit, True), "ADMIN002", "checkout changed during validation"
    )
    return {
        "status": "observed-controls-consistent",
        "deployment_authorized": False,
        "cutover_authorized": False,
        "remaining_gates": [
            "environment approval, branch restrictions and administrator bypass verified",
            "reviewer identity, key enrollment/custody and protected commit provenance",
            "cutover evidence consumption and explicit operational approval",
        ],
    }


def collect(root: Path, *, query: Callable[[str], dict[str, Any]] | None = None) -> bytes:
    policy, commit, bindings = _context(root)
    start = datetime.now(UTC)
    base = "repos/" + policy["repository"]
    endpoints = {
        "repository": base,
        "branch": base + "/branches/main",
        "protection": base + "/branches/main/protection",
    }
    fetch = query or (lambda endpoint: _get(root, endpoint))
    responses = {name: fetch(endpoint) for name, endpoint in endpoints.items()}
    payload = json.dumps(
        {
            "schema_version": 1,
            "commit": commit,
            "policy_sha256": bindings,
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
