"""Bounded Management API observations; billing and database usage are supplements."""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from infra_core.governance.contracts import GovernanceError, require
from infra_core.inventory.http import observe_get
from infra_core.provider_evidence import Observation

PAGE_SIZE = 100
MAX_CALLS = 128
MAX_BYTES = 16 * 1024 * 1024
MAX_PROJECTS = 10000


@dataclass(frozen=True, slots=True)
class ProjectIdentity:
    id: str
    scope_id: str


@dataclass(frozen=True, slots=True)
class SupabaseCollection:
    account_id: str
    free_organizations: tuple[str, ...]
    projects: tuple[ProjectIdentity, ...]
    observations: tuple[Observation, ...]


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        require(key not in result, "SB002", "duplicate API field")
        result[key] = value
    return result


def collect_management(
    account_id: str, organizations: tuple[str, ...], *, token: str
) -> SupabaseCollection:
    """Reconcile all visible memberships; conservatively count every Free project."""
    require(
        isinstance(account_id, str)
        and bool(account_id.strip())
        and isinstance(organizations, tuple)
        and 1 <= len(organizations) <= 32
        and all(
            isinstance(slug, str) and re.fullmatch(r"[a-z][a-z0-9-]{1,62}", slug)
            for slug in organizations
        )
        and len(set(organizations)) == len(organizations),
        "SB001",
        "independent user and complete organization expectations required",
    )
    observations: list[Observation] = []
    size = 0

    def get(target: str) -> Any:
        nonlocal size
        require(len(observations) < MAX_CALLS, "SB003", "management call budget exceeded")
        try:
            observation = observe_get("supabase", target, token=token)
            size += len(observation.response)
            require(size <= MAX_BYTES, "SB003", "management byte budget exceeded")
            start, end = observation.collection_started_at, observation.collection_finished_at
            first = observations[0].collection_started_at if observations else start
            require(
                observation.provider == "supabase"
                and datetime.now(UTC) - timedelta(minutes=15)
                <= first
                <= start
                <= end
                <= datetime.now(UTC)
                and (not observations or observations[-1].collection_finished_at <= start),
                "SB003",
                "management clocks must be fresh and ordered",
            )
            data = json.loads(observation.response.decode("utf-8"), object_pairs_hook=_object)
            json.dumps(data, allow_nan=False)
            observations.append(observation)
            return data
        except GovernanceError:
            raise
        except Exception:
            raise GovernanceError(
                "SB002: management observation failed; raw details withheld"
            ) from None

    profile = get("/v1/profile")
    require(
        isinstance(profile, dict) and profile.get("gotrue_id") == account_id,
        "SB001",
        "management user differs from expected account",
    )
    visible = get("/v1/organizations")
    require(
        isinstance(visible, list) and len(visible) == len(organizations),
        "SB001",
        "organization visibility differs from reviewed membership",
    )
    membership: dict[str, str] = {}
    for org in visible:
        require(
            isinstance(org, dict)
            and org.get("slug") in organizations
            and org["slug"] not in membership
            and isinstance(org.get("id"), str)
            and bool(org["id"])
            and org["id"] not in membership.values(),
            "SB001",
            "duplicate, missing or unexpected organization",
        )
        membership[org["slug"]] = org["id"]
    projects: list[ProjectIdentity] = []
    free = []
    ids: set[str] = set()
    for slug in sorted(membership):
        org = get(f"/v1/organizations/{slug}")
        require(
            isinstance(org, dict)
            and org.get("id") == membership[slug]
            and isinstance(org.get("plan"), str)
            and org["plan"] in {"free", "pro", "team", "enterprise", "platform"},
            "SB001",
            "organization identity or plan is unclassified",
        )
        if org["plan"] != "free":
            continue
        free.append(slug)
        entitlements = get(f"/v1/organizations/{slug}/entitlements")
        require(
            isinstance(entitlements, dict)
            and isinstance(entitlements.get("entitlements"), list)
            and 0 < len(entitlements["entitlements"]) <= 1000,
            "SB002",
            "organization entitlements are missing",
        )
        features: set[str] = set()
        for item in entitlements["entitlements"]:
            require(
                isinstance(item, dict) and isinstance(item.get("feature"), dict),
                "SB002",
                "invalid entitlement metadata",
            )
            key = item["feature"].get("key")
            require(
                isinstance(key, str)
                and bool(key)
                and key not in features
                and type(item.get("hasAccess")) is bool,
                "SB002",
                "duplicate or invalid entitlement feature",
            )
            features.add(key)
        offset, total = 0, None
        while True:
            data = get(f"/v1/organizations/{slug}/projects?offset={offset}&limit={PAGE_SIZE}")
            require(
                isinstance(data, dict)
                and isinstance(data.get("projects"), list)
                and isinstance(data.get("pagination"), dict),
                "SB003",
                "missing project pagination",
            )
            items, info = data["projects"], data["pagination"]
            require(
                all(type(info.get(k)) is int for k in ("count", "limit", "offset")),
                "SB003",
                "project pagination must use integer counts",
            )
            total = info["count"] if total is None else total
            require(
                0 <= total <= MAX_PROJECTS
                and info["count"] == total
                and info["offset"] == offset
                and info["limit"] == PAGE_SIZE
                and len(items) == min(PAGE_SIZE, total - offset),
                "SB003",
                "changing, incomplete or excessive project pagination",
            )
            for item in items:
                require(
                    isinstance(item, dict)
                    and isinstance(item.get("ref"), str)
                    and re.fullmatch(r"[a-z0-9]{20}", item["ref"]) is not None
                    and item["ref"] not in ids
                    and item.get("is_branch") is False,
                    "SB003",
                    "duplicate, malformed or unsupported branch project",
                )
                ids.add(item["ref"])
                projects.append(ProjectIdentity(item["ref"], slug))
            require(len(projects) <= MAX_PROJECTS, "SB003", "project budget exceeded")
            offset += len(items)
            if offset == total:
                break
    return SupabaseCollection(account_id, tuple(free), tuple(projects), tuple(observations))
