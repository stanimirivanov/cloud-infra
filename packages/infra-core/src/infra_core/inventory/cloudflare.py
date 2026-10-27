"""Paginated zone DNS observations; entitlement is independently reviewed."""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from infra_core.governance.contracts import GovernanceError, require
from infra_core.inventory.http import observe_get
from infra_core.provider_evidence import Observation

PAGE_SIZE = 100
MAX_PAGES = 100
MAX_RECORDS = 10000
MAX_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class DNSRecord:
    id: str
    name: str
    type: str


@dataclass(frozen=True, slots=True)
class CloudflareCollection:
    account_id: str
    zone_id: str
    zone_name: str
    reported_plan: str | None
    records: tuple[DNSRecord, ...]
    observations: tuple[Observation, ...]


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        require(key not in result, "CF002", "duplicate API JSON field")
        result[key] = value
    return result


def collect_zone(
    account_id: str, zone_id: str, zone_name: str, *, token: str
) -> CloudflareCollection:
    """Count all DNS types; never accept caller-selected endpoints or filters."""
    require(
        all(
            isinstance(value, str) and re.fullmatch(r"[a-f0-9]{32}", value)
            for value in (account_id, zone_id)
        ),
        "CF001",
        "explicit account and zone IDs required",
    )
    require(
        isinstance(zone_name, str)
        and len(zone_name) <= 253
        and re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            zone_name,
        )
        is not None,
        "CF001",
        "explicit lowercase zone domain required",
    )
    observations: list[Observation] = []
    size = 0

    def get(target: str) -> dict[str, Any]:
        nonlocal size
        try:
            observation = observe_get("cloudflare", target, token=token)
            size += len(observation.response)
            require(size <= MAX_BYTES, "CF005", "collection byte budget exceeded")
            start, end = observation.collection_started_at, observation.collection_finished_at
            require(
                observation.provider == "cloudflare"
                and datetime.now(UTC) - timedelta(minutes=15) <= start <= end <= datetime.now(UTC)
                and (not observations or observations[-1].collection_finished_at <= start),
                "CF005",
                "invalid or stale observation clocks",
            )
            require(
                not observations
                or datetime.now(UTC) - observations[0].collection_started_at
                <= timedelta(minutes=15),
                "CF005",
                "collection interval exceeded freshness",
            )
            data = json.loads(observation.response.decode("utf-8"), object_pairs_hook=_object)
            json.dumps(data, allow_nan=False)
            require(
                isinstance(data, dict) and data.get("success") is True and data.get("errors") == [],
                "CF002",
                "API response is not successful",
            )
            assert isinstance(data, dict)
            observations.append(observation)
            return data
        except GovernanceError:
            raise
        except Exception:
            raise GovernanceError("CF002: zone observation failed; raw details withheld") from None

    zone = get(f"/client/v4/zones/{zone_id}").get("result")
    require(
        isinstance(zone, dict)
        and zone.get("id") == zone_id
        and isinstance(zone.get("account"), dict)
        and zone["account"].get("id") == account_id
        and zone.get("name") == zone_name
        and zone.get("status") == "active",
        "CF001",
        "observed zone does not match the reviewed active scope",
    )
    assert isinstance(zone, dict)
    plan = zone.get("plan")
    require(
        plan is None or (isinstance(plan, dict) and isinstance(plan.get("legacy_id"), str)),
        "CF002",
        "unclassified zone plan metadata",
    )
    reported_plan = plan["legacy_id"] if plan is not None else None
    records: list[DNSRecord] = []
    ids: set[str] = set()
    total = None
    for page in range(1, MAX_PAGES + 1):
        data = get(f"/client/v4/zones/{zone_id}/dns_records?page={page}&per_page={PAGE_SIZE}")
        items, info = data.get("result"), data.get("result_info")
        require(
            isinstance(items, list) and isinstance(info, dict),
            "CF003",
            "DNS page requires records and pagination metadata",
        )
        assert isinstance(items, list) and isinstance(info, dict)
        require(
            all(
                type(info.get(k)) is int
                for k in ("page", "per_page", "count", "total_count", "total_pages")
            ),
            "CF003",
            "DNS pagination counts must be integers",
        )
        if total is None:
            total = info["total_count"]
        pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        require(
            0 <= total <= MAX_RECORDS
            and pages <= MAX_PAGES
            and info["page"] == page
            and info["per_page"] == PAGE_SIZE
            and info["total_count"] == total
            and info["count"] == len(items)
            and info["total_pages"] in ((0, 1) if total == 0 else (pages,))
            and len(items) == min(PAGE_SIZE, total - len(records)),
            "CF003",
            "incomplete, changing or excessive DNS pagination",
        )
        for item in items:
            require(isinstance(item, dict), "CF004", "invalid DNS record")
            rid, name, kind = (item.get(key) for key in ("id", "name", "type"))
            require(
                isinstance(rid, str)
                and re.fullmatch(r"[a-f0-9]{32}", rid) is not None
                and rid not in ids
                and isinstance(name, str)
                and 0 < len(name) <= 253
                and name == name.lower()
                and (name == zone_name or name.endswith("." + zone_name))
                and isinstance(kind, str)
                and re.fullmatch(r"[A-Z][A-Z0-9]{0,15}", kind) is not None,
                "CF004",
                "duplicate, malformed or out-of-zone DNS record",
            )
            assert isinstance(rid, str) and isinstance(name, str) and isinstance(kind, str)
            ids.add(rid)
            records.append(DNSRecord(rid, name, kind))
        if page == pages:
            return CloudflareCollection(
                account_id, zone_id, zone_name, reported_plan, tuple(records), tuple(observations)
            )
    raise GovernanceError("CF005: DNS page budget exhausted")
