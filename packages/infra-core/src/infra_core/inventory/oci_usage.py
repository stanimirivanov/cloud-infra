"""Bounded usage observations; query completion never establishes billing coverage."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from typing import Any, Protocol

from infra_core.governance.contracts import GovernanceError, number, require, timestamp
from infra_core.provider_evidence import Observation, record_observation

# Oracle price-list SKUs and dimensional units; no cost-to-quantity inference.
_SKUS = {
    "B93297": ("a1_ocpu_hours", "OCPU Per Hour"),
    "B93298": ("a1_memory_gb_hours", "Gigabyte Per Hour"),
    "B91961": ("block_gb_months", "Gigabyte Storage Capacity Per Month"),
    "B91445": ("block_gb_months", "Gigabyte Storage Capacity Per Month"),
}
_METRICS = ("a1_ocpu_hours", "a1_memory_gb_hours", "block_gb_months")
MAX_PAGES = 64
MAX_ROWS = 10000
MAX_BYTES = 16 * 1024 * 1024


class UsageReader(Protocol):
    def usage_page(
        self,
        *,
        account_id: str,
        region: str,
        started: datetime,
        ended: datetime,
        page: str | None,
    ) -> tuple[dict[str, Any], str | None]: ...


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class UsageCollection:
    account_id: str
    query_started_at: datetime
    query_ended_at: datetime
    observations: tuple[Observation, ...]
    # Missing metric is unknown; present zero is an explicit returned quantity.
    totals: tuple[tuple[str, str | None], ...]
    covered_through: None = None


def _date(value: object) -> str:
    if isinstance(value, datetime) and value.utcoffset() is not None:
        return value.isoformat()
    raise GovernanceError("USAGE001: unsupported SDK snapshot value")


def collect_usage(
    reader: UsageReader, account_id: str, home_region: str, *, cutoff: datetime
) -> UsageCollection:
    """Read current UTC month through an explicit completed hour, in <=36h windows.

    Canonical SDK snapshots are retained, not claimed as exact HTTP wire bytes.
    SDK numeric decoding may already have lost precision; Decimal arithmetic here
    cannot reconstruct it. Source completeness/watermark must be proven separately.
    """
    observed = _now()
    require(
        isinstance(cutoff, datetime) and cutoff.utcoffset() is not None,
        "USAGE002",
        "explicit timezone-aware usage cutoff required",
    )
    cutoff = cutoff.astimezone(UTC)
    start = observed.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    require(
        start < cutoff <= observed and not (cutoff.minute or cutoff.second or cutoff.microsecond),
        "USAGE002",
        "cutoff must be an elapsed whole hour in the current UTC month",
    )
    require(
        bool(account_id) and isinstance(account_id, str), "USAGE001", "explicit tenancy required"
    )
    totals: dict[str, Decimal] = {}
    observations: list[Observation] = []
    rows = size = 0
    seen_rows: set[tuple[str, str, str, str]] = set()
    with localcontext() as context:
        context.prec = 80
        while start < cutoff:
            end = min(start + timedelta(hours=36), cutoff)
            page = None
            seen_pages: set[str] = set()
            while True:
                require(len(observations) < MAX_PAGES, "USAGE001", "usage page budget exceeded")
                began = _now()
                try:
                    data, next_page = reader.usage_page(
                        account_id=account_id,
                        region=home_region,
                        started=start,
                        ended=end,
                        page=page,
                    )
                    items = data["items"]
                    require(
                        isinstance(items, list) and len(items) <= 1000,
                        "USAGE001",
                        "invalid usage page rows",
                    )
                    payload = json.dumps(
                        data, default=_date, sort_keys=True, separators=(",", ":"), allow_nan=False
                    ).encode()
                    request = json.dumps(
                        {
                            "operation": "request_summarized_usages",
                            "query_type": "USAGE_ONLY",
                            "granularity": "HOURLY",
                            "group_by": ["tenantId", "skuPartNumber", "unit"],
                            "account_id": account_id,
                            "region": home_region,
                            "start": start.isoformat(),
                            "end": end.isoformat(),
                            "page": page,
                        },
                        sort_keys=True,
                    ).encode()
                    observation = record_observation(
                        "oci", request, payload, started=began, finished=_now()
                    )
                    size += len(payload)
                    rows += len(items)
                    require(
                        size <= MAX_BYTES and rows <= MAX_ROWS,
                        "USAGE001",
                        "usage collection budget exceeded",
                    )
                    for item in items:
                        _accumulate(item, account_id, start, end, totals, seen_rows)
                    require(
                        next_page is None
                        or (
                            isinstance(next_page, str)
                            and 1 <= len(next_page) <= 4096
                            and next_page not in seen_pages
                        ),
                        "USAGE001",
                        "invalid or repeated usage pagination token",
                    )
                except GovernanceError:
                    raise
                except Exception:
                    raise GovernanceError(
                        "USAGE001: usage collection failed; raw details withheld"
                    ) from None
                observations.append(observation)
                if next_page is None:
                    break
                seen_pages.add(next_page)
                page = next_page
            start = end
    return UsageCollection(
        account_id,
        observed.replace(day=1, hour=0, minute=0, second=0, microsecond=0),
        cutoff,
        tuple(observations),
        tuple(
            (metric, format(totals[metric], "f") if metric in totals else None)
            for metric in _METRICS
        ),
    )


def _accumulate(
    item: dict[str, Any],
    account_id: str,
    start: datetime,
    end: datetime,
    totals: dict[str, Decimal],
    seen: set[tuple[str, str, str, str]],
) -> None:
    require(item.get("tenant_id") == account_id, "USAGE003", "usage row tenancy mismatch")
    sku = item.get("sku_part_number")
    require(isinstance(sku, str) and sku in _SKUS, "USAGE003", "unclassified usage SKU")
    assert isinstance(sku, str)
    metric, unit = _SKUS[sku]
    require(item.get("unit") == unit, "USAGE003", "unclassified usage unit")
    began = timestamp(
        _date(item["time_usage_started"])
        if isinstance(item["time_usage_started"], datetime)
        else item["time_usage_started"],
        "usage row start",
    )
    ended = timestamp(
        _date(item["time_usage_ended"])
        if isinstance(item["time_usage_ended"], datetime)
        else item["time_usage_ended"],
        "usage row end",
    )
    require(
        start <= began < ended <= end
        and ended - began == timedelta(hours=1)
        and not (began.minute or began.second or began.microsecond),
        "USAGE003",
        "usage row must be an elapsed hour within its query window",
    )
    key = (sku, unit, began.isoformat(), ended.isoformat())
    require(key not in seen, "USAGE003", "duplicate aggregated usage row")
    seen.add(key)
    value = number(item.get("computed_quantity"), "usage quantity")
    require(
        len(value.as_tuple().digits) <= 40 and abs(int(value.as_tuple().exponent)) <= 20,
        "USAGE003",
        "usage quantity precision exceeds reviewed bound",
    )
    totals[metric] = totals.get(metric, Decimal(0)) + value
