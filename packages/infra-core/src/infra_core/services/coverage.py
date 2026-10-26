"""Service collection clocks and explicit metric windows; no provider or filesystem access."""

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from infra_core.governance.contracts import fields, number, require, timestamp


def usage_coverage(
    evidence: dict[str, Any],
    metrics: set[str],
    now: datetime,
    period: dict[str, str] | None,
) -> tuple[dict[str, Decimal], dict[str, dict[str, str]]]:
    start = timestamp(evidence["collection_started_at"], "service collection start")
    end = timestamp(evidence["collection_completed_at"], "service collection completion")
    observed = timestamp(evidence["observed_at"], "service observation")
    require(
        now - timedelta(minutes=15) <= start == observed <= end <= now,
        "EXT022",
        "service collection must be fresh, ordered and bound to observation",
    )
    usage = fields(evidence["usage"], metrics, "current target-scope usage")
    values: dict[str, Decimal] = {}
    coverage: dict[str, dict[str, str]] = {}
    for metric in sorted(metrics):
        gauge = metric == "storage_mb"
        clock = "as_of" if gauge else "covered_through"
        reading = fields(
            usage[metric],
            {"value", clock} | (set() if gauge else {"covered_from"}),
            "service metric reading",
        )
        cutoff = timestamp(reading[clock], "service metric coverage")
        require(
            now - timedelta(minutes=15) <= cutoff <= end,
            "EXT022",
            "each metric must have fresh coverage no later than collection completion",
        )
        coverage[metric] = {clock: cutoff.isoformat()}
        if not gauge:
            beginning = timestamp(reading["covered_from"], "service metric window start")
            require(
                period is not None
                and beginning == timestamp(period["starts_at"], "billing period start")
                and beginning <= cutoff,
                "EXT022",
                "cumulative metrics must cover the current billing cycle from its start",
            )
            coverage[metric]["covered_from"] = beginning.isoformat()
        if metric == "storage_gb_hours":
            require(
                type(reading["value"]) in (int, str, Decimal),
                "GOV001",
                "storage GB-hours require an integer or exact decimal string",
            )
        values[metric] = number(reading["value"], "service metric value")
    return values, coverage
