"""Service collection clocks and explicit metric windows; no provider or filesystem access."""

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from infra_core.governance.contracts import fields, number, require, timestamp


def usage_coverage(
    evidence: dict[str, Any],
    metrics: set[str],
    now: datetime,
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
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
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
                beginning == month_start and beginning <= cutoff,
                "EXT022",
                "monthly metrics must cover the current UTC month from its start",
            )
            coverage[metric]["covered_from"] = beginning.isoformat()
        values[metric] = number(reading["value"], "service metric value")
    return values, coverage
