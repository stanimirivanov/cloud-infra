"""Source-attested organization anniversaries; consistency is not authenticity."""

from calendar import monthrange
from datetime import datetime, timedelta
from typing import Any

from infra_core.governance.contracts import fields, require, timestamp


def billing_period(value: object, *, metered: bool, now: datetime) -> dict[str, str] | None:
    """Require the current half-open monthly period, preserving the original anchor day.

    Month-end clamping never moves the original anniversary (January 31 becomes
    February 28/29 then March 31). All comparisons and anniversaries use UTC.
    """
    if not metered:
        require(value is None, "EXT024", "unmetered DNS evidence must have no billing period")
        return None
    period: dict[str, Any] = fields(
        value, {"anchor_at", "starts_at", "ends_at"}, "organization billing period"
    )
    anchor = timestamp(period["anchor_at"], "organization billing anchor")
    start = timestamp(period["starts_at"], "billing period start")
    end = timestamp(period["ends_at"], "billing period end")
    require(
        anchor <= now and 1 < now.year < 9999,
        "EXT024",
        "billing anchor must not be in the future and cycle must be representable",
    )

    def anniversary(month: datetime) -> datetime:
        return anchor.replace(
            year=month.year,
            month=month.month,
            day=min(anchor.day, monthrange(month.year, month.month)[1]),
        )

    month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    expected_start = anniversary(month)
    if now < expected_start:
        month = (month - timedelta(days=1)).replace(day=1)
        expected_start = anniversary(month)
    expected_end = anniversary((month + timedelta(days=32)).replace(day=1))
    require(
        anchor <= start == expected_start <= now < end == expected_end,
        "EXT024",
        "billing period must match the current organization anniversary cycle",
    )
    return {
        "anchor_at": anchor.isoformat(),
        "starts_at": start.isoformat(),
        "ends_at": end.isoformat(),
    }
