"""Strict governance contracts. Parsed documents are evidence, never authorization."""

import math
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any


class GovernanceError(ValueError):
    """Stable diagnostic without echoing credentials or arbitrary input values."""


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise GovernanceError(f"{code}: {message}")


def number(value: object, label: str, *, positive: bool = False) -> Decimal:
    require(
        type(value) in (int, float, str, Decimal), "GOV001", f"{label} must be known numeric data"
    )
    try:
        result = Decimal(str(value))
    except InvalidOperation:
        raise GovernanceError(f"GOV001: {label} must be known numeric data") from None
    require(
        result.is_finite() and result >= 0 and (not positive or result > 0),
        "GOV001",
        f"{label} must be finite and nonnegative (positive where required)",
    )
    return result


def timestamp(value: object, label: str) -> datetime:
    require(isinstance(value, str), "GOV002", f"{label} requires a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        raise GovernanceError(f"GOV002: invalid {label} timestamp") from None
    require(parsed.tzinfo is not None, "GOV002", f"{label} requires an explicit timezone")
    return parsed.astimezone(UTC)


def mapping(value: object, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), "GOV003", f"{label} must be an object")
    assert isinstance(value, dict)
    require(all(isinstance(key, str) for key in value), "GOV003", f"{label} keys must be strings")
    return value


def fields(value: object, required: set[str], label: str) -> dict[str, Any]:
    result = mapping(value, label)
    require(set(result) == required, "GOV003", f"{label} has missing or unrecognized fields")
    return result


def records(value: object, label: str) -> list[dict[str, Any]]:
    require(isinstance(value, list), "GOV003", f"{label} must be a list")
    assert isinstance(value, list)
    return [mapping(item, label) for item in value]


def text(value: object, label: str) -> str:
    require(
        isinstance(value, str) and bool(value.strip()), "GOV003", f"{label} must be nonempty text"
    )
    return str(value)


def hours_remaining(now: datetime) -> Decimal:
    end = now.replace(
        year=now.year + (now.month == 12),
        month=now.month % 12 + 1,
        day=1,
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
    )
    # Round conservatively up to a whole hour; elapsed usage is supplied separately.
    return Decimal(math.ceil((end - now).total_seconds() / 3600))
