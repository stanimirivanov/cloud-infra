"""Account-wide final/peak capacity and remaining-month budget evaluation."""

import calendar
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from infra_core.governance.contracts import (
    fields,
    hours_remaining,
    mapping,
    number,
    records,
    require,
    text,
    timestamp,
)
from infra_core.governance.resources import CAPACITY, INVENTORY_TYPES, MONTHLY, footprint


def _fresh(value: object, now: datetime, limit: timedelta, label: str) -> None:
    age = now - timestamp(value, label)
    require(timedelta(0) <= age <= limit, "GOV004", f"{label} is stale or in the future")


def audit(
    account: dict[str, Any],
    profile: dict[str, Any],
    inventory: dict[str, Any],
    plan: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    require(now.tzinfo is not None, "GOV002", "audit clock requires an explicit timezone")
    now = now.astimezone(UTC)
    account = fields(
        account,
        {
            "provider",
            "account_id",
            "home_region",
            "profile",
            "profile_revision",
            "verified",
            "verified_at",
            "other_services_reviewed",
            "reservations",
        },
        "account",
    )
    require(
        account["verified"] is True and account["other_services_reviewed"] is True,
        "GOV005",
        "account entitlement and out-of-scope service review must be verified",
    )
    _fresh(account["verified_at"], now, timedelta(days=30), "entitlement evidence")
    require(
        profile.get("enabled") is True
        and account["profile"] == profile.get("id")
        and type(account["profile_revision"]) is int
        and account["profile_revision"] == profile.get("revision")
        and account["provider"] == profile.get("provider") == "oci",
        "GOV006",
        "profile/provider is disabled, unsupported or mismatched",
    )
    _fresh(profile.get("reviewed_at"), now, timedelta(days=90), "published entitlement profile")
    fields(
        inventory,
        {
            "schema_version",
            "account_id",
            "provider",
            "observed_at",
            "complete",
            "covered_types",
            "all_regions",
            "all_compartments",
            "resources",
            "usage",
        },
        "inventory",
    )
    fields(plan, {"schema_version", "account_id", "provider", "complete", "units"}, "proposal")
    require(
        type(inventory["schema_version"]) is int
        and type(plan["schema_version"]) is int
        and inventory["schema_version"] == plan["schema_version"] == 1,
        "GOV003",
        "unsupported document schema",
    )
    identity = text(account["account_id"], "billing account identity")
    require(
        identity == inventory.get("account_id") == plan.get("account_id")
        and inventory.get("provider") == plan.get("provider") == "oci",
        "GOV007",
        "evidence must refer to the same provider and billing account",
    )
    require(
        inventory.get("complete") is True and plan.get("complete") is True,
        "GOV008",
        "partial inventory or proposal cannot pass",
    )
    _fresh(inventory.get("observed_at"), now, timedelta(minutes=15), "inventory")
    coverage = inventory["covered_types"]
    require(
        isinstance(coverage, list)
        and all(isinstance(kind, str) for kind in coverage)
        and len(coverage) == len(INVENTORY_TYPES)
        and set(coverage) == INVENTORY_TYPES,
        "GOV008",
        "inventory does not cover all required OCI resource families",
    )
    require(
        inventory.get("all_regions") is True and inventory.get("all_compartments") is True,
        "GOV008",
        "inventory must cover the tenancy, not one compartment or unit",
    )
    inventory_records = records(inventory.get("resources"), "inventory resources")
    live: dict[str, dict[str, Any]] = {}
    for item in inventory_records:
        fields(item, {"id", "type", "region", "owner", "retained", "props"}, "inventory resource")
        rid = text(item["id"], "resource ID")
        require(rid not in live, "GOV009", "duplicate resource IDs in inventory")
        require(
            item["region"] == account["home_region"],
            "GOV010",
            "resource is outside the home region",
        )
        require(type(item["retained"]) is bool, "GOV003", "retained must be explicit")
        live[rid] = item
    capacities = {
        rid: footprint(item["type"], mapping(item["props"], "resource properties"), planned=False)
        for rid, item in live.items()
    }
    reservations = mapping(account["reservations"], "reservations")
    require(set(reservations) <= CAPACITY, "GOV003", "unknown reservation metric")
    final = {
        metric: sum((value[metric] for value in capacities.values()), Decimal(0))
        + number(reservations.get(metric, 0), "reservation")
        for metric in CAPACITY
    }
    peak = final.copy()
    claimed: set[str] = set()
    units: set[str] = set()
    keys: set[str] = set()
    for unit in records(plan.get("units"), "proposal units"):
        fields(unit, {"name", "changes"}, "proposal unit")
        name = text(unit["name"], "unit name")
        require(name not in units, "GOV009", "duplicate units would double count or hide changes")
        units.add(name)
        for change in records(unit["changes"], "changes"):
            fields(change, {"key", "action", "existing_ids", "resource"}, "change")
            key = name + "/" + text(change["key"], "change key")
            require(key not in keys, "GOV009", "duplicate change key")
            keys.add(key)
            action = change["action"]
            require(
                isinstance(action, str) and action in {"create", "update", "replace", "delete"},
                "GOV011",
                "unknown change action",
            )
            ids = change["existing_ids"]
            require(
                isinstance(ids, list)
                and all(isinstance(rid, str) for rid in ids)
                and len(set(ids)) == len(ids),
                "GOV009",
                "existing IDs must be distinct strings",
            )
            require(
                (not ids) if action == "create" else bool(ids),
                "GOV011",
                "invalid ownership/change mapping",
            )
            old = dict.fromkeys(CAPACITY, Decimal(0))
            for rid in ids:
                require(
                    rid in live and rid not in claimed and live[rid]["owner"] == name,
                    "GOV012",
                    "existing IDs must have independently evidenced matching unit ownership",
                )
                require(
                    live[rid]["retained"] is False,
                    "GOV013",
                    "retained resources cannot be subtracted",
                )
                claimed.add(rid)
                for metric in CAPACITY:
                    old[metric] += capacities[rid][metric]
            desired = dict.fromkeys(CAPACITY, Decimal(0))
            if action != "delete":
                resource = fields(
                    change["resource"], {"type", "region", "props"}, "desired resource"
                )
                require(
                    resource["region"] == account["home_region"],
                    "GOV010",
                    "desired region must match home",
                )
                desired = footprint(
                    resource["type"], mapping(resource["props"], "desired properties"), planned=True
                )
            else:
                require(
                    change["resource"] is None, "GOV011", "deletions cannot hide desired resources"
                )
            for metric in CAPACITY:
                final[metric] += desired[metric] - old[metric]
                # No credit for other deletions; replacements conservatively overlap in full.
                peak[metric] += (
                    desired[metric]
                    if action in {"create", "replace"}
                    else max(Decimal(0), desired[metric] - old[metric])
                )
    limits = mapping(profile.get("capacity"), "capacity limits")
    require(set(limits) == CAPACITY, "GOV003", "profile must bound every capacity metric")
    for metric in sorted(CAPACITY):
        cap = number(limits[metric], "capacity limit", positive=True)
        require(
            final[metric] <= cap and peak[metric] <= cap,
            "GOV030",
            f"{metric} final/peak exceeds entitlement",
        )
    usage = fields(
        inventory.get("usage"),
        {"account_id", "provider", "month", "observed_at", "source", "values"},
        "monthly usage",
    )
    require(
        usage["account_id"] == identity and usage["provider"] == "oci",
        "GOV007",
        "monthly usage belongs to another billing scope",
    )
    require(
        usage["month"] == now.strftime("%Y-%m"), "GOV031", "usage evidence is for another month"
    )
    _fresh(usage["observed_at"], now, timedelta(minutes=15), "monthly usage")
    text(usage["source"], "monthly usage source")
    values = mapping(usage["values"], "monthly usage values")
    monthly = mapping(profile.get("monthly"), "monthly limits")
    require(
        set(values) == set(monthly) == set(MONTHLY),
        "GOV031",
        "every monthly usage metric is required",
    )
    forecast = {}
    hours = hours_remaining(timestamp(usage["observed_at"], "monthly usage"))
    for metric, capacity in MONTHLY.items():
        factor = (
            hours
            if metric != "block_gb_months"
            else hours / Decimal(calendar.monthrange(now.year, now.month)[1] * 24)
        )
        # Peak for the remaining month is conservative and includes retained/unmanaged capacity.
        forecast[metric] = (
            number(values[metric], "consumed monthly usage") + peak[capacity] * factor
        )
        require(
            forecast[metric] <= number(monthly[metric], "monthly allowance", positive=True),
            "GOV032",
            f"{metric} consumed plus remaining-month forecast exceeds entitlement",
        )
    return {
        "status": "within-modeled-limits",
        "provider": "oci",
        "account_id": identity,
        "profile": profile["id"],
        "final": {k: str(v) for k, v in sorted(final.items())},
        "peak": {k: str(v) for k, v in sorted(peak.items())},
        "monthly_forecast": {k: str(v) for k, v in sorted(forecast.items())},
        "deployment_authorized": False,
    }
