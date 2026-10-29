"""Read-only measured capacity/usage and original evidence clocks; never admission."""

import hashlib
import json
import tomllib
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Context, Decimal, localcontext
from functools import partial
from operator import getitem
from pathlib import Path
from typing import Any

from infra_core import operations
from infra_core.administration import private_path
from infra_core.governance.contracts import fields, mapping, number, records, timestamp
from infra_core.governance.coverage import validate_coverage
from infra_core.governance.resources import CAPACITY, INVENTORY_TYPES, MONTHLY, footprint
from infra_core.services.billing import billing_period
from infra_core.services.coverage import usage_coverage
from infra_core.services.governance import MAXIMUM, METRICS, _dns_name

MESSAGE = "FND001: invalid monitoring inputs or policy; diagnostics withheld"
PROVIDERS = dict(
    zip(
        ("oci-network", "oci-oke", "cloudflare-edge", "supabase-database"),
        ("oci", "oci", "cloudflare", "supabase"),
        strict=True,
    )
)
AGES = dict(observation=900, billing_lag=900, profile=90 * 86400, entitlement=30 * 86400)


def require(value: bool) -> None:
    if not value:
        raise ValueError(MESSAGE)


def exact(value: object, *, positive: bool = False) -> Decimal:
    require(type(value) in (int, str, Decimal))
    result = number(value, "monitoring measurement", positive=positive)
    # 100-character operands and bounded magnitudes fit the 256-digit cross products.
    require(len(str(value)) <= 100 and -50 <= result.adjusted() <= 12)
    return result


def policy(value: dict[str, Any]) -> dict[str, Any]:
    fields(
        value,
        {
            "schema_version",
            "enabled",
            "warning_utilization_percent",
            "critical_utilization_percent",
            "warning_age_percent",
            "max_age_seconds",
        },
        "monitoring policy",
    )
    require(
        type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["enabled"] is True
    )
    warning, critical = (
        exact(value[k], positive=True)
        for k in ("warning_utilization_percent", "critical_utilization_percent")
    )
    require(warning < critical <= 100 and 0 < exact(value["warning_age_percent"]) < 100)
    ages = fields(value["max_age_seconds"], set(AGES), "monitoring ages")
    require(all(type(ages[k]) is int and 0 < ages[k] <= cap for k, cap in AGES.items()))
    return value


def evaluate(
    config: dict[str, Any],
    scope: dict[str, Any],
    profile: dict[str, Any],
    evidence: dict[str, Any],
    account: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate captured readings, retaining unknown per metric, without incident state."""
    config = policy(config)
    fields(scope, {"unit", "account_id", "scope_id", "profile"}, "monitoring scope")
    require(
        all(type(v) is str and 0 < len(v) <= 256 for v in scope.values())
        and scope["unit"] in PROVIDERS
    )
    now = now or datetime.now(UTC)
    require(now.tzinfo is not None)
    now = now.astimezone(UTC)
    provider = PROVIDERS[scope["unit"]]
    require(
        scope["profile"]
        in ({"oci-free", "oci-paid-a1"} if provider == "oci" else {provider + "-free"})
    )
    findings: list[dict[str, Any]] = []
    scope_hash = operations.digest(scope)

    def add(metric: str, status: str, reason: str, **details: Any) -> None:
        findings.append(
            dict(
                id=scope["unit"] + "/" + scope_hash + "/" + metric,
                metric=metric,
                status=status,
                reason=reason,
                **details,
            )
        )

    def attempt(metric: str, read: Callable[[], Any]) -> Any:
        try:
            return read()
        except (ValueError, KeyError, TypeError, ArithmeticError):
            add(metric, "unknown", "missing_invalid_or_incomplete")
            return None

    def gate(metric: str, read: Callable[[], Any]) -> Any:
        value = attempt(metric, read)
        if value is not None:
            add(metric, "normal", "coverage_consistent")
        return value

    def limit(section: str, metric: str) -> object:
        value = profile.get(section)
        return value.get(metric) if type(value) is dict else None

    def age(metric: str, value: object, category: str) -> bool:
        def read() -> bool:
            instant = timestamp(value, "measurement clock")
            seconds = Decimal(str((now - instant).total_seconds()))
            require(seconds >= 0)
            maximum = config["max_age_seconds"][category]
            with localcontext(Context(prec=256)):
                status = (
                    "critical"
                    if seconds >= maximum
                    else "warning"
                    if (seconds * 100 >= maximum * exact(config["warning_age_percent"]))
                    else "normal"
                )
            add(
                metric,
                status,
                "age_threshold",
                observed_at=value,
                age_seconds=str(seconds),
                max_age_seconds=maximum,
            )
            return bool(seconds <= maximum)

        return attempt(metric, read) is True

    def measurement(metric: str, read: Callable[[], object], limit: object, valid: bool) -> None:
        def calculate() -> None:
            require(valid)
            used, maximum = exact(read()), exact(limit, positive=True)
            with localcontext(Context(prec=256)):
                percent = used * 100 / maximum
                status = (
                    "critical"
                    if used * 100 >= maximum * exact(config["critical_utilization_percent"])
                    else "warning"
                    if used * 100 >= maximum * exact(config["warning_utilization_percent"])
                    else "normal"
                )
                headroom = maximum - used
            add(
                metric,
                status,
                "exhausted" if used >= maximum else "utilization_threshold",
                value=str(used),
                limit=str(maximum),
                headroom=str(headroom),
                utilization_percent=str(percent),
            )

        attempt(metric, calculate)

    def identity() -> bool:
        require(
            evidence["provider"] == profile["provider"] == provider
            and evidence["account_id"] == scope["account_id"]
            and profile["id"] == scope["profile"]
            and profile["enabled"] is True
            and type(profile["revision"]) is int
        )
        entitled = account if provider == "oci" else evidence
        require(
            entitled is not None
            and entitled["verified"] is True
            and entitled["other_services_reviewed"] is True
            and entitled["profile_revision"] == profile["revision"]
            and type(entitled["profile_revision"]) is int
        )
        assert entitled is not None
        if provider == "oci":
            require(
                entitled["provider"] == "oci"
                and entitled["account_id"] == scope["account_id"]
                and entitled["home_region"] == scope["scope_id"]
                and entitled["profile"] == scope["profile"]
            )
        else:
            require(
                account is None
                and evidence["scope_id"] == scope["scope_id"]
                and evidence["plan"] == "free"
                and type(evidence["source"]) is str
                and bool(evidence["source"].strip())
            )
        add("scope", "normal", "scope_consistent")
        return True

    bound = attempt("scope", identity) is True
    entitlement = account if provider == "oci" else evidence
    reviewed = age("profile_age", profile.get("reviewed_at"), "profile")
    verified = age("entitlement_age", (entitlement or {}).get("verified_at"), "entitlement")
    fresh = age("observation_age", evidence.get("observed_at"), "observation")

    def collection() -> bool:
        start = timestamp(evidence["collection_started_at"], "collection start")
        end = timestamp(evidence["collection_completed_at"], "collection end")
        observed = timestamp(evidence["observed_at"], "observation")
        require(start == observed <= end <= now and evidence["complete"] is True)
        require(
            type(evidence["schema_version"]) is int
            and evidence["schema_version"] == (2 if provider == "oci" else 4)
        )
        return True

    collected = gate("collection", collection) is True
    valid = bound and reviewed and verified and fresh and collected
    if provider == "oci":

        def capacity() -> dict[str, Decimal]:
            require(
                valid
                and account is not None
                and evidence["all_regions"] is True
                and evidence["all_compartments"] is True
                and type(evidence["covered_types"]) is list
                and len(evidence["covered_types"]) == len(INVENTORY_TYPES)
                and set(evidence["covered_types"]) == INVENTORY_TYPES
            )
            validate_coverage(evidence, scope["scope_id"], now)
            limits = fields(profile["capacity"], CAPACITY, "capacity limits")
            require(all(exact(v, positive=True) for v in limits.values()))
            assert account is not None
            reservation = account["reservations"]
            require(type(reservation) is dict and set(reservation) <= CAPACITY)
            totals = {k: exact(reservation.get(k, 0)) for k in CAPACITY}
            seen: set[str] = set()
            for row in records(evidence["resources"], "inventory"):
                fields(
                    row,
                    {"id", "type", "region", "owner", "retained", "props"},
                    "inventory resource",
                )
                require(
                    type(row["id"]) is str
                    and bool(row["id"])
                    and row["id"] not in seen
                    and row["region"] == scope["scope_id"]
                    and row["type"] in INVENTORY_TYPES
                    and type(row["retained"]) is bool
                )
                seen.add(row["id"])
                # Never subtract unmanaged/retained capacity or double-count node pool membership.
                with localcontext(Context(prec=256)):
                    sizes = footprint(
                        row["type"], mapping(row["props"], "resource properties"), planned=False
                    )
                    for metric in CAPACITY:
                        totals[metric] += exact(sizes[metric])
            return totals

        totals = gate("inventory_coverage", capacity)
        for metric in sorted(CAPACITY):
            measurement(
                "capacity/" + metric,
                partial(getitem, totals, metric),
                limit("capacity", metric),
                totals is not None,
            )

        usage = evidence.get("usage")
        usage = usage if type(usage) is dict else {}
        billing_fresh = age("billing_observation_age", usage.get("observed_at"), "observation")
        coverage_fresh = age("billing_coverage_age", usage.get("covered_through"), "billing_lag")

        def window() -> bool:
            require(
                valid
                and usage["provider"] == "oci"
                and usage["account_id"] == scope["account_id"]
                and usage["month"] == now.strftime("%Y-%m")
                and type(usage["source"]) is str
                and bool(usage["source"].strip())
                and type(usage["values"]) is dict
                and set(usage["values"]) <= set(MONTHLY)
            )
            cutoff = timestamp(usage["covered_through"], "billing coverage")
            observed = timestamp(usage["observed_at"], "billing observation")
            require(
                cutoff.strftime("%Y-%m") == usage["month"]
                and cutoff
                <= observed
                <= timestamp(evidence["collection_completed_at"], "collection completion")
            )
            fields(profile["monthly"], set(MONTHLY), "monthly limits")
            return True

        covered = gate("billing_window", window) is True
        for metric in sorted(MONTHLY):
            measurement(
                "usage/" + metric,
                partial(getitem, usage.get("values", {}), metric),
                limit("monthly", metric),
                covered and billing_fresh and coverage_fresh,
            )
        windows = dict(
            month=usage.get("month"),
            observed_at=usage.get("observed_at"),
            covered_through=usage.get("covered_through"),
        )
    else:

        def capacity_service() -> tuple[int, Decimal]:
            require(
                valid
                and evidence["coverage"]
                == (
                    "all-zone-dns-records"
                    if provider == "cloudflare"
                    else "all-owned-admin-free-projects-and-target-org-usage"
                )
            )
            require(profile["max_resources"] == (200 if provider == "cloudflare" else 2))
            rows = records(evidence["resources"], "service inventory")
            seen: set[str] = set()
            maximum = Decimal(0)
            zone = (
                _dns_name(evidence["scope_name"]) if provider == "cloudflare" else scope["scope_id"]
            )
            require(provider == "cloudflare" or evidence["scope_name"] == zone)
            for row in rows:
                fields(
                    row,
                    {"id", "name", "type"}
                    if provider == "cloudflare"
                    else {"id", "scope_id", "database_mb"},
                    "service resource",
                )
                require(type(row["id"]) is str and bool(row["id"]) and row["id"] not in seen)
                seen.add(row["id"])
                if provider == "cloudflare":
                    require(
                        type(row["name"]) is str
                        and row["name"] == row["name"].lower()
                        and (row["name"] == zone or row["name"].endswith("." + zone))
                        and type(row["type"]) is str
                        and bool(row["type"])
                    )
                else:
                    require(type(row["scope_id"]) is str and bool(row["scope_id"]))
                    maximum = max(maximum, exact(row["database_mb"]))
            return len(rows), maximum

        sizes = gate("inventory_coverage", capacity_service)
        measurement(
            "capacity/resources", lambda: sizes[0], profile.get("max_resources"), sizes is not None
        )
        if provider == "supabase":
            measurement("capacity/max_database_mb", lambda: sizes[1], 500, sizes is not None)

        def period_read() -> dict[str, str] | None:
            require(
                valid
                and type(evidence["usage"]) is dict
                and set(evidence["usage"]) <= (METRICS if provider == "supabase" else set())
            )
            return billing_period(
                evidence["billing_period"], metered=provider == "supabase", now=now
            )

        # None is the valid unmetered Cloudflare result, so record success separately.
        period_ok = False

        def period_check() -> dict[str, str] | None:
            nonlocal period_ok
            period = period_read()
            period_ok = True
            return period

        period = attempt("billing_window", period_check)
        if period_ok:
            add("billing_window", "normal", "coverage_consistent")
        windows = {}
        for metric in sorted(METRICS if provider == "supabase" else set()):
            readings = evidence.get("usage")
            reading = readings.get(metric, {}) if type(readings) is dict else {}
            reading = reading if type(reading) is dict else {}
            clock = "as_of" if metric == "storage_mb" else "covered_through"
            timely = age("coverage_age/" + metric, reading.get(clock), "billing_lag")

            def metered(m: str = metric, reading: dict[str, Any] = reading) -> Decimal:
                require(valid and period_ok and profile["usage_limits"][m] == MAXIMUM[m])
                exact(reading["value"])
                values, _ = usage_coverage(dict(evidence, usage={m: reading}), {m}, now, period)
                return values[m]

            measurement("usage/" + metric, metered, limit("usage_limits", metric), timely)
            windows[metric] = {k: reading.get(k) for k in (clock, "covered_from") if k in reading}

    # Only validated timestamps/month labels can leave the private evidence boundary.
    def safe_clocks(value: dict[str, Any]) -> dict[str, Any]:
        clean: dict[str, Any] = {}
        for key, item in value.items():
            if key in METRICS and type(item) is dict:
                clean[key] = safe_clocks(item)
            elif item is not None:
                try:
                    if key == "month":
                        require(item == now.strftime("%Y-%m"))
                    else:
                        timestamp(item, "source clock")
                    clean[key] = item
                except (ValueError, TypeError):
                    clean[key] = None
        return clean

    status = next(
        (s for s in ("unknown", "critical", "warning") if any(f["status"] == s for f in findings)),
        "normal",
    )
    return dict(
        schema_version=1,
        kind="operational-findings",
        unit=scope["unit"],
        provider=provider,
        scope_sha256=scope_hash,
        evaluated_at=now.isoformat(),
        status=status,
        complete=not any(f["status"] == "unknown" for f in findings),
        findings=findings,
        source_clocks=safe_clocks(
            {
                k: evidence.get(k)
                for k in ("observed_at", "collection_started_at", "collection_completed_at")
            }
        ),
        usage_windows=safe_clocks(windows),
        deployment_authorized=False,
        remediation_authorized=False,
    )


def check(root: Path, index: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Read bounded private snapshots only; never collect, persist or advance journals."""
    try:

        def read(path: Path) -> bytes:
            require(path.is_file() and path.stat().st_size <= operations.MAX_BYTES)
            raw = path.read_bytes()
            require(0 < len(raw) <= operations.MAX_BYTES)
            return raw

        def parse(raw: bytes) -> dict[str, Any]:
            value = json.loads(raw, object_pairs_hook=operations._pairs)
            json.dumps(value, allow_nan=False)
            require(type(value) is dict)
            assert isinstance(value, dict)
            return value

        index_raw = read(private_path(root, index))
        item = parse(index_raw)
        fields(
            item, {"schema_version", "scope", "policy", "evidence", "account"}, "monitoring index"
        )
        require(type(item["schema_version"]) is int and item["schema_version"] == 1)
        raw = {key: read(private_path(root, Path(item[key]))) for key in ("policy", "evidence")}
        profile_raw = read(root / "config/quotas/profiles.toml")
        profiles = tomllib.loads(profile_raw.decode())["profiles"]
        account = None
        if item["account"] is not None:
            account_path = (root / item["account"]).resolve()
            require(
                account_path.is_relative_to(root.resolve() / ".infra")
                and account_path.suffix == ".toml"
            )
            raw["account"] = read(account_path)
            account = tomllib.loads(raw["account"].decode())
        result = evaluate(
            parse(raw["policy"]),
            item["scope"],
            profiles[item["scope"]["profile"]],
            parse(raw["evidence"]),
            account,
            now=now,
        )
        result["inputs_sha256"] = {
            k: hashlib.sha256(v).hexdigest()
            for k, v in dict(raw, index=index_raw, profiles=profile_raw).items()
        }
        return result
    except Exception:
        raise ValueError(MESSAGE) from None
