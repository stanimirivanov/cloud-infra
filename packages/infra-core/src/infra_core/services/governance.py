"""Closed additive service contracts and scope-aware, evidence-bound cost preflight."""

import ipaddress
import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

from infra_core.governance.contracts import (
    GovernanceError,
    fields,
    number,
    records,
    require,
    text,
    timestamp,
)
from infra_core.services.coverage import usage_coverage

DNS = "cloudflare:index/dnsRecord:DnsRecord"
PROJECT = "supabase:index/project:Project"
UNITS = {"cloudflare": "cloudflare-edge", "supabase": "supabase-database"}
METRICS = {"egress_mb", "cached_egress_mb", "storage_mb", "mau"}
MAXIMUM = {"egress_mb": 5000, "cached_egress_mb": 5000, "storage_mb": 1000, "mau": 50000}


def _dns_name(value: object) -> str:
    name = text(value, "DNS name")
    require(
        len(name) <= 253
        and name == name.lower()
        and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in name.split("."))
        and "." in name,
        "EXT010",
        "DNS names must be explicit lowercase FQDNs without wildcards or trailing dots",
    )
    return name


def validate_resource(kind: str, props: dict[str, Any]) -> None:
    """Validate resource-local structure; account preflight remains mandatory."""
    if kind == DNS:
        fields(props, {"zoneId", "name", "type", "ttl", "content", "proxied"}, "DNS record")
        require(
            bool(re.fullmatch(r"[0-9a-f]{32}", text(props["zoneId"], "zone ID"))),
            "EXT010",
            "zone must have an explicit Cloudflare ID",
        )
        _dns_name(props["name"])
        require(props["proxied"] is False, "EXT010", "only DNS-only records are reviewed")
        require(
            type(props["ttl"]) is int and 60 <= props["ttl"] <= 86400,
            "EXT010",
            "TTL must be an explicit integer between 60 and 86400 seconds",
        )
        require(props["type"] in ("A", "AAAA", "CNAME"), "EXT010", "record type is not reviewed")
        if props["type"] == "CNAME":
            _dns_name(props["content"])
        else:
            try:
                address = ipaddress.ip_address(text(props["content"], "record content"))
            except ValueError:
                raise GovernanceError("EXT010: invalid address for DNS record") from None
            require(
                address.version == (4 if props["type"] == "A" else 6),
                "EXT010",
                "address family disagrees with record type",
            )
    elif kind == PROJECT:
        fields(
            props,
            {"organizationId", "name", "region", "instanceSize", "legacyApiKeysEnabled"},
            "Supabase project",
        )
        for key in ("organizationId", "name"):
            require(
                bool(re.fullmatch(r"[a-z][a-z0-9-]{1,62}", text(props[key], key))),
                "EXT011",
                "organization and project names must be explicit safe identifiers",
            )
        require(
            props["region"] in ("eu-central-1", "us-east-1"),
            "EXT011",
            "region is outside the reviewed project subset",
        )
        require(
            props["instanceSize"] == "nano" and props["legacyApiKeysEnabled"] is False,
            "EXT011",
            "only Nano Free projects without legacy API keys are reviewed",
        )
    else:
        require(False, "EXT012", "external resource type has no reviewed cost classification")


def _fresh(value: object, now: datetime, days: int = 0) -> None:
    age = now - timestamp(value, "service evidence")
    require(
        timedelta(0) <= age <= (timedelta(days=days) if days else timedelta(minutes=15)),
        "EXT002",
        "service evidence is stale or in the future",
    )


def audit(
    config: dict[str, Any],
    evidence: dict[str, Any],
    profile: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Audit all new objects without subtracting any live object or trusting tags.

    Evidence is an operator attestation, not an API collector or deployment permit.
    Growth is a conservative remaining-month traffic budget, not a rate prediction.
    """
    now = now or datetime.now(UTC)
    require(now.tzinfo is not None, "EXT002", "clock must include a timezone")
    now = now.astimezone(UTC)
    config = fields(
        config,
        {"schema_version", "provider", "unit", "account_id", "scope_id", "resources", "growth"},
        "service proposal",
    )
    evidence = fields(
        evidence,
        {
            "schema_version",
            "provider",
            "account_id",
            "scope_id",
            "scope_name",
            "profile_revision",
            "verified",
            "verified_at",
            "observed_at",
            "collection_started_at",
            "collection_completed_at",
            "complete",
            "source",
            "plan",
            "other_services_reviewed",
            "coverage",
            "resources",
            "usage",
            "usage_month",
        },
        "service evidence",
    )
    provider = text(config["provider"], "provider")
    require(
        provider in UNITS and config["unit"] == UNITS[provider],
        "EXT001",
        "provider/unit is unsupported or mismatched",
    )
    require(
        type(config["schema_version"]) is int
        and type(evidence["schema_version"]) is int
        and config["schema_version"] == 1
        and evidence["schema_version"] == 2,
        "EXT001",
        "unsupported schema",
    )
    require(
        profile.get("id") == provider + "-free"
        and profile.get("provider") == provider
        and profile.get("enabled") is True
        and type(evidence["profile_revision"]) is int
        and evidence["profile_revision"] == profile.get("revision"),
        "EXT001",
        "profile is disabled or revision/provider does not match",
    )
    _fresh(profile.get("reviewed_at"), now, 90)
    require(
        evidence["verified"] is True
        and evidence["complete"] is True
        and evidence["other_services_reviewed"] is True
        and evidence["plan"] == "free",
        "EXT003",
        "complete Free entitlement and other-service review are required",
    )
    _fresh(evidence["verified_at"], now, 30)
    _fresh(evidence["observed_at"], now)
    require(
        evidence["usage_month"] == now.strftime("%Y-%m"),
        "EXT002",
        "usage evidence must refer to the current billing month",
    )
    metrics = set() if provider == "cloudflare" else METRICS
    usage, coverage = usage_coverage(evidence, metrics, now)
    text(evidence["source"], "evidence source")
    for key in ("provider", "account_id", "scope_id"):
        require(text(config[key], key) == evidence[key], "EXT004", "evidence billing scope differs")
    expected_coverage = (
        "all-zone-dns-records"
        if provider == "cloudflare"
        else "all-owned-admin-free-projects-and-target-org-usage"
    )
    require(evidence["coverage"] == expected_coverage, "EXT003", "inventory coverage is incomplete")
    zone = _dns_name(evidence["scope_name"]) if provider == "cloudflare" else ""
    if provider == "supabase":
        require(
            evidence["scope_name"] == config["scope_id"],
            "EXT004",
            "organization scope name must match its identity",
        )
    live = records(evidence["resources"], "service inventory")
    desired = records(config["resources"], "desired resources")
    require(bool(desired), "EXT001", "proposal must contain resources")
    identifiers: set[str] = set()
    names: set[str] = set()
    for item in live:
        fields(
            item,
            (
                {"id", "name", "type"}
                if provider == "cloudflare"
                else {"id", "scope_id", "database_mb"}
            ),
            "inventory entry",
        )
        rid = text(item["id"], "resource identity")
        require(rid not in identifiers, "EXT005", "duplicate inventory identity")
        identifiers.add(rid)
        if provider == "cloudflare":
            # Existing TXT/SRV/wildcard records count too, including underscore labels.
            name = text(item["name"], "existing DNS name")
            require(
                name == name.lower() and (name == zone or name.endswith("." + zone)),
                "EXT004",
                "inventory record is outside the reviewed zone",
            )
            names.add(name)
            text(item["type"], "existing DNS type")
        else:
            text(item["scope_id"], "existing organization")
            require(
                number(item["database_mb"], "project database") <= 500,
                "EXT020",
                "existing database exceeds the reviewed Free limit",
            )
    keys: set[str] = set()
    for item in desired:
        fields(item, {"key", "type", "props"}, "desired entry")
        key = text(item["key"], "resource key")
        require(
            bool(re.fullmatch(r"[a-z][a-z0-9-]{0,62}", key)) and key not in keys,
            "EXT005",
            "resource keys must be safe and unique",
        )
        keys.add(key)
        kind = DNS if provider == "cloudflare" else PROJECT
        require(item["type"] == kind, "EXT012", "cross-provider or unsupported resource")
        props = fields(
            item["props"],
            (
                {"zoneId", "name", "type", "ttl", "content", "proxied"}
                if provider == "cloudflare"
                else {"organizationId", "name", "region", "instanceSize", "legacyApiKeysEnabled"}
            ),
            "desired properties",
        )
        validate_resource(kind, props)
        require(
            props["zoneId" if provider == "cloudflare" else "organizationId"] == config["scope_id"],
            "EXT004",
            "resource belongs to another zone/organization",
        )
        require(
            props["name"] not in names,
            "EXT005",
            "existing or duplicate name requires adoption review",
        )
        names.add(props["name"])
        if provider == "cloudflare":
            require(
                props["name"] == zone or props["name"].endswith("." + zone),
                "EXT004",
                "record is outside the reviewed zone",
            )
    peak = len(live) + len(desired)
    # Even paused Free projects count here: no capacity credit from pause/delete operations.
    bound = 200 if provider == "cloudflare" else 2
    require(
        profile.get("max_resources") == bound and peak <= bound,
        "EXT020",
        "additive peak exceeds the conservative service capacity",
    )
    growth = fields(config["growth"], metrics, "remaining-month growth budget")
    limits = fields(profile.get("usage_limits"), metrics, "published usage limits")
    forecasts = {}
    for metric in sorted(metrics):
        require(limits[metric] == MAXIMUM[metric], "EXT001", "unreviewed usage limit")
        projected = usage[metric] + number(growth[metric], "growth budget")
        require(
            projected <= MAXIMUM[metric], "EXT021", "consumed usage plus growth exceeds Free quota"
        )
        forecasts[metric] = str(projected)
    return {
        "schema_version": 2,
        "provider": provider,
        "unit": config["unit"],
        "account_id": config["account_id"],
        "scope_id": config["scope_id"],
        "resources": deepcopy(desired),
        "peak_resources": peak,
        "forecast": forecasts,
        "usage_coverage": coverage,
        "deployment_authorized": False,
    }
