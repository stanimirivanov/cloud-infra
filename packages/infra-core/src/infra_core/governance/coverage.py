"""Offline coverage evidence: successful queries, scope, and collection clocks."""

from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from infra_core.governance.contracts import fields, mapping, records, require, text, timestamp
from infra_core.governance.resources import BOOT, CLUSTER, INSTANCE, VOLUME


def validate_coverage(inventory: dict[str, Any], home: str, now: datetime) -> None:
    start = timestamp(inventory.get("collection_started_at"), "collection start")
    end = timestamp(inventory.get("collection_completed_at"), "collection completion")
    observed = timestamp(inventory.get("observed_at"), "inventory observation")
    require(
        now - timedelta(minutes=15) <= start == observed <= end <= now,
        "GOV042",
        "collection must be fresh, ordered and bound to the original observation",
    )
    coverage = fields(
        inventory.get("coverage"),
        {"regions", "compartments", "availability_domains", "queries"},
        "coverage",
    )

    def names(value: object) -> list[str]:
        require(isinstance(value, list) and bool(value), "GOV042", "coverage scope is missing")
        assert isinstance(value, list)
        result = [text(item, "coverage identity") for item in value]
        require(len(result) == len(set(result)), "GOV042", "duplicate coverage identity")
        return result

    regions, compartments = names(coverage["regions"]), names(coverage["compartments"])
    require(
        home in regions and inventory["account_id"] in compartments,
        "GOV042",
        "root/home scope is missing",
    )
    domains = mapping(coverage["availability_domains"], "availability domains")
    require(set(domains) == set(regions), "GOV042", "region/AD coverage differs")
    expected: set[tuple[str, str, str, str | None]] = {
        ("regions", home, inventory["account_id"], None),
        ("compartments", home, inventory["account_id"], None),
    }
    for region in regions:
        ads = names(domains[region])
        expected.add(("ads", region, inventory["account_id"], None))
        for compartment in compartments:
            expected.update(
                (op, region, compartment, None)
                for op in ("instances", "volumes", "clusters", "virtual_pools")
            )
            expected.update(("boots", region, compartment, ad) for ad in ads)
    actual = []
    for row in records(coverage["queries"], "successful queries"):
        fields(row, {"operation", "region", "compartment", "availability_domain", "count"}, "query")
        require(
            type(row["count"]) is int and row["count"] >= 0,
            "GOV042",
            "query count must be nonnegative",
        )
        ad = row["availability_domain"]
        require(ad is None or isinstance(ad, str), "GOV042", "invalid query AD")
        actual.append(
            (
                text(row["operation"], "operation"),
                text(row["region"], "region"),
                text(row["compartment"], "compartment"),
                ad,
            )
        )
        operation, query_region, _, _ = actual[-1]
        count = row["count"]
        consistent = (
            (operation != "regions" or count == len(regions))
            and (operation != "compartments" or count >= len(compartments) - 1)
            and (
                operation != "ads"
                or (query_region in domains and count == len(domains[query_region]))
            )
            and (operation != "virtual_pools" or count == 0)
        )
        require(
            consistent, "GOV042", "discovery counts must agree with scope and exclude virtual pools"
        )
    require(
        len(actual) == len(set(actual)) and set(actual) == expected,
        "GOV042",
        "missing, extra or duplicate successful queries",
    )

    families = {BOOT: "boots", CLUSTER: "clusters", INSTANCE: "instances", VOLUME: "volumes"}
    observed_counts = Counter(
        (families[item["type"]], str(item.get("region")))
        for item in records(inventory.get("resources"), "inventory resources")
        if isinstance(item.get("type"), str)
        and item["type"] in families
        and item.get("region") in regions
    )
    for (operation, region), count in observed_counts.items():
        require(
            sum(
                row["count"]
                for row in coverage["queries"]
                if row["operation"] == operation and row["region"] == region
            )
            >= count,
            "GOV042",
            "query counts cannot be smaller than retained inventory records",
        )
