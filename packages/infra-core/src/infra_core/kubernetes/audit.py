"""Aggregate namespace allocation and conservative new-workload peak accounting."""

from datetime import UTC, datetime, timedelta
from typing import Any

from infra_core.governance.contracts import fields, mapping, records, require, text, timestamp
from infra_core.kubernetes.config import METRICS, KubernetesConfig, capacity, integer
from infra_core.kubernetes.resources import controls, validate_resource


def audit(
    config: KubernetesConfig, inventory: object, manifests: object, *, now: datetime | None = None
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    require(now.tzinfo is not None, "K8S020", "audit clock requires an explicit timezone")
    now = now.astimezone(UTC)
    data = fields(
        inventory,
        {
            "schema_version",
            "account_id",
            "cluster_id",
            "region",
            "policy_version",
            "node_ids",
            "observed_at",
            "complete",
            "source",
            "network_policy_enforced",
            "allocatable",
            "unmanaged_used",
            "namespaces",
        },
        "Kubernetes inventory",
    )
    require(
        type(data["schema_version"]) is int and data["schema_version"] == 1,
        "K8S020",
        "unsupported inventory schema",
    )
    require(
        data["account_id"] == config.account_id
        and data["cluster_id"] == config.cluster_id
        and data["region"] == config.region
        and data["policy_version"] == config.policy_version,
        "K8S020",
        "cluster identity/region/Pod Security version does not match evidence",
    )
    require(
        data["complete"] is True and data["network_policy_enforced"] is True,
        "K8S020",
        "complete cluster usage and verified network-policy enforcement required",
    )
    require(
        timedelta(0)
        <= now - timestamp(data["observed_at"], "cluster observation")
        <= timedelta(minutes=15),
        "K8S020",
        "cluster evidence is stale or in the future",
    )
    text(data["source"], "cluster evidence source")
    node_ids = data["node_ids"]
    require(
        isinstance(node_ids, list)
        and bool(node_ids)
        and all(isinstance(item, str) and item.startswith("ocid1.instance.") for item in node_ids)
        and len(set(node_ids)) == len(node_ids),
        "K8S020",
        "unique OCI node provider IDs required in cluster evidence",
    )
    allocatable = capacity(data["allocatable"], "measured allocatable", positive=True)
    unmanaged = capacity(data["unmanaged_used"], "system and unmanaged usage")
    reserved = capacity(config.reserved, "platform/headroom reservation", positive=True)
    used = mapping(data["namespaces"], "namespace usage")
    budgets = {budget.name: budget for budget in config.namespaces}
    require(set(used) == set(budgets), "K8S020", "usage must cover every managed namespace exactly")
    namespace_used = {}
    for name, item in used.items():
        values = fields(item, METRICS | {"services", "deployments"}, "namespace usage")
        namespace_used[name] = {
            key: integer(value, "namespace used") for key, value in values.items()
        }
    for metric in sorted(METRICS):
        allocated = sum(budget.resources[metric] for budget in config.namespaces)
        require(
            allocated + reserved[metric] + unmanaged[metric] <= allocatable[metric],
            "K8S021",
            f"aggregate namespace {metric} envelopes plus unmanaged/headroom exceed allocatable",
        )
    bundle = fields(manifests, {"apiVersion", "kind", "items"}, "desired manifest bundle")
    require(
        bundle["apiVersion"] == "v1" and bundle["kind"] == "List",
        "K8S010",
        "explicit v1 List bundle required",
    )
    desired = records(bundle["items"], "desired objects")
    expected = {
        (
            item["kind"],
            item["metadata"].get("namespace", item["metadata"]["name"]),
            item["metadata"]["name"],
        ): item
        for budget in config.namespaces
        for item in controls(budget, config.policy_version)
    }
    seen = set()
    peaks = {name: values.copy() for name, values in namespace_used.items()}
    for item in desired:
        workload = validate_resource(item)
        kind = item["kind"]
        meta = item["metadata"]
        name = meta["name"] if kind == "Namespace" else meta["namespace"]
        require(name in budgets, "K8S022", "resource targets an unmanaged namespace")
        identity = (kind, name, meta["name"])
        require(identity not in seen, "K8S022", "duplicate resource identity")
        seen.add(identity)
        if kind not in ("Deployment", "Service"):
            require(
                item == expected.get(identity),
                "K8S022",
                "namespace controls differ from reviewed budgets",
            )
        elif kind == "Service":
            peaks[name]["services"] += 1
        else:
            peaks[name]["deployments"] += 1
            for metric, value in workload.items():
                peaks[name][metric] += value
    require(
        set(expected) <= seen,
        "K8S022",
        "every namespace requires all four admission/isolation controls",
    )
    for name, budget in budgets.items():
        envelope = budget.resources | {
            "services": budget.services,
            "deployments": budget.deployments,
        }
        require(
            all(value <= envelope[key] for key, value in peaks[name].items()),
            "K8S023",
            "current usage plus desired rollout peak exceeds namespace envelope",
        )
    return {
        "status": "within-kubernetes-envelope",
        "cluster_id": config.cluster_id,
        "namespace_peaks": peaks,
        "deployment_authorized": False,
    }
