"""Closed desired-manifest subset and namespace admission control generation."""

import re
from typing import Any

from infra_core.governance.contracts import fields, mapping, records, require, text
from infra_core.kubernetes.config import KubernetesConfig, NamespaceBudget, integer

KINDS = {("v1", name) for name in ("Namespace", "ResourceQuota", "LimitRange", "Service")}
KINDS |= {("networking.k8s.io/v1", "NetworkPolicy"), ("apps/v1", "Deployment")}
QUOTA_ZERO = {
    "persistentvolumeclaims",
    "requests.storage",
    "services.loadbalancers",
    "services.nodeports",
    "count/statefulsets.apps",
    "count/daemonsets.apps",
    "count/jobs.batch",
    "count/cronjobs.batch",
}


def quantity(value: object, metric: str) -> int:
    require(
        isinstance(value, str) and len(value) <= 32, "K8S003", "explicit resource quantity required"
    )
    pattern = r"([1-9][0-9]*)(m)?" if metric == "cpu" else r"([1-9][0-9]*)(Mi|Gi)"
    match = re.fullmatch(pattern, str(value))
    require(match is not None, "K8S003", "use positive whole millicores/cores or Mi/Gi quantities")
    assert match is not None
    factor = (
        (1 if match[2] == "m" else 1000) if metric == "cpu" else (1024 if match[2] == "Gi" else 1)
    )
    return int(match[1]) * factor


def labels(version: str) -> dict[str, str]:
    return {
        key: value
        for level in ("enforce", "audit", "warn")
        for key, value in (
            (f"pod-security.kubernetes.io/{level}", "restricted"),
            (f"pod-security.kubernetes.io/{level}-version", version),
        )
    }


def controls(budget: NamespaceBudget, version: str) -> list[dict[str, Any]]:
    quantities = {
        "cpu": f"{budget.cpu_m}m",
        "memory": f"{budget.memory_mi}Mi",
        "ephemeral-storage": f"{budget.ephemeral_mi}Mi",
    }
    hard = {
        **{
            f"{mode}.{key}": value
            for mode in ("requests", "limits")
            for key, value in quantities.items()
        },
        **dict.fromkeys(sorted(QUOTA_ZERO), "0"),
        "pods": str(budget.pods),
        "services": str(budget.services),
        "count/deployments.apps": str(budget.deployments),
    }
    default = {
        "cpu": f"{min(100, budget.cpu_m)}m",
        "memory": f"{min(128, budget.memory_mi)}Mi",
        "ephemeral-storage": f"{min(128, budget.ephemeral_mi)}Mi",
    }
    return [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": budget.name, "labels": labels(version)},
        },
        {
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": {"name": "envelope", "namespace": budget.name},
            "spec": {"hard": hard},
        },
        {
            "apiVersion": "v1",
            "kind": "LimitRange",
            "metadata": {"name": "containers", "namespace": budget.name},
            "spec": {
                "limits": [
                    {
                        "type": "Container",
                        "default": default,
                        "defaultRequest": default,
                        "min": {"cpu": "1m", "memory": "1Mi", "ephemeral-storage": "1Mi"},
                        "max": quantities,
                    }
                ]
            },
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "default-deny", "namespace": budget.name},
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
        },
    ]


def render(config: KubernetesConfig) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            item for budget in config.namespaces for item in controls(budget, config.policy_version)
        ],
    }


def metadata(value: object, *, namespace: bool = True) -> dict[str, Any]:
    data = mapping(value, "metadata")
    required = {"name", "namespace"} if namespace else {"name", "labels"}
    require(
        required <= set(data) <= required | {"labels"},
        "K8S004",
        "explicit metadata without annotations or generateName required",
    )
    for key in required - {"labels"}:
        name = text(data[key], "resource identity")
        require(
            bool(re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", name)),
            "K8S004",
            "explicit DNS-label resource identity required",
        )
    if "labels" in data:
        require(
            all(
                isinstance(key, str) and isinstance(item, str) and bool(item)
                for key, item in mapping(data["labels"], "labels").items()
            ),
            "K8S004",
            "labels must be known strings",
        )
    return data


def resources(value: object) -> dict[str, int]:
    data = fields(value, {"requests", "limits"}, "container resources")
    result = {}
    for mode in ("requests", "limits"):
        values = fields(data[mode], {"cpu", "memory", "ephemeral-storage"}, "resource quantities")
        result[mode] = {
            "cpu_m": quantity(values["cpu"], "cpu"),
            "memory_mi": quantity(values["memory"], "memory"),
            "ephemeral_mi": quantity(values["ephemeral-storage"], "ephemeral-storage"),
        }
    require(
        all(result["requests"][key] <= result["limits"][key] for key in result["limits"]),
        "K8S003",
        "container requests must not exceed limits",
    )
    return result["limits"]


def deployment(spec: object) -> tuple[dict[str, int], int]:
    data = fields(
        spec,
        {"replicas", "selector", "template", "strategy", "revisionHistoryLimit"},
        "Deployment spec",
    )
    replicas = integer(data["replicas"], "replicas", positive=True)
    require(
        data["revisionHistoryLimit"] == 1 and type(data["revisionHistoryLimit"]) is int,
        "K8S005",
        "retain exactly one deployment revision",
    )
    strategy = mapping(data["strategy"], "rollout strategy")
    if strategy.get("type") == "Recreate":
        fields(strategy, {"type"}, "Recreate strategy")
        surge = 0
    else:
        fields(strategy, {"type", "rollingUpdate"}, "rollout strategy")
        require(strategy["type"] == "RollingUpdate", "K8S005", "reviewed rollout strategy required")
        rolling = fields(
            strategy["rollingUpdate"], {"maxSurge", "maxUnavailable"}, "rollout bounds"
        )
        surge = integer(rolling["maxSurge"], "maxSurge")
        unavailable = integer(rolling["maxUnavailable"], "maxUnavailable")
        require(
            surge <= replicas and unavailable <= replicas and surge + unavailable > 0,
            "K8S005",
            "rollout requires bounded integral surge/unavailability",
        )
    template = fields(data["template"], {"metadata", "spec"}, "pod template")
    pod_labels = fields(template["metadata"], {"labels"}, "template metadata")["labels"]
    require(
        all(
            isinstance(value, str) and bool(value)
            for value in mapping(pod_labels, "pod labels").values()
        ),
        "K8S004",
        "pod label values must be explicit strings",
    )
    require(
        bool(mapping(pod_labels, "pod labels"))
        and fields(data["selector"], {"matchLabels"}, "selector")["matchLabels"] == pod_labels,
        "K8S005",
        "selector must exactly match explicit pod labels",
    )
    pod = fields(
        template["spec"],
        {"containers", "securityContext", "nodeSelector", "automountServiceAccountToken"},
        "pod spec",
    )
    require(
        pod["nodeSelector"] == {"kubernetes.io/arch": "arm64", "kubernetes.io/os": "linux"}
        and pod["automountServiceAccountToken"] is False,
        "K8S006",
        "Linux ARM nodes and disabled service-account token mount required",
    )
    security = fields(
        pod["securityContext"],
        {"runAsNonRoot", "runAsUser", "runAsGroup", "seccompProfile"},
        "pod security",
    )
    require(
        security["runAsNonRoot"] is True
        and security["seccompProfile"] == {"type": "RuntimeDefault"},
        "K8S006",
        "non-root RuntimeDefault seccomp required",
    )
    integer(security["runAsUser"], "runAsUser", positive=True)
    integer(security["runAsGroup"], "runAsGroup", positive=True)
    containers = records(pod["containers"], "containers")
    require(bool(containers), "K8S006", "at least one explicit container required")
    seen = set()
    per_pod = dict.fromkeys(("cpu_m", "memory_mi", "ephemeral_mi"), 0)
    for container in containers:
        fields(container, {"name", "image", "resources", "securityContext"}, "container")
        name = text(container["name"], "container name")
        require(name not in seen, "K8S004", "duplicate container identity")
        seen.add(name)
        require(
            isinstance(container["image"], str)
            and bool(re.fullmatch(r"[A-Za-z0-9./:_-]+@sha256:[a-f0-9]{64}", container["image"])),
            "K8S006",
            "pin a reviewed ARM-compatible image digest",
        )
        require(
            container["securityContext"]
            == {
                "privileged": False,
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
            },
            "K8S006",
            "explicit restricted container security context required",
        )
        # Equality alone would accept 0/1 in place of booleans.
        context = container["securityContext"]
        require(
            all(
                type(context[key]) is bool
                for key in ("privileged", "allowPrivilegeEscalation", "readOnlyRootFilesystem")
            ),
            "K8S006",
            "security switches must be booleans",
        )
        for key, value in resources(container["resources"]).items():
            per_pod[key] += value
    peak = replicas + surge
    return {**{key: value * peak for key, value in per_pod.items()}, "pods": peak}, peak


def validate_resource(value: object) -> dict[str, int]:
    """Validate one desired object; whole-bundle audit supplies aggregate context."""
    data = mapping(value, "Kubernetes object")
    require(
        isinstance(data.get("apiVersion"), str)
        and isinstance(data.get("kind"), str)
        and (data["apiVersion"], data["kind"]) in KINDS,
        "K8S010",
        "resource kind/version is not reviewed (billing/privileged/hidden resources denied)",
    )
    kind = data["kind"]
    fields(
        data,
        {"apiVersion", "kind", "metadata"} | (set() if kind == "Namespace" else {"spec"}),
        "Kubernetes object",
    )
    meta = metadata(data["metadata"], namespace=kind != "Namespace")
    from infra_core.kubernetes.config import SYSTEM_NAMESPACES

    namespace = meta["name"] if kind == "Namespace" else meta["namespace"]
    require(
        namespace not in SYSTEM_NAMESPACES and not namespace.startswith("kube-"),
        "K8S002",
        "system namespaces are excluded from application governance",
    )
    if kind == "Namespace":
        require(
            meta["name"] not in SYSTEM_NAMESPACES and not meta["name"].startswith("kube-"),
            "K8S002",
            "system namespaces cannot be governed as application namespaces",
        )
        version = meta["labels"].get("pod-security.kubernetes.io/enforce-version")
        require(
            isinstance(version, str)
            and bool(re.fullmatch(r"v1\.[0-9]+", version))
            and meta["labels"] == labels(version),
            "K8S006",
            "pinned restricted Pod Security labels required",
        )
    elif kind == "Deployment":
        return deployment(data["spec"])[0]
    elif kind == "Service":
        spec = fields(data["spec"], {"type", "selector", "ports"}, "Service spec")
        require(
            spec["type"] == "ClusterIP" and bool(mapping(spec["selector"], "service selector")),
            "K8S010",
            "only internal ClusterIP services allowed; no external IPs/annotations",
        )
        ports = records(spec["ports"], "service ports")
        require(len(ports) == 1, "K8S010", "one explicit TCP port per service is reviewed")
        for port in ports:
            fields(port, {"port", "targetPort", "protocol"}, "service port")
            require(
                port["protocol"] == "TCP"
                and all(0 < integer(port[key], key) <= 65535 for key in ("port", "targetPort")),
                "K8S010",
                "bounded TCP service ports required",
            )
    elif kind == "NetworkPolicy":
        require(
            data["spec"]
            == {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
            "K8S011",
            "only complete default-deny is reviewed; allow rules need separate design",
        )
    elif kind == "ResourceQuota":
        hard = fields(data["spec"], {"hard"}, "quota")["hard"]
        hard = fields(
            hard,
            QUOTA_ZERO
            | {"pods", "services", "count/deployments.apps"}
            | {
                f"{mode}.{metric}"
                for mode in ("requests", "limits")
                for metric in ("cpu", "memory", "ephemeral-storage")
            },
            "quota hard limits",
        )
        require(
            all(hard[key] == "0" for key in QUOTA_ZERO),
            "K8S010",
            "billable storage/services and unsupported controllers must have zero quota",
        )
        for metric in ("cpu", "memory", "ephemeral-storage"):
            require(
                quantity(hard["requests." + metric], metric)
                == quantity(hard["limits." + metric], metric),
                "K8S003",
                "namespace request/limit envelopes must be equal",
            )
        for key in ("pods", "services", "count/deployments.apps"):
            require(
                isinstance(hard[key], str) and bool(re.fullmatch(r"[1-9][0-9]{0,8}", hard[key])),
                "K8S003",
                "bounded positive object quota required",
            )
    elif kind == "LimitRange":
        entries = records(
            fields(data["spec"], {"limits"}, "LimitRange")["limits"], "container limits"
        )
        require(len(entries) == 1, "K8S003", "one explicit Container LimitRange required")
        entry = fields(
            entries[0], {"type", "default", "defaultRequest", "min", "max"}, "LimitRange entry"
        )
        require(
            entry["type"] == "Container" and entry["default"] == entry["defaultRequest"],
            "K8S003",
            "equal default requests/limits required",
        )
        for metric in ("cpu", "memory", "ephemeral-storage"):
            for key in ("default", "defaultRequest", "min", "max"):
                fields(entry[key], {"cpu", "memory", "ephemeral-storage"}, "LimitRange quantities")
            require(
                quantity(entry["min"][metric], metric)
                <= quantity(entry["default"][metric], metric)
                <= quantity(entry["max"][metric], metric),
                "K8S003",
                "LimitRange default must fit min/max",
            )
    return {}
