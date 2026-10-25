"""Small explicit namespace envelopes, measured in millicores and MiB."""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from infra_core.governance.contracts import fields, records, require, text

METRICS = {"cpu_m", "memory_mi", "ephemeral_mi", "pods"}
SYSTEM_NAMESPACES = {"default", "kube-system", "kube-public", "kube-node-lease"}


def integer(value: object, label: str, *, positive: bool = False) -> int:
    require(
        type(value) is int and value >= (1 if positive else 0),
        "K8S001",
        f"{label} must be a known nonnegative integer",
    )
    assert isinstance(value, int)
    return value


def capacity(value: object, label: str, *, positive: bool = False) -> dict[str, int]:
    return {
        key: integer(item, label, positive=positive)
        for key, item in fields(value, METRICS, label).items()
    }


@dataclass(frozen=True, slots=True)
class NamespaceBudget:
    name: str
    cpu_m: int
    memory_mi: int
    ephemeral_mi: int
    pods: int
    services: int
    deployments: int

    def __post_init__(self) -> None:
        require(
            isinstance(self.name, str)
            and bool(re.fullmatch(r"[a-z][a-z0-9-]{0,61}[a-z0-9]|[a-z]", self.name))
            and self.name not in SYSTEM_NAMESPACES
            and not self.name.startswith("kube-"),
            "K8S002",
            "explicit application namespace required; system namespaces are excluded",
        )
        for value in (
            self.cpu_m,
            self.memory_mi,
            self.ephemeral_mi,
            self.pods,
            self.services,
            self.deployments,
        ):
            integer(value, "namespace budget", positive=True)

    @property
    def resources(self) -> dict[str, int]:
        return {key: getattr(self, key) for key in sorted(METRICS)}


@dataclass(frozen=True, slots=True)
class KubernetesConfig:
    account_id: str
    cluster_id: str
    region: str
    policy_version: str
    reserved: dict[str, int]
    namespaces: tuple[NamespaceBudget, ...]

    def __post_init__(self) -> None:
        require(
            text(self.account_id, "account").startswith("ocid1.tenancy.")
            and text(self.cluster_id, "cluster").startswith("ocid1.cluster.")
            and bool(re.fullmatch(r"[a-z]+-[a-z]+-\d+", self.region)),
            "K8S002",
            "explicit OCI tenancy, cluster and region required",
        )
        require(
            bool(re.fullmatch(r"v1\.[0-9]+", self.policy_version)),
            "K8S002",
            "Pod Security version must be pinned to the reviewed cluster minor",
        )
        capacity(self.reserved, "platform/headroom reservation", positive=True)
        require(
            bool(self.namespaces)
            and len({item.name for item in self.namespaces}) == len(self.namespaces),
            "K8S002",
            "namespace budgets must be nonempty and unique",
        )


def load_config(path: Path) -> KubernetesConfig:
    return parse_config(tomllib.loads(path.read_text(encoding="utf-8")))


def parse_config(value: dict[str, Any]) -> KubernetesConfig:
    data = fields(value, {"cluster", "reserved", "namespaces"}, "Kubernetes configuration")
    cluster = fields(
        data["cluster"], {"account_id", "cluster_id", "region", "policy_version"}, "cluster"
    )
    require(
        all(isinstance(item, str) for item in cluster.values()),
        "K8S002",
        "cluster fields must be strings",
    )
    budgets = tuple(
        NamespaceBudget(
            **fields(item, {"name", *METRICS, "services", "deployments"}, "namespace budget")
        )
        for item in records(data["namespaces"], "namespace budgets")
    )
    return KubernetesConfig(
        **cluster, reserved=capacity(data["reserved"], "reservation"), namespaces=budgets
    )
