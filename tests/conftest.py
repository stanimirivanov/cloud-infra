"""Synthetic Kubernetes evidence shared by governance and cutover tests."""

from datetime import UTC, datetime

import pytest
from infra_core.kubernetes.config import KubernetesConfig, NamespaceBudget


@pytest.fixture
def kube_config():
    return KubernetesConfig(
        "ocid1.tenancy.oc1..fixture",
        "ocid1.cluster.oc1.eu-frankfurt-1.fixture",
        "eu-frankfurt-1",
        "v1.34",
        {"cpu_m": 500, "memory_mi": 1024, "ephemeral_mi": 1024, "pods": 10},
        (NamespaceBudget("applications", 1000, 2048, 2048, 8, 4, 3),),
    )


@pytest.fixture
def kube_inventory(kube_config):
    return {
        "schema_version": 1,
        "account_id": kube_config.account_id,
        "cluster_id": kube_config.cluster_id,
        "region": kube_config.region,
        "policy_version": kube_config.policy_version,
        "observed_at": datetime.now(UTC).isoformat(),
        "complete": True,
        "source": "synthetic cluster snapshot; not live evidence",
        "network_policy_enforced": True,
        "node_ids": ["ocid1.instance.oc1..node-a", "ocid1.instance.oc1..node-b"],
        "allocatable": {"cpu_m": 2000, "memory_mi": 10240, "ephemeral_mi": 4096, "pods": 50},
        "unmanaged_used": {"cpu_m": 200, "memory_mi": 512, "ephemeral_mi": 256, "pods": 5},
        "namespaces": {
            "applications": {
                "cpu_m": 0,
                "memory_mi": 0,
                "ephemeral_mi": 0,
                "pods": 0,
                "services": 0,
                "deployments": 0,
            }
        },
    }


@pytest.fixture
def workload():
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "application", "namespace": "applications"},
        "spec": {
            "replicas": 2,
            "revisionHistoryLimit": 1,
            "selector": {"matchLabels": {"app": "application"}},
            "strategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0},
            },
            "template": {
                "metadata": {"labels": {"app": "application"}},
                "spec": {
                    "nodeSelector": {"kubernetes.io/arch": "arm64", "kubernetes.io/os": "linux"},
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 1000,
                        "runAsGroup": 1000,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "application",
                            "image": "example.invalid/application@sha256:" + "1" * 64,
                            "resources": {
                                "requests": {
                                    "cpu": "100m",
                                    "memory": "128Mi",
                                    "ephemeral-storage": "128Mi",
                                },
                                "limits": {
                                    "cpu": "200m",
                                    "memory": "256Mi",
                                    "ephemeral-storage": "256Mi",
                                },
                            },
                            "securityContext": {
                                "privileged": False,
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }
                    ],
                },
            },
        },
    }
