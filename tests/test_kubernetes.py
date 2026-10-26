"""Fail-closed desired-object, quota, capacity and rollout sensors."""

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from infra_core import cli
from infra_core.governance.contracts import GovernanceError
from infra_core.kubernetes.audit import audit
from infra_core.kubernetes.config import NamespaceBudget, load_config
from infra_core.kubernetes.resources import quantity, render, validate_resource
from infra_program.governance import validate_resource as validate_policy

ROOT = Path(__file__).resolve().parents[1]


def bundle(config, *workloads):
    result = render(config)
    result["items"].extend(workloads)
    return result


def test_controls_pin_restricted_security_and_deny_paid_resources(kube_config, kube_inventory):
    objects = render(kube_config)
    assert len(objects["items"]) == 4
    assert {item["kind"] for item in objects["items"]} == {
        "Namespace",
        "ResourceQuota",
        "LimitRange",
        "NetworkPolicy",
    }
    for item in objects["items"]:
        assert validate_resource(item) == {}
    result = audit(kube_config, kube_inventory, objects)
    assert result["deployment_authorized"] is False
    assert objects["items"][1]["spec"]["hard"]["persistentvolumeclaims"] == "0"
    assert objects["items"][1]["spec"]["hard"]["services.loadbalancers"] == "0"


def test_limits_include_replicas_and_surge(kube_config, kube_inventory, workload):
    result = audit(kube_config, kube_inventory, bundle(kube_config, workload))
    assert result["namespace_peaks"]["applications"]["cpu_m"] == 600
    assert result["namespace_peaks"]["applications"]["pods"] == 3
    kube_inventory["namespaces"]["applications"]["cpu_m"] = 401
    with pytest.raises(GovernanceError, match="K8S023"):
        audit(kube_config, kube_inventory, bundle(kube_config, workload))


def test_other_deployments_containers_and_old_usage_cannot_reuse_budget(
    kube_config, kube_inventory, workload
):
    second = deepcopy(workload)
    second["metadata"]["name"] = "another"
    with pytest.raises(GovernanceError, match="K8S023"):
        audit(kube_config, kube_inventory, bundle(kube_config, workload, second))
    workload["spec"]["template"]["spec"]["containers"].append(
        dict(deepcopy(workload["spec"]["template"]["spec"]["containers"][0]), name="sidecar")
    )
    with pytest.raises(GovernanceError, match="K8S023"):
        audit(kube_config, kube_inventory, bundle(kube_config, workload))


def test_cross_namespace_allocations_reserve_platform_capacity(kube_config, kube_inventory):
    config = replace(
        kube_config,
        namespaces=kube_config.namespaces + (NamespaceBudget("second", 1000, 1024, 512, 4, 2, 2),),
    )
    kube_inventory["namespaces"]["second"] = kube_inventory["namespaces"]["applications"].copy()
    with pytest.raises(GovernanceError, match="K8S021"):
        audit(config, kube_inventory, render(config))


@pytest.mark.parametrize(
    "field,value",
    [
        ("complete", False),
        ("network_policy_enforced", False),
        ("cluster_id", "other"),
        ("policy_version", "v1.33"),
        ("schema_version", True),
        ("observed_at", timedelta(minutes=-16)),
        ("observed_at", timedelta(minutes=1)),
    ],
)
def test_missing_stale_partial_wrong_scope_evidence_fails(
    kube_config, kube_inventory, field, value
):
    # Relative evidence clocks must be evaluated at execution, not module collection.
    if isinstance(value, timedelta):
        value = (datetime.now(UTC) + value).isoformat()
    kube_inventory[field] = value
    with pytest.raises(GovernanceError, match="K8S020"):
        audit(kube_config, kube_inventory, render(kube_config))


@pytest.mark.parametrize(
    "value", [None, True, -1, "NaN", "0m", "0.1m", "100e2", "Infinity", "100M"]
)
def test_unknown_or_ambiguous_quantities_fail(value):
    with pytest.raises(GovernanceError, match="K8S003"):
        quantity(value, "cpu")


def test_quantity_units_are_exact():
    assert quantity("1", "cpu") == 1000
    assert quantity("1Gi", "memory") == 1024
    assert quantity("10m", "cpu") == 10


@pytest.mark.parametrize(
    "version,kind",
    [
        ("v1", "PersistentVolumeClaim"),
        ("v1", "PersistentVolume"),
        ("v1", "Pod"),
        ("storage.k8s.io/v1", "StorageClass"),
        ("apps/v1", "StatefulSet"),
        ("apps/v1", "DaemonSet"),
        ("apps/v1", "ReplicaSet"),
        ("batch/v1", "Job"),
        ("batch/v1", "CronJob"),
        ("autoscaling/v2", "HorizontalPodAutoscaler"),
        ("rbac.authorization.k8s.io/v1", "ClusterRoleBinding"),
        ("networking.k8s.io/v1", "Ingress"),
        ("gateway.networking.k8s.io/v1", "Gateway"),
        ("apiextensions.k8s.io/v1", "CustomResourceDefinition"),
        ("v1", "List"),
        ("helm.sh/v3", "Release"),
        ("yaml", "ConfigFile"),
    ],
)
def test_billing_privileged_unknown_and_hidden_resources_are_denied(version, kind):
    with pytest.raises(GovernanceError, match="K8S010"):
        validate_resource({"apiVersion": version, "kind": kind, "metadata": {"name": "denied"}})


@pytest.mark.parametrize("service_type", ["LoadBalancer", "NodePort", "ExternalName"])
def test_paid_service_types_fail(service_type):
    with pytest.raises(GovernanceError, match="K8S010"):
        validate_resource(
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"name": "app", "namespace": "applications"},
                "spec": {
                    "type": service_type,
                    "selector": {"app": "app"},
                    "ports": [{"port": 80, "targetPort": 8080, "protocol": "TCP"}],
                },
            }
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("hostNetwork", True),
        ("hostPID", True),
        ("hostIPC", True),
        ("initContainers", []),
        ("ephemeralContainers", []),
        ("volumes", []),
        ("overhead", {}),
        ("runtimeClassName", "unreviewed"),
        ("resources", {}),
    ],
)
def test_unsupported_pod_features_fail_before_accounting(workload, field, value):
    workload["spec"]["template"]["spec"][field] = value
    with pytest.raises(GovernanceError):
        validate_resource(workload)


@pytest.mark.parametrize(
    "field,value",
    [
        ("privileged", True),
        ("privileged", 0),
        ("allowPrivilegeEscalation", True),
        ("readOnlyRootFilesystem", False),
        ("capabilities", {"add": ["SYS_ADMIN"], "drop": ["ALL"]}),
    ],
)
def test_privilege_and_boolean_bypasses_fail(workload, field, value):
    workload["spec"]["template"]["spec"]["containers"][0]["securityContext"][field] = value
    with pytest.raises(GovernanceError, match="K8S006"):
        validate_resource(workload)


def test_missing_limits_latest_images_root_users_and_unknown_surge_fail(workload):
    for mutation in ("limits", "image", "root", "surge"):
        item = deepcopy(workload)
        pod = item["spec"]["template"]["spec"]
        if mutation == "limits":
            del pod["containers"][0]["resources"]["limits"]
        elif mutation == "image":
            pod["containers"][0]["image"] = "app:latest"
        elif mutation == "root":
            pod["securityContext"]["runAsUser"] = 0
        else:
            item["spec"]["strategy"]["rollingUpdate"]["maxSurge"] = "25%"
        with pytest.raises(GovernanceError):
            validate_resource(item)


def test_missing_modified_duplicate_controls_and_external_namespace_fail(
    kube_config, kube_inventory, workload
):
    for mutation in ("missing", "quota", "duplicate", "namespace"):
        items = bundle(kube_config, deepcopy(workload))
        if mutation == "missing":
            items["items"].pop(0)
        elif mutation == "quota":
            items["items"][1]["spec"]["hard"]["services.loadbalancers"] = "1"
        elif mutation == "duplicate":
            items["items"].append(items["items"][-1])
        else:
            items["items"][-1]["metadata"]["namespace"] = "unmanaged"
        with pytest.raises(GovernanceError):
            audit(kube_config, kube_inventory, items)


def test_mandatory_policy_accepts_controls_and_rejects_unsafe_service(kube_config):
    violations = []
    for item in render(kube_config)["items"]:
        group = "core/v1" if item["apiVersion"] == "v1" else item["apiVersion"]
        args = SimpleNamespace(resource_type=f"kubernetes:{group}:{item['kind']}", props=item)
        validate_policy(args, lambda message, urn: violations.append(message))
    assert violations == []
    validate_policy(
        SimpleNamespace(
            resource_type="kubernetes:core/v1:Service",
            props={
                "metadata": {"name": "denied", "namespace": "applications"},
                "spec": {
                    "type": "LoadBalancer",
                    "selector": {"app": "app"},
                    "ports": [{"port": 80, "targetPort": 8080, "protocol": "TCP"}],
                },
            },
        ),
        lambda message, urn: violations.append(message),
    )
    assert violations and "K8S010" in violations[-1]


def test_cli_render_audit_and_invalid_example(kube_config, kube_inventory, tmp_path, capsys):
    source = (
        (ROOT / "config/kubernetes.example.toml")
        .read_text()
        .replace('account_id = ""', f'account_id = "{kube_config.account_id}"')
        .replace('cluster_id = ""', f'cluster_id = "{kube_config.cluster_id}"')
        .replace('policy_version = ""', 'policy_version = "v1.34"')
    )
    config = tmp_path / "config.toml"
    config.write_text(source)
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps(kube_inventory))
    resources = tmp_path / "resources.json"
    resources.write_text(json.dumps(render(load_config(config))))
    args = ["--root", str(ROOT), "kubernetes"]
    assert cli.main([*args, "render", "--config", str(config)]) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "List"
    assert (
        cli.main(
            [
                *args,
                "audit",
                "--config",
                str(config),
                "--inventory",
                str(inventory),
                "--resources",
                str(resources),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["deployment_authorized"] is False
    with pytest.raises(GovernanceError):
        load_config(ROOT / "config/kubernetes.example.toml")
