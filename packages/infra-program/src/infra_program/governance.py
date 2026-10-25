"""Governance adapters; no Pulumi resource registration is allowed before audit."""

import math
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from infra_core.governance.audit import audit
from infra_core.governance.contracts import GovernanceError
from infra_core.governance.resources import CAPACITY, footprint
from infra_core.kubernetes.resources import validate_resource as validate_kubernetes
from infra_core.oci.security import COMPONENTS, PROVIDER
from infra_core.oci.security import validate_resource as validate_oci
from pulumi_policy import (
    EnforcementLevel,
    PolicyPack,
    ReportViolation,
    ResourceValidationArgs,
    ResourceValidationPolicy,
)


def _properties(value: Any) -> Any:
    """Materialize policy SDK proxies at the boundary, preserving unknown errors.

    Protobuf Struct carries all numbers as doubles. Only exactly representable,
    finite whole numbers become Python integers; core JSON/TOML validation stays strict.
    """
    if isinstance(value, Mapping):
        return {key: _properties(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [_properties(item) for item in value]
    if type(value) is float and math.isfinite(value) and value.is_integer() and abs(value) < 2**53:
        return int(value)
    return value


def preflight[T](
    account: dict[str, Any],
    profile: dict[str, Any],
    inventory: dict[str, Any],
    plan: dict[str, Any],
    register: Callable[[], T],
) -> T:
    audit(account, profile, inventory, plan)
    return register()


def validate_resource(args: ResourceValidationArgs, report: ReportViolation) -> None:
    if args.resource_type == "pulumi:pulumi:Stack":
        return
    try:
        properties = _properties(args.props)
        if args.resource_type.startswith("kubernetes:"):
            parts = args.resource_type.split(":")
            if len(parts) != 3 or parts[1] not in {"core/v1", "apps/v1", "networking.k8s.io/v1"}:
                raise GovernanceError("K8S010: Kubernetes resource type/group is not reviewed")
            _, group, kind = parts
            version = "v1" if group == "core/v1" else group
            props = properties
            if "apiVersion" in props and props["apiVersion"] != version:
                raise GovernanceError("K8S010: resource type and API version disagree")
            if "kind" in props and props["kind"] != kind:
                raise GovernanceError("K8S010: resource type and kind disagree")
            validate_kubernetes({"apiVersion": version, "kind": kind, **props})
            return
        if args.resource_type in COMPONENTS or args.resource_type == PROVIDER:
            validate_oci(args.resource_type, properties)
            return
        modeled = footprint(args.resource_type, properties, planned=True)
        validate_oci(args.resource_type, properties)
        # Resource-local ceilings supplement account-wide preflight; never replace it.
        ceilings = {"ocpus": 4, "memory_gb": 24, "block_gb": 200}
        for metric in CAPACITY:
            if modeled[metric] > ceilings[metric]:
                raise GovernanceError(
                    f"GOV030: {metric} resource exceeds the maximum reviewed profile"
                )
    except GovernanceError as error:
        report(str(error), None)


def policy_pack() -> PolicyPack:
    return PolicyPack(
        name="always-free-governance",
        enforcement_level=EnforcementLevel.MANDATORY,
        policies=[
            ResourceValidationPolicy(
                name="reviewed-resource-costs",
                description="Fail closed on unknown or paid resource configurations",
                enforcement_level=EnforcementLevel.MANDATORY,
                validate=validate_resource,
            )
        ],
    )
