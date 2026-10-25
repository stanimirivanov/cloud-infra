"""Governance adapters; no Pulumi resource registration is allowed before audit."""

from collections.abc import Callable
from typing import Any

from infra_core.governance.audit import audit
from infra_core.governance.contracts import GovernanceError
from infra_core.governance.resources import CAPACITY, footprint
from pulumi_policy import (
    EnforcementLevel,
    PolicyPack,
    ReportViolation,
    ResourceValidationArgs,
    ResourceValidationPolicy,
)


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
        modeled = footprint(args.resource_type, dict(args.props), planned=True)
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
