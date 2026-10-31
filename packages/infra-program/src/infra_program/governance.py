"""Governance adapters; no Pulumi resource registration is allowed before audit."""

import hashlib
import json
import math
import tomllib
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

from infra_core.governance.audit import audit
from infra_core.governance.contracts import GovernanceError, number
from infra_core.governance.resources import CAPACITY, footprint
from infra_core.inventory_evidence import validate_inventory_evidence
from infra_core.kubernetes.resources import validate_resource as validate_kubernetes
from infra_core.oci.security import COMPONENTS, PROVIDER
from infra_core.oci.security import validate_resource as validate_oci
from infra_core.services.governance import DNS, PROJECT
from infra_core.services.governance import validate_resource as validate_service
from pulumi_policy import (
    EnforcementLevel,
    PolicyConfigSchema,
    PolicyPack,
    ReportViolation,
    ResourceValidationArgs,
    ResourceValidationPolicy,
)

from infra_program.oci.dependencies import NETWORK_STACK


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
    inventory: bytes,
    plan: dict[str, Any],
    register: Callable[[], T],
    *,
    envelope: bytes,
    commit: str,
) -> T:
    account, profile, plan = deepcopy((account, profile, plan))
    observed = validate_inventory_evidence(account, profile, inventory, envelope, commit=commit)
    audit(account, profile, observed, plan)
    return register()


def validate_resource(args: ResourceValidationArgs, report: ReportViolation) -> None:
    if args.resource_type == "pulumi:pulumi:Stack":
        return
    try:
        properties = _properties(args.props)
        if args.resource_type == "pulumi:providers:pulumi":
            # Pinned engine infrastructure for StackReference, with no cloud configuration.
            if args.name != "default" or properties:
                raise GovernanceError(
                    "OCI041: only the empty built-in stack-reference provider is allowed"
                )
            return
        if args.resource_type == "pulumi:pulumi:StackReference":
            if properties.get("name") != NETWORK_STACK or set(properties) - {
                "name",
                "outputs",
                "secretOutputNames",
            }:
                raise GovernanceError("OCI041: only the explicit OCI network reference is allowed")
            return
        if args.resource_type in {DNS, PROJECT}:
            if args.resource_type == PROJECT:
                # The generated SDK marks this sensitive input secret. Do not inspect/echo it.
                if "databasePassword" not in properties:
                    raise GovernanceError("EXT031: project password input is required")
                properties = {
                    key: value for key, value in properties.items() if key != "databasePassword"
                }
            validate_service(args.resource_type, properties)
            return
        if args.resource_type == "infrastructure:services:Independent":
            if properties:
                raise GovernanceError("EXT012: service component inputs must be empty")
            return
        if args.resource_type in {"pulumi:providers:cloudflare", "pulumi:providers:supabase"}:
            is_dns = args.resource_type.endswith(":cloudflare")
            expected = {"apiToken", "baseUrl"} if is_dns else {"accessToken", "endpoint"}
            # Provider SDK metadata may also be supplied by the Pulumi engine.
            if (
                properties.get("version", "6.23.1" if is_dns else "1.11.0")
                != ("6.23.1" if is_dns else "1.11.0")
                or properties.get("pluginDownloadURL", "") != ""
            ):
                raise GovernanceError("EXT012: unreviewed provider version/download source")
            props = {
                key: value
                for key, value in properties.items()
                if key not in {"version", "pluginDownloadURL"}
            }
            endpoint = (
                "https://api.cloudflare.com/client/v4" if is_dns else "https://api.supabase.com"
            )
            if set(props) != expected or props.get("baseUrl" if is_dns else "endpoint") != endpoint:
                raise GovernanceError(
                    "EXT012: provider fields/endpoint are outside the reviewed subset"
                )
            return
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


def _profile_settings(profile: dict[str, Any]) -> dict[str, Any]:
    digest = hashlib.sha256(
        json.dumps(profile, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return {"id": profile["id"], "revision": profile["revision"], "sha256": digest}


def _selected_profile(settings: Any) -> dict[str, Any]:
    profiles = tomllib.loads(
        (Path(__file__).resolve().parents[4] / "config/quotas/profiles.toml").read_text()
    )["profiles"]
    if not isinstance(settings, Mapping) or set(settings) != {"id", "revision", "sha256"}:
        raise GovernanceError("GOV031: explicit selected OCI profile context required")
    name = settings["id"]
    if not isinstance(name, str) or name not in {"oci-free", "oci-paid-a1"}:
        raise GovernanceError("GOV031: unreviewed selected OCI profile")
    profile: dict[str, Any] = profiles[name]
    if (
        type(settings["revision"]) is not int
        or dict(settings) != _profile_settings(profile)
        or profile["enabled"] is not True
        or profile["provider"] != "oci"
    ):
        raise GovernanceError("GOV031: selected OCI profile binding mismatch")
    return profile


def policy_configuration(account: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    """Called after preflight; bind the independently selected account profile."""
    settings = _profile_settings(profile)
    if (
        account.get("profile") != settings["id"]
        or account.get("profile_revision") != settings["revision"]
    ):
        raise GovernanceError("GOV031: account and selected OCI profile disagree")
    return {"reviewed-resource-costs": {"enforcementLevel": "mandatory", "ociProfile": settings}}


def validate_profiled_resource(args: ResourceValidationArgs, report: ReportViolation) -> None:
    """Mandatory pack entry point; local maximum checks remain an additional layer."""
    validate_resource(args, report)
    if not (
        args.resource_type.startswith("oci:")
        or args.resource_type == PROVIDER
        or args.resource_type in COMPONENTS
    ):
        return
    try:
        config = _properties(args.get_config())
        if set(config) != {"ociProfile"}:
            raise GovernanceError("GOV031: explicit selected OCI profile context required")
        profile = _selected_profile(config["ociProfile"])
        if args.resource_type not in COMPONENTS and args.resource_type != PROVIDER:
            modeled = footprint(args.resource_type, _properties(args.props), planned=True)
            for metric in CAPACITY:
                if modeled[metric] > number(profile["capacity"][metric], "profile capacity"):
                    raise GovernanceError(f"GOV030: {metric} resource exceeds selected OCI profile")
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
                validate=validate_profiled_resource,
                config_schema=PolicyConfigSchema(
                    properties={
                        "ociProfile": {"type": "object"},
                    }
                ),
            )
        ],
    )
