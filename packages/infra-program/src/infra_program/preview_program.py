"""In-process preview admission; a context is not an operational authorization token."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import pulumi
from infra_core.foundation import FoundationConfig
from infra_core.oci.config import FoundationConfig as OciConfig
from infra_core.preview_contracts import PreviewContract, describe_preview

from infra_program.services.components import Services
from infra_program.services.configuration import register_services_from_config

if TYPE_CHECKING:
    from infra_program.oci.components import Network, Oke


@dataclass(frozen=True)
class PreviewContext:
    """Explicit inputs from a reviewed caller, never discovered from environment/files.

    The future constrained driver must establish clean checkout identity, backend,
    tool verification and operational evidence independently. This adapter only
    validates program admission and delegates existing evidence preflight.
    Factories snapshot mutable reviewed inputs before auditing and registration.
    """

    foundation: FoundationConfig
    contract: PreviewContract
    expected_commit: str


@dataclass(frozen=True)
class ServicePreviewContext(PreviewContext):
    """Existing service factory inputs, snapshotted at dispatch."""

    proposal: dict[str, Any] = field(repr=False)
    profile: dict[str, Any] = field(repr=False)
    evidence: bytes = field(repr=False)
    envelope: bytes = field(repr=False)


@dataclass(frozen=True)
class NetworkPreviewContext(PreviewContext):
    """Existing OCI inputs; credentials are not carried in the context."""

    configuration: OciConfig = field(repr=False)
    account: dict[str, Any] = field(repr=False)
    profile: dict[str, Any] = field(repr=False)
    inventory: bytes = field(repr=False)
    envelope: bytes = field(repr=False)


@dataclass(frozen=True)
class OkePreviewContext(NetworkPreviewContext):
    """OKE uses the exact dependency identity from its reviewed preview contract."""


def dispatch_preview(
    context: ServicePreviewContext | NetworkPreviewContext | OkePreviewContext | None,
) -> Services | Network | pulumi.Output[Oke]:
    """Deny before secret lookup/registration unless SDK and explicit inputs agree."""
    message = "PREVIEW002: Provisioning is not enabled; valid preview admission required"
    if (
        type(context) not in (ServicePreviewContext, NetworkPreviewContext, OkePreviewContext)
        or pulumi.runtime.is_dry_run() is not True
    ):
        raise RuntimeError(message)
    assert context is not None
    if (
        type(context.foundation) is not FoundationConfig
        or type(context.contract) is not PreviewContract
        or type(context.expected_commit) is not str
    ):
        raise RuntimeError(message)
    try:
        expected = describe_preview(
            context.foundation, context.contract.unit, context.expected_commit
        )
        runtime_identity = (
            f"{pulumi.get_organization()}/{pulumi.get_project()}/{pulumi.get_stack()}"
        )
    except (ValueError, TypeError, AttributeError):
        raise RuntimeError(message) from None
    providers = {"cloudflare-edge": "cloudflare", "supabase-database": "supabase"}
    if (
        context.contract != expected
        or expected.preview_enabled is not True
        or expected.stack_identity != runtime_identity
    ):
        raise RuntimeError(message)
    if type(context) in (NetworkPreviewContext, OkePreviewContext):
        assert isinstance(context, NetworkPreviewContext)
        if (
            expected.unit != ("oci-oke" if type(context) is OkePreviewContext else "oci-network")
            or type(context.configuration) is not OciConfig
            or type(context.account) is not dict
            or type(context.profile) is not dict
            or type(context.inventory) is not bytes
            or type(context.envelope) is not bytes
        ):
            raise RuntimeError(message)
        if type(context) is OkePreviewContext:
            from infra_program.oci.components import register_oke

            result = register_oke(
                context.configuration,
                context.account,
                context.profile,
                context.inventory,
                envelope=context.envelope,
                commit=context.expected_commit,
                dependency_stack=expected.dependency_stacks[0],
            )

            def export_oke(oke: Oke) -> Oke:
                pulumi.export(
                    "oke",
                    {
                        "schema_version": 1,
                        "region": context.configuration.region,
                        "cluster_id": oke.cluster_id,
                        "node_pool_id": oke.node_pool_id,
                    },
                )
                return oke

            return result.apply(export_oke)
        from infra_program.oci.components import register_network

        network = register_network(
            context.configuration,
            context.account,
            context.profile,
            context.inventory,
            envelope=context.envelope,
            commit=context.expected_commit,
        )
        outputs = network.outputs
        pulumi.export("network_stack_identity", expected.stack_identity)
        pulumi.export(
            "network",
            {
                "schema_version": outputs.schema_version,
                "account_id": outputs.account_id,
                "region": outputs.region,
                "compartment_id": outputs.compartment_id,
                "cidrs": outputs.cidrs,
                "ids": outputs.ids,
            },
        )
        return network
    assert isinstance(context, ServicePreviewContext)
    if (
        expected.unit not in providers
        or type(context.proposal) is not dict
        or type(context.profile) is not dict
        or type(context.evidence) is not bytes
        or type(context.envelope) is not bytes
    ):
        raise RuntimeError(message)
    proposal, profile = deepcopy((context.proposal, context.profile))
    if (
        proposal.get("unit") != expected.unit
        or proposal.get("provider") != providers[expected.unit]
    ):
        raise RuntimeError(message)
    # Factory audits immutable evidence before Config/require_secret and rechecks
    # frozen inputs before registration. Do not implement an alternate composition path.
    return register_services_from_config(
        proposal,
        context.evidence,
        profile,
        envelope=context.envelope,
        commit=context.expected_commit,
    )
