"""In-process preview admission; a context is not an operational authorization token."""

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

import pulumi
from infra_core.foundation import FoundationConfig
from infra_core.preview_contracts import PreviewContract, describe_preview

from infra_program.services.components import Services
from infra_program.services.configuration import register_services_from_config


@dataclass(frozen=True)
class ServicePreviewContext:
    """Explicit inputs from a reviewed caller, never discovered from environment/files.

    The future constrained driver must establish clean checkout identity, backend,
    tool verification and operational evidence independently. This adapter only
    validates program admission and delegates existing service evidence preflight.
    Mutable proposal/profile inputs are snapshotted again at dispatch.
    """

    foundation: FoundationConfig
    contract: PreviewContract
    expected_commit: str
    proposal: dict[str, Any] = field(repr=False)
    profile: dict[str, Any] = field(repr=False)
    evidence: bytes = field(repr=False)
    envelope: bytes = field(repr=False)


def dispatch_preview(context: ServicePreviewContext | None) -> Services:
    """Deny before secret lookup/registration unless SDK and explicit inputs agree."""
    message = "PREVIEW002: Provisioning is not enabled; valid service preview admission required"
    if type(context) is not ServicePreviewContext or pulumi.runtime.is_dry_run() is not True:
        raise RuntimeError(message)
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
        or expected.unit not in providers
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
