"""Explicit-provider components emitted only after complete service preflight."""

from typing import Any

import pulumi
import pulumi_cloudflare as cloudflare
import pulumi_supabase as supabase
from infra_core.governance.contracts import require
from infra_core.service_evidence import validate_service_evidence

_PERMIT = object()


class Services(pulumi.ComponentResource):
    def __init__(
        self,
        proposal: dict[str, Any],
        token: pulumi.Output[str],
        passwords: dict[str, pulumi.Output[str]],
        *,
        _permit: object | None = None,
    ) -> None:
        require(_permit is _PERMIT, "EXT030", "use register_services for governed registration")
        unit = proposal["unit"]
        super().__init__(
            "infrastructure:services:Independent", unit, {}, pulumi.ResourceOptions(protect=True)
        )
        if proposal["provider"] == "cloudflare":
            self.provider, self.resources = _register_cloudflare(self, proposal, token)
        else:
            self.provider, self.resources = _register_supabase(self, proposal, token, passwords)
        self.register_outputs(
            {
                "schema_version": 1,
                "account_id": proposal["account_id"],
                "scope_id": proposal["scope_id"],
                "provider": proposal["provider"],
                "ids": {key: resource.id for key, resource in self.resources.items()},
            }
        )


def _register_cloudflare(
    parent: Services,
    proposal: dict[str, Any],
    token: pulumi.Output[str],
) -> tuple[pulumi.ProviderResource, dict[str, pulumi.CustomResource]]:
    """Compose the validated DNS subset under the existing component identity."""
    unit = proposal["unit"]
    secret_token: pulumi.Output[str] = pulumi.Output.secret(token)
    provider = cloudflare.Provider(
        unit + "-provider",
        api_token=secret_token,
        base_url="https://api.cloudflare.com/client/v4",
        opts=pulumi.ResourceOptions(parent=parent, protect=True),
    )
    resources: dict[str, pulumi.CustomResource] = {}
    for item in proposal["resources"]:
        props = item["props"]
        resources[item["key"]] = cloudflare.DnsRecord(
            unit + "-" + item["key"],
            zone_id=props["zoneId"],
            name=props["name"],
            type=props["type"],
            ttl=props["ttl"],
            content=props["content"],
            proxied=props["proxied"],
            opts=pulumi.ResourceOptions(parent=parent, provider=provider, protect=True),
        )
    return provider, resources


def _register_supabase(
    parent: Services,
    proposal: dict[str, Any],
    token: pulumi.Output[str],
    passwords: dict[str, pulumi.Output[str]],
) -> tuple[pulumi.ProviderResource, dict[str, pulumi.CustomResource]]:
    """Compose validated Free projects with a separate secret password per key."""
    unit = proposal["unit"]
    secret_token: pulumi.Output[str] = pulumi.Output.secret(token)
    provider = supabase.Provider(
        unit + "-provider",
        access_token=secret_token,
        endpoint="https://api.supabase.com",
        opts=pulumi.ResourceOptions(parent=parent, protect=True),
    )
    resources: dict[str, pulumi.CustomResource] = {}
    for item in proposal["resources"]:
        props = item["props"]
        secret_password: pulumi.Output[str] = pulumi.Output.secret(passwords[item["key"]])
        resources[item["key"]] = supabase.Project(
            unit + "-" + item["key"],
            organization_id=props["organizationId"],
            name=props["name"],
            region=props["region"],
            instance_size=props["instanceSize"],
            legacy_api_keys_enabled=props["legacyApiKeysEnabled"],
            database_password=secret_password,
            opts=pulumi.ResourceOptions(parent=parent, provider=provider, protect=True),
        )
    return provider, resources


def register_services(
    config: dict[str, Any],
    evidence: bytes,
    profile: dict[str, Any],
    token: pulumi.Output[str],
    passwords: dict[str, pulumi.Output[str]] | None = None,
    *,
    envelope: bytes,
    commit: str,
) -> Services:
    """Library only: no stack selection, credential lookup, backend or apply path."""
    proposal = validate_service_evidence(config, profile, evidence, envelope, commit=commit)
    passwords = dict(passwords or {})
    expected = (
        {item["key"] for item in proposal["resources"]}
        if proposal["provider"] == "supabase"
        else set()
    )
    require(
        isinstance(token, pulumi.Output)
        and set(passwords) == expected
        and all(isinstance(value, pulumi.Output) for value in passwords.values()),
        "EXT031",
        "supply an explicit token Output and one password Output per project",
    )
    return Services(proposal, token, passwords, _permit=_PERMIT)
