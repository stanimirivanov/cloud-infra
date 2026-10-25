"""Explicit-provider components emitted only after complete service preflight."""

from copy import deepcopy
from typing import Any

import pulumi
import pulumi_cloudflare as cloudflare
import pulumi_supabase as supabase
from infra_core.governance.contracts import require
from infra_core.services.governance import DNS, audit

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
        self.provider: pulumi.ProviderResource
        secret_token: pulumi.Output[str] = pulumi.Output.secret(token)
        if proposal["provider"] == "cloudflare":
            self.provider = cloudflare.Provider(
                unit + "-provider",
                api_token=secret_token,
                base_url="https://api.cloudflare.com/client/v4",
                opts=pulumi.ResourceOptions(parent=self, protect=True),
            )
        else:
            self.provider = supabase.Provider(
                unit + "-provider",
                access_token=secret_token,
                endpoint="https://api.supabase.com",
                opts=pulumi.ResourceOptions(parent=self, protect=True),
            )
        self.resources: dict[str, pulumi.CustomResource] = {}
        for item in proposal["resources"]:
            props = item["props"]
            opts = pulumi.ResourceOptions(parent=self, provider=self.provider, protect=True)
            name = unit + "-" + item["key"]
            resource: pulumi.CustomResource
            if item["type"] == DNS:
                resource = cloudflare.DnsRecord(
                    name,
                    zone_id=props["zoneId"],
                    name=props["name"],
                    type=props["type"],
                    ttl=props["ttl"],
                    content=props["content"],
                    proxied=props["proxied"],
                    opts=opts,
                )
            else:
                secret_password: pulumi.Output[str] = pulumi.Output.secret(passwords[item["key"]])
                resource = supabase.Project(
                    name,
                    organization_id=props["organizationId"],
                    name=props["name"],
                    region=props["region"],
                    instance_size=props["instanceSize"],
                    legacy_api_keys_enabled=props["legacyApiKeysEnabled"],
                    database_password=secret_password,
                    opts=opts,
                )
            self.resources[item["key"]] = resource
        self.register_outputs(
            {
                "schema_version": 1,
                "account_id": proposal["account_id"],
                "scope_id": proposal["scope_id"],
                "provider": proposal["provider"],
                "ids": {key: resource.id for key, resource in self.resources.items()},
            }
        )


def register_services(
    config: dict[str, Any],
    evidence: dict[str, Any],
    profile: dict[str, Any],
    token: pulumi.Output[str],
    passwords: dict[str, pulumi.Output[str]] | None = None,
) -> Services:
    """Library only: no stack selection, credential lookup, backend or apply path."""
    proposal = audit(deepcopy(config), deepcopy(evidence), deepcopy(profile))
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
