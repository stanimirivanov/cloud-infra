"""Closed service graph matching for pinned, secret-filtered engine observations."""

import hashlib
import json
import re
from typing import Any

from infra_core.services.governance import DNS, PROJECT, validate_resource

MESSAGE = "PREVIEW009: service preview graph does not match reviewed proposal"
COMPONENT = "infrastructure:services:Independent"
UNKNOWN = "04da6b54-80e4-46f7-96ec-b56ff0331ba9"
SECRET = {
    "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
    "ciphertext": "[secret]",
}


def require(value: bool) -> None:
    if not value:
        raise ValueError(MESSAGE)


def encoded(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class ServicePreviewGraph:
    def __init__(self, unit: str, configuration: dict[str, Any], pins: dict[str, Any]):
        self._initialize()
        try:
            provider = {"cloudflare-edge": "cloudflare", "supabase-database": "supabase"}[unit]
            require(configuration["unit"] == unit and configuration["provider"] == provider)
            require(
                type(configuration["schema_version"]) is int
                and configuration["schema_version"] == 2
            )
            prefix = f"urn:pulumi:{unit}::free-infrastructure::"
            root = prefix + "pulumi:pulumi:Stack::free-infrastructure-" + unit
            component = prefix + COMPONENT + "::" + unit
            kind = "pulumi:providers:" + provider
            self.provider = prefix + COMPONENT + "$" + kind + "::" + unit + "-provider"
            self.version = (
                pins["providers"][provider]["version"]
                if provider == "cloudflare"
                else pins["downstream"]["version"]
            )
            token, endpoint, url = (
                ("apiToken", "baseUrl", "https://api.cloudflare.com/client/v4")
                if provider == "cloudflare"
                else ("accessToken", "endpoint", "https://api.supabase.com")
            )
            self.add(root, "pulumi:pulumi:Stack", "", False, False, "", {})
            self.add(component, COMPONENT, root, False, True, "", {})
            self.add(self.provider, kind, component, True, True, "", {token: SECRET, endpoint: url})
            require(
                type(configuration["resources"]) is list and len(configuration["resources"]) <= 200
            )
            for item in configuration["resources"]:
                require(
                    type(item["key"]) is str
                    and bool(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", item["key"]))
                )
                resource_type = DNS if provider == "cloudflare" else PROJECT
                require(item["type"] == resource_type)
                require(type(item["props"]) is dict)
                props = dict(item["props"])
                validate_resource(resource_type, props)
                require(
                    props["zoneId" if provider == "cloudflare" else "organizationId"]
                    == configuration["scope_id"]
                )
                if provider == "supabase":
                    props["databasePassword"] = SECRET
                self.add(
                    prefix + COMPONENT + "$" + resource_type + "::" + unit + "-" + item["key"],
                    resource_type,
                    component,
                    True,
                    True,
                    self.provider,
                    props,
                )
        except (KeyError, TypeError, ValueError):
            raise ValueError(MESSAGE) from None

    def _initialize(self) -> None:
        self.expected: dict[str, dict[str, Any]] = {}
        self.pre: set[str] = set()
        self.post: set[str] = set()
        self.provider_ids: dict[str, set[str]] = {}
        self.references: dict[str, set[str]] = {}

    def normalize_inputs(self, urn: str, inputs: dict[str, Any]) -> dict[str, Any]:
        return inputs

    def external(self, urn: str) -> bool:
        return False

    def operations(self, urn: str) -> set[str]:
        return {"create", "same", "update"}

    def add(
        self,
        urn: str,
        kind: str,
        parent: str,
        custom: bool,
        protect: bool,
        provider: str,
        inputs: dict[str, Any],
    ) -> None:
        require(urn not in self.expected)
        self.expected[urn] = dict(
            type=kind,
            parent=parent,
            custom=custom,
            protect=protect,
            provider=provider,
            inputs=inputs,
        )

    def stamp(self) -> dict[str, Any]:
        return {
            "sha256": hashlib.sha256(encoded(self.expected)).hexdigest(),
            "resource_count": len(self.expected),
        }

    def observe(self, kind: str, body: dict[str, Any]) -> None:
        """Validate every desired state; never include private values in diagnostics."""
        try:
            metadata = body["metadata"]
            urn = metadata["urn"]
            require(type(urn) is str and urn in self.expected and body.get("planning") is True)
            require(metadata["op"] in self.operations(urn))
            expected = self.expected[urn]
            state = metadata["new"]
            require(metadata["type"] == state["type"] == expected["type"] and state["urn"] == urn)
            for key in ("custom", "protect"):
                require(
                    type(state.get(key, False)) is bool and state.get(key, False) == expected[key]
                )
            for key in ("delete", "retainOnDelete", "taint"):
                require(state.get(key, False) is False)
            require(state.get("external", False) is self.external(urn))
            require(state.get("initErrors", []) == [])
            require(state.get("parent", "") == expected["parent"])
            reference = state.get("provider", "")
            require(metadata.get("provider", "") == reference)
            if expected["provider"]:
                require(
                    type(reference) is str
                    and reference.rpartition("::")[0] == expected["provider"]
                    and bool(reference.rpartition("::")[2])
                )
                self.references.setdefault(expected["provider"], set()).add(
                    reference.rpartition("::")[2]
                )
            else:
                require(reference == "")
            require(type(state.get("inputs", {})) is dict)
            inputs = dict(state.get("inputs", {}))
            defaults = inputs.pop("__defaults", [])
            require(
                type(defaults) is list and all(type(v) is str and v in inputs for v in defaults)
            )
            if expected["type"].startswith("pulumi:providers:"):
                identifier = state.get("id", "")
                require(type(identifier) is str)
                if identifier and identifier != UNKNOWN:
                    self.provider_ids.setdefault(urn, set()).add(identifier)
            if urn == self.provider:
                require(
                    inputs.pop("version", self.version) == self.version
                    and inputs.pop("pluginDownloadURL", "") == ""
                )
            # Only the pinned engine's redacted secret representation is accepted.
            require(encoded(self.normalize_inputs(urn, inputs)) == encoded(expected["inputs"]))
            if kind == "resourcePreEvent":
                require(urn not in self.pre)
                self.pre.add(urn)
            else:
                require(kind == "resOutputsEvent" and urn in self.pre)
                self.post.add(urn)
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ValueError(MESSAGE) from None

    def finish(self) -> None:
        require(self.pre == self.post == set(self.expected))
        for identifiers in self.provider_ids.values():
            require(len(identifiers) <= 1)
        for provider, references in self.references.items():
            require(references - {UNKNOWN} <= self.provider_ids.get(provider, set()))
