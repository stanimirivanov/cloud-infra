"""OCI desired graph correspondence; unresolved reference IDs are never proof of a match."""

import hashlib
from typing import Any

from infra_core.governance.contracts import number
from infra_core.governance.resources import footprint
from infra_core.network_outputs import NETWORK_STACK, network_digest, validate_network
from infra_core.oci.config import parse_config
from infra_core.oci.graph import network_graph, oke_graph, wire
from infra_core.service_preview_graph import UNKNOWN, ServicePreviewGraph, encoded, require

MESSAGE = "PREVIEW010: OCI preview graph does not match reviewed proposal"
REFERENCE = "pulumi:pulumi:StackReference"


class OciPreviewGraph(ServicePreviewGraph):
    def __init__(
        self,
        unit: str,
        configuration: dict[str, Any],
        account: dict[str, Any],
        profile: dict[str, Any],
        pins: dict[str, Any],
        dependency: dict[str, Any] | None,
    ):
        self._initialize()
        self.ids: dict[str, str] = {}
        self.dependency = dependency
        self.profile = profile
        try:
            require(unit in {"oci-network", "oci-oke"})
            values = dict(configuration)
            image = values.pop("image")
            cfg = parse_config({"foundation": values, "image": image})
            require(
                account["provider"] == profile["provider"] == "oci" and profile["enabled"] is True
            )
            require(
                account["profile"] == profile["id"]
                and account["profile_revision"] == profile["revision"]
                and type(account["profile_revision"]) is int
                and type(profile["revision"]) is int
            )
            require(profile["id"] in {"oci-free", "oci-paid-a1"})
            require(account["home_region"] == cfg.region)
            require(
                type(account["account_id"]) is str
                and account["account_id"].startswith("ocid1.tenancy.")
            )
            require((unit == "oci-oke") == (dependency is not None))
            network = (
                validate_network(dependency, cfg, account["account_id"])
                if dependency is not None
                else None
            )
            graph = oke_graph(cfg, network) if unit == "oci-oke" else network_graph(cfg)
            prefix = f"urn:pulumi:{unit}::free-infrastructure::"
            root = prefix + "pulumi:pulumi:Stack::free-infrastructure-" + unit
            kind = "infrastructure:oci:" + ("Oke" if unit == "oci-oke" else "Network")
            component = (
                prefix + kind + "::" + cfg.name + ("-oke" if unit == "oci-oke" else "-network")
            )
            self.provider = prefix + "pulumi:providers:oci::" + cfg.name + "-provider"
            self.version = pins["providers"]["oci"]["version"]
            self.add(root, "pulumi:pulumi:Stack", "", False, False, "", {})
            self.add(component, kind, root, False, True, "", {})
            self.add(
                self.provider,
                "pulumi:providers:oci",
                root,
                True,
                True,
                "",
                {"region": cfg.region, "tenancyOcid": account["account_id"]},
            )
            urns = {
                item.key: prefix + kind + "$" + item.kind + "::" + cfg.name + "-" + item.key
                for item in graph
            }

            def template(value: Any) -> Any:
                if isinstance(value, str) and value.startswith("${"):
                    require(value.endswith(".id}") and value[2:-4] in urns)
                    return {"$ref": urns[value[2:-4]]}
                if type(value) is dict:
                    return {k: template(v) for k, v in value.items()}
                if type(value) is list:
                    return [template(v) for v in value]
                return value

            for item in graph:
                props = wire(item.props)
                for metric, value in footprint(item.kind, props, planned=True).items():
                    require(value <= number(profile["capacity"][metric], "selected capacity"))
                self.add(
                    urns[item.key], item.kind, component, True, True, self.provider, template(props)
                )
            if dependency is not None:
                builtin = prefix + "pulumi:providers:pulumi::default"
                self.add(builtin, "pulumi:providers:pulumi", "", True, False, "", {})
                self.add(
                    prefix + REFERENCE + "::" + cfg.name + "-network-reference",
                    REFERENCE,
                    root,
                    True,
                    False,  # The pinned engine does not retain protect on an external read.
                    builtin,
                    {"name": NETWORK_STACK},
                )
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ValueError(MESSAGE) from None

    def normalize_inputs(self, urn: str, inputs: dict[str, Any]) -> dict[str, Any]:
        def resolve(actual: Any, expected: Any) -> Any:
            if type(expected) is dict and set(expected) == {"$ref"}:
                target = self.ids.get(expected["$ref"])
                require(target is not None and actual == target)
                return expected
            if type(expected) is dict:
                require(type(actual) is dict and set(actual) == set(expected))
                return {key: resolve(actual[key], value) for key, value in expected.items()}
            if type(expected) is list:
                require(type(actual) is list and len(actual) == len(expected))
                return [resolve(a, e) for a, e in zip(actual, expected, strict=True)]
            return actual

        if self.expected[urn]["type"] == REFERENCE:
            for key, expected in (("outputs", self.dependency), ("secretOutputNames", [])):
                if key in inputs:
                    value = inputs.pop(key)
                    require(
                        value is None or value == UNKNOWN or encoded(value) == encoded(expected)
                    )
        result: dict[str, Any] = resolve(inputs, self.expected[urn]["inputs"])
        return result

    def external(self, urn: str) -> bool:
        return bool(self.expected[urn]["type"] == REFERENCE)

    def operations(self, urn: str) -> set[str]:
        return (
            {"read", "same"} if self.expected[urn]["type"] == REFERENCE else super().operations(urn)
        )

    def observe(self, kind: str, body: dict[str, Any]) -> None:
        try:
            state = body["metadata"]["new"]
            urn = body["metadata"]["urn"]
            identifier = state.get("id", "")
            require(type(identifier) is str)
            if identifier and identifier != UNKNOWN:
                require(self.ids.get(urn, identifier) == identifier)
                self.ids[urn] = identifier
            super().observe(kind, body)
            if state["type"] == REFERENCE:
                require(identifier == NETWORK_STACK)
            if state["type"] == REFERENCE and kind == "resOutputsEvent":
                outputs = state["outputs"]
                require(outputs["name"] == NETWORK_STACK and outputs["secretOutputNames"] == [])
                require(encoded(outputs["outputs"]) == encoded(self.dependency))
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ValueError(MESSAGE) from None

    def finish(self) -> None:
        try:
            super().finish()
        except ValueError:
            raise ValueError(MESSAGE) from None

    def stamp(self) -> dict[str, Any]:
        return dict(
            super().stamp(),
            profile_sha256=hashlib.sha256(encoded(self.profile)).hexdigest(),
            dependency_sha256=network_digest(self.dependency)
            if self.dependency is not None
            else None,
        )
