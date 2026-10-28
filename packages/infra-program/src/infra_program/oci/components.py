"""Protected OCI components compiled from the preflighted pure resource graph."""

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

import pulumi
import pulumi_oci as oci
from infra_core.governance.contracts import require, text
from infra_core.oci.config import FoundationConfig
from infra_core.oci.graph import (
    NETWORK_UNIT,
    OKE_UNIT,
    Ref,
    Resource,
    foundation_graph,
    network_graph,
    oke_graph,
    proposal,
    wire,
)
from infra_core.oci.security import validate_resource

from infra_program.governance import preflight
from infra_program.oci.dependencies import NETWORK_STACK, read_network

# Closed constructor table: no arbitrary resource types, SDK lookups or dynamic imports.
CONSTRUCTORS: dict[str, Callable[..., pulumi.CustomResource]] = {
    "oci:Core/vcn:Vcn": oci.core.Vcn,
    "oci:Core/internetGateway:InternetGateway": oci.core.InternetGateway,
    "oci:Core/serviceGateway:ServiceGateway": oci.core.ServiceGateway,
    "oci:Core/routeTable:RouteTable": oci.core.RouteTable,
    "oci:Core/securityList:SecurityList": oci.core.SecurityList,
    "oci:Core/subnet:Subnet": oci.core.Subnet,
    "oci:Core/networkSecurityGroup:NetworkSecurityGroup": oci.core.NetworkSecurityGroup,
    "oci:Core/networkSecurityGroupSecurityRule:NetworkSecurityGroupSecurityRule": (
        oci.core.NetworkSecurityGroupSecurityRule
    ),
    "oci:ContainerEngine/cluster:Cluster": oci.containerengine.Cluster,
    "oci:ContainerEngine/nodePool:NodePool": oci.containerengine.NodePool,
}
_PERMIT = object()


def resolve(value: Any, registered: dict[str, pulumi.CustomResource]) -> Any:
    if isinstance(value, Ref):
        return registered[value.key].id
    if isinstance(value, dict):
        return {key: resolve(item, registered) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve(item, registered) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class NetworkOutputs:
    """Versioned state-unit interface; no kubeconfig, credentials or reverse references."""

    schema_version: int
    region: str
    compartment_id: str
    account_id: str
    cidrs: dict[str, str]
    ids: dict[str, pulumi.Output[str]]


def _network_outputs(
    cfg: FoundationConfig,
    registered: dict[str, pulumi.CustomResource],
    account_id: str,
) -> NetworkOutputs:
    """Construct the existing version-1 interface from registered network IDs."""
    return NetworkOutputs(
        1,
        cfg.region,
        cfg.compartment_id,
        account_id,
        {
            "vcn": cfg.vcn_cidr,
            "api": cfg.api_cidr,
            "worker": cfg.worker_cidr,
            "pod": cfg.pod_cidr,
        },
        {
            key: registered[key].id
            for key in (
                "vcn",
                "api-subnet",
                "worker-subnet",
                "pod-subnet",
                "api-nsg",
                "worker-nsg",
                "pod-nsg",
            )
        },
    )


class Network(pulumi.ComponentResource):
    def __init__(
        self,
        cfg: FoundationConfig,
        graph: tuple[Resource, ...],
        provider: oci.Provider,
        registered: dict[str, pulumi.CustomResource],
        account_id: str,
        *,
        _permit: object | None = None,
    ) -> None:
        require(_permit is _PERMIT, "OCI040", "use register_foundation for governed registration")
        super().__init__(
            "infrastructure:oci:Network",
            cfg.name + "-network",
            {},
            pulumi.ResourceOptions(protect=True),
        )
        _emit(self, NETWORK_UNIT, cfg, graph, provider, registered)
        self.outputs = _network_outputs(cfg, registered, account_id)
        self.register_outputs(
            {
                "schema_version": 1,
                "region": cfg.region,
                "compartment_id": cfg.compartment_id,
                "account_id": account_id,
                "cidrs": self.outputs.cidrs,
                "ids": self.outputs.ids,
            }
        )


def _validate_network_outputs(
    outputs: NetworkOutputs, cfg: FoundationConfig, account_id: str
) -> None:
    """Keep OKE interface checks independent of the in-process network component."""
    require(
        outputs.schema_version == 1
        and outputs.region == cfg.region
        and outputs.compartment_id == cfg.compartment_id,
        "OCI001",
        "network interface must match schema, region and compartment",
    )
    require(
        outputs.account_id == account_id
        and outputs.cidrs
        == {
            "vcn": cfg.vcn_cidr,
            "api": cfg.api_cidr,
            "worker": cfg.worker_cidr,
            "pod": cfg.pod_cidr,
        },
        "OCI001",
        "network billing scope and CIDRs must match",
    )


class Oke(pulumi.ComponentResource):
    def __init__(
        self,
        cfg: FoundationConfig,
        graph: tuple[Resource, ...],
        provider: oci.Provider,
        registered: dict[str, pulumi.CustomResource],
        network: Network | pulumi.StackReference,
        account_id: str,
        *,
        _permit: object | None = None,
    ) -> None:
        require(_permit is _PERMIT, "OCI040", "use register_foundation for governed registration")
        if isinstance(network, Network):
            _validate_network_outputs(network.outputs, cfg, account_id)
        super().__init__(
            "infrastructure:oci:Oke",
            cfg.name + "-oke",
            {},
            pulumi.ResourceOptions(protect=True, depends_on=[network]),
        )
        _emit(self, OKE_UNIT, cfg, graph, provider, registered)
        self.cluster_id = registered["cluster"].id
        self.node_pool_id = registered["workers"].id
        self.register_outputs(
            {
                "schema_version": 1,
                "cluster_id": self.cluster_id,
                "node_pool_id": self.node_pool_id,
                "region": cfg.region,
            }
        )


def _emit(
    parent: pulumi.ComponentResource,
    unit: str,
    cfg: FoundationConfig,
    graph: tuple[Resource, ...],
    provider: oci.Provider,
    registered: dict[str, pulumi.CustomResource],
) -> None:
    for item in graph:
        if item.unit == unit:
            registered[item.key] = CONSTRUCTORS[item.kind](
                cfg.name + "-" + item.key,
                opts=pulumi.ResourceOptions(parent=parent, provider=provider, protect=True),
                **resolve(item.props, registered),
            )


def _register_provider(cfg: FoundationConfig, account_id: str) -> oci.Provider:
    """Called only inside the preflight registration closure, never during planning."""
    return oci.Provider(
        cfg.name + "-provider",
        region=cfg.region,
        tenancy_ocid=account_id,
        opts=pulumi.ResourceOptions(protect=True),
    )


def register_foundation(
    cfg: FoundationConfig,
    account: dict[str, Any],
    profile: dict[str, Any],
    inventory: bytes,
    *,
    envelope: bytes,
    commit: str,
) -> tuple[Network, Oke]:
    """Library composition only; normal CLI/program activation remains forbidden."""
    cfg, account, profile = deepcopy((cfg, account, profile))
    graph = foundation_graph(cfg)
    require(account.get("home_region") == cfg.region, "OCI001", "provider must match account home")
    account_id = text(account.get("account_id"), "tenancy identity")
    for item in graph:
        validate_resource(item.kind, wire(item.props))

    def register() -> tuple[Network, Oke]:
        # This closure owns the same frozen configuration and graph used by the audit.
        provider = _register_provider(cfg, account_id)
        registered: dict[str, pulumi.CustomResource] = {}
        network = Network(cfg, graph, provider, registered, account_id, _permit=_PERMIT)
        oke = Oke(cfg, graph, provider, registered, network, account_id, _permit=_PERMIT)
        return network, oke

    return preflight(
        account,
        profile,
        inventory,
        proposal(graph, account_id, cfg.region),
        register,
        envelope=envelope,
        commit=commit,
    )


def register_network(
    cfg: FoundationConfig,
    account: dict[str, Any],
    profile: dict[str, Any],
    inventory: bytes,
    *,
    envelope: bytes,
    commit: str,
) -> Network:
    """Governed independent graph; no OKE registration, stack selection or state moves."""
    cfg, account, profile = deepcopy((cfg, account, profile))
    graph = network_graph(cfg)
    require(account.get("home_region") == cfg.region, "OCI001", "provider must match account home")
    account_id = text(account.get("account_id"), "tenancy identity")
    for item in graph:
        validate_resource(item.kind, wire(item.props))

    def register() -> Network:
        provider = _register_provider(cfg, account_id)
        return Network(cfg, graph, provider, {}, account_id, _permit=_PERMIT)

    return preflight(
        account,
        profile,
        inventory,
        proposal(graph, account_id, cfg.region, units=(NETWORK_UNIT,)),
        register,
        envelope=envelope,
        commit=commit,
    )


def register_oke(
    cfg: FoundationConfig,
    account: dict[str, Any],
    profile: dict[str, Any],
    inventory: bytes,
    *,
    envelope: bytes,
    commit: str,
    dependency_stack: str,
    expected_network_sha256: str | None = None,
) -> pulumi.Output[Oke]:
    """Read one committed dependency, then audit the exact OKE graph before emitting."""
    cfg, account, profile = deepcopy((cfg, account, profile))
    require(dependency_stack == NETWORK_STACK, "OCI041", "explicit network stack required")
    graph = oke_graph(cfg)
    require(account.get("home_region") == cfg.region, "OCI001", "provider must match account home")
    account_id = text(account.get("account_id"), "tenancy identity")

    def read() -> pulumi.Output[Oke]:
        reference = pulumi.StackReference(
            cfg.name + "-network-reference",
            stack_name=dependency_stack,
            opts=pulumi.ResourceOptions(protect=True),
        )

        async def resolved() -> Oke:
            ids = await read_network(reference, cfg, account_id, expected_network_sha256)
            bound = oke_graph(cfg, ids)
            for item in bound:
                validate_resource(item.kind, wire(item.props))

            def register() -> Oke:
                provider = _register_provider(cfg, account_id)
                return Oke(cfg, bound, provider, {}, reference, account_id, _permit=_PERMIT)

            return preflight(
                account,
                profile,
                inventory,
                proposal(bound, account_id, cfg.region, units=(OKE_UNIT,)),
                register,
                envelope=envelope,
                commit=commit,
            )

        return pulumi.Output.from_input(resolved())

    return preflight(
        account,
        profile,
        inventory,
        proposal(graph, account_id, cfg.region, units=(OKE_UNIT,)),
        read,
        envelope=envelope,
        commit=commit,
    )
