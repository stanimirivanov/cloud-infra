"""OCI-only graph shared verbatim by governance and native SDK registration."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from infra_core.oci.config import FoundationConfig

NETWORK_UNIT = "oci-network"
OKE_UNIT = "oci-oke"


@dataclass(frozen=True, slots=True)
class Ref:
    key: str


@dataclass(frozen=True, slots=True)
class Resource:
    key: str
    kind: str
    unit: str
    props: dict[str, Any]


def wire(value: Any) -> Any:
    """Translate Python SDK property names to OCI wire names; preserve references."""
    if isinstance(value, Ref):
        return "${" + value.key + ".id}"
    if isinstance(value, dict):
        return {
            key.split("_")[0] + "".join(part.title() for part in key.split("_")[1:]): wire(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [wire(item) for item in value]
    return value


def proposal(resources: tuple[Resource, ...], account_id: str, region: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "provider": "oci",
        "account_id": account_id,
        "complete": True,
        "units": [
            {
                "name": unit,
                "changes": [
                    {
                        "key": item.key,
                        "action": "create",
                        "existing_ids": [],
                        "resource": {
                            "type": item.kind,
                            "region": region,
                            "props": wire(item.props),
                        },
                    }
                    for item in resources
                    if item.unit == unit
                ],
            }
            for unit in (NETWORK_UNIT, OKE_UNIT)
        ],
    }


def foundation_graph(cfg: FoundationConfig, *, now: datetime | None = None) -> tuple[Resource, ...]:
    cfg.validate(now=now)
    return _network_graph(cfg) + _oke_graph(cfg)


def _network_graph(cfg: FoundationConfig) -> tuple[Resource, ...]:
    """Build the network layer; validation remains at the governed caller boundary."""
    resources: list[Resource] = []

    def add(key: str, family: str, name: str, props: dict[str, Any]) -> None:
        resources.append(
            Resource(
                key,
                f"oci:{family}/{name[0].lower() + name[1:]}:{name}",
                NETWORK_UNIT,
                props,
            )
        )

    def network(key: str, name: str, **props: Any) -> None:
        add(
            key,
            "Core",
            name,
            {"compartment_id": cfg.compartment_id, "display_name": cfg.name + "-" + key, **props},
        )

    network("vcn", "Vcn", cidr_blocks=[cfg.vcn_cidr], dns_label=cfg.name.replace("-", "") + "vcn")
    network("internet", "InternetGateway", vcn_id=Ref("vcn"), enabled=True)
    network(
        "services", "ServiceGateway", vcn_id=Ref("vcn"), services=[{"service_id": cfg.service_id}]
    )
    service_route = {
        "destination": cfg.service_cidr,
        "destination_type": "SERVICE_CIDR_BLOCK",
        "network_entity_id": Ref("services"),
    }
    network(
        "public-routes",
        "RouteTable",
        vcn_id=Ref("vcn"),
        route_rules=[
            service_route,
            {
                "destination": "0.0.0.0/0",
                "destination_type": "CIDR_BLOCK",
                "network_entity_id": Ref("internet"),
            },
        ],
    )
    network("pod-routes", "RouteTable", vcn_id=Ref("vcn"), route_rules=[service_route])
    # Explicit empty list replaces attachment of the VCN default allow rules.
    network(
        "empty-security",
        "SecurityList",
        vcn_id=Ref("vcn"),
        ingress_security_rules=[],
        egress_security_rules=[],
    )
    for role, cidr in (("api", cfg.api_cidr), ("worker", cfg.worker_cidr), ("pod", cfg.pod_cidr)):
        network(
            role + "-subnet",
            "Subnet",
            vcn_id=Ref("vcn"),
            cidr_block=cidr,
            dns_label=role,
            prohibit_public_ip_on_vnic=role == "pod",
            route_table_id=Ref("pod-routes" if role == "pod" else "public-routes"),
            security_list_ids=[Ref("empty-security")],
        )
        network(role + "-nsg", "NetworkSecurityGroup", vcn_id=Ref("vcn"))

    def rule(
        role: str,
        key: str,
        direction: str,
        peer: str,
        protocol: str = "all",
        port: int | None = None,
        *,
        service: bool = False,
        icmp: bool = False,
    ) -> None:
        field = "source" if direction == "INGRESS" else "destination"
        props: dict[str, Any] = {
            "network_security_group_id": Ref(role + "-nsg"),
            "direction": direction,
            "protocol": protocol,
            "stateless": False,
            field: peer,
            field + "_type": "SERVICE_CIDR_BLOCK" if service else "CIDR_BLOCK",
        }
        if port is not None:
            props["tcp_options" if protocol == "6" else "udp_options"] = {
                "destination_port_range": {"min": port, "max": port}
            }
        if icmp:
            props["icmp_options"] = {"type": 3, "code": 4}
        add(role + "-" + key, "Core", "NetworkSecurityGroupSecurityRule", props)

    for role, cidr in (("worker", cfg.worker_cidr), ("pod", cfg.pod_cidr)):
        for port in (6443, 12250):
            rule("api", role + str(port), "INGRESS", cidr, "6", port)
        rule("api", role + "-mtu", "INGRESS", cidr, "1", icmp=True)
    for index, cidr in enumerate(cfg.administrator_cidrs):
        rule("api", "admin" + str(index), "INGRESS", cidr, "6", 6443)
    rule("api", "kubelet", "EGRESS", cfg.worker_cidr, "6", 10250)
    rule("api", "worker-mtu-out", "EGRESS", cfg.worker_cidr, "1", icmp=True)
    rule("api", "pods", "EGRESS", cfg.pod_cidr)
    rule("api", "services", "EGRESS", cfg.service_cidr, "6", 443, service=True)
    for role in ("worker", "pod"):
        for peer, cidr in (("worker", cfg.worker_cidr), ("pod", cfg.pod_cidr)):
            for direction in ("INGRESS", "EGRESS"):
                rule(role, peer + "-" + direction.lower(), direction, cidr)
        rule(
            role,
            "control",
            "INGRESS",
            cfg.api_cidr,
            "6" if role == "worker" else "all",
            10250 if role == "worker" else None,
        )
        for port in (6443, 12250):
            rule(role, "api" + str(port), "EGRESS", cfg.api_cidr, "6", port)
        rule(
            role,
            "services",
            "EGRESS",
            cfg.service_cidr,
            "6",
            service=True,
            port=443 if role == "pod" else None,
        )
        for protocol in ("6", "17"):
            rule(role, "dns" + protocol, "EGRESS", "169.254.169.254/32", protocol, 53)
    for direction in ("INGRESS", "EGRESS"):
        rule("worker", "internet-mtu-" + direction.lower(), direction, "0.0.0.0/0", "1", icmp=True)
    for port in (80, 443):
        rule("worker", "internet" + str(port), "EGRESS", "0.0.0.0/0", "6", port)
    rule("worker", "metadata", "EGRESS", "169.254.169.254/32", "6", 80)
    return tuple(resources)


def _oke_graph(cfg: FoundationConfig) -> tuple[Resource, ...]:
    """Build OKE with symbolic network references; never register or look up IDs."""
    return (
        Resource(
            "cluster",
            "oci:ContainerEngine/cluster:Cluster",
            OKE_UNIT,
            {
                "compartment_id": cfg.compartment_id,
                "name": cfg.name + "-cluster",
                "vcn_id": Ref("vcn"),
                "kubernetes_version": cfg.kubernetes_version,
                "type": "BASIC_CLUSTER",
                "cluster_pod_network_options": [{"cni_type": "OCI_VCN_IP_NATIVE"}],
                "endpoint_config": {
                    "is_public_ip_enabled": True,
                    "subnet_id": Ref("api-subnet"),
                    "nsg_ids": [Ref("api-nsg")],
                },
                "options": {
                    "add_ons": {"is_kubernetes_dashboard_enabled": False},
                    "kubernetes_network_config": {"services_cidr": cfg.services_cidr},
                },
            },
        ),
        Resource(
            "workers",
            "oci:ContainerEngine/nodePool:NodePool",
            OKE_UNIT,
            {
                "compartment_id": cfg.compartment_id,
                "cluster_id": Ref("cluster"),
                "name": cfg.name + "-arm-pool",
                "kubernetes_version": cfg.kubernetes_version,
                "node_shape": "VM.Standard.A1.Flex",
                "node_shape_config": {
                    "ocpus": cfg.ocpus_per_node,
                    "memory_in_gbs": cfg.memory_gb_per_node,
                },
                "node_source_details": {
                    "source_type": "IMAGE",
                    "image_id": cfg.image.image_id,
                    "boot_volume_size_in_gbs": str(cfg.boot_gb_per_node),
                },
                "node_config_details": {
                    "size": cfg.nodes,
                    "is_pv_encryption_in_transit_enabled": True,
                    "placement_configs": [
                        {"availability_domain": ad, "subnet_id": Ref("worker-subnet")}
                        for ad in cfg.availability_domains
                    ],
                    "nsg_ids": [Ref("worker-nsg")],
                    "node_pool_pod_network_option_details": {
                        "cni_type": "OCI_VCN_IP_NATIVE",
                        "max_pods_per_node": cfg.max_pods_per_node,
                        "pod_subnet_ids": [Ref("pod-subnet")],
                        "pod_nsg_ids": [Ref("pod-nsg")],
                    },
                },
            },
        ),
    )
