"""Resource-local OCI security sensors shared by preflight and mandatory policy."""

import ipaddress
import re
from typing import Any

from infra_core.governance.contracts import mapping, require

COMPONENTS = {"infrastructure:oci:Network", "infrastructure:oci:Oke"}
PROVIDER = "pulumi:providers:oci"


def validate_resource(kind: str, props: dict[str, Any]) -> None:
    if kind == PROVIDER:
        require(
            isinstance(props.get("region"), str)
            and bool(re.fullmatch(r"[a-z]+-[a-z]+-\d+", props["region"])),
            "OCI001",
            "provider must pin a known OCI region",
        )
    elif kind == "oci:Core/securityList:SecurityList":
        require(
            props.get("ingressSecurityRules") == [] and props.get("egressSecurityRules") == [],
            "OCI030",
            "subnet security lists must be explicitly empty; use reviewed NSGs",
        )
    elif kind == "oci:Core/subnet:Subnet":
        require(
            isinstance(props.get("securityListIds"), list) and bool(props["securityListIds"]),
            "OCI030",
            "explicit security-list attachment required; no VCN default rules",
        )
    elif kind == "oci:Core/networkSecurityGroupSecurityRule:NetworkSecurityGroupSecurityRule":
        require(props.get("stateless") is False, "OCI030", "rules must be explicitly stateful")
        direction = props.get("direction")
        require(direction in ("INGRESS", "EGRESS"), "OCI030", "rule direction must be known")
        field = "source" if direction == "INGRESS" else "destination"
        if props.get(field + "Type") == "SERVICE_CIDR_BLOCK":
            require(
                direction == "EGRESS"
                and props.get("protocol") == "6"
                and isinstance(props.get(field), str)
                and bool(
                    re.fullmatch(r"all-[a-z0-9]+-services-in-oracle-services-network", props[field])
                ),
                "OCI030",
                "only TCP egress to reviewed All Services labels is supported",
            )
            return
        require(
            props.get(field + "Type") == "CIDR_BLOCK" and isinstance(props.get(field), str),
            "OCI030",
            "explicit CIDR rule required",
        )
        try:
            peer = ipaddress.IPv4Network(props[field], strict=True)
        except ValueError:
            require(False, "OCI030", "rule peer must be a known IPv4 network")
            return
        private = [
            ipaddress.IPv4Network(cidr)
            for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        ]
        if any(peer.subnet_of(block) for block in private):
            # The complete generated graph binds these peers to configured subnets.
            return
        icmp = props.get("protocol") == "1" and props.get("icmpOptions") == {"type": 3, "code": 4}
        tcp = mapping(props.get("tcpOptions", {}), "TCP rule").get("destinationPortRange", {})
        udp = mapping(props.get("udpOptions", {}), "UDP rule").get("destinationPortRange", {})
        if direction == "INGRESS":
            require(
                icmp
                or (
                    props.get("protocol") == "6"
                    and peer.prefixlen >= 24
                    and not peer.is_multicast
                    and not peer.is_loopback
                    and not peer.is_unspecified
                    and tcp == {"min": 6443, "max": 6443}
                ),
                "OCI030",
                "public ingress permits only restricted API TCP/6443 or ICMP 3,4",
            )
        else:
            metadata = str(peer) == "169.254.169.254/32"
            require(
                icmp
                or (
                    props.get("protocol") == "6"
                    and any(
                        tcp == {"min": port, "max": port}
                        for port in ((53, 80, 443) if metadata else (80, 443))
                    )
                )
                or (metadata and props.get("protocol") == "17" and udp == {"min": 53, "max": 53}),
                "OCI030",
                "public egress must be bounded HTTP/HTTPS, DNS metadata or ICMP 3,4",
            )
    elif kind == "oci:ContainerEngine/cluster:Cluster":
        require(
            props.get("clusterPodNetworkOptions") == [{"cniType": "OCI_VCN_IP_NATIVE"}],
            "OCI031",
            "Basic cluster must explicitly use VCN-native pod networking",
        )
        endpoint = mapping(props.get("endpointConfig"), "cluster endpoint")
        require(
            type(endpoint.get("isPublicIpEnabled")) is bool
            and bool(endpoint.get("nsgIds"))
            and bool(endpoint.get("subnetId")),
            "OCI031",
            "explicit endpoint subnet, NSGs and public/private selection required",
        )
    elif kind == "oci:ContainerEngine/nodePool:NodePool":
        config = mapping(props.get("nodeConfigDetails"), "node config")
        network = mapping(config.get("nodePoolPodNetworkOptionDetails"), "pod networking")
        source = mapping(props.get("nodeSourceDetails"), "node image")
        require(
            network.get("cniType") == "OCI_VCN_IP_NATIVE"
            and bool(network.get("podSubnetIds"))
            and bool(network.get("podNsgIds"))
            and config.get("isPvEncryptionInTransitEnabled") is True
            and bool(config.get("placementConfigs"))
            and bool(config.get("nsgIds"))
            and source.get("sourceType") == "IMAGE"
            and isinstance(source.get("imageId"), str)
            and source["imageId"].startswith("ocid1.image."),
            "OCI031",
            "node pool needs explicit image, placement, encryption and native CNI/NSGs",
        )
