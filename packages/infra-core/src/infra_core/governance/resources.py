"""Closed OCI resource classification shared by preflight and Pulumi policies."""

from decimal import Decimal
from typing import Any

from infra_core.governance.contracts import mapping, number, require

INSTANCE = "oci:Core/instance:Instance"
NODE_POOL = "oci:ContainerEngine/nodePool:NodePool"
BOOT = "oci:Core/bootVolume:BootVolume"
VOLUME = "oci:Core/volume:Volume"
CLUSTER = "oci:ContainerEngine/cluster:Cluster"
NETWORK = {
    "oci:Core/vcn:Vcn",
    "oci:Core/subnet:Subnet",
    "oci:Core/internetGateway:InternetGateway",
    "oci:Core/routeTable:RouteTable",
    "oci:Core/networkSecurityGroup:NetworkSecurityGroup",
    "oci:Core/networkSecurityGroupSecurityRule:NetworkSecurityGroupSecurityRule",
    "oci:Core/securityList:SecurityList",
    "oci:Core/serviceGateway:ServiceGateway",
}
CAPACITY = {"ocpus", "memory_gb", "block_gb"}
MONTHLY = {
    "a1_ocpu_hours": "ocpus",
    "a1_memory_gb_hours": "memory_gb",
    "block_gb_months": "block_gb",
}
INVENTORY_TYPES = {INSTANCE, BOOT, VOLUME, CLUSTER}


def footprint(kind: str, props: dict[str, Any], *, planned: bool) -> dict[str, Decimal]:
    require(isinstance(kind, str), "GOV003", "resource type must be a string")
    result = dict.fromkeys(CAPACITY, Decimal(0))
    if kind in NETWORK:
        # Network classification is a cost allowlist, not a complete security policy.
        return result
    if kind == CLUSTER:
        require(
            props.get("type") == "BASIC_CLUSTER", "GOV020", "only explicit Basic OKE is allowed"
        )
        return result
    if kind in (BOOT, VOLUME):
        require(
            number(props.get("vpusPerGb"), "volume VPUs") <= 10,
            "GOV021",
            "paid volume performance is prohibited",
        )
        require(
            props.get("isAutoTuneEnabled") is False, "GOV021", "volume auto tuning must be disabled"
        )
        result["block_gb"] = number(props.get("sizeInGbs"), "volume size", positive=True)
        return result
    require(
        kind in (INSTANCE, NODE_POOL), "GOV022", "resource type has no reviewed cost classification"
    )
    pool = kind == NODE_POOL
    require(
        props.get("nodeShape" if pool else "shape") == "VM.Standard.A1.Flex",
        "GOV023",
        "only the reviewed A1 shape is supported",
    )
    shape = mapping(props.get("nodeShapeConfig" if pool else "shapeConfig"), "shape configuration")
    count = (
        number(
            mapping(props.get("nodeConfigDetails"), "node config").get("size"),
            "node count",
            positive=True,
        )
        if pool
        else Decimal(1)
    )
    require(count == count.to_integral_value(), "GOV024", "node count must be a positive integer")
    result["ocpus"] = count * number(shape.get("ocpus"), "OCPUs", positive=True)
    result["memory_gb"] = count * number(shape.get("memoryInGbs"), "memory", positive=True)
    if planned:
        source = mapping(props.get("nodeSourceDetails" if pool else "sourceDetails"), "boot source")
        result["block_gb"] = count * number(
            source.get("bootVolumeSizeInGbs"), "boot size", positive=True
        )
        require(
            result["block_gb"] >= count * 50,
            "GOV025",
            "use explicit boot volumes of at least 50 GB",
        )
        # Do not infer performance/retention/cycling defaults from provider behavior.
        if not pool:
            require(
                number(source.get("bootVolumeVpusPerGb"), "boot VPUs") == 10,
                "GOV021",
                "instance boot VPUs must be explicit balanced 10",
            )
        if pool:
            require(
                "nodePoolCyclingDetails" not in props,
                "GOV026",
                "node cycling needs a reviewed peak model",
            )
    return result
