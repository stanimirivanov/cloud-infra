"""Closed, non-secret committed network interface; no fallback to preview IDs."""

import re
from typing import Any

import pulumi
from infra_core.governance.contracts import GovernanceError, require
from infra_core.oci.config import FoundationConfig

NETWORK_STACK = "organization/free-infrastructure/oci-network"
_MESSAGE = "OCI041: valid non-secret committed network outputs required"
_KINDS = {
    "vcn": "vcn",
    "api-subnet": "subnet",
    "worker-subnet": "subnet",
    "pod-subnet": "subnet",
    "api-nsg": "networksecuritygroup",
    "worker-nsg": "networksecuritygroup",
    "pod-nsg": "networksecuritygroup",
}


def validate_network(value: Any, cfg: FoundationConfig, account_id: str) -> dict[str, str]:
    """Closed metadata/ID consistency validation; does not prove live OCI ownership."""
    require(
        type(value) is dict and set(value) == {"network", "network_stack_identity"},
        "OCI041",
        "committed network export fields required",
    )
    network = value["network"]
    require(
        value["network_stack_identity"] == NETWORK_STACK
        and type(network) is dict
        and set(network)
        == {"schema_version", "account_id", "region", "compartment_id", "cidrs", "ids"},
        "OCI041",
        "network source/schema mismatch",
    )
    require(
        type(network["schema_version"]) is int
        and network["schema_version"] == 1
        and network["account_id"] == account_id
        and network["region"] == cfg.region
        and network["compartment_id"] == cfg.compartment_id
        and network["cidrs"]
        == {
            "vcn": cfg.vcn_cidr,
            "api": cfg.api_cidr,
            "worker": cfg.worker_cidr,
            "pod": cfg.pod_cidr,
        },
        "OCI041",
        "network scope or CIDRs mismatch",
    )
    ids = network["ids"]
    require(type(ids) is dict and set(ids) == set(_KINDS), "OCI041", "network IDs incomplete")
    for key, kind in _KINDS.items():
        require(
            type(ids[key]) is str
            and len(ids[key]) <= 256
            and re.fullmatch(
                r"ocid1\." + kind + r"\.[a-z0-9]+\.[a-z0-9-]*\.[a-z0-9.]*[a-z0-9]", ids[key]
            )
            is not None,
            "OCI041",
            "known typed network OCIDs required",
        )
    require(len(set(ids.values())) == len(ids), "OCI041", "network IDs must be distinct")
    return dict(ids)


async def read_network(
    reference: pulumi.StackReference, cfg: FoundationConfig, account_id: str
) -> dict[str, str]:
    """Await SDK metadata explicitly; ordinary apply would silently skip unknowns."""
    try:
        require(
            await reference.name.is_known()
            and await reference.name.future() == NETWORK_STACK
            and await reference.outputs.is_known()
            and not await reference.outputs.is_secret()
            and await reference.secret_output_names.is_known()
            and await reference.secret_output_names.future() == [],
            "OCI041",
            _MESSAGE,
        )
        value = await reference.outputs.future(with_unknowns=True)
        # Protobuf Struct represents schema integers as doubles at this SDK boundary.
        if type(value) is dict and type(value.get("network")) is dict:
            network = dict(value["network"])
            if type(network.get("schema_version")) is float and network["schema_version"] == 1.0:
                network["schema_version"] = 1
            value = dict(value, network=network)
        return validate_network(value, cfg, account_id)
    except Exception:
        # Do not forward dependency diagnostics or output values in this adapter's exception.
        raise GovernanceError(_MESSAGE) from None
