"""Pure committed OCI network interface shared by runtime reads and owner handoff."""

import hashlib
import json
import re
from typing import Any

from infra_core.governance.contracts import require
from infra_core.oci.config import FoundationConfig

NETWORK_STACK = "organization/free-infrastructure/oci-network"
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


def network_digest(value: dict[str, Any]) -> str:
    """Canonical dependency identity; raw capture bytes are separately receipt-bound."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
