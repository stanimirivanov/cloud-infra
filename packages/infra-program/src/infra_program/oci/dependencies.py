"""Closed, non-secret committed network interface; no fallback to preview IDs."""

import pulumi
from infra_core.governance.contracts import GovernanceError, require
from infra_core.network_outputs import NETWORK_STACK as NETWORK_STACK
from infra_core.network_outputs import network_digest as network_digest
from infra_core.network_outputs import validate_network as validate_network
from infra_core.oci.config import FoundationConfig

_MESSAGE = "OCI041: valid non-secret committed network outputs required"


async def read_network(
    reference: pulumi.StackReference,
    cfg: FoundationConfig,
    account_id: str,
    expected_sha256: str | None = None,
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
        ids = validate_network(value, cfg, account_id)
        if expected_sha256 is not None:
            assert isinstance(value, dict)
            require(network_digest(value) == expected_sha256, "OCI041", _MESSAGE)
        return ids
    except Exception:
        # Do not forward dependency diagnostics or output values in this adapter's exception.
        raise GovernanceError(_MESSAGE) from None
