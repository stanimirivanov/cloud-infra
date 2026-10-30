"""Offline OKE network/cluster consistency; never live acceptance or activation."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infra_core.cutover import repository_state
from infra_core.kubernetes.audit import audit
from infra_core.kubernetes.config import parse_config as parse_kubernetes
from infra_core.network_outputs import network_digest, validate_network
from infra_core.oci.config import parse_config as parse_oci
from infra_core.readiness import digest, parsed, private, read

MESSAGE = "STAGE002: OKE staging input rejected; private diagnostics withheld"


def require(condition: bool) -> None:
    if not condition:
        raise ValueError(MESSAGE)


def check(
    root: Path,
    configuration: Path,
    oci_configuration: Path,
    network_outputs: Path,
    inventory: Path,
    resources: Path,
    *,
    account_id: str,
    cluster_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    try:
        return _check(
            root,
            [configuration, oci_configuration, network_outputs, inventory, resources],
            account_id,
            cluster_id,
            now or datetime.now(UTC),
        )
    except (
        ValueError,
        RuntimeError,
        OSError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
    ) as error:
        raise ValueError(MESSAGE) from error


def _check(
    root: Path, inputs: list[Path], account_id: str, cluster_id: str, now: datetime
) -> dict[str, Any]:
    commit, clean = repository_state(root)
    require(clean)
    paths = [private(root, str(path)) for path in inputs]
    require(len(set(paths)) == len(paths))
    captured = {path: read(path) for path in paths}
    configuration, oci_configuration, network_outputs, inventory, resources = (
        parsed(captured[path]) for path in paths
    )
    kube = parse_kubernetes(configuration)
    oci = parse_oci(oci_configuration)
    require(
        type(account_id) is str
        and kube.account_id == account_id
        and type(cluster_id) is str
        and kube.cluster_id == cluster_id
        and kube.region == oci.region
        and kube.policy_version == oci.kubernetes_version.rsplit(".", 1)[0]
    )
    validate_network(network_outputs, oci, account_id)
    audit(kube, inventory, resources, now=now)
    # These assertions do not discover that the cluster actually uses this network.
    # Runtime dependency admission and independent live topology review remain required.
    require(repository_state(root) == (commit, True))
    require(all(read(path) == raw for path, raw in captured.items()))
    return {
        "schema_version": 1,
        "status": "pending",
        "unit": "oci-oke",
        "commit": commit,
        "staging_evidence": "inputs-consistent",
        "input_sha256": dict(
            zip(
                ("configuration", "oci_configuration", "network_outputs", "inventory", "resources"),
                (digest(captured[path]) for path in paths),
                strict=True,
            )
        ),
        "network_outputs_sha256": network_digest(network_outputs),
        "remaining_reviews": [
            "live cluster/node/subnet identities and exact committed network checkpoint dependency",
            "account eligibility, protected execution, independent backup and writer exclusion",
            "native OKE import, exact saved plan, no-op equivalence and signed operation admission",
            "live ARM scheduling, admission rejection and isolation including all allow rules",
            "paired owner handoff, independent source release and separate writer activation",
        ],
        "activation_authorized": False,
        "execution_authorized": False,
        "live_controls_verified": False,
    }
