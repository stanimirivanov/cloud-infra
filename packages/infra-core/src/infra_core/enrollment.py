"""Read-only enrollment gap report; observations never confer operational authority."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infra_core import administration, operation_admission
from infra_core.cutover import repository_state
from infra_core.readiness import digest, parsed, private, read

UNITS = ("oci-network", "oci-oke", "cloudflare-edge", "supabase-database")
# Supported operational contracts, not every reserved slot in operations-policy.json.
OPERATIONS = {
    **{
        f"{action}/{unit}": f"{unit}-{action}"
        for action in ("apply", "recovery", "monitor")
        for unit in UNITS
    },
    **{f"import/{unit}": f"{unit}-import" for unit in UNITS[:2]},
    "handoff/oci": "oci-handoff",
}
ENVIRONMENTS = frozenset(OPERATIONS.values()) | {
    "pulumi-backend-qualification",
    "recovery-rehearsal",
    "monitor-watchdog",
    *(f"pulumi-preview-{unit}" for unit in UNITS),
}
RUNNER_GATES = {
    "service-operations": [
        "restricted repository and reviewed main workflows only",
        "no untrusted PR jobs or shared untrusted workspaces",
        "durable operation journals and monitoring outbox; no automatic reinitialization",
        "separate collection, drift and delivery credentials",
    ],
    "recovery": [
        "restricted repository and reviewed main workflows only",
        "isolated recovery host and independent backup access",
        "durable recovery journals; no automatic reinitialization",
        "read-only observers separated from state-writer credentials",
    ],
}
MESSAGE = "ENROLL001: enrollment input rejected; private diagnostics withheld"


def require(condition: bool) -> None:
    if not condition:
        raise ValueError(MESSAGE)


def check(
    root: Path, evidence: Path | None = None, *, now: datetime | None = None
) -> dict[str, Any]:
    """Inspect optional private observations without network, writes or enrollment."""
    try:
        return _check(root, evidence, now or datetime.now(UTC))
    except (ValueError, TypeError, KeyError, AttributeError, OSError, OverflowError) as error:
        raise ValueError(MESSAGE) from error


def _check(root: Path, evidence: Path | None, now: datetime) -> dict[str, Any]:
    commit, clean = repository_state(root)
    require(clean)
    captured: dict[Path, bytes] = {}

    def capture(path: Path) -> bytes:
        raw = read(path)
        if path in captured:
            require(captured[path] == raw)
        captured[path] = raw
        return raw

    policy_raw = capture(root / administration.POLICY)
    policy = administration._policy(policy_raw)
    reviewer_raw = capture(root / administration.KEYS)
    operation_raw = capture(root / "config/operations-policy.json")
    operations = parsed(operation_raw)
    require(
        operations.get("repository") == policy["repository"]
        and type(operations.get("repository_id")) is int
        and operations["repository_id"] == policy["repository_id"]
        and policy["environment"] == "pulumi-backend-qualification"
        and type(operations.get("enabled")) is bool
        and type(operations.get("environments")) is dict
        and all(operations["environments"].get(key) == value for key, value in OPERATIONS.items())
    )
    trust = "pending"
    if operations["enabled"]:
        _, reviewers = operation_admission._policy(operation_raw)
        require(
            any(
                "operator" in a.roles and "approver" in b.roles and a.principal != b.principal
                for a in reviewers
                for b in reviewers
            )
        )
        trust = "configuration-consistent"
    index: dict[str, Any] = {"schema_version": 1, "administration": None, "environments": {}}
    if evidence is not None:
        index = parsed(capture(private(root, str(evidence))))
    require(
        set(index) == {"schema_version", "administration", "environments"}
        and type(index["schema_version"]) is int
        and index["schema_version"] == 1
        and type(index["environments"]) is dict
        and set(index["environments"]) <= ENVIRONMENTS
    )
    administration_status = "pending"
    paths = list(index["environments"].values())
    if index["administration"] is not None:
        paths.append(index["administration"])
    require(all(type(path) is str for path in paths) and len(set(paths)) == len(paths))
    if index["administration"] is not None:
        administration.validate_snapshot(
            capture(private(root, index["administration"])),
            policy=policy_raw,
            reviewer_policy=reviewer_raw,
            commit=commit,
            now=now,
        )
        administration_status = "observed-controls-consistent"
    environments = dict.fromkeys(sorted(ENVIRONMENTS), "pending")
    for name, path in index["environments"].items():
        administration.validate_operation_environment(
            capture(private(root, path)),
            repository=policy["repository"],
            repository_id=policy["repository_id"],
            environment=name,
            commit=commit,
            now=now,
        )
        environments[name] = "observed-controls-consistent"
    require(repository_state(root) == (commit, True))
    require(all(read(path) == raw for path, raw in captured.items()))
    return {
        "schema_version": 1,
        "status": "pending",
        "commit": commit,
        "repository": policy["repository"],
        "repository_id": policy["repository_id"],
        "policy_sha256": digest(policy_raw),
        "operations_policy_sha256": digest(operation_raw),
        "administration": administration_status,
        "operation_trust": trust,
        "environments": environments,
        "runner_custody": {
            group: {"status": "pending", "required_review": gates}
            for group, gates in RUNNER_GATES.items()
        },
        "independent_review": [
            "public-key identities, role separation and private-key custody",
            "effective reviewer permissions, team membership and last-push independence",
            "runner isolation, repository/workflow restrictions and durable storage custody",
            "environment administrator bypass and secret visibility",
        ],
        "enrollment_complete": False,
        "execution_authorized": False,
        "activation_authorized": False,
        "live_controls_verified": False,
    }
