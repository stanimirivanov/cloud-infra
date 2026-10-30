"""Read-only authenticated acceptance assertions; never operational authority."""

import hashlib
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infra_core import operation_admission, operations
from infra_core.cutover import repository_state
from infra_core.review_signatures import verify_payload

MESSAGE = "READY001: invalid readiness input; private diagnostics withheld"
PAYLOAD_TYPE = "application/vnd.cloud-infra.readiness.v1+json"
UNITS = {"oci-network", "oci-oke", "cloudflare-edge", "supabase-database"}
GATES = {
    "protected-execution": "readiness",
    "backend-readiness": "readiness",
    "account-readiness": "readiness",
    "writer-exclusion": "readiness",
    "controlled-apply": "activation",
    "owner-handoff": "activation",
    "drift-health": "acceptance",
    "monitoring-delivery": "acceptance",
    "backup-recovery": "readiness",
    "state-recovery": "acceptance",
}


def require(value: bool) -> None:
    if not value:
        raise ValueError(MESSAGE)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parsed(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw, object_pairs_hook=operations._pairs)
    require(type(value) is dict)
    json.dumps(value, allow_nan=False)
    assert isinstance(value, dict)
    return value


def private(root: Path, value: str) -> Path:
    require(type(value) is str and len(value) <= 512)
    path = Path(value)
    require(
        not path.is_absolute()
        and path.parts[:1] == (".infra",)
        and ".." not in path.parts
        and path.suffix == ".json"
        and str(path) == value
    )
    path = root / path
    require(not any(p.is_symlink() for p in (path, *path.parents)))
    return path


def read(path: Path) -> bytes:
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode))
        raw = stream.read(operations.MAX_BYTES + 1)
    require(0 < len(raw) <= operations.MAX_BYTES)
    return raw


def record(raw: bytes, root: Path, unit: str) -> dict[str, Any]:
    value = parsed(raw)
    require(
        set(value)
        == {
            "schema_version",
            "unit",
            "commit",
            "configuration_sha256",
            "policy_sha256",
            "actor",
            "gates",
        }
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["unit"] == unit
        and type(value["commit"]) is str
        and re.fullmatch("[a-f0-9]{40}", value["commit"]) is not None
        and operations._hash(value["configuration_sha256"])
        and operations._hash(value["policy_sha256"])
        and type(value["actor"]) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}", value["actor"]) is not None
        and type(value["gates"]) is list
        and len(value["gates"]) <= len(GATES)
    )
    seen = set()
    for row in value["gates"]:
        require(
            type(row) is dict
            and set(row)
            == {
                "gate",
                "stage",
                "observed_at",
                "reviewed_at",
                "expires_at",
                "reviewer",
                "outcome",
                "evidence",
            }
        )
        require(type(row["gate"]) is str and row["gate"] in GATES and row["gate"] not in seen)
        seen.add(row["gate"])
        require(row["stage"] == GATES[row["gate"]] and row["outcome"] in ("accepted", "failed"))
        require(type(row["reviewer"]) is str and 0 < len(row["reviewer"]) <= 128)
        observed, reviewed, expiry = (
            operations._time(row[k]) for k in ("observed_at", "reviewed_at", "expires_at")
        )
        require(observed <= reviewed < expiry)
        require(type(row["evidence"]) is list and 1 <= len(row["evidence"]) <= 8)
        paths = set()
        for item in row["evidence"]:
            require(type(item) is dict and set(item) == {"path", "sha256"})
            path = private(root, item["path"])
            require(path not in paths and operations._hash(item["sha256"]))
            paths.add(path)
    return value


def check(root: Path, evidence: Path, *, unit: str, now: datetime | None = None) -> dict[str, Any]:
    """Report signed reviewer assertions against current local inputs, without writes."""
    try:
        return _check(root.resolve(), evidence, unit, now or datetime.now(UTC))
    except (ValueError, TypeError, KeyError, OSError, RecursionError, OverflowError):
        raise ValueError(MESSAGE) from None


def _check(root: Path, evidence: Path, unit: str, now: datetime) -> dict[str, Any]:
    require(unit in UNITS and now.tzinfo is not None)
    now = now.astimezone(UTC)
    index_path = private(root, str(evidence))
    index_raw = read(index_path)
    index = parsed(index_raw)
    require(
        set(index) == {"schema_version", "record", "operator", "approver", "configuration"}
        and type(index["schema_version"]) is int
        and index["schema_version"] == 1
    )
    paths = {
        k: private(root, index[k]) for k in ("record", "operator", "approver", "configuration")
    }
    require(len(set(paths.values()) | {index_path}) == 5)
    fixed = {index_path: index_raw}
    for path in paths.values():
        fixed[path] = read(path)
    policy_path = root / "config/operations-policy.json"
    require(not policy_path.is_symlink())
    fixed[policy_path] = read(policy_path)
    raw = fixed[paths["record"]]
    value = record(raw, root, unit)
    head, clean = repository_state(root)
    context_matches = (
        clean
        and head == value["commit"]
        and digest(fixed[paths["configuration"]]) == value["configuration_sha256"]
        and digest(fixed[policy_path]) == value["policy_sha256"]
    )
    authenticated = False
    approver = ""
    try:
        _, reviewers = operation_admission._policy(fixed[policy_path])
        principals = [
            verify_payload(role, raw, fixed[paths[role]], reviewers, payload_type=PAYLOAD_TYPE)
            for role in ("operator", "approver")
        ]
        authenticated = len({p.casefold() for p in principals} | {value["actor"].casefold()}) == 3
        approver = principals[1]
    except (ValueError, TypeError, KeyError):
        pass
    rows = {r["gate"]: r for r in value["gates"]}
    results = []
    observed_files: dict[Path, bytes | None] = {}
    total = sum(map(len, fixed.values()))
    for gate, stage in GATES.items():
        row = rows.get(gate)
        status, reason = "missing", "no_record"
        if row is not None:
            missing, changed, foreign = False, False, False
            for item in row["evidence"]:
                path = private(root, item["path"])
                require(path not in fixed)
                if path not in observed_files:
                    try:
                        observed_files[path] = read(path)
                        total += len(observed_files[path] or b"")
                        require(total <= 12 * operations.MAX_BYTES)
                    except FileNotFoundError:
                        observed_files[path] = None
                payload = observed_files[path]
                missing |= payload is None
                changed |= payload is not None and digest(payload) != item["sha256"]
                if payload is not None and digest(payload) == item["sha256"]:
                    document = json.loads(payload, object_pairs_hook=operations._pairs)
                    json.dumps(document, allow_nan=False)
                    foreign |= (
                        type(document) is dict and "unit" in document and document["unit"] != unit
                    )
            if not authenticated or row["reviewer"].casefold() != approver.casefold():
                status, reason = "failed", "review_unverified"
            elif foreign:
                status, reason = "failed", "evidence_scope_mismatch"
            elif not context_matches:
                status, reason = "stale", "context_changed"
            elif operations._time(row["reviewed_at"]) > now or now >= operations._time(
                row["expires_at"]
            ):
                status, reason = "stale", "outside_acceptance_window"
            elif changed:
                status, reason = "stale", "evidence_changed"
            elif row["outcome"] == "failed":
                status, reason = "failed", "review_failed"
            elif missing:
                status, reason = "missing", "evidence_unavailable"
            else:
                status, reason = "accepted", "authenticated_assertion"
        results.append(dict(gate=gate, stage=stage, status=status, reason=reason))
    # Fail the complete report if files or checkout changed during evaluation.
    require(repository_state(root) == (head, clean))
    require(all(read(p) == raw for p, raw in fixed.items()))
    for path, payload in observed_files.items():
        require(not path.exists() if payload is None else read(path) == payload)
    return dict(
        schema_version=1,
        kind="operational-readiness",
        unit=unit,
        evaluated_at=now.isoformat(),
        record_sha256=digest(raw),
        status="accepted" if all(r["status"] == "accepted" for r in results) else "incomplete",
        gates=results,
        execution_authorized=False,
        activation_authorized=False,
        live_controls_verified=False,
    )
