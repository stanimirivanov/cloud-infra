"""Offline independent-backup evidence checks; no repository access or restore."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infra_core import operations, recovery_contracts
from infra_core.cutover import repository_state
from infra_core.foundation import load_foundation
from infra_core.readiness import digest, parsed, private, read

ARTIFACTS = frozenset(
    {
        "restore_checkpoint",
        "restore_configuration",
        "restore_manifest",
        "restore_receipt",
        "restore_policy",
        "rehearsal",
    }
)
MESSAGE = "BSAFE001: backup readiness input rejected; private diagnostics withheld"


def require(condition: bool) -> None:
    if not condition:
        raise ValueError(MESSAGE)


def check(
    root: Path,
    evidence: Path | None = None,
    *,
    unit: str,
    repository_id: str,
    recovery_host_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    try:
        return _check(
            root, evidence, unit, repository_id, recovery_host_id, now or datetime.now(UTC)
        )
    except (
        ValueError,
        RuntimeError,
        OSError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        OverflowError,
    ) as error:
        raise ValueError(MESSAGE) from error


def _check(
    root: Path,
    evidence: Path | None,
    unit: str,
    repository_id: str,
    recovery_host_id: str,
    now: datetime,
) -> dict[str, Any]:
    require(operations._hash(repository_id) and operations._hash(recovery_host_id))
    commit, clean = repository_state(root)
    require(clean)
    captures: dict[Path, bytes] = {}

    def capture(path: Path) -> bytes:
        raw = read(path)
        if path in captures:
            require(captures[path] == raw)
        captures[path] = raw
        return raw

    config_raw = capture(root / "config/pulumi.toml")
    config = load_foundation(root)
    require(read(root / "config/pulumi.toml") == config_raw)
    require(unit in {entry.name for entry in config.units})
    status = "pending"
    if evidence is not None:
        index = parsed(capture(private(root, str(evidence))))
        require(
            set(index) == {"schema_version", "unit", "commit", "foundation_sha256", "artifacts"}
            and type(index["schema_version"]) is int
            and index["schema_version"] == 1
            and index["unit"] == unit
            and index["commit"] == commit
            and index["foundation_sha256"] == config.digest
            and type(index["artifacts"]) is dict
            and set(index["artifacts"]) == ARTIFACTS
        )
        paths = list(index["artifacts"].values())
        require(
            all(type(path) is str for path in paths)
            and len(paths) == len(set(paths))
            and str(evidence) not in paths
        )
        raw = {name: capture(private(root, path)) for name, path in index["artifacts"].items()}
        # Decode each input with duplicate-field/non-finite rejection before legacy consumers.
        documents = {name: parsed(value) for name, value in raw.items()}
        manifest = documents["restore_manifest"]
        require(manifest["repository_id"] == repository_id)
        require(operations._hash(manifest["request_sha256"]))
        # A historical backup commit is not relabeled as the current review commit.
        historical = manifest["commit"]
        require(
            type(historical) is str
            and len(historical) in (40, 64)
            and all(c in "0123456789abcdef" for c in historical)
        )
        recovery_contracts.pair(raw["restore_checkpoint"], raw["restore_configuration"], unit)
        recovery_contracts.restore_evidence(raw, unit, recovery_host_id, now=now)
        exported = operations._time(manifest["source_exported_at"])
        capture_start = operations._time(manifest["capture_started_at"])
        captured = operations._time(manifest["captured_at"])
        report = documents["rehearsal"]
        start, end = (operations._time(report[key]) for key in ("started_at", "completed_at"))
        require(exported <= capture_start <= captured)
        require(report["restore_seconds"] > 0)
        # The producer measures age during retrieval, between rehearsal start and completion.
        require(
            (start - exported).total_seconds() - 1
            <= report["backup_age_seconds"]
            <= (end - exported).total_seconds() + 1
        )
        status = "off-host-evidence-consistent"
    require(repository_state(root) == (commit, True))
    require(all(read(path) == raw for path, raw in captures.items()))
    return {
        "schema_version": 1,
        "status": "pending",
        "unit": unit,
        "commit": commit,
        "foundation_sha256": config.digest,
        "foundation_file_sha256": digest(config_raw),
        "backup_evidence": status,
        "remaining_reviews": [
            "physical storage independence and separately available repository access",
            "separate restic password and Pulumi passphrase custody and retrieval",
            "retention, storage budget and pruning exclusion during lock-free rehearsal",
            "independent provenance and per-unit backup-age/restore objective acceptance",
        ],
        "backup_ready": False,
        "execution_authorized": False,
        "activation_authorized": False,
        "live_controls_verified": False,
    }
