"""Offline backend readiness observations; never bootstrap or activation authority."""

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from infra_core import backend, backend_posture
from infra_core.cutover import repository_state
from infra_core.foundation import FoundationConfig, load_foundation
from infra_core.governance.contracts import timestamp
from infra_core.readiness import digest, parsed, private, read

MESSAGE = "BREADY001: backend readiness input rejected; private diagnostics withheld"


def require(condition: bool) -> None:
    if not condition:
        raise ValueError(MESSAGE)


def validate_stacks(
    data: dict[str, Any], config: FoundationConfig, *, account_id: str, commit: str, now: datetime
) -> None:
    """Validate operator observations, not live discovery or actual key custody."""
    require(
        set(data)
        == {
            "schema_version",
            "account_id",
            "commit",
            "configuration_sha256",
            "backend",
            "collection_started_at",
            "collection_completed_at",
            "stacks",
        }
    )
    require(
        type(data["schema_version"]) is int
        and data["schema_version"] == 1
        and data["account_id"] == account_id
        and data["commit"] == commit
        and data["configuration_sha256"] == config.digest
        and data["backend"] == config.backend.url()
    )
    start = timestamp(data["collection_started_at"], "stack observation start")
    end = timestamp(data["collection_completed_at"], "stack observation completion")
    require(now - timedelta(hours=1) <= start <= end <= now)
    rows = data["stacks"]
    require(type(rows) is list and len(rows) == len(config.units))
    expected = {unit.name: unit.stack_identity for unit in config.units}
    seen = set()
    for row in rows:
        require(
            type(row) is dict
            and set(row)
            == {
                "unit",
                "stack_identity",
                "exists",
                "secrets_provider",
                "pending_operations",
            }
        )
        require(type(row["unit"]) is str and row["unit"] in expected and row["unit"] not in seen)
        require(
            row["stack_identity"] == expected[row["unit"]]
            and row["exists"] is True
            and row["secrets_provider"] == config.secrets_provider
            and type(row["pending_operations"]) is int
            and row["pending_operations"] == 0
        )
        seen.add(row["unit"])


def check(
    root: Path, evidence: Path | None = None, *, account_id: str, now: datetime | None = None
) -> dict[str, Any]:
    try:
        return _check(root, evidence, account_id=account_id, now=now or datetime.now(UTC))
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


def _check(root: Path, evidence: Path | None, *, account_id: str, now: datetime) -> dict[str, Any]:
    require(
        type(account_id) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}", account_id) is not None
    )
    commit, clean = repository_state(root)
    require(clean)
    captured: dict[Path, bytes] = {}

    def capture(path: Path) -> bytes:
        raw = read(path)
        if path in captured:
            require(raw == captured[path])
        captured[path] = raw
        return raw

    config_raw = capture(root / "config/pulumi.toml")
    config = load_foundation(root)
    require(read(root / "config/pulumi.toml") == config_raw)
    index: dict[str, Any] = dict(schema_version=1, qualification=None, posture=None, stacks=None)
    if evidence is not None:
        index = parsed(capture(private(root, str(evidence))))
    require(
        set(index) == {"schema_version", "qualification", "posture", "stacks"}
        and type(index["schema_version"]) is int
        and index["schema_version"] == 1
    )
    paths = [index[key] for key in ("qualification", "posture", "stacks") if index[key] is not None]
    require(all(type(path) is str for path in paths))
    if index["posture"] is not None:
        paths.append(index["posture"] + ".envelope.json")
    require(len(paths) == len(set(paths)) and (evidence is None or str(evidence) not in paths))
    status = dict.fromkeys(("qualification", "posture", "stacks"), "pending")
    if index["qualification"] is not None:
        value = parsed(capture(private(root, index["qualification"])))
        backend.validate_receipt(config, value, now=now)
        status["qualification"] = "observed-controls-consistent"
    if index["posture"] is not None:
        payload = capture(private(root, index["posture"]))
        envelope = capture(private(root, index["posture"] + ".envelope.json"))
        backend_posture.validate_posture_evidence(
            config,
            payload,
            envelope,
            account_id=account_id,
            commit=commit,
            now=now,
        )
        status["posture"] = "observed-controls-consistent"
    if index["stacks"] is not None:
        validate_stacks(
            parsed(capture(private(root, index["stacks"]))),
            config,
            account_id=account_id,
            commit=commit,
            now=now,
        )
        status["stacks"] = "operator-observations-consistent"
    require(repository_state(root) == (commit, True))
    require(all(read(path) == raw for path, raw in captured.items()))
    return {
        "schema_version": 1,
        "status": "pending",
        "commit": commit,
        "configuration_sha256": config.digest,
        "configuration_file_sha256": digest(config_raw),
        "evidence": status,
        "remaining_reviews": [
            "independent provenance review of qualification, posture and stack observations",
            "effective least-privilege S3 identity and reviewed namespace exclusion",
            "passphrase custody and independent recovery access for all four existing stacks",
            "version-history retention, recovery access and storage budget",
        ],
        "backend_ready": False,
        "execution_authorized": False,
        "activation_authorized": False,
        "live_controls_verified": False,
    }
