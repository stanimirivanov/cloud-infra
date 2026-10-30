"""Read-only writer-freeze assertions and journal consistency; never a writer fence."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from infra_core import operations
from infra_core.cutover import repository_state
from infra_core.foundation import load_foundation
from infra_core.readiness import digest, parsed, private, read

MESSAGE = "WREADY001: writer readiness input rejected; private diagnostics withheld"


def require(condition: bool) -> None:
    if not condition:
        raise ValueError(MESSAGE)


def idle(raw: bytes, unit: str, frozen: datetime) -> str | None:
    """A terminal failure after running is uncertain, even if later work succeeded."""
    entries = operations._validate(json.loads(raw, object_pairs_hook=operations._pairs))
    launched = False
    for entry in entries:
        require(entry["request"]["unit"] == unit and operations._time(entry["at"]) <= frozen)
        if entry["state"] == "prepared":
            launched = False
        if entry["state"] == "running":
            launched = True
        require(entry["state"] != "indeterminate")
        require(not (launched and entry["state"] == "failed"))
    require(not entries or entries[-1]["state"] in {"succeeded", "failed"})
    return operations.digest(entries[-1]) if entries else None


def check(
    root: Path,
    writers: Path,
    evidence: Path | None = None,
    *,
    unit: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    try:
        return _check(root, writers, evidence, unit, now or datetime.now(UTC))
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
    root: Path, writers: Path, evidence: Path | None, unit: str, now: datetime
) -> dict[str, Any]:
    commit, clean = repository_state(root)
    require(clean)
    captured: dict[Path, bytes] = {}

    def capture(path: Path) -> bytes:
        raw = read(path)
        if path in captured:
            require(captured[path] == raw)
        captured[path] = raw
        return raw

    config_raw = capture(root / "config/pulumi.toml")
    config = load_foundation(root)
    require(read(root / "config/pulumi.toml") == config_raw)
    require(unit in {u.name for u in config.units})
    units = {"oci-network", "oci-oke"} if unit.startswith("oci-") else {unit}
    writer_path = private(root, str(writers))
    writer_raw = capture(writer_path)
    registry = parsed(writer_raw)
    require(
        set(registry) == {"schema_version", "units"}
        and type(registry["schema_version"]) is int
        and registry["schema_version"] == 1
        and type(registry["units"]) is dict
        and set(registry["units"]) == units
    )
    for identities in registry["units"].values():
        require(
            type(identities) is list
            and 1 <= len(identities) <= 32
            and all(operations._hash(value) for value in identities)
            and len(set(identities)) == len(identities)
        )
    status = "pending"
    if evidence is not None:
        evidence_path = private(root, str(evidence))
        journals = {name: private(root, f".infra/operations/{name}.json") for name in units}
        require(len({writer_path, evidence_path, *journals.values()}) == len(units) + 2)
        observation = parsed(capture(evidence_path))
        require(
            set(observation)
            == {
                "schema_version",
                "commit",
                "foundation_sha256",
                "writers_sha256",
                "frozen_at",
                "observed_at",
                "expires_at",
                "complete",
                "other_writers_reviewed",
                "units",
            }
        )
        require(
            type(observation["schema_version"]) is int
            and observation["schema_version"] == 1
            and observation["commit"] == commit
            and observation["foundation_sha256"] == config.digest
            and observation["writers_sha256"] == digest(writer_raw)
            and observation["complete"] is True
            and observation["other_writers_reviewed"] is True
            and type(observation["units"]) is dict
            and set(observation["units"]) == units
        )
        frozen, observed, expires = (
            operations._time(observation[k]) for k in ("frozen_at", "observed_at", "expires_at")
        )
        require(frozen <= observed <= now < expires <= frozen + timedelta(minutes=15))
        for name, path in journals.items():
            raw = capture(path)
            head = idle(raw, name, frozen)
            row = observation["units"][name]
            require(
                type(row) is dict
                and set(row) == {"journal_sha256", "journal_head", "writers"}
                and row["journal_sha256"] == digest(raw)
                and row["journal_head"] == head
                and type(row["writers"]) is list
            )
            identities = []
            for writer in row["writers"]:
                require(
                    type(writer) is dict
                    and set(writer) == {"identity_sha256", "frozen", "active_operations"}
                    and operations._hash(writer["identity_sha256"])
                    and writer["frozen"] is True
                    and type(writer["active_operations"]) is int
                    and writer["active_operations"] == 0
                )
                identities.append(writer["identity_sha256"])
            require(
                len(identities) == len(set(identities))
                and set(identities) == set(registry["units"][name])
            )
        status = "freeze-assertions-consistent"
    require(repository_state(root) == (commit, True))
    require(all(read(path) == raw for path, raw in captured.items()))
    return {
        "schema_version": 1,
        "status": "pending",
        "unit": unit,
        "scope": sorted(units),
        "commit": commit,
        "foundation_sha256": config.digest,
        "writers_sha256": digest(writer_raw),
        "writer_evidence": status,
        "remaining_reviews": [
            "effective external freeze and exhaustive administrator/non-cooperating writer review",
            "shared authoritative durable journals and lock namespace across cooperating runners",
            "independent freeze provenance, clock trust and continuous exclusion after observation",
            "empty journal enrollment, history retention and uncertain-outcome reconciliation",
        ],
        "writers_excluded": False,
        "locks_verified": False,
        "writer_release_authorized": False,
        "execution_authorized": False,
        "activation_authorized": False,
        "live_controls_verified": False,
    }
