"""Offline recovery pair compatibility; no keys, runtime or recovery authority."""

from pathlib import Path
from typing import Any

from infra_core import recovery_contracts as contracts
from infra_core.cutover import repository_state
from infra_core.readiness import UNITS, digest, parsed, private, read

MESSAGE = "RESTAGE001: recovery staging input rejected; private diagnostics withheld"


def require(condition: bool) -> None:
    if not condition:
        raise ValueError(MESSAGE)


def check(
    root: Path,
    *,
    unit: str,
    current_checkpoint: Path,
    current_configuration: Path,
    restore_checkpoint: Path,
    restore_configuration: Path,
) -> dict[str, Any]:
    try:
        return _check(
            root,
            unit,
            [current_checkpoint, current_configuration, restore_checkpoint, restore_configuration],
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


def _check(root: Path, unit: str, inputs: list[Path]) -> dict[str, Any]:
    require(unit in UNITS)
    commit, clean = repository_state(root)
    require(clean)
    paths = [private(root, str(path)) for path in inputs]
    require(len(set(paths)) == 4)
    captured = {path: read(path) for path in paths}
    raw = [captured[path] for path in paths]
    for value in raw:
        parsed(value)  # reject duplicate fields/nonfinite values before legacy consumers
    current = contracts.pair(raw[0], raw[1], unit)
    restored = contracts.pair(raw[2], raw[3], unit)
    require(contracts.identities(current) == contracts.identities(restored))
    contracts.unchanged_resources(current, restored)
    if unit == "oci-network":
        roots = [
            next(r for r in state["deployment"]["resources"] if r["type"] == "pulumi:pulumi:Stack")
            for state in (current, restored)
        ]
        require(roots[0]["outputs"] == roots[1]["outputs"])
    require(repository_state(root) == (commit, True))
    require(
        all(
            private(root, str(original)) == path
            for original, path in zip(inputs, paths, strict=True)
        )
    )
    require(all(read(path) == value for path, value in captured.items()))
    return {
        "schema_version": 1,
        "status": "pending",
        "unit": unit,
        "commit": commit,
        "pair_evidence": "inputs-compatible",
        "input_sha256": dict(
            zip(
                (
                    "current_checkpoint",
                    "current_configuration",
                    "restore_checkpoint",
                    "restore_configuration",
                ),
                (digest(value) for value in raw),
                strict=True,
            )
        ),
        "remaining_reviews": [
            "current safety backup and exact selected snapshot with independent host/key rehearsal",
            "graph, dependency and credential review, owner provenance and external idle freeze",
            "fresh signed recovery admission and protected runtime/environment controls",
            "exact readback, immutable configuration publication and no-op reconciliation",
            "separate configuration activation and writer-release review",
        ],
        "activation_authorized": False,
        "execution_authorized": False,
        "writer_release_authorized": False,
        "live_controls_verified": False,
    }
