"""Service audit transport adapter; unsigned consistency is never authority."""

import hashlib
import json
import subprocess
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from infra_core.cutover import repository_state
from infra_core.evidence import (
    MAX_ARTIFACT_BYTES,
    MAX_ENVELOPE_BYTES,
    EvidenceError,
    create_envelope,
    validate_envelope,
)
from infra_core.governance.contracts import require
from infra_core.services.governance import audit


def reviewed_commit(root: Path) -> str:
    try:
        commit, clean = repository_state(root)
    except (OSError, subprocess.SubprocessError):
        raise EvidenceError("EXT023: cannot establish checkout identity") from None
    require(clean, "EXT023", "service evidence requires a clean reviewed checkout")
    return commit


def read_service_pair(path: Path) -> tuple[bytes, bytes]:
    captured = []
    sidecar = path.with_name(path.name + ".envelope.json")
    for source, limit in ((path, MAX_ARTIFACT_BYTES), (sidecar, MAX_ENVELOPE_BYTES)):
        try:
            with source.open("rb") as stream:
                content = stream.read(limit + 1)
        except OSError:
            raise EvidenceError("EXT023: service payload and sidecar are required") from None
        require(len(content) <= limit, "EXT023", "service evidence exceeds capture limit")
        captured.append(content)
    return captured[0], captured[1]


def _scope(config: dict[str, Any], profile: dict[str, Any], commit: str) -> dict[str, str]:
    try:
        encoded = json.dumps(
            {"proposal": config, "profile": profile},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise EvidenceError("EXT023: invalid reviewed service configuration") from None
    return {
        "account_id": config.get("account_id", ""),
        "unit": config.get("unit", ""),
        "region": "global",  # Account/organization-wide observation, not project placement.
        "commit": commit,
        "configuration_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("EXT023: duplicate service JSON field")
        result[key] = value
    return result


def _payload(payload: bytes) -> dict[str, Any]:
    require(
        type(payload) is bytes and len(payload) <= MAX_ARTIFACT_BYTES,
        "EXT023",
        "service payload must be bounded immutable bytes",
    )
    try:
        data = json.loads(payload.decode("utf-8"), object_pairs_hook=_object)
        # Reject nonfinite constants anywhere, including fields not used as numbers.
        json.dumps(data, allow_nan=False)
    except (ValueError, RecursionError):
        raise EvidenceError("EXT023: invalid service JSON") from None
    require(isinstance(data, dict), "EXT023", "service payload must be an object")
    assert isinstance(data, dict)
    return data


def validate_service_evidence(
    config: dict[str, Any],
    profile: dict[str, Any],
    payload: bytes,
    envelope: bytes,
    *,
    commit: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Bind captured bytes to independent reviewed inputs, then audit domain semantics."""
    config, profile = deepcopy((config, profile))
    now = now or datetime.now(UTC)
    validate_envelope(
        envelope,
        kind="service-usage",
        artifacts={"usage": payload},
        scope=_scope(config, profile, commit),
        now=now,
        max_age=timedelta(minutes=15),
    )
    data = _payload(payload)
    result = audit(config, data, profile, now=now)
    predicate = json.loads(envelope)["predicate"]
    require(
        all(
            data[key] == predicate[key]
            for key in ("collection_started_at", "collection_completed_at")
        ),
        "EXT023",
        "service observation clocks do not match the envelope",
    )
    return result


def capture_service_evidence(
    config: dict[str, Any],
    profile: dict[str, Any],
    payload: bytes,
    *,
    commit: str,
    now: datetime | None = None,
) -> bytes:
    """Create a sidecar for original schema-3 bytes; never rewrite or restamp readings."""
    config, profile = deepcopy((config, profile))
    now = now or datetime.now(UTC)
    data = _payload(payload)
    audit(config, data, profile, now=now)
    return create_envelope(
        kind="service-usage",
        artifacts={"usage": payload},
        scope=_scope(config, profile, commit),
        producer={"name": "infra-core", "version": "1"},
        collection_started_at=data["collection_started_at"],
        collection_completed_at=data["collection_completed_at"],
        now=now,
        max_age=timedelta(minutes=15),
    )
