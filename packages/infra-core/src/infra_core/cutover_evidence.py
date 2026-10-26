"""Unsigned cutover review-set binding; no I/O, authentication or authorization."""

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

from infra_core.evidence import MAX_ARTIFACT_BYTES, create_envelope, validate_envelope
from infra_core.governance.contracts import require

REPORTS = frozenset({"ownership", "preview", "health", "rollback"})
SIDECARS = frozenset(role + "_envelope" for role in REPORTS)
SIGNATURES = frozenset(role + "_signature" for role in REPORTS)
TRUSTED_INPUTS = frozenset({"quota_profiles", "reviewer_policy"})
SUBJECTS = frozenset(
    {
        "backend_receipt",
        "account",
        "inventory",
        "inventory_envelope",
        "oci_proposal",
        "oci_config",
        "kubernetes_config",
        "kubernetes_inventory",
        "kubernetes_resources",
        "ownership",
        "preview",
        "health",
        "rollback",
        "quota_profiles",
        "reviewer_policy",
    }
)


def review_scope(
    role: str,
    *,
    account_id: str,
    region: str,
    cluster_id: str,
    commit: str,
    configuration_sha256: str,
) -> dict[str, str]:
    """Use independently reviewed expectations, never scope read from a sidecar."""
    require(role in REPORTS, "CUT008", "unsupported cutover review role")
    binding = json.dumps(
        {"backend_sha256": configuration_sha256, "cluster_id": cluster_id},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return dict(
        account_id=account_id,
        region=region,
        unit="cutover-" + role,
        commit=commit,
        configuration_sha256=hashlib.sha256(binding).hexdigest(),
    )


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        require(key not in result, "CUT008", "duplicate review JSON field")
        result[key] = value
    return result


def _report(payload: bytes) -> dict[str, Any]:
    require(
        type(payload) is bytes and len(payload) <= MAX_ARTIFACT_BYTES,
        "CUT008",
        "review must be bounded immutable bytes",
    )
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_object)
        json.dumps(value, allow_nan=False)
    except (ValueError, RecursionError):
        raise ValueError("CUT008: invalid cutover review JSON") from None
    require(isinstance(value, dict), "CUT008", "review must be an object")
    assert isinstance(value, dict)
    return value


def _inputs(artifacts: Mapping[str, bytes]) -> dict[str, bytes]:
    require(set(artifacts) == SUBJECTS, "CUT008", "complete exact review subject set required")
    return dict(artifacts)


def _ttl(role: str) -> timedelta:
    require(role in REPORTS, "CUT008", "unsupported cutover review role")
    return timedelta(hours=24) if role == "rollback" else timedelta(minutes=15)


def capture_review(
    role: str,
    artifacts: Mapping[str, bytes],
    *,
    scope: dict[str, str],
    now: datetime,
) -> bytes:
    """Return a sidecar over actual reviewed bytes; domain validity is checked at consumption."""
    ttl = _ttl(role)
    subjects = _inputs(artifacts)
    require(scope.get("unit") == "cutover-" + role, "CUT008", "review scope role differs")
    observed = _report(subjects[role]).get("observed_at")
    require(isinstance(observed, str), "CUT008", "review observation clock is required")
    assert isinstance(observed, str)
    return create_envelope(
        kind="cutover-review",
        artifacts=subjects,
        scope=scope,
        producer={"name": "infra-core", "version": "1"},
        collection_started_at=observed,
        collection_completed_at=observed,
        now=now,
        max_age=ttl,
    )


def validate_review(
    role: str,
    artifacts: Mapping[str, bytes],
    envelope: bytes,
    *,
    scope: dict[str, str],
    now: datetime,
) -> dict[str, Any]:
    """Verify the complete snapshot before parsing its role's normalized review."""
    ttl = _ttl(role)
    subjects = _inputs(artifacts)
    require(scope.get("unit") == "cutover-" + role, "CUT008", "review scope role differs")
    validate_envelope(
        envelope, kind="cutover-review", artifacts=subjects, scope=scope, now=now, max_age=ttl
    )
    value = _report(subjects[role])
    predicate = json.loads(envelope)["predicate"]
    require(
        predicate["collection_started_at"]
        == predicate["collection_completed_at"]
        == value.get("observed_at"),
        "CUT008",
        "review observation must match both original envelope clocks",
    )
    return value
