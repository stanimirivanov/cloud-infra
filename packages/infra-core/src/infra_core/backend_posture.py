"""Read-only backend metadata assessment; never changes bucket/IAM settings."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from infra_core.evidence import (
    MAX_ARTIFACT_BYTES,
    MAX_ENVELOPE_BYTES,
    EvidenceError,
    create_envelope,
    validate_envelope,
)
from infra_core.foundation import FoundationConfig
from infra_core.governance.contracts import fields, require, text, timestamp


def validate_posture(
    config: FoundationConfig, evidence: dict[str, Any], *, now: datetime | None = None
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    fields(
        evidence,
        {
            "schema_version",
            "configuration_sha256",
            "account_id",
            "namespace",
            "bucket",
            "region",
            "collection_started_at",
            "collection_completed_at",
            "public_access_type",
            "versioning",
            "storage_tier",
            "is_read_only",
            "lifecycle_policy_etag",
            "retention_rule_count",
            "preauthenticated_request_count",
        },
        "backend posture",
    )
    namespace = str(urlsplit(config.backend.endpoint).hostname).split(".")[0]
    require(
        type(evidence["schema_version"]) is int
        and evidence["schema_version"] == 1
        and evidence["configuration_sha256"] == config.digest
        and evidence["namespace"] == namespace
        and evidence["bucket"] == config.backend.bucket
        and evidence["region"] == config.backend.region,
        "BACKEND001",
        "posture does not bind to the configured backend",
    )
    text(evidence["account_id"], "posture tenancy")
    start = timestamp(evidence["collection_started_at"], "posture start")
    end = timestamp(evidence["collection_completed_at"], "posture completion")
    require(
        now - timedelta(hours=1) <= start <= end <= now,
        "BACKEND002",
        "posture must be fresh and ordered",
    )
    require(
        evidence["public_access_type"] == "NoPublicAccess"
        and evidence["versioning"] == "Enabled"
        and evidence["storage_tier"] == "Standard"
        and evidence["is_read_only"] is False,
        "BACKEND003",
        "backend must be private, versioned, Standard and writable",
    )
    require(
        evidence["lifecycle_policy_etag"] is None
        and all(
            type(evidence[key]) is int and evidence[key] == 0
            for key in ("retention_rule_count", "preauthenticated_request_count")
        ),
        "BACKEND004",
        "retention, public access grants or lifecycle policies require separate review",
    )
    return {"status": "within-reviewed-backend-posture", "deployment_authorized": False}


def envelope_path(path: Path) -> Path:
    """Append a stable suffix; never infer a sidecar from artifact-controlled paths."""
    return path.with_name(path.name + ".envelope.json")


def read_posture_pair(path: Path) -> tuple[bytes, bytes]:
    captured = []
    for source, limit in ((path, MAX_ARTIFACT_BYTES), (envelope_path(path), MAX_ENVELOPE_BYTES)):
        try:
            with source.open("rb") as stream:
                content = stream.read(limit + 1)
        except OSError:
            raise EvidenceError("BACKEND006: posture payload and sidecar are required") from None
        if len(content) > limit:
            raise EvidenceError("BACKEND006: posture evidence exceeds capture limit")
        captured.append(content)
    return captured[0], captured[1]


def _scope(config: FoundationConfig, account_id: str, commit: str) -> dict[str, str]:
    return dict(
        account_id=account_id,
        region=config.backend.region,
        unit="backend",
        commit=commit,
        configuration_sha256=config.digest,
    )


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("BACKEND006: duplicate posture JSON field")
        result[key] = value
    return result


def validate_posture_evidence(
    config: FoundationConfig,
    payload: bytes,
    envelope: bytes,
    *,
    account_id: str,
    commit: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Bind immutable captures to independent expectations, then check bucket semantics."""
    now = now or datetime.now(UTC)
    validate_envelope(
        envelope,
        kind="backend-posture",
        artifacts={"posture": payload},
        scope=_scope(config, account_id, commit),
        now=now,
        max_age=timedelta(hours=1),
    )
    try:
        posture = json.loads(payload.decode("utf-8"), object_pairs_hook=_object)
    except (ValueError, RecursionError):
        raise EvidenceError("BACKEND006: invalid posture JSON") from None
    result = validate_posture(config, posture, now=now)
    predicate = json.loads(envelope)["predicate"]
    require(
        posture["account_id"] == account_id
        and all(
            posture[key] == predicate[key]
            for key in ("collection_started_at", "collection_completed_at")
        ),
        "BACKEND006",
        "posture tenancy or observation clocks do not match the envelope",
    )
    return result


def capture_posture(
    config: FoundationConfig,
    posture: dict[str, Any],
    *,
    account_id: str,
    commit: str,
) -> tuple[bytes, bytes]:
    """Preserve collector clocks, without upgrading legacy or unsafe observations."""
    now = datetime.now(UTC)
    validate_posture(config, posture, now=now)
    payload = (json.dumps(posture, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    envelope = create_envelope(
        kind="backend-posture",
        artifacts={"posture": payload},
        scope=_scope(config, account_id, commit),
        producer={"name": "infra-core", "version": "1"},
        collection_started_at=posture["collection_started_at"],
        collection_completed_at=posture["collection_completed_at"],
        now=now,
        max_age=timedelta(hours=1),
    )
    validate_posture_evidence(
        config, payload, envelope, account_id=account_id, commit=commit, now=now
    )
    return payload, envelope
