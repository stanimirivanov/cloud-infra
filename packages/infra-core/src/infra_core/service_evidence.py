"""Service audit transport adapter; unsigned consistency is never authority."""

import hashlib
import json
import subprocess
from copy import deepcopy
from dataclasses import asdict
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
from infra_core.governance.contracts import fields, require, text, timestamp
from infra_core.inventory.cloudflare import CloudflareCollection
from infra_core.inventory.supabase import SupabaseCollection
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
    """Create a sidecar for original schema-4 bytes; never rewrite or restamp readings."""
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


def capture_cloudflare_evidence(
    config: dict[str, Any],
    profile: dict[str, Any],
    collection: CloudflareCollection,
    review: dict[str, Any],
    *,
    commit: str,
    now: datetime | None = None,
) -> tuple[bytes, bytes]:
    """Join API observations to independent review; never synthesize entitlement."""
    config, profile, review = deepcopy((config, profile, review))
    review = fields(
        review,
        {
            "schema_version",
            "account_id",
            "scope_id",
            "scope_name",
            "profile_revision",
            "verified",
            "verified_at",
            "plan",
            "other_services_reviewed",
            "source",
        },
        "Cloudflare review",
    )
    require(
        type(review["schema_version"]) is int
        and review["schema_version"] == 1
        and config.get("provider") == "cloudflare"
        and collection.account_id == config.get("account_id") == review["account_id"]
        and collection.zone_id == config.get("scope_id") == review["scope_id"]
        and collection.zone_name == review["scope_name"]
        and review["profile_revision"] == profile.get("revision")
        and collection.reported_plan in (None, "free")
        and bool(collection.observations),
        "CF001",
        "collection, independent review and proposal scope must agree",
    )
    provenance = hashlib.sha256(
        json.dumps(
            [
                {
                    "request": o.request_sha256,
                    "response": o.response_sha256,
                    "start": o.collection_started_at.isoformat(),
                    "end": o.collection_finished_at.isoformat(),
                }
                for o in collection.observations
            ],
            sort_keys=True,
        ).encode()
    ).hexdigest()
    payload = json.dumps(
        {
            **{key: value for key, value in review.items() if key != "schema_version"},
            "schema_version": 4,
            "provider": "cloudflare",
            "complete": True,
            "coverage": "all-zone-dns-records",
            "usage": {},
            "billing_period": None,
            "observed_at": collection.observations[0].collection_started_at.isoformat(),
            "collection_started_at": collection.observations[0].collection_started_at.isoformat(),
            "collection_completed_at": collection.observations[
                -1
            ].collection_finished_at.isoformat(),
            "resources": [asdict(record) for record in collection.records],
            "source": text(review["source"], "independent review source")
            + "; api-observations-sha256="
            + provenance,
        },
        sort_keys=True,
        allow_nan=False,
    ).encode()
    return payload, capture_service_evidence(config, profile, payload, commit=commit, now=now)


def capture_supabase_evidence(
    config: dict[str, Any],
    profile: dict[str, Any],
    collection: SupabaseCollection,
    supplement: bytes,
    *,
    commit: str,
    now: datetime | None = None,
) -> tuple[bytes, bytes]:
    """Reconcile explicit operator readings with management identities, never fill gaps."""
    config, profile = deepcopy((config, profile))
    now = now or datetime.now(UTC)
    wrapper = fields(
        _payload(supplement),
        {"schema_version", "classification", "evidence", "database_observations"},
        "Supabase supplement",
    )
    require(
        type(wrapper["schema_version"]) is int
        and wrapper["schema_version"] == 1
        and wrapper["classification"] == "supplemental-operator-observations",
        "SB004",
        "explicit supplemental observation classification required",
    )
    data = wrapper["evidence"]
    # Validate original clocks, all five metrics, billing cycle, DB sizes and review flags.
    audit(config, data, profile, now=now)
    require(
        config.get("provider") == "supabase"
        and collection.account_id == config["account_id"]
        and config["scope_id"] in collection.free_organizations
        and bool(collection.observations),
        "SB001",
        "management observations differ from reviewed Free target",
    )
    expected = {(project.id, project.scope_id) for project in collection.projects}
    require(
        {(item["id"], item["scope_id"]) for item in data["resources"]} == expected,
        "SB004",
        "supplement must cover every observed Free project exactly",
    )
    samples = wrapper["database_observations"]
    require(isinstance(samples, list), "SB004", "database source clocks are required")
    seen: set[tuple[str, str]] = set()
    start = timestamp(data["collection_started_at"], "supplement start")
    end = timestamp(data["collection_completed_at"], "supplement end")
    for sample in samples:
        sample = fields(sample, {"id", "scope_id", "as_of", "source"}, "database observation")
        key = (text(sample["id"], "database project"), text(sample["scope_id"], "database scope"))
        require(
            key not in seen
            and key in expected
            and start <= timestamp(sample["as_of"], "database observation") <= end,
            "SB004",
            "database source scope or original clock is invalid",
        )
        text(sample["source"], "database source")
        seen.add(key)
    require(seen == expected, "SB004", "missing database size source observation")
    api_start = collection.observations[0].collection_started_at
    api_end = collection.observations[-1].collection_finished_at
    data["observed_at"] = data["collection_started_at"] = min(start, api_start).isoformat()
    data["collection_completed_at"] = max(end, api_end).isoformat()
    provenance = hashlib.sha256(
        json.dumps(
            [
                (
                    o.request_sha256,
                    o.response_sha256,
                    o.collection_started_at.isoformat(),
                    o.collection_finished_at.isoformat(),
                )
                for o in collection.observations
            ]
        ).encode()
    ).hexdigest()
    data["source"] += (
        "; supplemental-operator-observations sha256=" + hashlib.sha256(supplement).hexdigest()
    )
    data["source"] += "; management-observations-sha256=" + provenance
    payload = json.dumps(data, sort_keys=True, allow_nan=False).encode()
    return payload, capture_service_evidence(config, profile, payload, commit=commit, now=now)
