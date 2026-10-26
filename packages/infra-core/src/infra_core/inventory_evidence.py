"""OCI inventory transport binding; observation consistency never grants authority."""

import hashlib
import json
import subprocess
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
from infra_core.governance.contracts import fields, records, require
from infra_core.governance.coverage import validate_coverage
from infra_core.governance.resources import INVENTORY_TYPES


def reviewed_commit(root: Path) -> str:
    try:
        commit, clean = repository_state(root)
    except (OSError, subprocess.SubprocessError):
        raise EvidenceError("GOV043: cannot establish checkout identity") from None
    require(clean, "GOV043", "inventory requires a clean reviewed checkout")
    return commit


def read_inventory_pair(path: Path) -> tuple[bytes, bytes]:
    captured = []
    for source, limit in (
        (path, MAX_ARTIFACT_BYTES),
        (path.with_name(path.name + ".envelope.json"), MAX_ENVELOPE_BYTES),
    ):
        try:
            with source.open("rb") as stream:
                content = stream.read(limit + 1)
        except OSError:
            raise EvidenceError("GOV043: inventory payload and sidecar are required") from None
        require(len(content) <= limit, "GOV043", "inventory exceeds capture limit")
        captured.append(content)
    return captured[0], captured[1]


def _scope(account: dict[str, Any], profile: dict[str, Any], commit: str) -> dict[str, str]:
    try:
        encoded = json.dumps(
            {"account": account, "profile": profile},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise EvidenceError("GOV043: invalid reviewed inventory configuration") from None
    return dict(
        account_id=account.get("account_id", ""),
        region=account.get("home_region", ""),
        unit="oci-account",
        commit=commit,
        configuration_sha256=hashlib.sha256(encoded).hexdigest(),
    )


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        require(key not in result, "GOV043", "duplicate inventory JSON field")
        result[key] = value
    return result


def _inventory(payload: bytes, account: dict[str, Any], now: datetime) -> dict[str, Any]:
    require(
        type(payload) is bytes and len(payload) <= MAX_ARTIFACT_BYTES,
        "GOV043",
        "inventory must be bounded immutable bytes",
    )
    try:
        data = json.loads(payload.decode("utf-8"), object_pairs_hook=_object)
        json.dumps(data, allow_nan=False)
    except (ValueError, RecursionError):
        raise EvidenceError("GOV043: invalid inventory JSON") from None
    data = fields(
        data,
        set(
            "schema_version account_id provider observed_at collection_started_at "
            "collection_completed_at coverage complete covered_types all_regions "
            "all_compartments resources usage".split()
        ),
        "inventory",
    )
    require(
        type(data["schema_version"]) is int
        and data["schema_version"] == 2
        and data["provider"] == account.get("provider") == "oci"
        and isinstance(data["account_id"], str)
        and bool(data["account_id"])
        and data["account_id"] == account.get("account_id")
        and all(data[key] is True for key in ("complete", "all_regions", "all_compartments"))
        and isinstance(data["covered_types"], list)
        and all(isinstance(kind, str) for kind in data["covered_types"])
        and len(data["covered_types"]) == len(INVENTORY_TYPES)
        and set(data["covered_types"]) == INVENTORY_TYPES,
        "GOV043",
        "inventory scope/schema/family coverage is incomplete or mismatched",
    )
    for item in records(data["resources"], "inventory resources"):
        fields(item, {"id", "type", "region", "owner", "retained", "props"}, "inventory resource")
    validate_coverage(data, account["home_region"], now)
    return data


def validate_inventory_evidence(
    account: dict[str, Any],
    profile: dict[str, Any],
    payload: bytes,
    envelope: bytes,
    *,
    commit: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return captured inventory after binding and coverage checks; billing audit is separate."""
    now = now or datetime.now(UTC)
    validate_envelope(
        envelope,
        kind="oci-inventory",
        artifacts={"inventory": payload},
        scope=_scope(account, profile, commit),
        now=now,
        max_age=timedelta(minutes=15),
    )
    data = _inventory(payload, account, now)
    predicate = json.loads(envelope)["predicate"]
    require(
        all(
            data[key] == predicate[key]
            for key in ("collection_started_at", "collection_completed_at")
        ),
        "GOV043",
        "inventory clocks do not match the envelope",
    )
    return data


def capture_inventory(
    account: dict[str, Any],
    profile: dict[str, Any],
    inventory: dict[str, Any],
    *,
    commit: str,
    now: datetime | None = None,
) -> tuple[bytes, bytes]:
    """Preserve original collector clocks; missing usage remains missing, never zero."""
    now = now or datetime.now(UTC)
    try:
        payload = (json.dumps(inventory, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    except (ValueError, TypeError, RecursionError):
        raise EvidenceError("GOV043: invalid inventory observation") from None
    data = _inventory(payload, account, now)
    envelope = create_envelope(
        kind="oci-inventory",
        artifacts={"inventory": payload},
        scope=_scope(account, profile, commit),
        producer={"name": "infra-core", "version": "1"},
        collection_started_at=data["collection_started_at"],
        collection_completed_at=data["collection_completed_at"],
        now=now,
        max_age=timedelta(minutes=15),
    )
    return payload, envelope
