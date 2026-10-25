"""Unsigned, bounded evidence sidecars; consistency is never operational authority."""

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn

STATEMENT = "https://in-toto.io/Statement/v1"
PREDICATES = {
    kind: f"https://github.com/stanimirivanov/oci-oke-terraform/evidence/{kind}/v1"
    for kind in (
        "backend-posture",
        "backend-recovery",
        "oci-inventory",
        "service-usage",
        "cutover-review",
    )
}
MAX_ENVELOPE_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_SUBJECTS = 16
SCOPE = {"account_id", "region", "unit", "commit", "configuration_sha256"}


class EvidenceError(ValueError):
    """Stable diagnostics without private source values or parser messages."""


def _check(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise EvidenceError(f"{code}: {message}")


def _fields(value: object, keys: set[str]) -> dict[str, Any]:
    _check(isinstance(value, dict) and set(value) == keys, "EVID001", "invalid object fields")
    assert isinstance(value, dict)
    return value


def _identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}", value) is not None
    )


def _scope(value: object) -> dict[str, Any]:
    data = _fields(value, SCOPE)
    _check(all(_identifier(item) for item in data.values()), "EVID003", "invalid scope")
    _check(
        re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", data["commit"]) is not None
        and re.fullmatch(r"[a-f0-9]{64}", data["configuration_sha256"]) is not None,
        "EVID003",
        "invalid commit/configuration digest",
    )
    return data


def _time(value: object) -> datetime:
    _check(isinstance(value, str) and len(value) <= 64, "EVID004", "invalid evidence clock")
    assert isinstance(value, str)
    try:
        parsed = datetime.fromisoformat(value)
        _check(parsed.utcoffset() is not None, "EVID004", "clock requires explicit timezone")
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        raise EvidenceError("EVID004: invalid evidence clock") from None


def _subjects(artifacts: Mapping[str, bytes]) -> dict[str, str]:
    _check(
        isinstance(artifacts, Mapping) and 1 <= len(artifacts) <= MAX_SUBJECTS,
        "EVID002",
        "invalid subject count",
    )
    total = 0
    result = {}
    for name, content in artifacts.items():
        _check(
            isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name) is not None,
            "EVID002",
            "invalid subject role",
        )
        _check(
            type(content) is bytes and len(content) <= MAX_ARTIFACT_BYTES,
            "EVID002",
            "subject must be bounded immutable bytes",
        )
        total += len(content)
        _check(total <= MAX_TOTAL_BYTES, "EVID002", "aggregate subject size exceeded")
        result[name] = hashlib.sha256(content).hexdigest()
    return result


def _validate(
    statement: object,
    *,
    kind: str,
    artifacts: Mapping[str, bytes],
    scope: dict[str, str],
    now: datetime,
    max_age: timedelta,
) -> None:
    _check(isinstance(kind, str) and kind in PREDICATES, "EVID001", "unknown evidence kind")
    expected = _subjects(artifacts)
    expected_scope = _scope(scope)
    data = _fields(statement, {"_type", "subject", "predicateType", "predicate"})
    _check(
        data["_type"] == STATEMENT and data["predicateType"] == PREDICATES[kind],
        "EVID001",
        "unsupported statement or predicate type",
    )
    subjects = data["subject"]
    _check(
        isinstance(subjects, list) and len(subjects) == len(expected),
        "EVID002",
        "subject set does not match",
    )
    actual: dict[str, str] = {}
    for item in subjects:
        item = _fields(item, {"name", "digest"})
        name = item["name"]
        _check(
            isinstance(name, str) and name in expected and name not in actual,
            "EVID002",
            "unknown or duplicate subject role",
        )
        digest = _fields(item["digest"], {"sha256"})["sha256"]
        _check(
            isinstance(digest, str) and digest == expected[name],
            "EVID002",
            "subject digest mismatch",
        )
        actual[name] = digest
    predicate = _fields(
        data["predicate"], {"scope", "producer", "collection_started_at", "collection_completed_at"}
    )
    _check(_scope(predicate["scope"]) == expected_scope, "EVID003", "scope mismatch")
    producer = _fields(predicate["producer"], {"name", "version"})
    _check(
        all(_identifier(item) for item in producer.values()), "EVID001", "invalid producer label"
    )
    _check(
        isinstance(now, datetime)
        and now.utcoffset() is not None
        and isinstance(max_age, timedelta)
        and max_age > timedelta(0),
        "EVID004",
        "consumer must supply an aware clock and positive freshness policy",
    )
    start = _time(predicate["collection_started_at"])
    end = _time(predicate["collection_completed_at"])
    try:
        age = now.astimezone(UTC) - start
    except (ValueError, OverflowError):
        raise EvidenceError("EVID004: invalid consumer clock") from None
    _check(
        timedelta(0) <= age <= max_age and start <= end <= now.astimezone(UTC),
        "EVID004",
        "collection is stale, future or unordered",
    )


def _duplicate_guard(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _check(key not in result, "EVID001", "duplicate JSON field")
        result[key] = value
    return result


def _invalid_constant(value: str) -> NoReturn:
    raise EvidenceError("EVID001: nonfinite JSON constant")


def validate_envelope(
    encoded: bytes,
    *,
    kind: str,
    artifacts: Mapping[str, bytes],
    scope: dict[str, str],
    now: datetime,
    max_age: timedelta,
) -> None:
    """Check a private sidecar against independently supplied expectations; no I/O."""
    _check(
        type(encoded) is bytes and len(encoded) <= MAX_ENVELOPE_BYTES,
        "EVID001",
        "envelope must be bounded immutable UTF-8 bytes",
    )
    try:
        data = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_duplicate_guard,
            parse_constant=_invalid_constant,
        )
    except (ValueError, RecursionError):
        raise EvidenceError("EVID001: invalid envelope JSON") from None
    _validate(data, kind=kind, artifacts=artifacts, scope=scope, now=now, max_age=max_age)


def create_envelope(
    *,
    kind: str,
    artifacts: Mapping[str, bytes],
    scope: dict[str, str],
    producer: dict[str, str],
    collection_started_at: str,
    collection_completed_at: str,
    now: datetime,
    max_age: timedelta,
) -> bytes:
    """Serialize explicit observations; never infer scope, timestamps or payload semantics."""
    _check(isinstance(kind, str) and kind in PREDICATES, "EVID001", "unknown evidence kind")
    statement = {
        "_type": STATEMENT,
        "subject": [
            {"name": name, "digest": {"sha256": digest}}
            for name, digest in sorted(_subjects(artifacts).items())
        ],
        "predicateType": PREDICATES[kind],
        "predicate": {
            "scope": scope,
            "producer": producer,
            "collection_started_at": collection_started_at,
            "collection_completed_at": collection_completed_at,
        },
    }
    _validate(statement, kind=kind, artifacts=artifacts, scope=scope, now=now, max_age=max_age)
    encoded = (json.dumps(statement, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    _check(len(encoded) <= MAX_ENVELOPE_BYTES, "EVID001", "envelope size exceeded")
    return encoded
