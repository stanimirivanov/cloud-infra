"""Exact-byte binding, closed-schema and clock failures for unsigned evidence sidecars."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from infra_core import evidence

NOW = datetime(2026, 10, 25, 12, tzinfo=UTC)
SCOPE = {
    "account_id": "synthetic-account",
    "region": "eu-test-1",
    "unit": "oci-network",
    "commit": "a" * 40,
    "configuration_sha256": "b" * 64,
}
ARTIFACTS = {"inventory": b'{"count":1}\n', "usage": b'{"hours":2}\n'}


def options(**changes):
    result = dict(
        kind="oci-inventory",
        artifacts=ARTIFACTS,
        scope=SCOPE,
        now=NOW,
        max_age=timedelta(minutes=15),
    )
    return result | changes


def create(**changes):
    return evidence.create_envelope(
        **(
            options()
            | dict(
                producer={"name": "infra-core", "version": "0.1.0"},
                collection_started_at=(NOW - timedelta(minutes=5)).isoformat(),
                collection_completed_at=(NOW - timedelta(minutes=1)).isoformat(),
            )
            | changes
        )
    )


@pytest.mark.parametrize("kind", list(evidence.PREDICATES))
def test_round_trip_all_reviewed_kinds_and_deterministic_serialization(kind):
    encoded = create(kind=kind)
    assert evidence.validate_envelope(encoded, **options(kind=kind)) is None
    assert create(kind=kind, artifacts=dict(reversed(list(ARTIFACTS.items())))) == encoded
    data = json.loads(encoded)
    assert data["_type"] == "https://in-toto.io/Statement/v1"
    assert set(data) == {"_type", "subject", "predicateType", "predicate"}
    assert "authorized" not in encoded.decode()


def test_exact_cutover_subject_capacity_stays_bounded_on_both_apis():
    assert evidence.MAX_SUBJECTS == 17
    artifacts = {f"item_{index}": b"x" for index in range(17)}
    envelope = create(artifacts=artifacts)
    assert evidence.validate_envelope(envelope, **options(artifacts=artifacts)) is None
    artifacts["item_17"] = b"x"
    with pytest.raises(evidence.EvidenceError, match="EVID002"):
        create(artifacts=artifacts)
    with pytest.raises(evidence.EvidenceError, match="EVID002"):
        evidence.validate_envelope(envelope, **options(artifacts=artifacts))


@pytest.mark.parametrize(
    "change",
    [
        "field",
        "missing",
        "type",
        "kind",
        "subject-extra",
        "subject-duplicate",
        "subject-missing",
        "subject-name",
        "digest",
        "algorithm",
        "subject-field",
        "scope",
        "scope-field",
        "producer",
        "producer-field",
        "predicate-field",
    ],
)
def test_document_substitution_and_schema_drift_fail_without_echoing_input(change):
    data = json.loads(create())
    if change == "field":
        data["private-diagnostic"] = "private-value"
    elif change == "missing":
        del data["predicate"]
    elif change == "type":
        data["_type"] = "private-value"
    elif change == "kind":
        data["predicateType"] = evidence.PREDICATES["backend-posture"]
    elif change == "subject-extra":
        data["subject"].append(data["subject"][0])
    elif change == "subject-duplicate":
        data["subject"][1] = data["subject"][0]
    elif change == "subject-missing":
        data["subject"].pop()
    elif change == "subject-name":
        data["subject"][0]["name"] = "private-value"
    elif change == "digest":
        data["subject"][0]["digest"]["sha256"] = "0" * 64
    elif change == "algorithm":
        data["subject"][0]["digest"] = {"sha512": "private-value"}
    elif change == "subject-field":
        data["subject"][0]["uri"] = "private-value"
    elif change == "scope":
        data["predicate"]["scope"]["account_id"] = "private-value"
    elif change == "scope-field":
        data["predicate"]["scope"]["provider"] = "private-value"
    elif change == "producer":
        data["predicate"]["producer"]["version"] = None
    elif change == "producer-field":
        data["predicate"]["producer"]["trusted"] = True
    else:
        data["predicate"]["max_age"] = 999999
    with pytest.raises(evidence.EvidenceError, match="EVID00") as error:
        evidence.validate_envelope(json.dumps(data).encode(), **options())
    assert "private-value" not in str(error.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("account_id", "other-account"),
        ("region", "eu-other-1"),
        ("unit", "oci-oke"),
        ("commit", "c" * 40),
        ("configuration_sha256", "d" * 64),
    ],
)
def test_consumer_scope_substitution_is_rejected(field, value):
    with pytest.raises(evidence.EvidenceError, match="EVID003"):
        evidence.validate_envelope(create(), **options(scope=SCOPE | {field: value}))


def test_equal_json_values_with_different_bytes_do_not_match():
    changed = ARTIFACTS | {"inventory": b'{ "count": 1 }\n'}
    assert json.loads(changed["inventory"]) == json.loads(ARTIFACTS["inventory"])
    with pytest.raises(evidence.EvidenceError, match="EVID002"):
        evidence.validate_envelope(create(), **options(artifacts=changed))


@pytest.mark.parametrize(
    "start,end",
    [
        (NOW - timedelta(minutes=15, microseconds=1), NOW),
        (NOW + timedelta(microseconds=1), NOW + timedelta(seconds=1)),
        (NOW, NOW + timedelta(microseconds=1)),
        (NOW, NOW - timedelta(seconds=1)),
        (NOW.replace(tzinfo=None), NOW),
        ("invalid-private-clock", NOW),
    ],
)
def test_collection_clocks_cannot_be_restamped_or_reordered(start, end):
    data = json.loads(create())
    for field, value in [("collection_started_at", start), ("collection_completed_at", end)]:
        data["predicate"][field] = value.isoformat() if isinstance(value, datetime) else value
    with pytest.raises(evidence.EvidenceError, match="EVID004") as error:
        evidence.validate_envelope(json.dumps(data).encode(), **options())
    assert "invalid-private-clock" not in str(error.value)


def test_exact_freshness_boundary_and_offset_equivalence():
    encoded = create(
        collection_started_at=(NOW - timedelta(minutes=15)).isoformat(),
        collection_completed_at="2026-10-25T13:00:00+01:00",
    )
    evidence.validate_envelope(encoded, **options())
    with pytest.raises(evidence.EvidenceError, match="EVID004"):
        evidence.validate_envelope(encoded, **options(max_age=timedelta(minutes=14)))


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"[]",
        b"null",
        b"\xff",
        b'{"private":"unterminated',
        b'{"predicate":{},"predicate":{}}',
        b'{"nested":{"x":1,"x":2}}',
        b'{"n":NaN}',
        b'{"n":Infinity}',
        b"[" * 2000 + b"]" * 2000,
    ],
)
def test_malformed_duplicate_nonfinite_or_deep_json_is_sanitized(raw):
    with pytest.raises(evidence.EvidenceError, match="EVID001") as error:
        evidence.validate_envelope(raw, **options())
    assert "private" not in str(error.value)


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": "unreviewed-kind"},
        {"artifacts": {}},
        {"artifacts": {"../escape": b""}},
        {"artifacts": {"inventory": bytearray(b"mutable")}},
        {"scope": SCOPE | {"commit": "bad"}},
        {"scope": SCOPE | {"account_id": "*"}},
        {"scope": SCOPE | {"region": True}},
        {"now": NOW.replace(tzinfo=None)},
        {"max_age": timedelta(0)},
        {"max_age": timedelta(seconds=-1)},
        {"producer": {"name": "private value", "version": "1"}},
    ],
)
def test_creation_uses_the_same_closed_contract(changes):
    with pytest.raises(evidence.EvidenceError, match="EVID00"):
        create(**changes)


def test_byte_and_subject_limits_are_enforced_on_both_apis(monkeypatch):
    encoded = create()
    monkeypatch.setattr(evidence, "MAX_ENVELOPE_BYTES", len(encoded) - 1)
    with pytest.raises(evidence.EvidenceError):
        evidence.validate_envelope(encoded, **options())
    with pytest.raises(evidence.EvidenceError):
        create()
    monkeypatch.setattr(evidence, "MAX_ENVELOPE_BYTES", len(encoded))
    evidence.validate_envelope(encoded, **options())
    for constant, limit in [("MAX_ARTIFACT_BYTES", 1), ("MAX_TOTAL_BYTES", 1), ("MAX_SUBJECTS", 1)]:
        with monkeypatch.context() as patch:
            patch.setattr(evidence, constant, limit)
            with pytest.raises(evidence.EvidenceError):
                create()
            with pytest.raises(evidence.EvidenceError):
                evidence.validate_envelope(encoded, **options())


def test_unverified_producer_claim_is_accepted_only_as_a_label():
    encoded = create(producer={"name": "claimed-producer", "version": "999"})
    assert evidence.validate_envelope(encoded, **options()) is None
