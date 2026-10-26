"""Rehashing the bundle cannot silently rebind an original normalized review."""

import hashlib
import json
from datetime import datetime, timedelta

import pytest
import test_cutover as fixtures
from infra_core import cutover
from infra_core.cutover_evidence import REPORTS, SIDECARS, SUBJECTS, capture_review, review_scope

review = fixtures.review


def snapshot(root, document):
    subjects = {
        role: (root / document["artifacts"][role]["path"]).read_bytes()
        for role in SUBJECTS - {"quota_profiles"}
    }
    subjects["quota_profiles"] = (root / "config/quotas/profiles.toml").read_bytes()
    return subjects


@pytest.mark.parametrize("role", sorted(REPORTS))
@pytest.mark.parametrize("fault", ["missing", "file", "oversize", "alias"])
def test_review_sidecars_are_mandatory_distinct_and_bounded(review, role, fault):
    root, document, _, write = review
    name = role + "_envelope"
    if fault == "missing":
        document["artifacts"].pop(name)
    elif fault == "file":
        (root / document["artifacts"][name]["path"]).unlink()
    elif fault == "oversize":
        write(name, b" " * (cutover.MAX_ENVELOPE_BYTES + 1), rebind=False)
    else:
        document["artifacts"][name] = document["artifacts"][role]
    with pytest.raises(ValueError, match="GOV003|CUT002"):
        cutover.check(root, document)


@pytest.mark.parametrize("role", sorted(REPORTS))
def test_rehashed_report_bytes_do_not_inherit_the_previous_review(review, role):
    root, document, artifacts, write = review
    artifacts[role]["source"] += " changed"
    write(role, artifacts[role], rebind=False)
    with pytest.raises(ValueError, match="EVID002"):
        cutover.check(root, document)


@pytest.mark.parametrize(
    "role",
    [
        "account",
        "oci_config",
        "kubernetes_config",
        "oci_proposal",
        "kubernetes_resources",
        "quota_profiles",
    ],
)
def test_semantically_equivalent_input_changes_still_require_new_reviews(review, role):
    root, document, _, write = review
    if role == "quota_profiles":
        path = root / "config/quotas/profiles.toml"
        path.write_bytes(path.read_bytes() + b"\n# changed profile bytes\n")
    else:
        path = root / document["artifacts"][role]["path"]
        write(role, path.read_bytes() + b"\n", rebind=False)
    with pytest.raises(ValueError, match="EVID002"):
        cutover.check(root, document)


@pytest.mark.parametrize(
    "fault",
    [
        "role",
        "account",
        "region",
        "commit",
        "configuration",
        "cluster",
        "kind",
        "missing-subject",
        "extra-subject",
        "clock",
        "stale",
        "future",
    ],
)
def test_rehashed_review_envelopes_reject_scope_subject_and_clock_replay(review, fault):
    root, document, artifacts, write = review
    name = "health_envelope"
    value = json.loads(artifacts[name])
    predicate = value["predicate"]
    scope = predicate["scope"]
    code = "EVID003"
    if fault == "role":
        scope["unit"] = "cutover-preview"
    elif fault in ("account", "region", "commit", "configuration"):
        key = {"account": "account_id", "configuration": "configuration_sha256"}.get(fault, fault)
        scope[key] = (
            "b" * (40 if key == "commit" else 64)
            if fault in ("commit", "configuration")
            else "other"
        )
    elif fault == "cluster":
        scope["configuration_sha256"] = review_scope(
            "health",
            account_id=document["account_id"],
            region=document["region"],
            cluster_id="another-cluster",
            commit=document["commit"],
            configuration_sha256=document["configuration_sha256"],
        )["configuration_sha256"]
    elif fault == "kind":
        value["predicateType"], code = "other", "EVID001"
    elif fault in ("missing-subject", "extra-subject"):
        if fault == "missing-subject":
            value["subject"].pop()
        else:
            value["subject"].append({"name": "other", "digest": {"sha256": "a" * 64}})
        code = "EVID002"
    else:
        observed = datetime.fromisoformat(artifacts["health"]["observed_at"])
        delta = {
            "clock": -timedelta(seconds=1),
            "stale": -timedelta(minutes=16),
            "future": timedelta(days=1),
        }[fault]
        predicate["collection_started_at"] = (observed + delta).isoformat()
        if fault != "stale":
            predicate["collection_completed_at"] = (observed + delta).isoformat()
        code = "CUT008" if fault == "clock" else "EVID004"
    write(name, json.dumps(value).encode(), rebind=False)
    with pytest.raises(ValueError, match=code):
        cutover.check(root, document)


@pytest.mark.parametrize("payload", [b'{"PRIVATE":', b"[]", b'{"x":NaN}', b'{"x":1,"x":2}'])
def test_forged_subject_hashes_cannot_upgrade_malformed_report_json(review, payload, capsys):
    root, document, artifacts, write = review
    write("health", payload, rebind=False)
    for name in SIDECARS:
        value = json.loads(artifacts[name])
        next(item for item in value["subject"] if item["name"] == "health")["digest"]["sha256"] = (
            hashlib.sha256(payload).hexdigest()
        )
        write(name, json.dumps(value).encode(), rebind=False)
    with pytest.raises(ValueError, match="CUT008") as error:
        cutover.check(root, document)
    assert "PRIVATE" not in str(error.value)
    index = root / ".infra/review.json"
    index.write_text(json.dumps(document), encoding="utf-8")
    assert (
        fixtures.cli.main(
            [
                "--root",
                str(root),
                "cutover",
                "check",
                "--evidence",
                str(index),
            ]
        )
        == 1
    )
    output = capsys.readouterr()
    assert "CUT008" in output.err and "PRIVATE" not in output.err and not output.out


def test_rollback_original_clock_preserves_24_hour_limit_without_restamping(review):
    root, document, artifacts, write = review
    now = datetime.fromisoformat(document["captured_at"])
    artifacts["rollback"]["observed_at"] = (now - timedelta(hours=24)).isoformat()
    write("rollback", artifacts["rollback"])
    assert cutover.check(root, document, now=now)["cutover_authorized"] is False
    with pytest.raises(ValueError, match="EVID004"):
        cutover.check(root, document, now=now + timedelta(microseconds=1))


def test_review_set_and_profiles_use_the_hashed_capture_without_reopening(review, monkeypatch):
    root, document, _, _ = review
    original = cutover.validate_receipt

    def change_after_capture(*args):
        original(*args)
        for role in REPORTS | SIDECARS:
            (root / document["artifacts"][role]["path"]).write_bytes(b"changed after capture")
        (root / "config/quotas/profiles.toml").write_bytes(b"changed after capture")

    monkeypatch.setattr(cutover, "validate_receipt", change_after_capture)
    assert cutover.check(root, document)["status"] == "evidence-consistent"
    with pytest.raises(ValueError, match="CUT002"):
        cutover.check(root, document)


def test_review_subjects_and_profile_bytes_share_the_aggregate_capture_budget(review, monkeypatch):
    root, document, _, _ = review
    subjects = snapshot(root, document)
    limit = sum(len(value) for key, value in subjects.items() if key != "quota_profiles")
    monkeypatch.setattr(cutover, "MAX_TOTAL_BYTES", limit)
    with pytest.raises(ValueError, match="CUT002"):
        cutover.check(root, document)


@pytest.mark.parametrize("fault", ["role", "missing", "extra", "mutable"])
def test_producer_requires_a_closed_immutable_subject_set_and_known_role(review, fault):
    root, document, _, _ = review
    role = "health"
    subjects = snapshot(root, document)
    scope = review_scope(
        role,
        account_id=document["account_id"],
        region=document["region"],
        cluster_id=document["cluster_id"],
        commit=document["commit"],
        configuration_sha256=document["configuration_sha256"],
    )
    if fault == "role":
        role = "other"
    elif fault == "missing":
        subjects.pop("quota_profiles")
    elif fault == "extra":
        subjects["extra"] = b"other"
    else:
        subjects["health"] = bytearray(subjects["health"])
    with pytest.raises(ValueError, match="CUT008|EVID002"):
        capture_review(
            role, subjects, scope=scope, now=datetime.fromisoformat(document["captured_at"])
        )
