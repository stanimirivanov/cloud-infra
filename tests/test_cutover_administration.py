"""Administrative observations must be valid and part of the signed review snapshot."""

import hashlib
import json
from datetime import datetime, timedelta

import pytest
import test_cutover as fixtures
from infra_core import administration, cutover
from infra_core.cutover_evidence import REPORTS, SUBJECTS, TRUSTED_INPUTS

review = fixtures.review


def test_every_review_signs_both_administrative_inputs(review):
    root, document, artifacts, _ = review
    snapshot = (root / document["artifacts"]["administration"]["path"]).read_bytes()
    policy = (root / "config/administration.json").read_bytes()
    assert len(SUBJECTS) == 17 and len(cutover.ARTIFACTS) == 22
    for role in REPORTS:
        subjects = {
            item["name"]: item["digest"]["sha256"]
            for item in json.loads(artifacts[role + "_envelope"])["subject"]
        }
        assert subjects["administration"] == hashlib.sha256(snapshot).hexdigest()
        assert subjects["administrative_policy"] == hashlib.sha256(policy).hexdigest()
    result = cutover.check(root, document)
    assert result["cutover_authorized"] is result["deployment_authorized"] is False
    assert "environment administrator bypass independently verified" in result["remaining_gates"]


@pytest.mark.parametrize(
    "fault", ["missing", "alias", "oversize", "missing-policy", "oversize-policy"]
)
def test_administrative_inputs_are_mandatory_distinct_and_bounded(review, fault):
    root, document, _, write = review
    code = "CUT002"
    if fault == "missing":
        document["artifacts"].pop("administration")
        code = "GOV003"
    elif fault == "alias":
        document["artifacts"]["administration"] = document["artifacts"]["health"]
    elif fault == "oversize":
        write("administration", b" " * (administration.MAX_BYTES + 1), rebind=False)
    else:
        path = root / "config/administration.json"
        if fault == "missing-policy":
            path.unlink()
            code = "CUT011"
        else:
            path.write_bytes(b" " * (administration.MAX_BYTES + 1))
    with pytest.raises(ValueError, match=code):
        cutover.check(root, document)


@pytest.mark.parametrize("role", ["administration", "administrative_policy"])
def test_rehashing_changed_administrative_bytes_cannot_reuse_old_reviews(review, role):
    root, document, _, write = review
    if role == "administrative_policy":
        path = root / "config/administration.json"
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        path = root / document["artifacts"][role]["path"]
        write(role, path.read_bytes() + b"\n", rebind=False)
    with pytest.raises(ValueError, match="EVID002"):
        cutover.check(root, document)


@pytest.mark.parametrize(
    "fault", ["commit", "stale", "policy", "unsafe-main", "unsafe-environment", "duplicate"]
)
def test_fresh_signatures_cannot_upgrade_invalid_administrative_observations(review, fault):
    root, document, artifacts, write = review
    value = artifacts["administration"]
    code = "ADMIN002"
    if fault == "commit":
        value["commit"] = "b" * 40
    elif fault == "stale":
        old = (datetime.fromisoformat(document["captured_at"]) - timedelta(minutes=16)).isoformat()
        value["started_at"] = value["completed_at"] = old
    elif fault == "policy":
        path = root / "config/administration.json"
        path.write_bytes(path.read_bytes() + b"\n")
    elif fault == "unsafe-main":
        value["responses"]["protection"]["enforce_admins"]["enabled"] = False
        code = "ADMIN003"
    elif fault == "unsafe-environment":
        value["responses"]["environment"]["protection_rules"][0]["prevent_self_review"] = False
        code = "ADMIN003"
    else:
        value = b'{"commit":"PRIVATE",' + json.dumps(value).encode()[1:]
        code = "ADMIN001"
    write("administration", value)  # Rebuild all envelopes and real ephemeral signatures.
    with pytest.raises(ValueError, match=code) as error:
        cutover.check(root, document)
    assert "PRIVATE" not in str(error.value)


def test_administrative_policy_bytes_share_the_aggregate_review_budget(review, monkeypatch):
    root, document, _, _ = review
    total = sum(
        len((root / document["artifacts"][role]["path"]).read_bytes())
        for role in SUBJECTS - TRUSTED_INPUTS
    )
    total += sum(
        len((root / path).read_bytes())
        for path in (
            "config/quotas/profiles.toml",
            "config/cutover-reviewers.toml",
            "config/administration.json",
        )
    )
    monkeypatch.setattr(cutover, "MAX_TOTAL_BYTES", total - 1)
    with pytest.raises(ValueError, match="CUT002"):
        cutover.check(root, document)
