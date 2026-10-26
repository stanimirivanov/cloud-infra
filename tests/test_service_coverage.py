"""Service evidence v2 distinguishes collection, cumulative windows and capacity samples."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
import test_services as fixtures
from infra_core.governance.contracts import GovernanceError
from infra_core.services.governance import audit

service = fixtures.service
NOW = datetime(2026, 10, 26, 12, tzinfo=UTC)


def clocks(service, now=NOW):
    config, evidence, profile = deepcopy(service)
    for field in ("observed_at", "collection_started_at", "collection_completed_at", "verified_at"):
        evidence[field] = now.isoformat()
    profile["reviewed_at"] = now.isoformat()  # Synthetic fixture only, never repository terms.
    evidence["usage_month"] = now.strftime("%Y-%m")
    for metric, reading in evidence["usage"].items():
        if metric == "storage_mb":
            reading["as_of"] = now.isoformat()
        else:
            reading["covered_from"] = now.replace(
                day=1, hour=0, minute=0, second=0, microsecond=0
            ).isoformat()
            reading["covered_through"] = now.isoformat()
    return config, evidence, profile


@pytest.mark.parametrize("version", [1, True, 3])
def test_legacy_or_unknown_evidence_cannot_be_upgraded_by_fresh_clocks(service, version):
    config, evidence, profile = clocks(service)
    evidence["schema_version"] = version
    with pytest.raises(GovernanceError, match="EXT001"):
        audit(config, evidence, profile, now=NOW)


@pytest.mark.parametrize(
    "change", ["stale-start", "start-after-end", "future-end", "before-start", "missing", "naive"]
)
def test_collection_clocks_bind_original_observation_and_are_ordered(service, change):
    config, evidence, profile = clocks(service)
    code = "EXT022"
    if change == "stale-start":
        evidence["collection_started_at"] = (NOW - timedelta(hours=1)).isoformat()
    elif change == "start-after-end":
        evidence["collection_started_at"] = (NOW + timedelta(seconds=1)).isoformat()
    elif change == "future-end":
        evidence["collection_completed_at"] = (NOW + timedelta(seconds=1)).isoformat()
    elif change == "before-start":
        evidence["collection_completed_at"] = (NOW - timedelta(seconds=1)).isoformat()
    elif change == "missing":
        evidence.pop("collection_started_at")
        code = "GOV003"
    else:
        evidence["collection_completed_at"] = "2026-10-26T12:00:00"
        code = "GOV002"
    with pytest.raises(GovernanceError, match=code):
        audit(config, evidence, profile, now=NOW)


@pytest.mark.parametrize("service", ["supabase"], indirect=True)
@pytest.mark.parametrize("metric", ["egress_mb", "cached_egress_mb", "storage_mb", "mau"])
@pytest.mark.parametrize("seconds", [-901, 1])
def test_one_lagging_or_future_metric_fails_despite_a_fresh_document(service, metric, seconds):
    config, evidence, profile = clocks(service)
    clock = "as_of" if metric == "storage_mb" else "covered_through"
    evidence["usage"][metric][clock] = (NOW + timedelta(seconds=seconds)).isoformat()
    with pytest.raises(GovernanceError, match="EXT022"):
        audit(config, evidence, profile, now=NOW)


@pytest.mark.parametrize("service", ["supabase"], indirect=True)
@pytest.mark.parametrize(
    "beginning",
    ["2026-09-01T00:00:00+00:00", "2026-10-25T00:00:00+00:00", "2026-11-01T00:00:00+00:00"],
)
def test_partial_reset_or_wrong_month_totals_fail(service, beginning):
    config, evidence, profile = clocks(service)
    evidence["usage"]["mau"]["covered_from"] = beginning
    with pytest.raises(GovernanceError, match="EXT022"):
        audit(config, evidence, profile, now=NOW)


@pytest.mark.parametrize("service", ["supabase"], indirect=True)
@pytest.mark.parametrize(
    "reading",
    [
        100,
        {},
        {"value": 0, "as_of": NOW.isoformat()},
        {
            "value": 0,
            "covered_from": NOW.isoformat(),
            "covered_through": NOW.isoformat(),
            "extra": True,
        },
    ],
)
def test_usage_readings_have_closed_required_windows(service, reading):
    config, evidence, profile = clocks(service)
    evidence["usage"]["egress_mb"] = reading
    with pytest.raises(GovernanceError, match="GOV003"):
        audit(config, evidence, profile, now=NOW)


@pytest.mark.parametrize("service", ["supabase"], indirect=True)
@pytest.mark.parametrize("value", [None, False, -1, float("nan"), "unknown"])
def test_missing_or_invalid_measurements_never_become_zero(service, value):
    config, evidence, profile = clocks(service)
    evidence["usage"]["storage_mb"]["value"] = value
    with pytest.raises(GovernanceError, match="GOV001"):
        audit(config, evidence, profile, now=NOW)


@pytest.mark.parametrize("service", ["supabase"], indirect=True)
def test_boundaries_offsets_and_each_coverage_cutoff_remain_visible(service):
    config, evidence, profile = clocks(service)
    cutoff = NOW - timedelta(minutes=15)
    evidence["usage"]["egress_mb"].update(
        covered_through=cutoff.isoformat(), covered_from="2026-10-01T02:00:00+02:00"
    )
    original = deepcopy(evidence)
    result = audit(config, evidence, profile, now=NOW)
    assert result["schema_version"] == 2 and result["deployment_authorized"] is False
    assert result["forecast"]["egress_mb"] == "200"
    assert result["usage_coverage"]["egress_mb"] == {
        "covered_from": "2026-10-01T00:00:00+00:00",
        "covered_through": cutoff.isoformat(),
    }
    assert evidence == original
    result["usage_coverage"]["egress_mb"]["covered_through"] = "changed"
    assert evidence == original


@pytest.mark.parametrize("service", ["supabase"], indirect=True)
def test_month_rollover_does_not_reset_lagging_totals_or_capacity(service):
    now = datetime(2026, 11, 1, 0, 5, tzinfo=UTC)
    config, evidence, profile = clocks(service, now)
    previous = (now - timedelta(minutes=6)).isoformat()
    evidence["usage"]["storage_mb"]["as_of"] = previous
    evidence["usage"]["egress_mb"]["covered_through"] = previous
    with pytest.raises(GovernanceError, match="EXT022"):
        audit(config, evidence, profile, now=now)
    evidence["usage"]["egress_mb"]["covered_through"] = now.isoformat()
    report = audit(config, evidence, profile, now=now)
    assert report["forecast"]["storage_mb"] == "200"
    assert report["usage_coverage"]["storage_mb"] == {"as_of": previous}


def test_cloudflare_has_no_fabricated_usage_metrics(service):
    config, evidence, profile = clocks(service)
    if config["provider"] == "cloudflare":
        assert audit(config, evidence, profile, now=NOW)["usage_coverage"] == {}
        evidence["usage"] = {"egress_mb": {"value": 0}}
        with pytest.raises(GovernanceError, match="GOV003"):
            audit(config, evidence, profile, now=NOW)
    else:
        assert set(audit(config, evidence, profile, now=NOW)["usage_coverage"]) == {
            "egress_mb",
            "cached_egress_mb",
            "storage_mb",
            "mau",
        }


@pytest.mark.parametrize("service", ["supabase"], indirect=True)
def test_recent_readings_cannot_postdate_the_claimed_collection(service):
    config, evidence, profile = clocks(service)
    evidence["observed_at"] = evidence["collection_started_at"] = (
        NOW - timedelta(minutes=5)
    ).isoformat()
    evidence["collection_completed_at"] = (NOW - timedelta(minutes=4)).isoformat()
    for metric, reading in evidence["usage"].items():
        reading["as_of" if metric == "storage_mb" else "covered_through"] = evidence[
            "collection_completed_at"
        ]
    evidence["usage"]["mau"]["covered_through"] = (NOW - timedelta(minutes=1)).isoformat()
    with pytest.raises(GovernanceError, match="EXT022"):
        audit(config, evidence, profile, now=NOW)
