"""Service evidence v3 distinguishes collection, cumulative windows and capacity samples."""

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
    if evidence["billing_period"] is not None:
        evidence["billing_period"]["starts_at"] = now.replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        ).isoformat()
        evidence["billing_period"]["ends_at"] = (
            (now.replace(day=1) + timedelta(days=32))
            .replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            .isoformat()
        )
    for metric, reading in evidence["usage"].items():
        if metric == "storage_mb":
            reading["as_of"] = now.isoformat()
        else:
            reading["covered_from"] = now.replace(
                day=1, hour=0, minute=0, second=0, microsecond=0
            ).isoformat()
            reading["covered_through"] = now.isoformat()
    return config, evidence, profile


@pytest.mark.parametrize("version", [1, 2, True, 4])
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
    assert result["schema_version"] == 3 and result["deployment_authorized"] is False
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


@pytest.mark.parametrize("service", ["supabase"], indirect=True)
@pytest.mark.parametrize(
    "anchor,clock,beginning,ending",
    [
        (
            "2020-01-06T13:45:00+00:00",
            "2026-10-26T12:00:00+00:00",
            "2026-10-06T13:45:00+00:00",
            "2026-11-06T13:45:00+00:00",
        ),
        (
            "2020-01-31T08:00:00+00:00",
            "2028-02-29T08:00:00+00:00",
            "2028-02-29T08:00:00+00:00",
            "2028-03-31T08:00:00+00:00",
        ),
        (
            "2020-01-31T08:00:00+00:00",
            "2027-02-28T07:59:59+00:00",
            "2027-01-31T08:00:00+00:00",
            "2027-02-28T08:00:00+00:00",
        ),
        (
            "2020-01-31T08:00:00+00:00",
            "2027-03-30T12:00:00+00:00",
            "2027-02-28T08:00:00+00:00",
            "2027-03-31T08:00:00+00:00",
        ),
        (
            "2020-01-31T08:00:00+00:00",
            "2027-04-30T08:00:00+00:00",
            "2027-04-30T08:00:00+00:00",
            "2027-05-31T08:00:00+00:00",
        ),
        (
            "2020-01-31T08:00:00+00:00",
            "2026-12-31T08:00:00+00:00",
            "2026-12-31T08:00:00+00:00",
            "2027-01-31T08:00:00+00:00",
        ),
        (
            "2020-01-01T01:00:00+02:00",
            "2027-01-01T00:00:00+00:00",
            "2026-12-31T23:00:00+00:00",
            "2027-01-31T23:00:00+00:00",
        ),
    ],
)
def test_actual_anniversary_cycles_clamp_without_losing_original_day(
    service, anchor, clock, beginning, ending
):
    now = datetime.fromisoformat(clock)
    config, evidence, profile = clocks(service, now)
    evidence["billing_period"] = {"anchor_at": anchor, "starts_at": beginning, "ends_at": ending}
    for metric, reading in evidence["usage"].items():
        if metric != "storage_mb":
            reading["covered_from"] = beginning
    original = deepcopy(evidence)
    report = audit(config, evidence, profile, now=now)
    assert report["billing_period"] == {
        "anchor_at": datetime.fromisoformat(anchor).astimezone(UTC).isoformat(),
        "starts_at": beginning,
        "ends_at": ending,
    }
    assert all(v == "200" for v in report["forecast"].values())
    report["billing_period"]["starts_at"] = "changed"
    assert evidence == original


@pytest.mark.parametrize("service", ["supabase"], indirect=True)
@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "null",
        "extra",
        "missing-anchor",
        "naive",
        "future-anchor",
        "prior-cycle",
        "future-cycle",
        "wrong-end",
        "calendar-substitution",
        "clamped-anchor",
    ],
)
def test_period_metadata_is_closed_current_and_anchored(service, change):
    now = datetime(2027, 3, 30, 12, tzinfo=UTC)
    config, evidence, profile = clocks(service, now)
    period = {
        "anchor_at": "2020-01-31T08:00:00+00:00",
        "starts_at": "2027-02-28T08:00:00+00:00",
        "ends_at": "2027-03-31T08:00:00+00:00",
    }
    evidence["billing_period"] = period
    for metric, reading in evidence["usage"].items():
        if metric != "storage_mb":
            reading["covered_from"] = period["starts_at"]
    code = "EXT024"
    if change == "missing":
        evidence.pop("billing_period")
        code = "GOV003"
    elif change == "null":
        evidence["billing_period"] = None
        code = "GOV003"
    elif change == "extra":
        period["usage_month"] = "2027-03"
        code = "GOV003"
    elif change == "missing-anchor":
        period.pop("anchor_at")
        code = "GOV003"
    elif change == "naive":
        period["anchor_at"] = "2020-01-31T08:00:00"
        code = "GOV002"
    elif change == "future-anchor":
        period["anchor_at"] = "2028-01-31T08:00:00+00:00"
    elif change == "prior-cycle":
        period.update(starts_at="2027-01-31T08:00:00+00:00", ends_at="2027-02-28T08:00:00+00:00")
    elif change == "future-cycle":
        period.update(starts_at="2027-03-31T08:00:00+00:00", ends_at="2027-04-30T08:00:00+00:00")
    elif change == "wrong-end":
        period["ends_at"] = "2027-04-01T08:00:00+00:00"
    elif change == "calendar-substitution":
        period.update(starts_at="2027-03-01T00:00:00+00:00", ends_at="2027-04-01T00:00:00+00:00")
    else:
        period["ends_at"] = "2027-03-28T08:00:00+00:00"
    with pytest.raises(GovernanceError, match=code):
        audit(config, evidence, profile, now=now)


@pytest.mark.parametrize("service", ["supabase"], indirect=True)
@pytest.mark.parametrize("metric", ["egress_mb", "cached_egress_mb", "mau"])
def test_cycle_reset_rejects_fresh_totals_from_previous_or_partial_window(service, metric):
    now = datetime(2026, 10, 6, 12, 5, tzinfo=UTC)
    config, evidence, profile = clocks(service, now)
    evidence["billing_period"] = {
        "anchor_at": "2020-01-06T12:00:00+00:00",
        "starts_at": "2026-10-06T12:00:00+00:00",
        "ends_at": "2026-11-06T12:00:00+00:00",
    }
    for name, reading in evidence["usage"].items():
        if name != "storage_mb":
            reading["covered_from"] = evidence["billing_period"]["starts_at"]
    for beginning, cutoff in [
        ("2026-09-06T12:00:00+00:00", now.isoformat()),
        ("2026-10-06T12:00:00+00:00", "2026-10-06T11:59:59+00:00"),
        ("2026-10-06T12:01:00+00:00", now.isoformat()),
    ]:
        evidence["usage"][metric].update(covered_from=beginning, covered_through=cutoff)
        with pytest.raises(GovernanceError, match="EXT022"):
            audit(config, evidence, profile, now=now)


@pytest.mark.parametrize("service", ["cloudflare"], indirect=True)
def test_dns_requires_explicit_absence_of_a_billing_period(service):
    config, evidence, profile = clocks(service)
    assert audit(config, evidence, profile, now=NOW)["billing_period"] is None
    evidence["billing_period"] = {}
    with pytest.raises(GovernanceError, match="EXT024"):
        audit(config, evidence, profile, now=NOW)


@pytest.mark.parametrize("service", ["supabase"], indirect=True)
def test_period_offsets_normalize_and_old_profile_evidence_does_not_inherit_revision(service):
    config, evidence, profile = clocks(service)
    evidence["billing_period"] = {
        "anchor_at": "2020-01-01T02:00:00+02:00",
        "starts_at": "2026-10-01T02:00:00+02:00",
        "ends_at": "2026-11-01T02:00:00+02:00",
    }
    result = audit(config, evidence, profile, now=NOW)
    assert result["billing_period"]["starts_at"] == "2026-10-01T00:00:00+00:00"
    assert result["billing_period"]["ends_at"] == "2026-11-01T00:00:00+00:00"
    assert profile["revision"] == 2
    evidence["profile_revision"] = 1
    with pytest.raises(GovernanceError, match="EXT001"):
        audit(config, evidence, profile, now=NOW)


def test_original_legacy_month_payload_has_no_silent_conversion(service):
    config, evidence, profile = clocks(service)
    evidence["schema_version"] = 2
    evidence["usage_month"] = "2026-10"
    evidence.pop("billing_period")
    with pytest.raises(GovernanceError, match="GOV003"):
        audit(config, evidence, profile, now=NOW)
