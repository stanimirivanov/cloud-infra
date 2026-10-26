"""Storage capacity and cumulative billing are independent, mandatory cost guards."""

import json
from datetime import datetime
from decimal import ROUND_FLOOR, Decimal, localcontext

import pytest
import test_services as fixtures
from infra_core.governance.contracts import GovernanceError
from infra_core.services.governance import audit
from test_service_coverage import NOW, clocks

service = fixtures.service
pytestmark = pytest.mark.parametrize("service", ["supabase"], indirect=True)


def storage(service):
    config, evidence, profile = clocks(service)
    evidence["usage"]["storage_mb"]["value"] = 1
    config["growth"]["storage_mb"] = 0
    evidence["usage"]["storage_gb_hours"]["value"] = "743.875"
    config["growth"]["storage_gb_hours"] = "0.125"
    return config, evidence, profile


def test_fractional_cycle_history_and_budget_use_published_allowance(service):
    config, evidence, profile = storage(service)
    report = audit(config, evidence, profile, now=NOW)
    assert Decimal(report["forecast"]["storage_gb_hours"]) == 744
    assert report["forecast"]["storage_mb"] == "1"
    assert report["usage_coverage"]["storage_gb_hours"] == {
        "covered_from": evidence["billing_period"]["starts_at"],
        "covered_through": NOW.isoformat(),
    }
    assert report["deployment_authorized"] is False


@pytest.mark.parametrize(
    "history,budget",
    [
        ("744.001", 0),
        ("743.875", "0.126"),
        (744, "0.0000000000000000000000000000000001"),
        ("743.8750000000000000000000000000001", "0.125"),
        ("1E1000000", 0),
        (0, "1E1000000"),
    ],
)
def test_history_or_forecast_overage_fails_even_after_deletion(service, history, budget):
    config, evidence, profile = storage(service)
    evidence["usage"]["storage_gb_hours"]["value"] = history
    config["growth"]["storage_gb_hours"] = budget
    with localcontext(prec=4, rounding=ROUND_FLOOR):
        with pytest.raises(GovernanceError, match="EXT021"):
            audit(config, evidence, profile, now=NOW)


def test_rounding_cannot_hide_overage_or_inherit_callers_decimal_context(service):
    config, evidence, profile = storage(service)
    evidence["usage"]["storage_gb_hours"]["value"] = "743.9999999999999999999999999999999999"
    config["growth"]["storage_gb_hours"] = "0.0000000000000000000000000000000001"
    with localcontext(prec=4, rounding=ROUND_FLOOR):
        assert (
            Decimal(audit(config, evidence, profile, now=NOW)["forecast"]["storage_gb_hours"])
            == 744
        )


def test_low_history_does_not_relax_instantaneous_capacity_guard(service):
    config, evidence, profile = storage(service)
    evidence["usage"]["storage_gb_hours"]["value"] = 0
    evidence["usage"]["storage_mb"]["value"] = 1001
    with pytest.raises(GovernanceError, match="EXT021"):
        audit(config, evidence, profile, now=NOW)


@pytest.mark.parametrize("value", [None, False, -1, "NaN", "Infinity", "unknown", 0.1, 744.0])
@pytest.mark.parametrize("field", ["history", "budget"])
def test_history_and_budget_are_known_finite_nonnegative_numbers(service, field, value):
    config, evidence, profile = storage(service)
    if field == "history":
        evidence["usage"]["storage_gb_hours"]["value"] = value
    else:
        config["growth"]["storage_gb_hours"] = value
    with pytest.raises(GovernanceError, match="GOV001"):
        audit(config, evidence, profile, now=NOW)


@pytest.mark.parametrize(
    "change", ["missing-history", "missing-budget", "scalar", "gauge", "extra"]
)
def test_storage_history_cannot_be_omitted_or_replaced_by_a_live_sample(service, change):
    config, evidence, profile = storage(service)
    if change == "missing-history":
        evidence["usage"].pop("storage_gb_hours")
    elif change == "missing-budget":
        config["growth"].pop("storage_gb_hours")
    elif change == "scalar":
        evidence["usage"]["storage_gb_hours"] = 0
    elif change == "gauge":
        evidence["usage"]["storage_gb_hours"] = {"value": 0, "as_of": NOW.isoformat()}
    else:
        evidence["usage"]["storage_gb_hours"]["as_of"] = NOW.isoformat()
    with pytest.raises(GovernanceError, match="GOV003"):
        audit(config, evidence, profile, now=NOW)


@pytest.mark.parametrize("limit", [743, 745, None, True])
def test_storage_allowance_is_reviewed_and_not_implicitly_scaled(service, limit):
    config, evidence, profile = storage(service)
    profile["usage_limits"]["storage_gb_hours"] = limit
    with pytest.raises(GovernanceError, match="EXT001"):
        audit(config, evidence, profile, now=NOW)


@pytest.mark.parametrize("clock", ["2027-02-26T12:00:00+00:00", "2028-02-26T12:00:00+00:00"])
def test_short_and_leap_cycles_use_published_gb_hour_allowance(service, clock):
    now = datetime.fromisoformat(clock)
    config, evidence, profile = clocks(service, now)
    evidence["usage"]["storage_gb_hours"]["value"] = 744
    config["growth"]["storage_gb_hours"] = 0
    assert Decimal(audit(config, evidence, profile, now=now)["forecast"]["storage_gb_hours"]) == 744
    evidence["usage"]["storage_gb_hours"]["value"] = "744.01"
    with pytest.raises(GovernanceError, match="EXT021"):
        audit(config, evidence, profile, now=now)


def test_public_example_keeps_unknown_history_and_budget_unusable(service):
    example = json.loads((fixtures.ROOT / "config/service-evidence.example.json").read_text())
    proposal = json.loads((fixtures.ROOT / "config/supabase.example.json").read_text())
    assert example["schema_version"] == 4 and proposal["schema_version"] == 2
    assert example["verified"] is False and example["complete"] is False
    assert example["usage"]["storage_gb_hours"]["value"] is None
    assert proposal["growth"]["storage_gb_hours"] is None
    with pytest.raises(GovernanceError):
        audit(proposal, example, service[2], now=NOW)
