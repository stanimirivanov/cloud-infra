"""Account evidence, cross-unit accounting and fail-closed cost rules."""

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest
from evidence_helpers import upgrade_inventory
from infra_core.governance.audit import audit
from infra_core.governance.contracts import GovernanceError, number
from infra_core.governance.resources import (
    BOOT,
    CLUSTER,
    INSTANCE,
    INVENTORY_TYPES,
    NODE_POOL,
    footprint,
)
from infra_program.governance import preflight, validate_resource

NOW = datetime(2026, 10, 25, tzinfo=UTC)


@pytest.fixture
def evidence():
    import tomllib

    root = Path(__file__).resolve().parents[1]
    profile = tomllib.loads((root / "config/quotas/profiles.toml").read_text())["profiles"][
        "oci-free"
    ]
    account = {
        "account_id": "synthetic-tenancy",
        "provider": "oci",
        "home_region": "home",
        "profile": "oci-free",
        "profile_revision": 1,
        "verified": True,
        "verified_at": NOW.isoformat(),
        "other_services_reviewed": True,
        "reservations": {},
    }
    inventory = {
        "schema_version": 1,
        "account_id": "synthetic-tenancy",
        "provider": "oci",
        "observed_at": NOW.isoformat(),
        "complete": True,
        "covered_types": sorted(INVENTORY_TYPES),
        "all_regions": True,
        "all_compartments": True,
        "resources": [],
        "usage": {
            "account_id": "synthetic-tenancy",
            "provider": "oci",
            "month": "2026-10",
            "observed_at": NOW.isoformat(),
            "source": "synthetic test evidence; never account telemetry",
            "values": {"a1_ocpu_hours": 0, "a1_memory_gb_hours": 0, "block_gb_months": 0},
        },
    }
    resource = {
        "type": NODE_POOL,
        "region": "home",
        "props": {
            "nodeShape": "VM.Standard.A1.Flex",
            "nodeShapeConfig": {"ocpus": 1, "memoryInGbs": 6},
            "nodeConfigDetails": {"size": 2},
            "nodeSourceDetails": {"bootVolumeSizeInGbs": "50"},
        },
    }
    plan = {
        "schema_version": 1,
        "account_id": "synthetic-tenancy",
        "provider": "oci",
        "complete": True,
        "units": [
            {
                "name": "oke",
                "changes": [
                    {"key": "pool", "action": "create", "existing_ids": [], "resource": resource}
                ],
            }
        ],
    }
    upgrade_inventory(inventory, account["home_region"])
    return account, profile, inventory, plan


def evaluate(evidence):
    return audit(*evidence, now=NOW)


def live_instance(rid="unmanaged", *, owner=None, ocpus=1, memory=6):
    return {
        "id": rid,
        "type": INSTANCE,
        "region": "home",
        "owner": owner,
        "retained": False,
        "props": {
            "shape": "VM.Standard.A1.Flex",
            "shapeConfig": {"ocpus": ocpus, "memoryInGbs": memory},
        },
    }


def change(evidence):
    return evidence[3]["units"][0]["changes"][0]


def test_exact_capacity_boundary_and_never_authorizes_deployment(evidence):
    result = evaluate(evidence)
    assert result["peak"] == {"ocpus": "2", "memory_gb": "12", "block_gb": "100"}
    assert result["status"] == "within-modeled-limits"
    assert result["deployment_authorized"] is False


@pytest.mark.parametrize("value", [None, True, -1, "unknown", "NaN", "Infinity", [], {}])
def test_unknown_nonfinite_and_negative_capacity_fail(value):
    with pytest.raises(GovernanceError, match="GOV001"):
        number(value, "test")


@pytest.mark.parametrize("field,value", [("ocpus", 2), ("memoryInGbs", 8)])
def test_old_four_cpu_or_sixteen_gb_topology_does_not_pass_free_profile(evidence, field, value):
    change(evidence)["resource"]["props"]["nodeShapeConfig"][field] = value
    with pytest.raises(GovernanceError, match="GOV030"):
        evaluate(evidence)


def test_paid_profile_requires_explicit_verified_account_selection(evidence):
    import tomllib

    profiles = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "config/quotas/profiles.toml").read_text()
    )["profiles"]
    account, _, inventory, plan = evidence
    account["profile"] = "oci-paid-a1"
    change(evidence)["resource"]["props"]["nodeShapeConfig"] = {"ocpus": 2, "memoryInGbs": 12}
    assert audit(account, profiles["oci-paid-a1"], inventory, plan, now=NOW)["peak"]["ocpus"] == "4"
    account["verified"] = False
    with pytest.raises(GovernanceError, match="GOV005"):
        audit(account, profiles["oci-paid-a1"], inventory, plan, now=NOW)


def test_unmanaged_and_reserved_capacity_count(evidence):
    evidence[2]["resources"].append(live_instance())
    with pytest.raises(GovernanceError, match="GOV030"):
        evaluate(evidence)
    evidence[2]["resources"].clear()
    evidence[0]["reservations"] = {"ocpus": 1}
    with pytest.raises(GovernanceError, match="GOV030"):
        evaluate(evidence)


def test_cross_unit_aggregate_cannot_spend_same_allowance_twice(evidence):
    second = deepcopy(evidence[3]["units"][0])
    second["name"] = "another-stack"
    evidence[3]["units"].append(second)
    with pytest.raises(GovernanceError, match="GOV030"):
        evaluate(evidence)


def test_replacement_peak_includes_existing_resources(evidence):
    evidence[2]["resources"] = [live_instance("old", owner="oke")]
    change(evidence).update(action="replace", existing_ids=["old"])
    with pytest.raises(GovernanceError, match="GOV030"):
        evaluate(evidence)
    change(evidence)["action"] = "update"
    assert evaluate(evidence)["peak"]["ocpus"] == "2"


@pytest.mark.parametrize("owner", [None, "another-stack"])
def test_no_subtraction_without_independent_ownership(evidence, owner):
    evidence[2]["resources"] = [live_instance("old", owner=owner)]
    change(evidence).update(action="update", existing_ids=["old"])
    with pytest.raises(GovernanceError, match="GOV012"):
        evaluate(evidence)


def test_retained_storage_and_duplicate_claims_fail(evidence):
    record = live_instance("old", owner="oke")
    record["retained"] = True
    evidence[2]["resources"] = [record]
    change(evidence).update(action="delete", existing_ids=["old"], resource=None)
    with pytest.raises(GovernanceError, match="GOV013"):
        evaluate(evidence)
    record["retained"] = False
    duplicate = deepcopy(change(evidence))
    duplicate["key"] = "second"
    evidence[3]["units"][0]["changes"].append(duplicate)
    with pytest.raises(GovernanceError, match="GOV012"):
        evaluate(evidence)


def test_actual_boot_inventory_not_double_counted_and_retained_counts(evidence):
    evidence[2]["resources"] = [
        live_instance(),
        {
            "id": "boot",
            "type": BOOT,
            "region": "home",
            "owner": None,
            "retained": True,
            "props": {"sizeInGbs": 200, "vpusPerGb": 10, "isAutoTuneEnabled": False},
        },
    ]
    evidence[3]["units"] = []
    result = evaluate(evidence)
    assert result["peak"]["block_gb"] == "200"
    assert result["peak"]["ocpus"] == "1"


@pytest.mark.parametrize(
    "target,field,value,code",
    [
        (0, "verified", False, "GOV005"),
        (0, "other_services_reviewed", False, "GOV005"),
        (0, "profile", "unreviewed", "GOV006"),
        (0, "profile_revision", 0, "GOV006"),
        (1, "enabled", False, "GOV006"),
        (2, "account_id", "other", "GOV007"),
        (2, "complete", False, "GOV008"),
        (2, "covered_types", [], "GOV008"),
        (2, "all_compartments", False, "GOV008"),
        (2, "all_regions", False, "GOV008"),
        (2, "usage", None, "GOV003"),
        (3, "provider", "aws", "GOV007"),
        (3, "complete", False, "GOV008"),
        (3, "schema_version", True, "GOV003"),
    ],
)
def test_incomplete_or_mismatched_evidence_fails(evidence, target, field, value, code):
    evidence[target][field] = value
    with pytest.raises(GovernanceError, match=code):
        evaluate(evidence)


@pytest.mark.parametrize(
    "target,field,age",
    [
        (0, "verified_at", timedelta(days=31)),
        (1, "reviewed_at", timedelta(days=91)),
        (2, "observed_at", timedelta(minutes=16)),
        (2, "observed_at", timedelta(minutes=-1)),
    ],
)
def test_stale_or_future_evidence_fails(evidence, target, field, age):
    evidence[target][field] = (NOW - age).isoformat()
    with pytest.raises(GovernanceError, match="GOV004"):
        evaluate(evidence)


def test_monthly_usage_survives_deletions_and_time_lag(evidence):
    evidence[2]["resources"] = [live_instance("old", owner="oke")]
    change(evidence).update(action="delete", existing_ids=["old"], resource=None)
    evidence[2]["usage"]["values"]["a1_ocpu_hours"] = 1499
    with pytest.raises(GovernanceError, match="GOV032"):
        evaluate(evidence)
    evidence[2]["usage"]["values"]["a1_ocpu_hours"] = 0
    evidence[2]["usage"]["observed_at"] = (NOW - timedelta(minutes=16)).isoformat()
    with pytest.raises(GovernanceError, match="GOV004"):
        evaluate(evidence)


def test_wrong_month_and_missing_metric_fail(evidence):
    evidence[2]["usage"]["month"] = "2026-09"
    with pytest.raises(GovernanceError, match="GOV031"):
        evaluate(evidence)
    evidence[2]["usage"]["month"] = "2026-10"
    del evidence[2]["usage"]["values"]["a1_ocpu_hours"]
    with pytest.raises(GovernanceError, match="GOV031"):
        evaluate(evidence)


def test_duplicate_resources_units_and_changes_fail(evidence):
    record = live_instance()
    evidence[2]["resources"] = [record, record]
    with pytest.raises(GovernanceError, match="GOV009"):
        evaluate(evidence)
    evidence[2]["resources"] = []
    evidence[3]["units"] *= 2
    with pytest.raises(GovernanceError, match="GOV009"):
        evaluate(evidence)


@pytest.mark.parametrize(
    "kind,props,code",
    [
        ("aws:ec2/instance:Instance", {}, "GOV022"),
        ("oci:loadBalancer/loadBalancer:LoadBalancer", {}, "GOV022"),
        (CLUSTER, {"type": "ENHANCED_CLUSTER"}, "GOV020"),
        (BOOT, {"sizeInGbs": 50, "vpusPerGb": 20, "isAutoTuneEnabled": False}, "GOV021"),
        (BOOT, {"sizeInGbs": 50, "vpusPerGb": 10, "isAutoTuneEnabled": True}, "GOV021"),
    ],
)
def test_unknown_paid_and_unbounded_types_fail(kind, props, code):
    with pytest.raises(GovernanceError, match=code):
        footprint(kind, props, planned=True)


def test_unknown_shape_values_and_cycling_fail(evidence):
    props = change(evidence)["resource"]["props"]
    props["nodeShapeConfig"]["ocpus"] = None
    with pytest.raises(GovernanceError, match="GOV001"):
        evaluate(evidence)
    props["nodeShapeConfig"]["ocpus"] = 1
    props["nodePoolCyclingDetails"] = {}
    with pytest.raises(GovernanceError, match="GOV026"):
        evaluate(evidence)


def test_preflight_failure_prevents_resource_registration(evidence):
    evidence[0]["verified"] = False
    registered = []
    with pytest.raises(GovernanceError, match="GOV005"):
        preflight(*evidence, lambda: registered.append(True))
    assert registered == []


def test_mandatory_policy_uses_same_cost_classifier(evidence):
    violations = []
    resource = change(evidence)["resource"]
    resource["props"]["nodeShape"] = "VM.Standard.E5.Flex"
    validate_resource(
        SimpleNamespace(resource_type=NODE_POOL, props=resource["props"]),
        lambda message, urn: violations.append(message),
    )
    assert len(violations) == 1 and "GOV023" in violations[0]
    assert number("1.25", "test") == Decimal("1.25")


def test_instance_boot_and_basic_cluster_classification():
    instance = footprint(
        INSTANCE,
        {
            "shape": "VM.Standard.A1.Flex",
            "shapeConfig": {"ocpus": 1, "memoryInGbs": 6},
            "sourceDetails": {"bootVolumeSizeInGbs": "50", "bootVolumeVpusPerGb": "10"},
        },
        planned=True,
    )
    assert instance == {"ocpus": Decimal(1), "memory_gb": Decimal(6), "block_gb": Decimal(50)}
    assert sum(footprint(CLUSTER, {"type": "BASIC_CLUSTER"}, planned=True).values()) == 0
    assert sum(footprint("oci:Core/vcn:Vcn", {}, planned=True).values()) == 0


def test_cross_region_and_monthly_account_mismatch_fail(evidence):
    change(evidence)["resource"]["region"] = "other"
    with pytest.raises(GovernanceError, match="GOV010"):
        evaluate(evidence)
    change(evidence)["resource"]["region"] = "home"
    evidence[2]["usage"]["account_id"] = "other"
    with pytest.raises(GovernanceError, match="GOV007"):
        evaluate(evidence)


def test_preflight_success_calls_registration_only_after_audit(evidence, monkeypatch):
    # Production clock remains real; inject a deterministic clock at the pure boundary.
    monkeypatch.setattr("infra_program.governance.audit", lambda *args: audit(*args, now=NOW))
    assert preflight(*evidence, lambda: "registered") == "registered"


def test_cli_reports_failed_audit_without_traceback(tmp_path, evidence, monkeypatch, capsys):
    from infra_core import cli

    monkeypatch.setattr("infra_core.inventory_evidence.reviewed_commit", lambda root: "a" * 40)

    (tmp_path / "pyproject.toml").write_text('[project]\nname="oci-oke-infrastructure"\n')
    (tmp_path / "config/quotas").mkdir(parents=True)
    (tmp_path / "config/quotas/profiles.toml").write_bytes(
        (Path(__file__).resolve().parents[1] / "config/quotas/profiles.toml").read_bytes()
    )
    (tmp_path / "account.toml").write_text('provider="oci"\nprofile="oci-free"\n')
    (tmp_path / "inventory.json").write_text(json.dumps(evidence[2]))
    (tmp_path / "proposal.json").write_text(json.dumps(evidence[3]))
    assert (
        cli.main(
            [
                "--root",
                str(tmp_path),
                "governance",
                "audit",
                "--account",
                "account.toml",
                "--inventory",
                "inventory.json",
                "--plan",
                "proposal.json",
            ]
        )
        == 1
    )
    assert "GOV043" in capsys.readouterr().err


def test_cli_failed_inventory_removes_stale_snapshot_and_rejects_escape(tmp_path, monkeypatch):
    from infra_core import cli

    monkeypatch.setattr("infra_core.inventory_evidence.reviewed_commit", lambda root: "a" * 40)
    (tmp_path / "pyproject.toml").write_text('[project]\nname="oci-oke-infrastructure"\n')
    (tmp_path / "config/quotas").mkdir(parents=True)
    (tmp_path / "config/quotas/profiles.toml").write_text("[profiles]\n")
    (tmp_path / "account.toml").write_text(
        'provider="oci"\naccount_id="synthetic-tenancy"\nhome_region="home"\n'
    )
    (tmp_path / ".infra").mkdir()
    output = tmp_path / ".infra/inventory.json"
    output.write_text("stale-success")
    calls = []

    def fail(*args):
        calls.append(True)
        raise RuntimeError("synthetic SDK credential details must be withheld")

    monkeypatch.setattr("infra_core.inventory.oci.OCIReader", fail)
    args = [
        "--root",
        str(tmp_path),
        "governance",
        "inventory",
        "--account",
        "account.toml",
        "--oci-config",
        "nonexistent-synthetic-credentials",
    ]
    assert cli.main(args) == 1
    assert not output.exists()
    assert calls == [True]
    calls.clear()
    assert cli.main([*args, "--output", "../escape.json"]) == 1
    assert calls == []


@pytest.mark.parametrize(
    "fault",
    [
        "missing-query",
        "duplicate-query",
        "missing-region",
        "missing-compartment",
        "missing-ad",
        "negative-count",
        "boolean-count",
        "old-start",
        "future-end",
        "reversed-clocks",
        "v1",
    ],
)
def test_inventory_coverage_must_be_complete_measured_and_fresh(evidence, fault):
    inventory = evidence[2]
    coverage = inventory["coverage"]
    if fault == "missing-query":
        coverage["queries"].pop()
    elif fault == "duplicate-query":
        coverage["queries"].append(coverage["queries"][0].copy())
    elif fault == "missing-region":
        coverage["regions"] = []
    elif fault == "missing-compartment":
        coverage["compartments"] = ["another-compartment"]
    elif fault == "missing-ad":
        coverage["availability_domains"]["home"] = []
    elif fault in {"negative-count", "boolean-count"}:
        coverage["queries"][0]["count"] = -1 if fault == "negative-count" else True
    elif fault == "old-start":
        inventory["collection_started_at"] = (NOW - timedelta(hours=1)).isoformat()
    elif fault == "future-end":
        inventory["collection_completed_at"] = (NOW + timedelta(minutes=1)).isoformat()
    elif fault == "reversed-clocks":
        inventory["collection_completed_at"] = (NOW - timedelta(minutes=1)).isoformat()
    else:
        inventory["schema_version"] = 1
    with pytest.raises(GovernanceError, match="GOV042|GOV003"):
        evaluate(evidence)


def test_usage_report_observation_cannot_retimestamp_old_coverage(evidence):
    evidence[2]["usage"]["covered_through"] = (NOW - timedelta(minutes=16)).isoformat()
    with pytest.raises(GovernanceError, match="GOV004"):
        evaluate(evidence)
    evidence[2]["usage"].update(
        observed_at=(NOW - timedelta(minutes=2)).isoformat(),
        covered_through=(NOW - timedelta(minutes=1)).isoformat(),
    )
    with pytest.raises(GovernanceError, match="GOV043"):
        evaluate(evidence)


def test_zero_query_counts_cannot_cover_existing_resources(evidence):
    evidence[2]["resources"] = [live_instance()]
    for row in evidence[2]["coverage"]["queries"]:
        if row["operation"] == "instances":
            row["count"] = 0
    with pytest.raises(GovernanceError, match="GOV042"):
        evaluate(evidence)


@pytest.mark.parametrize("operation", ["regions", "ads", "virtual_pools"])
def test_discovery_counts_and_virtual_pool_exclusion_are_enforced(evidence, operation):
    row = next(row for row in evidence[2]["coverage"]["queries"] if row["operation"] == operation)
    row["count"] = 2
    with pytest.raises(GovernanceError, match="GOV042"):
        evaluate(evidence)
