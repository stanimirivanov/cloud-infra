"""Measured limits and immutable coverage clocks, without collectors or authorization."""

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from decimal import localcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_governance
import test_services
from infra_core import operational_findings as f

ROOT = Path(__file__).resolve().parents[1]


def policy():
    return dict(
        schema_version=1,
        enabled=True,
        warning_utilization_percent=80,
        critical_utilization_percent=95,
        warning_age_percent=80,
        max_age_seconds=dict(f.AGES),
    )


@pytest.fixture(params=["oci-network", "oci-oke", "cloudflare-edge", "supabase-database"])
def case(request):
    unit = request.param
    if unit.startswith("oci-"):
        account, profile, data, _ = test_governance.evidence.__wrapped__()
        now = test_governance.NOW
        scope = dict(
            unit=unit,
            account_id=account["account_id"],
            scope_id=account["home_region"],
            profile=profile["id"],
        )
    else:
        proposal, data, profile = test_services.service.__wrapped__(
            SimpleNamespace(param="cloudflare" if unit == "cloudflare-edge" else "supabase")
        )
        now = datetime.now(UTC)
        account = None
        scope = dict(
            unit=unit,
            account_id=proposal["account_id"],
            scope_id=proposal["scope_id"],
            profile=profile["id"],
        )
    return dict(
        config=policy(), scope=scope, profile=profile, evidence=data, account=account, now=now
    )


def indexed(result):
    values = {v["metric"]: v for v in result["findings"]}
    assert len(values) == len(result["findings"])
    return values


def test_normal_four_units_are_read_only_and_preserve_original_clocks(case):
    before = deepcopy(case)
    report = f.evaluate(**case)
    assert case == before
    assert report["status"] == "normal" and report["complete"]
    assert report["deployment_authorized"] is report["remediation_authorized"] is False
    assert report["source_clocks"]["observed_at"] == case["evidence"]["observed_at"]
    assert indexed(report)["scope"]["status"] == "normal"
    assert "synthetic-account" not in json.dumps(report)


@pytest.mark.parametrize(
    "value,status",
    [
        (0, "normal"),
        ("79.9999999999999999999999", "normal"),
        (80, "warning"),
        ("94.9999999999999999999999", "warning"),
        (95, "critical"),
        (100, "critical"),
        (101, "critical"),
    ],
)
def test_exact_observed_thresholds_exhaustion_and_recovery(case, value, status):
    if case["scope"]["unit"] == "cloudflare-edge":
        case["evidence"]["resources"] = [
            dict(id=str(n), name=f"_txt{n}.example.com", type="TXT")
            for n in range(int(f.exact(value) * 2))
        ]
        metric = "capacity/resources"
    elif case["account"] is None:
        case["profile"]["usage_limits"]["storage_mb"] = 1000
        case["evidence"]["usage"]["storage_mb"]["value"] = str(f.exact(value) * 10)
        metric = "usage/storage_mb"
    else:
        case["profile"]["monthly"]["a1_ocpu_hours"] = 100
        case["evidence"]["usage"]["values"]["a1_ocpu_hours"] = value
        metric = "usage/a1_ocpu_hours"
    with localcontext() as ctx:
        ctx.prec = 3  # comparisons must not inherit callers' lossy decimal settings
        report = f.evaluate(**case)
    reading = indexed(report)[metric]
    assert reading["status"] == status
    if f.exact(value) >= 100:
        assert reading["reason"] == "exhausted"
    original_id = reading["id"]
    if case["account"]:
        case["evidence"]["usage"]["values"]["a1_ocpu_hours"] = 0
    elif case["scope"]["unit"] == "cloudflare-edge":
        case["evidence"]["resources"] = []
    else:
        case["evidence"]["usage"]["storage_mb"]["value"] = 0
    recovered = indexed(f.evaluate(**case))[metric]
    assert recovered["id"] == original_id and recovered["status"] == "normal"


@pytest.mark.parametrize("bad", [None, True, -1, "NaN", "Infinity", "unknown", {}, [], 1.5])
def test_missing_invalid_measurements_never_become_zero(case, bad):
    if case["account"]:
        case["evidence"]["usage"]["values"]["a1_ocpu_hours"] = bad
        metric = "usage/a1_ocpu_hours"
    elif case["scope"]["unit"] == "supabase-database":
        case["evidence"]["usage"]["mau"]["value"] = bad
        metric = "usage/mau"
    else:
        if bad == []:
            del case["evidence"]["resources"]
        else:
            case["evidence"]["resources"] = bad
        metric = "capacity/resources"
    report = f.evaluate(**case)
    assert report["status"] == "unknown" and not report["complete"]
    assert indexed(report)[metric]["status"] == "unknown"
    assert "value" not in indexed(report)[metric]


@pytest.mark.parametrize(
    "fault", ["late", "future", "order", "partial", "scope", "unverified", "profile", "duplicate"]
)
def test_coverage_and_identity_failures_are_unknown(case, fault):
    data = case["evidence"]
    if fault == "late":
        data["observed_at"] = (case["now"] - timedelta(seconds=901)).isoformat()
    elif fault == "future":
        data["observed_at"] = (case["now"] + timedelta(seconds=1)).isoformat()
    elif fault == "order":
        data["collection_completed_at"] = (case["now"] + timedelta(seconds=1)).isoformat()
    elif fault == "partial":
        data["complete"] = False
    elif fault == "scope":
        data["account_id"] = "PRIVATE-OTHER-ACCOUNT"
    elif fault == "unverified":
        (case["account"] or data)["verified"] = False
    elif fault == "profile":
        case["profile"]["enabled"] = False
    elif fault == "duplicate":
        data["resources"] = [dict(id="duplicate"), dict(id="duplicate")]
    report = f.evaluate(**case)
    assert report["status"] == "unknown"
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize(
    "age,status",
    [(719, "normal"), (720, "warning"), (899, "warning"), (900, "critical"), (901, "critical")],
)
def test_evidence_age_threshold_boundary(case, age, status):
    original = case["evidence"]["observed_at"]
    observed = (case["now"] - timedelta(seconds=age)).isoformat()
    case["evidence"].update(observed_at=observed, collection_started_at=observed)
    report = f.evaluate(**case)
    assert indexed(report)["observation_age"]["status"] == status
    assert report["source_clocks"]["observed_at"] == observed
    if age > 900:
        assert report["status"] == "unknown"
    case["evidence"].update(observed_at=original, collection_started_at=original)
    assert indexed(f.evaluate(**case))["observation_age"]["status"] == "normal"


@pytest.mark.parametrize("field,days", [("profile", 91), ("entitlement", 31)])
def test_expired_reviews_do_not_refresh_when_re_evaluated(case, field, days):
    target = case["profile"] if field == "profile" else (case["account"] or case["evidence"])
    target["reviewed_at" if field == "profile" else "verified_at"] = (
        case["now"] - timedelta(days=days)
    ).isoformat()
    report = f.evaluate(**case)
    assert indexed(report)[field + "_age"]["status"] == "critical"
    assert report["status"] == "unknown"


def test_partial_billing_preserves_other_readings_and_missing_is_unknown():
    case = globals()["case"].__wrapped__(SimpleNamespace(param="supabase-database"))
    del case["evidence"]["usage"]["mau"]
    report = f.evaluate(**case)
    values = indexed(report)
    assert values["usage/mau"]["status"] == "unknown"
    assert values["usage/egress_mb"]["status"] == "normal"
    assert (
        report["usage_windows"]["egress_mb"]["covered_from"]
        == case["evidence"]["billing_period"]["starts_at"]
    )


@pytest.mark.parametrize(
    "fault", ["late", "future", "missing", "wrong-month", "wrong-account", "cutoff-order"]
)
def test_oci_billing_watermarks_are_not_collection_freshness(fault):
    case = globals()["case"].__wrapped__(SimpleNamespace(param="oci-network"))
    usage = case["evidence"]["usage"]
    if fault == "late":
        usage["covered_through"] = (case["now"] - timedelta(seconds=901)).isoformat()
    elif fault == "future":
        usage["covered_through"] = (case["now"] + timedelta(seconds=1)).isoformat()
    elif fault == "missing":
        del usage["covered_through"]
    elif fault == "wrong-month":
        usage["month"] = "2025-01"
    elif fault == "wrong-account":
        usage["account_id"] = "different"
    else:
        usage["observed_at"] = (case["now"] - timedelta(seconds=2)).isoformat()
    report = f.evaluate(**case)
    assert indexed(report)["usage/a1_ocpu_hours"]["status"] == "unknown"
    assert indexed(report)["capacity/ocpus"]["status"] == "normal"


def test_oci_retained_unmanaged_and_reserved_capacity_all_count():
    case = globals()["case"].__wrapped__(SimpleNamespace(param="oci-network"))
    row = test_governance.live_instance(ocpus=1, memory=6)
    row.update(retained=True, owner=None)
    case["evidence"]["resources"] = [row]
    case["account"]["reservations"] = dict(ocpus=1, memory_gb=6)
    values = indexed(f.evaluate(**case))
    assert values["capacity/ocpus"]["value"] == "2"
    assert values["capacity/ocpus"]["status"] == "critical"
    case["evidence"]["coverage"]["queries"].pop()
    assert indexed(f.evaluate(**case))["capacity/ocpus"]["status"] == "unknown"


def test_supabase_anniversary_must_cover_cycle_start_and_gauge_clock():
    case = globals()["case"].__wrapped__(SimpleNamespace(param="supabase-database"))
    case["now"] = datetime(2026, 3, 1, tzinfo=UTC)
    data = case["evidence"]
    instant = case["now"].isoformat()
    data.update(
        observed_at=instant,
        collection_started_at=instant,
        collection_completed_at=instant,
        verified_at=instant,
    )
    case["profile"]["reviewed_at"] = instant
    data["billing_period"] = dict(
        anchor_at="2020-01-31T00:00:00+00:00",
        starts_at="2026-02-28T00:00:00+00:00",
        ends_at="2026-03-31T00:00:00+00:00",
    )
    for metric, reading in data["usage"].items():
        if metric == "storage_mb":
            reading["as_of"] = instant
        else:
            reading.update(
                covered_from=data["billing_period"]["starts_at"], covered_through=instant
            )
    assert f.evaluate(**case)["status"] == "normal"
    data["usage"]["mau"]["covered_from"] = instant
    assert indexed(f.evaluate(**case))["usage/mau"]["status"] == "unknown"
    assert indexed(f.evaluate(**case))["usage/storage_mb"]["status"] == "normal"


@pytest.mark.parametrize(
    "fault", ["disabled", "missing", "ages", "thresholds", "float", "zero", "bool", "extra"]
)
def test_incomplete_example_and_invalid_policies_are_rejected(fault):
    value = policy()
    if fault == "disabled":
        value["enabled"] = False
    elif fault == "missing":
        value["warning_age_percent"] = None
    elif fault == "ages":
        value["max_age_seconds"]["billing_lag"] = 901
    elif fault == "thresholds":
        value["warning_utilization_percent"] = 95
    elif fault == "float":
        value["warning_age_percent"] = 80.0
    elif fault == "zero":
        value["max_age_seconds"]["profile"] = 0
    elif fault == "bool":
        value["schema_version"] = True
    else:
        value["activate"] = True
    with pytest.raises(ValueError):
        f.policy(value)
    with pytest.raises(ValueError):
        f.policy(json.loads((ROOT / "config/monitoring.example.json").read_bytes()))


@pytest.fixture
def bundle(case, tmp_path):
    import shutil

    from infra_core import operations

    private = tmp_path / ".infra"
    private.mkdir()
    (tmp_path / "config/quotas").mkdir(parents=True)
    shutil.copyfile(ROOT / "config/quotas/profiles.toml", tmp_path / "config/quotas/profiles.toml")
    for name, value in (("policy", case["config"]), ("evidence", case["evidence"])):
        (private / (name + ".json")).write_bytes(operations.encoded(value))
    account_path = None
    if case["account"]:
        account_path = ".infra/account.toml"
        account = case["account"]
        values = "\n".join(
            key + " = " + json.dumps(value)
            for key, value in account.items()
            if key != "reservations"
        )
        (tmp_path / account_path).write_text(values + "\n[reservations]\n")
    index = dict(
        schema_version=1,
        scope=case["scope"],
        policy=".infra/policy.json",
        evidence=".infra/evidence.json",
        account=account_path,
    )
    path = private / "index.json"
    path.write_bytes(operations.encoded(index))
    return tmp_path, path, case


def test_offline_private_bundle_binds_exact_bytes_and_never_writes(bundle, monkeypatch, capsys):
    from infra_core import cli

    root, path, case = bundle
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    report = f.check(root, path, now=case["now"])
    assert report["status"] == "normal"
    assert set(report["inputs_sha256"]) == {"policy", "evidence", "index", "profiles"} | (
        {"account"} if case["account"] else set()
    )
    real = f.check
    monkeypatch.setattr(f, "check", lambda root, path: real(root, path, now=case["now"]))
    monkeypatch.setattr(cli, "find_repository", lambda root: bundle[0])
    assert cli.main(["monitoring", "findings", "--evidence", str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert before == {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize(
    "fault",
    ["path", "oversized", "duplicate", "nan", "missing", "schema", "symlink", "account-path"],
)
def test_invalid_index_io_is_redacted(bundle, fault):
    root, path, case = bundle
    index = json.loads(path.read_bytes())
    if fault == "path":
        index["evidence"] = "config/quotas/profiles.toml"
    elif fault == "oversized":
        (root / index["evidence"]).write_bytes(b"PRIVATE" * 200000)
    elif fault == "duplicate":
        path.write_bytes(b'{"PRIVATE":1,"PRIVATE":2}')
    elif fault == "nan":
        path.write_bytes(b'{"PRIVATE":NaN}')
    elif fault == "missing":
        index["evidence"] = ".infra/PRIVATE.json"
    elif fault == "schema":
        index["schema_version"] = True
    elif fault == "symlink":
        (root / ".infra/link.json").symlink_to(ROOT / "config/operations.example.json")
        index["evidence"] = ".infra/link.json"
    else:
        index["account"] = "config/quotas/profiles.toml"
    if fault not in {"duplicate", "nan"}:
        path.write_text(json.dumps(index))
    with pytest.raises(ValueError, match="^FND001:.*withheld$") as error:
        f.check(root, path, now=case["now"])
    assert "PRIVATE" not in str(error.value)


def test_unknown_cli_keeps_machine_readable_report_and_returns_failure(bundle, monkeypatch, capsys):
    from infra_core import cli

    root, path, case = bundle
    data = json.loads((root / ".infra/evidence.json").read_bytes())
    data["complete"] = False
    (root / ".infra/evidence.json").write_text(json.dumps(data))
    real = f.check
    monkeypatch.setattr(f, "check", lambda root, path: real(root, path, now=case["now"]))
    monkeypatch.setattr(cli, "find_repository", lambda root: bundle[0])
    assert cli.main(["monitoring", "findings", "--evidence", str(path)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "unknown" and not report["complete"]


def test_untrusted_nested_clocks_and_raw_diagnostics_do_not_escape(case):
    case["evidence"]["observed_at"] = {"PRIVATE-KEY": "2026-01-01T00:00:00+00:00"}
    case["evidence"]["source"] = "PRIVATE-TOKEN"
    report = f.evaluate(**case)
    assert report["status"] == "unknown"
    assert "PRIVATE" not in json.dumps(report)


def test_partial_oci_billing_preserves_known_metrics():
    case = globals()["case"].__wrapped__(SimpleNamespace(param="oci-network"))
    del case["evidence"]["usage"]["values"]["a1_memory_gb_hours"]
    values = indexed(f.evaluate(**case))
    assert values["usage/a1_memory_gb_hours"]["status"] == "unknown"
    assert values["usage/a1_ocpu_hours"]["status"] == "normal"


def test_different_scopes_do_not_share_incident_identity():
    case = globals()["case"].__wrapped__(SimpleNamespace(param="cloudflare-edge"))
    first = indexed(f.evaluate(**case))["capacity/resources"]["id"]
    case["scope"]["scope_id"] = case["evidence"]["scope_id"] = "b" * 32
    second = indexed(f.evaluate(**case))["capacity/resources"]["id"]
    assert first != second


def test_unmodeled_oci_billing_metric_is_unknown():
    case = globals()["case"].__wrapped__(SimpleNamespace(param="oci-network"))
    case["evidence"]["usage"]["values"]["unreviewed-paid-usage"] = 0
    report = f.evaluate(**case)
    assert report["status"] == "unknown"
    assert indexed(report)["billing_window"]["status"] == "unknown"


def test_paid_a1_profile_is_explicit_not_inherited():
    import tomllib

    case = globals()["case"].__wrapped__(SimpleNamespace(param="oci-oke"))
    profiles = tomllib.loads((ROOT / "config/quotas/profiles.toml").read_text())["profiles"]
    case["scope"]["profile"] = "oci-paid-a1"
    case["profile"] = profiles["oci-paid-a1"]
    case["account"].update(profile="oci-paid-a1", profile_revision=case["profile"]["revision"])
    assert indexed(f.evaluate(**case))["capacity/ocpus"]["limit"] == "4"
    case["account"]["profile"] = "oci-free"
    assert f.evaluate(**case)["status"] == "unknown"


def test_threshold_cross_product_preserves_small_positive_difference():
    from decimal import Decimal

    case = globals()["case"].__wrapped__(SimpleNamespace(param="oci-network"))
    with localcontext() as context:
        context.prec = 256
        epsilon = Decimal("1e-70")
        case["profile"]["monthly"]["a1_ocpu_hours"] = str(1 + epsilon)
        case["evidence"]["usage"]["values"]["a1_ocpu_hours"] = str(
            Decimal("0.8") + Decimal("1.6") * epsilon
        )
        case["config"]["warning_utilization_percent"] = str(80 + 80 * epsilon)
    # The threshold cross product exceeds value*100 by 80*epsilon**2.
    assert indexed(f.evaluate(**case))["usage/a1_ocpu_hours"]["status"] == "normal"
