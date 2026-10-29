"""Protected scheduler composition; every external operation is replaced by a spy."""

import json
import os
import runpy
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from infra_core import incidents as i
from infra_core import operations
from infra_program import drift
from infra_program import monitoring as m
from test_incidents import producer

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40


@pytest.fixture(params=["oci-network", "oci-oke", "cloudflare-edge", "supabase-database"])
def runner(request, tmp_path, monkeypatch):
    unit = request.param
    (tmp_path / "config").mkdir()
    (tmp_path / ".infra").mkdir()
    config = json.loads((ROOT / m.POLICY).read_bytes())
    config.update(
        enabled=True,
        delivery_enabled=False,
        heartbeat_seconds=1800,
        state_host_sha256="f" * 64,
        scheduled_actor_id=7,
        scheduled_actor_login="owner",
        notification_actor_id=8,
        notification_actor_login="monitor-bot",
    )
    (tmp_path / m.POLICY).write_text(json.dumps(config))
    source = dict(
        GITHUB_REF="refs/heads/main",
        GITHUB_REPOSITORY=config["repository"],
        GITHUB_REPOSITORY_ID=str(config["repository_id"]),
        GITHUB_SHA=COMMIT,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_ACTOR="owner",
        GITHUB_ACTOR_ID="7",
        GITHUB_REPOSITORY_OWNER="owner",
        GITHUB_RUN_ID="101",
        GITHUB_RUN_NUMBER="1",
        MONITOR_UNIT=unit,
        MONITOR_ENVIRONMENT=unit + "-monitor",
        MONITOR_INDEX=".infra/monitor.json",
        MONITOR_DELIVERY_ENABLED="false",
        GH_TOKEN="read-only",
    )
    cs = dict(
        unit=unit,
        account_id="PRIVATE-account",
        scope_id="home" if unit.startswith("oci-") else "PRIVATE-service",
        profile="fixture",
    )
    hs = dict(
        unit=unit,
        account_id=cs["account_id"],
        scope_id="PRIVATE-network" if unit.startswith("oci-") else cs["scope_id"],
        region="home",
    )
    for name, scope in (("cost", cs), ("health", hs)):
        (tmp_path / f".infra/{name}.json").write_text(json.dumps(dict(scope=scope)))
    (tmp_path / ".infra/drift.json").write_text(json.dumps(dict(output=".infra/drift-result.json")))
    index = dict(
        schema_version=1,
        unit=unit,
        cost_index=".infra/cost.json",
        health_index=".infra/health.json",
        drift_bundle=".infra/drift.json",
        max_age_seconds=900,
    )
    (tmp_path / ".infra/monitor.json").write_text(json.dumps(index))
    calls = []
    monkeypatch.setattr(m, "repository_state", lambda root: (COMMIT, True))
    monkeypatch.setattr(
        m.administration,
        "collect_operation_environment",
        lambda *a, **kw: calls.append("environment"),
    )
    monkeypatch.setattr(drift, "check", lambda *a: calls.append("drift-check"))

    def report(name):
        value = producer(name)
        value["unit"] = unit
        value["scope_sha256"] = operations.digest(cs if name == "cost" else hs)
        now = datetime.now(UTC).isoformat()
        for key in ("evaluated_at", "started_at", "completed_at"):
            if key in value:
                value[key] = now
        if name == "cost":
            value["source_clocks"]["observed_at"] = now
        if name == "health":
            for row in value["endpoints"]:
                row["completed_at"] = now
        return value

    def cost(*args):
        calls.append("cost")
        return report("cost")

    def healthy(*args, **kwargs):
        calls.append("health-observe" if kwargs["network"] else "health-check")
        if kwargs["network"]:
            assert "GH_TOKEN" not in os.environ and "AWS_ACCESS_KEY_ID" not in os.environ
        return report("health")

    def execute(root, args, credentials):
        calls.append("drift-execute")
        state = m.i.Store(root, unit).read(m.catalog(root, source)[1])
        assert state["phase"] == "running" and state["stage"] == "pending"
        assert args.actor == source["GITHUB_ACTOR"] and args.environment == unit + "-monitor"
        assert credentials() == {"fixture": "credential"}
        (root / ".infra/drift-result.json").write_text(json.dumps(report("drift")))

    monkeypatch.setattr(m.operational_findings, "check", cost)
    monkeypatch.setattr(m.health, "check", healthy)
    monkeypatch.setattr(drift, "execute", execute)
    monkeypatch.setattr(m, "host_id", lambda: "f" * 64)
    binding = m.catalog(tmp_path, source)[1]
    with i.Store(tmp_path, unit).locked() as store:
        store.save(i.empty(unit, binding))
    return tmp_path, source, config, index, calls, report


def test_disabled_defaults_reject_before_context_or_credentials():
    with pytest.raises(ValueError):
        m.settings(ROOT)
    assert not json.loads((ROOT / m.POLICY).read_bytes())["delivery_enabled"]


def test_preflight_is_read_only_then_separate_steps_complete_and_duplicate_does_not_reobserve(
    runner, monkeypatch
):
    root, source, _, _, calls, _ = runner
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert m.preflight(root, source)["drift_admitted"]
    assert before == {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert "drift-execute" not in calls
    m.run_drift(root, source, lambda: {"fixture": "credential"})
    monkeypatch.setenv("GH_TOKEN", "PRIVATE-token")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "PRIVATE-ambient")
    state = m.collect(root, source)
    assert state["phase"] == "complete" and state["severity"] == "normal" and not state["pending"]
    assert (
        os.environ["GH_TOKEN"] == "PRIVATE-token"
        and os.environ["AWS_ACCESS_KEY_ID"] == "PRIVATE-ambient"
    )
    before_calls = calls.copy()
    assert m.collect(root, source) == state
    assert calls == before_calls + ["environment"]
    assert not m.preflight(root, source)["drift_admitted"]
    assert calls.count("drift-execute") == 1


def test_failed_drift_admission_never_loads_credentials_and_is_visible_unknown(runner, monkeypatch):
    root, source, _, _, calls, _ = runner
    monkeypatch.setattr(drift, "check", lambda *a: (_ for _ in ()).throw(ValueError("PRIVATE")))
    assert not m.preflight(root, source)["drift_admitted"]
    # The workflow skips run_drift when preflight declines; collect contains no credential callback.
    state = m.collect(root, source)
    assert state["severity"] == "unknown" and not state["sources"]["drift"]["available"]
    assert "drift-execute" not in calls


def test_provider_failure_uses_unknown_without_replaying_drift(runner, monkeypatch):
    root, source, _, _, calls, _ = runner

    def fail(*a):
        calls.append("failed-drift")
        raise ValueError("PRIVATE")

    monkeypatch.setattr(drift, "execute", fail)
    m.run_drift(root, source, lambda: pytest.fail("credentials"))
    state = m.collect(root, source)
    assert state["severity"] == "unknown"
    m.collect(root, source)
    assert calls.count("failed-drift") == 1


@pytest.mark.parametrize(
    "fault",
    [
        "event",
        "branch",
        "repository",
        "actor",
        "sha",
        "environment",
        "schedule-id",
        "schedule-login",
    ],
)
def test_untrusted_context_never_calls_adapters(runner, fault):
    root, source, _, _, calls, _ = runner
    key = dict(
        event="GITHUB_EVENT_NAME",
        branch="GITHUB_REF",
        repository="GITHUB_REPOSITORY",
        actor="GITHUB_ACTOR",
        sha="GITHUB_SHA",
        environment="MONITOR_ENVIRONMENT",
    ).get(fault)
    if key:
        source[key] = "wrong"
    else:
        source["GITHUB_EVENT_NAME"] = "schedule"
        source["GITHUB_ACTOR_ID" if fault == "schedule-id" else "GITHUB_ACTOR"] = "wrong"
    with pytest.raises(ValueError):
        m.preflight(root, source)
    assert calls == []


def test_schedule_retains_real_context_and_signed_monitor_contract(runner):
    root, source, _, _, calls, _ = runner
    source["GITHUB_EVENT_NAME"] = "schedule"
    assert m.preflight(root, source)["drift_admitted"]
    m.run_drift(root, source, lambda: {"fixture": "credential"})
    assert source["GITHUB_EVENT_NAME"] == "schedule" and "drift-check" in calls


def test_interrupted_stage_cannot_repeat_provider_or_collection(runner):
    root, source, _, _, calls, _ = runner
    _, binding, _ = m.catalog(root, source)
    with i.Store(root, source["MONITOR_UNIT"]).locked() as store:
        store.save(i.begin(store.read(binding), 1, "101", datetime.now(UTC)))
    with pytest.raises(ValueError):
        m.run_drift(root, source, lambda: pytest.fail("replay"))
    with pytest.raises(ValueError):
        m.collect(root, source)
    assert "drift-execute" not in calls and "health-observe" not in calls


def test_independent_watchdog_has_no_provider_inputs_and_unknown_on_api_failure(
    runner, monkeypatch
):
    root, source, _, _, calls, _ = runner
    source["MONITOR_ENVIRONMENT"] = "monitor-watchdog"

    class Api:
        def __init__(self, *a):
            pass

        def heartbeats(self, **kw):
            raise ValueError("PRIVATE")

    monkeypatch.setattr(m, "GitHub", Api)
    result = m.watchdog(root, source)
    assert set(result) == i.UNITS and set(result.values()) == {"unknown"}
    assert calls == ["environment"]
    assert i.Store(root, source["MONITOR_UNIT"]).read(m.catalog(root, source)[1])["run_number"] == 0


def test_pending_delivery_can_resume_without_fresh_provider_admission(runner, monkeypatch):
    root, source, config, _, _, _ = runner
    config["delivery_enabled"] = True
    (root / m.POLICY).write_text(json.dumps(config))
    source["MONITOR_DELIVERY_ENABLED"] = "true"
    state = m.collect(root, source)  # no signed drift run: unknown queues one incident
    assert len(state["pending"]) == 1
    sent = []

    class Api:
        def __init__(self, *a):
            assert a[-1] == "notification-token"

        def send(self, event):
            sent.append(event["id"])

    monkeypatch.setattr(m, "GitHub", Api)
    done = m.deliver(root, source, lambda: "notification-token")
    assert not done["pending"] and len(sent) == 1


def test_raw_script_rejects_ambient_cloud_tokens_outside_drift(monkeypatch, capsys):
    import sys

    script = runpy.run_path(str(ROOT / ".github/scripts/monitor.py"))
    monkeypatch.setattr(sys, "argv", ["monitor.py", "--collect"])
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "PRIVATE")
    assert script["main"]() == 1
    assert "MON001" in capsys.readouterr().out


def test_workflow_has_protected_separate_secret_phases_and_independent_hosted_watchdog():
    workflow = yaml.load(
        (ROOT / ".github/workflows/monitor.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert set(workflow["on"]) == {"schedule", "workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["observe"]
    assert job["needs"] == "verify" and job["runs-on"]["group"] == "service-operations"
    assert (
        set(job["strategy"]["matrix"]["unit"]) == i.UNITS
        and job["strategy"]["fail-fast"] == "false"
    )
    assert (
        "oci-dependency" in job["concurrency"]["group"]
        and job["concurrency"]["cancel-in-progress"] == "false"
    )
    steps = job["steps"]
    assert (
        steps[0]["with"]["clean"] == "false" and steps[0]["with"]["persist-credentials"] == "false"
    )
    preflight = next(s for s in steps if s.get("id") == "preflight")
    drift_step = next(s for s in steps if s.get("id") == "drift")
    collect = next(s for s in steps if s.get("name") == "Persist admitted monitoring snapshot")
    deliver = next(s for s in steps if "--deliver" in s.get("run", ""))
    assert set(preflight["env"]) == set(collect["env"]) == {"GH_TOKEN"}
    assert "drift_admitted" in drift_step["if"] and "AWS_SECRET_ACCESS_KEY" in drift_step["env"]
    assert (
        set(deliver["env"]) == {"GH_TOKEN", "MONITOR_DELIVERY_TOKEN"}
        and "always()" in deliver["if"]
    )
    watch = workflow["jobs"]["watchdog"]
    assert (
        watch["runs-on"] == "ubuntu-24.04"
        and watch["needs"] == "verify"
        and watch["environment"] == "monitor-watchdog"
    )
    assert "AWS_" not in json.dumps(watch) and "PULUMI_CONFIG_PASSPHRASE" not in json.dumps(watch)
    assert all(
        "MONITORING_ENABLED" in workflow["jobs"][k]["if"] for k in ("verify", "observe", "watchdog")
    )


def test_missing_state_is_not_automatically_reinitialized(runner):
    root, source, _, _, calls, _ = runner
    i.Store(root, source["MONITOR_UNIT"]).path.unlink()
    with pytest.raises(ValueError):
        m.preflight(root, source)
    with pytest.raises(ValueError):
        m.collect(root, source)
    assert "drift-execute" not in calls and "health-observe" not in calls


def test_initialization_is_explicit_manual_only_and_never_overwrites(runner):
    root, source, _, _, _, _ = runner
    with pytest.raises(ValueError):
        m.initialize(root, source)
    source["MONITOR_ALLOW_INITIALIZE"] = "true"
    with pytest.raises(ValueError):
        m.initialize(root, source)
    i.Store(root, source["MONITOR_UNIT"]).path.unlink()
    source["GITHUB_EVENT_NAME"] = "schedule"
    with pytest.raises(ValueError):
        m.initialize(root, source)
    source["GITHUB_EVENT_NAME"] = "workflow_dispatch"
    m.initialize(root, source)
    state = i.Store(root, source["MONITOR_UNIT"]).read(m.catalog(root, source)[1])
    assert state["phase"] == "idle" and state["last_observed_at"] is None


def test_wrong_durable_host_fails_before_observation_or_tokens(runner, monkeypatch):
    root, source, _, _, calls, _ = runner
    monkeypatch.setattr(m, "host_id", lambda: "0" * 64)
    with pytest.raises(ValueError):
        m.preflight(root, source)
    assert calls == []


def test_rejected_drift_cannot_turn_a_leftover_clean_result_into_fresh_health(runner, monkeypatch):
    root, source, _, _, _, report = runner

    def rejected(*args):
        (root / ".infra/drift-result.json").write_text(json.dumps(report("drift")))
        raise ValueError("PRIVATE rejection")

    monkeypatch.setattr(drift, "execute", rejected)
    m.run_drift(root, source, lambda: pytest.fail("credentials"))
    result = m.collect(root, source)
    assert not result["sources"]["drift"]["available"] and result["severity"] == "unknown"
