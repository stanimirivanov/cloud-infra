"""Grouped observations, conservative recovery and crash-safe retryable outbox."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from infra_core import incidents as i
from infra_core import operations

NOW = datetime(2026, 10, 29, tzinfo=UTC)
UNIT = "oci-network"
BINDING = "b" * 64
KEY = "a" * 64


def samples(level="normal"):
    return {
        name: i.source(True, {KEY: level if name == "cost" else "normal"}) for name in i.SOURCES
    }


def cycle(state, level="normal", *, number=None, seconds=1, delivery=True, observations=None):
    number = number or state["run_number"] + 1
    instant = NOW + timedelta(seconds=seconds)
    started = i.begin(state, number, str(100 + number), instant)
    return i.commit(
        started,
        samples(level) if observations is None else observations,
        now=instant,
        heartbeat_seconds=60,
        delivery=delivery,
    )


def test_group_dedup_severity_recovery_and_duplicate_run():
    state = i.empty(UNIT, BINDING)
    state = cycle(state)
    assert state["pending"] == [] and state["severity"] == "normal"
    state = cycle(state, "warning", seconds=2)
    first = state["pending"][0]
    assert first["transition"] == "open"
    repeated = cycle(state, "warning", seconds=3)
    assert repeated["generation"] == state["generation"] and repeated["pending"] == state["pending"]
    assert (
        i.begin(repeated, repeated["run_number"], repeated["run_id"], NOW + timedelta(seconds=4))
        is None
    )
    changed = cycle(repeated, "critical", seconds=4)
    assert changed["pending"][-1]["transition"] == "change"
    recovery = cycle(changed, "normal", seconds=5)
    assert recovery["pending"][-1]["transition"] == "recovery" and recovery["severity"] == "normal"
    assert recovery["sources"]["cost"]["values"][KEY] == "normal"


@pytest.mark.parametrize("fault", ["missing-source", "missing-metric", "unknown-metric"])
def test_absence_and_unknown_cannot_clear_known_critical(fault):
    state = cycle(i.empty(UNIT, BINDING), "critical")
    observations = samples()
    if fault == "missing-source":
        observations["cost"] = i.source(False, {})
    elif fault == "missing-metric":
        observations["cost"] = i.source(True, {"c" * 64: "normal"})
    else:
        observations["cost"] = i.source(True, {KEY: "unknown"})
    state = cycle(state, seconds=2, observations=observations)
    assert state["severity"] == "critical" and state["sources"]["cost"]["values"][KEY] == "critical"
    assert state["sources"]["cost"]["available"] is False
    assert cycle(state, seconds=3)["severity"] == "normal"


def test_report_only_activation_sends_current_baseline_not_suppressed_history():
    state = cycle(i.empty(UNIT, BINDING), "warning", delivery=False)
    assert not state["pending"] and state["generation"] == 1
    state = cycle(state, "critical", seconds=2, delivery=False)
    assert not state["pending"]
    state = cycle(state, "critical", seconds=3, delivery=True)
    assert len(state["pending"]) == 1 and state["pending"][0]["transition"] == "baseline"
    assert state["pending"][0]["severity"] == "critical"


def test_late_run_is_visible_until_next_fresh_run_and_replay_is_rejected():
    state = cycle(i.empty(UNIT, BINDING))
    state = cycle(state, seconds=62)
    assert state["severity"] == "unknown"
    assert cycle(state, seconds=63)["severity"] == "normal"
    with pytest.raises(ValueError):
        i.begin(state, 1, "101", NOW + timedelta(seconds=64))
    with pytest.raises(ValueError):
        i.begin(state, state["run_number"], "999", NOW + timedelta(seconds=64))


def test_interrupted_run_is_not_replayed_and_binding_cannot_change(tmp_path):
    store = i.Store(tmp_path, UNIT)
    assert not store.path.exists()
    with store.locked():
        state = i.begin(store.read(BINDING), 1, "101", NOW)
        store.save(state)
    with pytest.raises(ValueError):
        i.begin(store.read(BINDING), 1, "101", NOW)
    with pytest.raises(ValueError):
        store.read("c" * 64)
    assert store.path.stat().st_mode & 0o777 == 0o600


def test_failed_delivery_retains_pending_and_lost_ack_can_be_reconciled(tmp_path):
    remote = []
    store = i.Store(tmp_path, UNIT)
    with store.locked():
        state = cycle(store.read(BINDING), "critical")
        store.save(state)

        def fail(event):
            remote.append(event["id"])
            raise OSError("PRIVATE lost acknowledgement")

        with pytest.raises(ValueError, match="MON001"):
            store.deliver(state, fail)
        pending = store.read(BINDING)
        assert pending["delivery_error"] and pending["pending"] == state["pending"]

        def reconcile(event):
            assert event["id"] in remote

        done = store.deliver(pending, reconcile)
        assert not done["pending"] and not done["delivery_error"]


def test_atomic_failure_preserves_old_state_and_temporary_files_are_removed(tmp_path, monkeypatch):
    store = i.Store(tmp_path, UNIT)
    with store.locked():
        state = cycle(store.read(BINDING), "warning")
        store.save(state)
        before = store.path.read_bytes()
        monkeypatch.setattr(i.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("PRIVATE")))
        with pytest.raises(RuntimeError, match="MON002"):
            store.save(cycle(state, "critical", seconds=2))
        assert store.path.read_bytes() == before
        assert sorted(p.suffix for p in store.path.parent.iterdir()) == [".json", ".lock"]


def test_local_overlap_is_rejected_before_callbacks(tmp_path):
    first, second = i.Store(tmp_path, UNIT), i.Store(tmp_path, UNIT)
    with first.locked(), pytest.raises(ValueError, match="MON001"):
        with second.locked():
            pytest.fail("overlapping writer")


def test_outbox_is_bounded_and_never_silently_dropped():
    state = i.empty(UNIT, BINDING)
    for number in range(1, 129):
        state = cycle(state, "warning" if number % 2 else "critical", number=number, seconds=number)
    before = deepcopy(state)
    with pytest.raises(ValueError):
        cycle(state, "warning", seconds=130)
    assert state == before and len(state["pending"]) == 128


def producer(name, status="normal"):
    clock = NOW.isoformat()
    base = dict(
        schema_version=1, unit=UNIT, deployment_authorized=False, remediation_authorized=False
    )
    if name == "cost":
        return dict(
            base,
            kind="operational-findings",
            scope_sha256=BINDING,
            evaluated_at=clock,
            source_clocks=dict(observed_at=clock),
            findings=[dict(id="metric", status=status)],
        )
    if name == "health":
        return dict(
            base,
            kind="infrastructure-health",
            scope_sha256=BINDING,
            mode="observe",
            completed_at=clock,
            cluster_isolation_verified=False,
            cluster=[],
            endpoints=[
                dict(
                    id="endpoint",
                    source="remote-probe",
                    completed_at=clock,
                    status={"normal": "healthy", "critical": "unhealthy", "unknown": "unknown"}[
                        status
                    ],
                )
            ],
        )
    return dict(
        base,
        kind="isolated-drift",
        commit="a" * 40,
        production_state_write_authorized=False,
        started_at=clock,
        completed_at=clock,
        status={"normal": "clean", "critical": "drifted", "unknown": "unknown"}[status],
        source_unchanged=True,
        local_checkpoint_unchanged=True,
        journal_head=KEY,
        approval_sha256=KEY,
    )


@pytest.mark.parametrize("name", sorted(i.SOURCES))
@pytest.mark.parametrize("fault", [None, "missing", "stale", "unit", "authority", "scope"])
def test_producer_adapters_reject_wrong_scope_age_and_authority(name, fault):
    report = producer(name)
    if fault == "missing":
        report = None
    elif fault == "stale":
        if name == "cost":
            report["source_clocks"]["observed_at"] = (NOW - timedelta(seconds=901)).isoformat()
        elif name == "health":
            report["completed_at"] = (NOW - timedelta(seconds=901)).isoformat()
        else:
            report["started_at"] = (NOW - timedelta(seconds=901)).isoformat()
    elif fault == "unit":
        report["unit"] = "oci-oke"
    elif fault == "authority":
        report["remediation_authorized"] = True
    elif fault == "scope":
        if name == "drift":
            report["source_unchanged"] = False
        else:
            report["scope_sha256"] = "c" * 64
    result = i.normalize(
        name, report, unit=UNIT, scope_hash=BINDING, commit="a" * 40, now=NOW, max_age_seconds=900
    )
    assert result["available"] is (fault is None)
    if fault is None:
        assert set(result["values"].values()) == {"normal"}


def test_symlink_and_large_state_reject_without_following(tmp_path):
    path = tmp_path / ".infra/monitoring/state"
    path.mkdir(parents=True)
    outside = tmp_path / "PRIVATE"
    outside.write_bytes(b"PRIVATE")
    (path / (UNIT + ".json")).symlink_to(outside)
    with pytest.raises(ValueError):
        i.Store(tmp_path, UNIT)
    (path / (UNIT + ".json")).unlink()
    (path / (UNIT + ".json")).write_bytes(b"x" * (operations.MAX_BYTES + 1))
    with pytest.raises(ValueError):
        i.Store(tmp_path, UNIT).read(BINDING)


def test_original_source_clocks_are_retained_without_timestamp_only_alerts():
    reports = {
        name: producer(name, "critical" if name == "cost" else "normal") for name in i.SOURCES
    }
    reports["cost"]["usage_windows"] = {"month": "2026-10", "covered_through": NOW.isoformat()}
    observations = {
        name: i.normalize(
            name,
            value,
            unit=UNIT,
            scope_hash=BINDING,
            commit="a" * 40,
            now=NOW,
            max_age_seconds=900,
        )
        for name, value in reports.items()
    }
    first = cycle(i.empty(UNIT, BINDING), observations=observations)
    proof = first["sources"]["cost"]["evidence"]
    assert proof["source_clocks/observed_at"] == NOW.isoformat()
    assert proof["usage/covered_through"] == NOW.isoformat()
    second_samples = deepcopy(observations)
    second_samples["cost"]["evidence"]["report_sha256"] = "e" * 64
    second_samples["cost"]["evidence"]["report/evaluated_at"] = (
        NOW + timedelta(seconds=1)
    ).isoformat()
    second = cycle(first, observations=second_samples, seconds=2)
    assert second["generation"] == first["generation"] and second["pending"] == first["pending"]
    assert second["sources"]["cost"]["evidence"] == second_samples["cost"]["evidence"]
