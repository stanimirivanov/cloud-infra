"""Read-only monitoring commissioning checks retain uncertainty and durable history."""

import json
from datetime import timedelta

import pytest
from infra_core import cli, incidents
from infra_core import monitoring_readiness as m
from test_incidents import BINDING, KEY, NOW, cycle, samples

COMMIT = "a" * 40


@pytest.fixture(params=sorted(incidents.UNITS))
def bundle(request, tmp_path, monkeypatch):
    unit = request.param
    path = tmp_path / f".infra/monitoring/state/{unit}.json"
    path.parent.mkdir(parents=True)
    value = cycle(incidents.empty(unit, BINDING))
    path.write_text(json.dumps(value))
    monkeypatch.setattr(m, "repository_state", lambda root: (COMMIT, True))
    return tmp_path, path, value


def check(bundle, **kwargs):
    root, path, value = bundle
    return m.check(
        root,
        **(
            dict(
                unit=path.stem,
                binding_sha256=BINDING,
                heartbeat_seconds=60,
                now=NOW + timedelta(seconds=2),
            )
            | kwargs
        ),
    )


def test_fresh_normal_never_authorizes_or_writes(bundle):
    root, _, _ = bundle
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = check(bundle)
    assert result["status"] == "pending" and result["gaps"] == []
    assert result["state_evidence"] == "inputs-consistent"
    assert not any(
        result[k]
        for k in (
            "activation_authorized",
            "execution_authorized",
            "live_controls_verified",
        )
    )
    assert KEY not in json.dumps(result)
    assert before == {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize(
    "fault,gap",
    [
        ("missing", "state-missing"),
        ("idle", "state-unobserved"),
        ("running", "unfinished-run-requires-reconciliation"),
        ("overdue", "heartbeat-overdue"),
        ("stricter-deadline", "heartbeat-overdue"),
        ("unknown", "unknown-findings"),
        ("unavailable", "source-unavailable"),
        ("critical", "active-incident"),
        ("pending", "outbox-pending"),
        ("delivery", "delivery-error"),
    ],
)
def test_pending_conditions_are_visible_without_mutation(bundle, fault, gap):
    root, path, value = bundle
    now = NOW + timedelta(seconds=2)
    if fault == "idle":
        value = incidents.empty(value["unit"], BINDING)
    elif fault == "running":
        value = incidents.begin(value, 2, "102", now)
    elif fault == "overdue":
        now += timedelta(seconds=61)
    elif fault == "stricter-deadline":
        value["next_due_at"] = (NOW + timedelta(seconds=1.5)).isoformat()
    elif fault in {"unknown", "unavailable"}:
        observations = samples()
        observations["cost"] = incidents.source(fault != "unavailable", {KEY: "unknown"})
        value = cycle(value, seconds=2, observations=observations)
    elif fault in {"critical", "pending", "delivery"}:
        value = cycle(value, "critical", seconds=2)
        value["delivery_error"] = fault == "delivery"
    path.write_text(json.dumps(value))
    if fault == "missing":
        path.unlink()
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert gap in check(bundle, now=now)["gaps"]
    assert before == {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize(
    "fault",
    [
        "binding",
        "unit",
        "future",
        "duplicate",
        "oversize",
        "symlink",
        "parent-symlink",
        "dirty",
        "changed",
        "commit-change",
        "missing-created",
        "schema",
        "invalid-event",
    ],
)
def test_invalid_or_changed_snapshot_is_rejected(bundle, monkeypatch, fault):
    root, path, value = bundle
    if fault == "binding":
        value["binding"] = "c" * 64
    elif fault == "unit":
        value["unit"] = next(u for u in incidents.UNITS if u != value["unit"])
    elif fault == "future":
        value["last_observed_at"] = (NOW + timedelta(seconds=30)).isoformat()
    elif fault == "schema":
        value["schema_version"] = True
    elif fault == "invalid-event":
        value["pending"] = [{"PRIVATE": "PRIVATE"}]
    path.write_text(json.dumps(value))
    if fault == "duplicate":
        path.write_text('{"unit":"PRIVATE","unit":"PRIVATE"}')
    elif fault == "oversize":
        path.write_bytes(b" " * (1024 * 1024 + 1))
    elif fault == "symlink":
        target = root / ".infra/target.json"
        path.rename(target)
        path.symlink_to(target)
    elif fault == "parent-symlink":
        directory = path.parent
        target = root / ".infra/other"
        directory.rename(target)
        directory.symlink_to(target)
    elif fault == "dirty":
        monkeypatch.setattr(m, "repository_state", lambda root: (COMMIT, False))
    elif fault in {"changed", "commit-change", "missing-created"}:
        if fault == "missing-created":
            path.unlink()
        calls = []

        def state(root):
            calls.append(1)
            if len(calls) == 2:
                if fault == "commit-change":
                    return "b" * 40, True
                path.write_text(json.dumps(value) + " ")
            return COMMIT, True

        monkeypatch.setattr(m, "repository_state", state)
    with pytest.raises(ValueError, match="^" + m.MESSAGE + "$"):
        check(bundle)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"unit": "../other"},
        {"binding_sha256": "PRIVATE"},
        {"heartbeat_seconds": True},
        {"heartbeat_seconds": 0},
        {"heartbeat_seconds": 3601},
        {"now": NOW.replace(tzinfo=None)},
    ],
)
def test_expected_context_is_strict(bundle, kwargs):
    with pytest.raises(ValueError, match="MONREADY001"):
        check(bundle, **kwargs)


def test_cli_reports_pending_and_invalid_without_private_diagnostics(bundle, monkeypatch, capsys):
    root, path, value = bundle
    monkeypatch.setattr(cli, "find_repository", lambda _: root)
    # No state never initializes or locks. This does not depend on a fixture clock.
    path.unlink()
    args = [
        "monitoring",
        "check-readiness",
        "--unit",
        value["unit"],
        "--binding-sha256",
        BINDING,
        "--heartbeat-seconds",
        "60",
    ]
    assert cli.main(args) == 1
    assert json.loads(capsys.readouterr().out)["gaps"] == ["state-missing"]
    assert not path.exists()
    path.write_text('{"PRIVATE":"PRIVATE"}')
    assert cli.main(args) == 1
    output = capsys.readouterr()
    assert "MONREADY001" in output.err and "PRIVATE" not in output.err + output.out
