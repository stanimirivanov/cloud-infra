"""Cross-process failure sequences; runtime/cloud/remote effects are synthetic.

Production drivers, signed recovery admission, locks, journals and incident storage
remain real. Linux fork inherits fixture scaffolding; each child clears its environment.
The existing runtime suites separately exercise pinned Pulumi and restic engines.
"""

import json
import multiprocessing
import os
from datetime import timedelta
from pathlib import Path

import pytest
import test_monitoring as monitor_cases
import test_recovery_driver as recovery_cases
import test_service_apply as apply_cases
import yaml
from infra_core import incidents, operations
from infra_program import monitoring, service_apply
from infra_program import recovery_driver as recovery

ROOT = Path(__file__).resolve().parents[1]
config = recovery_cases.config
case = recovery_cases.case
prepared = recovery_cases.prepared
monitor_runner = monitor_cases.runner
CRASH = 73


def child(action, *, expected=0):
    """Bound and reap every child, including a failure before the intended crash."""

    def isolated():
        os.environ.clear()
        action()

    process = multiprocessing.get_context("fork").Process(target=isolated)
    process.start()
    try:
        process.join(15)
        assert not process.is_alive(), "failure rehearsal exceeded its process deadline"
        assert process.exitcode == expected
    finally:
        if process.is_alive():
            process.terminate()
            process.join(2)
        if process.is_alive():
            process.kill()
            process.join(2)
        assert not process.is_alive()
        process.close()


def effect(path, value):
    """A durable synthetic external effect, independent of the driver journal."""
    with path.open("ab") as stream:
        stream.write(value + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


@pytest.mark.operation_integration
@pytest.mark.skipif(os.environ.get("RUN_OPERATION_INTEGRATION") != "1", reason="opt-in rehearsal")
@pytest.mark.parametrize(
    "unit,importing",
    [(u, False) for u in sorted(incidents.UNITS)] + [(u, True) for u in ("oci-network", "oci-oke")],
)
@pytest.mark.parametrize("ack", ["runtime", "receipt"])
def test_mutation_crash_restart_does_not_repeat_uncertain_effect(
    tmp_path, monkeypatch, unit, importing, ack
):
    args, bundle, credentials, _, oci = apply_cases.prepare_lifecycle(
        tmp_path, monkeypatch, unit, None, importing
    )
    from infra_program import import_driver

    runtime = import_driver.ImportRuntime if importing else service_apply.Runtime
    marker = tmp_path / ".infra/synthetic-effect"

    class Interrupted(runtime):
        def operation(self, *, preview):
            result = super().operation(preview=preview)
            if not preview:
                effect(marker, b"import" if importing else b"apply")
                if ack == "runtime":
                    os._exit(CRASH)
            return result

    monkeypatch.setattr(service_apply, "Runtime", Interrupted)
    monkeypatch.setattr(import_driver, "ImportRuntime", Interrupted)
    journal = operations.journal

    def lose_receipt(*args, **kwargs):
        head = journal(*args, **kwargs)
        if args[3] == "succeeded":
            os._exit(CRASH)
        return head

    if ack == "receipt":
        monkeypatch.setattr(operations, "journal", lose_receipt)
    child(
        lambda: service_apply.execute(tmp_path, args, credentials, oci, importing), expected=CRASH
    )
    saved = args.journal.read_bytes()
    assert operations.inspect_journal(args.journal)["state"] == (
        "running" if ack == "runtime" else "succeeded"
    )
    assert not Path(bundle["output"]).exists()

    def restart():
        # Even synthetic admission cannot bypass durable lifecycle/CAS on restart.
        with pytest.raises(ValueError, match="APPLY001"):
            service_apply.execute(
                tmp_path, args, lambda: pytest.fail("replayed keys"), oci, importing
            )

    child(restart)
    assert args.journal.read_bytes() == saved
    assert marker.read_bytes().splitlines() == [b"import" if importing else b"apply"]


@pytest.mark.operation_integration
@pytest.mark.skipif(os.environ.get("RUN_OPERATION_INTEGRATION") != "1", reason="opt-in rehearsal")
@pytest.mark.parametrize("scenario", ["complete", "interrupted", "stale"])
def test_signed_recovery_freeze_survives_process_boundaries(prepared, monkeypatch, scenario):
    root, args, bundle, raw, _, _ = prepared
    real_admit = recovery.admit
    credentials, _ = recovery_cases.prepare_lifecycle(prepared, monkeypatch, None)
    # Fixture adapters replace provider/runtime work; actual two-role signatures,
    # ownership provenance, freeze and execution binding remain verified here.
    monkeypatch.setattr(recovery, "admit", real_admit)
    monkeypatch.setattr(recovery.preview, "_checkout", lambda root: None)
    marker = root / ".infra/synthetic-effect"
    writer = recovery.Writer

    class Recorded(writer):
        def restore(self, path):
            super().restore(path)
            effect(marker, b"restore")
            if scenario == "interrupted":
                os._exit(CRASH)

    monkeypatch.setattr(recovery, "Writer", Recorded)
    freeze = (root / bundle["paths"]["freeze"]).read_bytes()
    child(lambda: recovery.check(root, args))  # Independent credential-free review process.
    if scenario == "stale":
        saved = args.journal.read_bytes()
        admit = recovery.operation_admission.admit
        late = operations._time(json.loads(raw["approval"])["expires_at"]) + timedelta(seconds=1)

        def expired(*a, **kw):
            return admit(*a, **kw, now=late)

        monkeypatch.setattr(recovery.operation_admission, "admit", expired)

        def reject():
            with pytest.raises(ValueError, match="RESTORE001"):
                recovery.execute(root, args, lambda: pytest.fail("stale keys"))

        child(reject)
        assert args.journal.read_bytes() == saved and not marker.exists()
    else:
        child(
            lambda: recovery.execute(root, args, credentials),
            expected=CRASH if scenario == "interrupted" else 0,
        )
        saved = args.journal.read_bytes()
        assert operations.inspect_journal(args.journal)["state"] == (
            "running" if scenario == "interrupted" else "succeeded"
        )

        def restart():
            with pytest.raises(ValueError, match="RESTORE001"):
                recovery.execute(root, args, lambda: pytest.fail("replayed recovery keys"))

        child(restart)
        assert args.journal.read_bytes() == saved and marker.read_bytes() == b"restore\n"
        if scenario == "complete":
            report = json.loads((root / bundle["output"]).read_bytes())
            assert report["reconciliation_verified"] and report["configuration_published"]
            assert (
                not report["writer_release_authorized"] and not report["freeze_release_attempted"]
            )
        else:
            assert not (root / bundle["output"]).exists()
            assert not (root / bundle["configuration_destination"]).exists()
    assert (root / bundle["paths"]["freeze"]).read_bytes() == freeze


@pytest.mark.operation_integration
@pytest.mark.skipif(os.environ.get("RUN_OPERATION_INTEGRATION") != "1", reason="opt-in rehearsal")
def test_monitor_outage_restart_retains_incident_and_outbox(monitor_runner, monkeypatch):
    root, source, config, _, _, report = monitor_runner
    config["delivery_enabled"] = True
    (root / monitoring.POLICY).write_bytes(operations.encoded(config))
    source["MONITOR_DELIVERY_ENABLED"] = "true"

    def critical(*args):
        value = report("cost")
        value["findings"][0]["status"] = "critical"
        return value

    monkeypatch.setattr(monitoring.operational_findings, "check", critical)

    def first_run():
        monitoring.run_drift(root, source, lambda: {"fixture": "credential"})
        monitoring.collect(root, source)

    child(first_run)
    _, binding, _ = monitoring.catalog(root, source)
    store = incidents.Store(root, source["MONITOR_UNIT"])
    known = store.read(binding)
    assert known["severity"] == "critical" and len(known["pending"]) == 1
    source.update(GITHUB_RUN_ID="102", GITHUB_RUN_NUMBER="2")
    (root / ".infra/drift-result.json").unlink()
    monkeypatch.setattr(
        monitor_cases.drift,
        "execute",
        lambda *a: os._exit(CRASH),
    )
    child(lambda: monitoring.run_drift(root, source, lambda: pytest.fail("keys")), expected=CRASH)
    stopped = store.path.read_bytes()

    def restart():
        with pytest.raises(ValueError):
            monitoring.run_drift(root, source, lambda: pytest.fail("replayed monitor keys"))
        with pytest.raises(ValueError):
            monitoring.collect(root, source)

    child(restart)
    assert store.path.read_bytes() == stopped
    assert store.read(binding)["pending"] == known["pending"]
    # Independent watchdog transport outage cannot refresh the durable observation.
    source["MONITOR_ENVIRONMENT"] = "monitor-watchdog"

    class Unreachable:
        def __init__(self, *args):
            pass

        def heartbeats(self, **kwargs):
            raise OSError("synthetic transport outage")

    monkeypatch.setattr(monitoring, "GitHub", Unreachable)

    def watchdog():
        result = monitoring.watchdog(root, source)
        assert set(result) == incidents.UNITS and set(result.values()) == {"unknown"}

    child(watchdog)
    assert store.path.read_bytes() == stopped
    remote = root / ".infra/synthetic-remote-issue"

    def lost_ack():
        with store.locked():

            def send(event):
                effect(remote, event["id"].encode())
                os._exit(CRASH)

            store.deliver(store.read(binding), send)

    child(lost_ack, expected=CRASH)
    assert store.read(binding)["pending"] == known["pending"]

    def reconcile_ack():
        with store.locked():

            def send(event):
                # Fake remote recognizes the durable ID; real GitHub marker lookup
                # and pagination are covered by test_monitor_delivery.py.
                assert remote.read_bytes() == (event["id"] + "\n").encode()

            store.deliver(store.read(binding), send)

    child(reconcile_ack)
    result = store.read(binding)
    assert not result["pending"] and result["severity"] == "critical"
    assert result["phase"] == "running" and result["last_observed_at"] == known["last_observed_at"]
    assert remote.read_bytes().splitlines() == [known["pending"][0]["id"].encode()]


def test_ci_requires_final_failure_rehearsal_without_credentials():
    workflow = yaml.load(
        (ROOT / ".github/workflows/verify.yml").read_text(), Loader=yaml.BaseLoader
    )
    steps = workflow["jobs"]["verify"]["steps"]
    step = next(
        s
        for s in steps
        if s.get("name") == "Rehearse interrupted operations and acceptance boundaries (no cloud)"
    )
    assert step["env"] == {"RUN_OPERATION_INTEGRATION": "1"}
    assert "tests/test_operations_integration.py" in step["run"] and "if" not in step
    assert "secrets." not in json.dumps(step)
    assert not workflow["jobs"]["verify"].get("environment")
    protocol = next(s for s in steps if "-m operation_integration --ignore=" in s.get("run", ""))
    assert "--ignore=tests/test_operations_integration.py" in protocol["run"]
    assert "if" not in protocol and steps.index(protocol) < steps.index(step)
