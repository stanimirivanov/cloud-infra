"""Real SDK/process/gRPC boundary with a synthetic worker; no engine/provider/cloud."""

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_preview_results as receipts
import test_preview_runtime as fixtures
import yaml
from infra_core.foundation import load_foundation
from infra_core.preview_results import create_preview_result, validate_preview_result
from infra_program import preview_runtime as runtime

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    (unit, None) for unit in ("oci-network", "oci-oke", "cloudflare-edge", "supabase-database")
]
CASES += [
    ("oci-network", fault)
    for fault in (
        "no-policy",
        "no-terminal",
        "update",
        "diagnostic",
        "malformed",
        "oversize",
        "timeout",
    )
]


@pytest.mark.preview_integration
@pytest.mark.skipif(
    os.environ.get("RUN_SYNTHETIC_PREVIEW_INTEGRATION") != "1",
    reason="CI-only synthetic process/RPC integration",
)
@pytest.mark.parametrize("unit,fault", CASES)
def test_sdk_process_rpc_and_receipt_boundary(tmp_path, monkeypatch, capsys, unit, fault):
    # Fixture asset hashes replace release hashes only inside the synthetic root.
    root, archive, work = fixtures.prepared.__wrapped__(tmp_path, monkeypatch)
    cli = runtime.cli_runtime(root, archive, work / "bin")
    env = fixtures.environment(work)
    command = runtime.Command(
        cli,
        work,
        env,
        "organization/free-infrastructure/" + unit,
        ROOT / "policies",
        policy_configuration=b"{}",
    )
    command.deadline = time.monotonic() + 20
    workspace = runtime.auto.LocalWorkspace(
        work_dir=str(work), pulumi_home=env["PULUMI_HOME"], pulumi_command=command
    )
    calls, processes = [], []
    real_popen = subprocess.Popen

    def launch(argv, **options):
        # Only substitute the verified synthetic binary at the OS launch boundary.
        assert argv[0] == str(cli.binary)
        assert options["env"] == env and options["cwd"] == work
        assert options["stdout"] == options["stderr"] == subprocess.DEVNULL
        calls.append(argv)
        process = real_popen(
            [sys.executable, str(ROOT / "tests/fixtures/preview_cli.py"), *argv[1:]], **options
        )
        processes.append(process)
        return process

    monkeypatch.setattr(runtime.subprocess, "Popen", launch)
    stack = runtime.Stack.select(command.stack, workspace)
    assert type(stack) is runtime.Stack
    contract, artifacts, template = receipts.inputs.__wrapped__(SimpleNamespace(param=unit))
    started = datetime.now(UTC)
    events = [{"stdoutEvent": {"message": "SYNTHETIC_PRIVATE_EVENT"}}] + [
        json.loads(raw) for raw in template
    ]
    for sequence, event in enumerate(events):
        event.update(sequence=sequence, timestamp=int(started.timestamp()))
    if fault == "no-policy":
        events = [e for e in events if "policyAnalyzeSummaryEvent" not in e]
    elif fault == "no-terminal":
        events.pop()
    elif fault == "update":
        next(e["summaryEvent"] for e in events if "summaryEvent" in e)["isPreview"] = False
    elif fault == "diagnostic":
        events[0] = dict(
            sequence=0,
            timestamp=int(started.timestamp()),
            diagnosticEvent={"severity": "error", "message": "SYNTHETIC_PRIVATE_FAILURE"},
        )
    raw = [json.dumps(e, indent=1) for e in events]
    if fault == "malformed":
        raw = ["invalid synthetic JSON"]
    elif fault == "oversize":
        raw = ["x" * (runtime.MAX_EVENT_BYTES + 1024)]
    (work / "synthetic-events.json").write_text(
        json.dumps(dict(events=raw, hang=fault == "timeout"))
    )
    if fault == "timeout":
        command.deadline = time.monotonic() + 1
    receipt = None

    def preview():
        nonlocal receipt
        result = stack.preview(
            policy_packs=[str(ROOT / "policies")],
            policy_pack_configs=[str(work / "policy.json")],
            parallel=1,
            color="never",
            suppress_outputs=True,
            suppress_progress=True,
            refresh=False,
            config_file=str(work / "stack.yaml"),
        )
        assert result.change_summary == {"same": 1, "create": 2}
        end = datetime.now(UTC)
        receipt = create_preview_result(
            contract,
            artifacts,
            stack.wire.records,
            exit_code=0,
            started_at=started.isoformat(),
            completed_at=end.isoformat(),
            now=end,
        )

    try:
        if fault:
            with pytest.raises((RuntimeError, ValueError)) as error:
                preview()
            assert "SYNTHETIC_PRIVATE" not in str(error.value) and receipt is None
        else:
            preview()
            assert stack.wire.records == [r.encode() for r in raw]
            result = validate_preview_result(receipt, contract, artifacts, now=datetime.now(UTC))
            digest = hashlib.sha256()
            for record in stack.wire.records:
                digest.update(len(record).to_bytes(8, "big"))
                digest.update(record)
            assert result["events_sha256"] == digest.hexdigest()
            assert result["policy"]["passed_checks"] == 1
            assert result["deployment_authorized"] is result["cutover_authorized"] is False
            assert b"SYNTHETIC_PRIVATE" not in receipt
        assert len(calls) == 2 and all(process.poll() is not None for process in processes)
        assert calls[0][1:3] == ["stack", "select"] and calls[1][-1] == "--refresh=false"
        cli.verify()
    finally:
        # Test-owned fallback only; never leave a worker behind if an assertion fails.
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    captured = capsys.readouterr()
    assert "SYNTHETIC_PRIVATE" not in captured.out + captured.err
    assert all(not u.preview_enabled for u in load_foundation(ROOT).units)


def test_ci_requires_synthetic_preview_integration_on_existing_matrix():
    config = yaml.load((ROOT / ".github/workflows/verify.yml").read_text(), Loader=yaml.BaseLoader)
    job = config["jobs"]["verify"]
    assert set(job["strategy"]["matrix"]["os"]) == {"ubuntu-24.04"}
    step = next(
        s for s in job["steps"] if s.get("env", {}).get("RUN_SYNTHETIC_PREVIEW_INTEGRATION")
    )
    assert step["env"] == {"RUN_SYNTHETIC_PREVIEW_INTEGRATION": "1"}
    assert "if" not in step and "continue-on-error" not in step
    assert step["run"] == (
        "uv run --locked pytest -q -m preview_integration --basetemp .infra/pytest-preview "
        "-o cache_dir=.infra/pytest-cache"
    )
