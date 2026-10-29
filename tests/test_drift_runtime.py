"""Closed commands, synthetic provider failure/deletion and real source-preserving previews."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
import test_preview_runtime as fixtures
from infra_program import drift
from infra_program import operation_runtime as transport
from infra_program import preview_runtime as runtime

ROOT = Path(__file__).resolve().parents[1]
STACK = "organization/free-infrastructure/cloudflare-edge"
OPT_IN = pytest.mark.skipif(
    os.environ.get("RUN_OPERATION_INTEGRATION") != "1",
    reason="opt-in isolated drift engine/transport",
)


def test_observer_rejects_backend_credentials_and_remote_target(tmp_path):
    (tmp_path / "aws").mkdir()
    with pytest.raises(ValueError):
        drift.LocalObserver(None, tmp_path / "aws", {"AWS_ACCESS_KEY_ID": "synthetic"}, STACK, 0)
    (tmp_path / "local").mkdir()
    # Constructor's transport validation needs a valid CLI, so the explicit method
    # guard is exercised independently before a process can be launched.
    observer = object.__new__(drift.LocalObserver)
    observer.backend = tmp_path / "local"
    from types import SimpleNamespace

    observer._transport = SimpleNamespace(env={"PULUMI_BACKEND_URL": "s3://production"})
    with pytest.raises(ValueError):
        observer._local()


@pytest.mark.operation_integration
@OPT_IN
@pytest.mark.parametrize("fault", [None, "deleted", "exit", "timeout", "incomplete"])
def test_synthetic_refresh_transport_reaps_and_suppresses_raw_output(
    tmp_path, monkeypatch, capsys, fault
):
    root, archive, work = fixtures.prepared.__wrapped__(tmp_path, monkeypatch)
    cli = runtime.cli_runtime(root, archive, work / "bin")
    env = {k: v for k, v in fixtures.environment(work).items() if not k.startswith("AWS_")}
    observer = drift.LocalObserver(cli, work, env, STACK, time.monotonic() + 30)
    (work / "case.json").write_text(json.dumps(dict(fault=fault)))
    real = transport.subprocess.Popen
    processes = []

    def launch(argv, **options):
        assert options["env"]["PULUMI_BACKEND_URL"] == observer.backend.as_uri()
        assert not any(k.startswith("AWS_") for k in options["env"])
        process = real(
            [sys.executable, str(ROOT / "tests/fixtures/drift_cli.py"), *argv[1:]], **options
        )
        processes.append(process)
        return process

    monkeypatch.setattr(transport.subprocess, "Popen", launch)
    if fault == "timeout":
        observer._transport.deadline = time.monotonic() + 0.5
    if fault in {"exit", "timeout", "incomplete"}:
        with pytest.raises((ValueError, subprocess.TimeoutExpired)):
            observer.refresh()
    else:
        expected = {"delete": 1} if fault == "deleted" else {"same": 1}
        assert observer.refresh()["resource_changes"] == expected
        assert observer.compare()["resource_changes"] == expected
    assert processes and all(p.poll() is not None for p in processes)
    assert "SYNTHETIC_PRIVATE_OUTPUT" not in str(capsys.readouterr())


@pytest.mark.operation_integration
@OPT_IN
@pytest.mark.parametrize("changed", [False, True])
def test_real_local_refresh_and_policy_comparison_preserve_source(tmp_path, changed):
    work = tmp_path / "source"
    (work / "bin").mkdir(parents=True)
    source = ROOT / ".infra/tools/pulumi"
    pin = json.loads((ROOT / "config/toolchain.json").read_bytes())["tools"]["pulumi"]
    assert (
        hashlib.sha256((source / "pulumi").read_bytes()).hexdigest()
        == pin["assets"]["linux-x64"]["binary_sha256"]
    )
    for path in source.iterdir():
        if path.is_file():
            shutil.copy2(path, work / "bin" / path.name)
    files = tuple(
        (p.name, p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
        for p in (work / "bin").iterdir()
    )
    cli = runtime.CliRuntime(work / "bin/pulumi", files, runtime._PERMIT)
    backend = tmp_path / "source-backend"
    backend.mkdir()
    env = dict(
        HOME=str(work),
        PULUMI_HOME=str(work / "home"),
        PULUMI_BACKEND_URL=backend.as_uri(),
        PULUMI_CONFIG_PASSPHRASE="synthetic-long-drift-passphrase",
        PULUMI_DEBUG_COMMANDS="true",
        PULUMI_SKIP_UPDATE_CHECK="true",
        PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION="true",
        PULUMI_IGNORE_AMBIENT_PLUGINS="true",
        PULUMI_PYTHON_CMD=sys.executable,
        UV_OFFLINE="1",
        PATH=os.pathsep.join(
            (str(Path(sys.executable).parent), str(work / "bin"), str(ROOT / ".infra/tools/uv"))
        ),
    )
    project = dict(
        name="free-infrastructure", runtime=dict(name="python", options=dict(virtualenv=sys.prefix))
    )
    (work / "Pulumi.yaml").write_text(json.dumps(project))
    program = (
        "import pulumi\n"
        'pulumi.ComponentResource("infrastructure:services:Independent", "fixture", {}, '
        "pulumi.ResourceOptions(protect=True))\n"
        'pulumi.export("synthetic", pulumi.Config().require_secret("sentinel"))\n'
    )
    (work / "__main__.py").write_text(program)
    for args in (
        ["stack", "init", "cloudflare-edge", "--secrets-provider", "passphrase"],
        ["config", "set", "sentinel", "PRIVATE-SYNTHETIC", "--secret", "--stack", STACK],
        ["up", "--yes", "--skip-preview", "--stack", STACK],
    ):
        completed = subprocess.run(
            [str(cli.binary), *args, "--non-interactive"],
            cwd=work,
            env=env,
            capture_output=True,
            timeout=120,
        )
        assert completed.returncode == 0, completed.stderr.decode()
    reader = drift.SourceReader(cli, work, env, STACK, time.monotonic() + 240)
    captured = reader.export(STACK)
    assert b"PRIVATE-SYNTHETIC" not in captured and b"ciphertext" in captured
    local = tmp_path / "local"
    local.mkdir()
    (local / "Pulumi.yaml").write_text(json.dumps(project))
    import yaml

    (local / "stack.yaml").write_text(
        json.dumps(yaml.safe_load((work / "Pulumi.cloudflare-edge.yaml").read_text()))
    )
    (local / "__main__.py").write_text(
        program
        + (
            'pulumi.ComponentResource("infrastructure:services:Independent", "added", {}, '
            "pulumi.ResourceOptions(protect=True))\n"
            if changed
            else ""
        )
    )
    local_env = dict(env, HOME=str(local), PULUMI_HOME=str(local / "home"))
    observer = drift.LocalObserver(cli, local, local_env, STACK, time.monotonic() + 180)
    observer.load("cloudflare-edge", captured)
    baseline = observer.checkpoint()
    refresh, comparison = observer.refresh(), observer.compare()
    assert refresh["resource_changes"].get("same", 0) > 0
    assert comparison["policy_checks"] > 0
    if changed:
        assert comparison["resource_changes"].get("create", 0) > 0
    else:
        assert set(comparison["resource_changes"]) <= {"same", "read"}
    assert observer.checkpoint() == baseline
    assert reader.export(STACK) == captured
    with pytest.raises(ValueError):
        reader.export("organization/free-infrastructure/supabase-database")
