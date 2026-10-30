"""Real pinned encrypted checkpoint recovery, only disposable filesystem state."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml
from infra_core import recovery_rehearsal
from infra_program import preview_runtime
from infra_program import recovery_driver as r

ROOT = Path(__file__).resolve().parents[1]
STACK = "organization/free-infrastructure/cloudflare-edge"
OPT_IN = pytest.mark.skipif(
    os.environ.get("RUN_OPERATION_INTEGRATION") != "1",
    reason="opt-in disposable checkpoint restore",
)


@pytest.mark.operation_integration
@OPT_IN
@pytest.mark.parametrize("wrong_key", [False, True])
def test_real_encrypted_restore_and_pair_publication(tmp_path, monkeypatch, wrong_key):
    work = tmp_path / "source"
    (work / "bin").mkdir(parents=True)
    source = ROOT / ".infra/tools/pulumi"
    pin = json.loads((ROOT / "config/toolchain.json").read_bytes())["tools"]["pulumi"]["assets"][
        "linux-x64"
    ]
    assert hashlib.sha256((source / "pulumi").read_bytes()).hexdigest() == pin["binary_sha256"]
    for path in source.iterdir():
        if path.is_file():
            shutil.copy2(path, work / "bin" / path.name)
    files = tuple(
        (p.name, p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
        for p in (work / "bin").iterdir()
    )
    cli = preview_runtime.CliRuntime(work / "bin/pulumi", files, preview_runtime._PERMIT)
    backend = tmp_path / "backend"
    backend.mkdir()
    env = dict(
        HOME=str(work),
        PULUMI_HOME=str(work / "home"),
        PULUMI_BACKEND_URL=backend.as_uri(),
        PULUMI_CONFIG_PASSPHRASE="synthetic-long-recovery-passphrase",
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
    project = json.dumps(
        dict(
            name="free-infrastructure",
            runtime=dict(name="python", options=dict(virtualenv=sys.prefix)),
        )
    )
    program = (
        "import pulumi\n"
        'pulumi.ComponentResource("infrastructure:services:Independent", "fixture", {}, '
        "pulumi.ResourceOptions(protect=True))\n"
        'pulumi.export("synthetic", pulumi.Config().require_secret("sentinel"))\n'
    )
    (work / "Pulumi.yaml").write_text(project)
    (work / "__main__.py").write_text(program)

    def run(args):
        result = subprocess.run(
            [str(cli.binary), *args, "--non-interactive"],
            cwd=work,
            env=env,
            capture_output=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr.decode()
        return result.stdout

    run(["stack", "init", "cloudflare-edge", "--secrets-provider", "passphrase"])
    run(["config", "set", "sentinel", "PRIVATE-OLD", "--secret", "--stack", STACK])
    run(["up", "--yes", "--skip-preview", "--stack", STACK])
    writer = r.Writer(cli, work, env, STACK, time.monotonic() + 180, backend.as_uri())
    saved = writer.export()
    configuration = json.dumps(
        yaml.safe_load((work / "Pulumi.cloudflare-edge.yaml").read_text())
    ).encode()
    run(["config", "set", "sentinel", "PRIVATE-NEW", "--secret", "--stack", STACK])
    run(["up", "--yes", "--skip-preview", "--stack", STACK])
    current = writer.export()
    assert saved != current and b"PRIVATE" not in saved + current + configuration

    def local(name, checkpoint, key):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "Pulumi.yaml").write_text(project)
        (directory / "__main__.py").write_text(program)
        (directory / "stack.yaml").write_bytes(configuration)
        observer = r.Observer(
            cli,
            directory,
            dict(
                env,
                PULUMI_HOME=str(directory / "home"),
                HOME=str(directory),
                PULUMI_CONFIG_PASSPHRASE=key,
            ),
            STACK,
            time.monotonic() + 90,
        )
        observer.load("cloudflare-edge", checkpoint)
        return observer

    observer = local("before", saved, env["PULUMI_CONFIG_PASSPHRASE"])
    baseline = observer.checkpoint()
    if wrong_key:
        observer._transport.env["PULUMI_CONFIG_PASSPHRASE"] = "wrong-synthetic-passphrase"
        with pytest.raises(ValueError):
            observer.key_check()
        assert writer.export() == current
        return
    observer.key_check()
    for stage in (observer.refresh, observer.compare):
        assert set(stage()["resource_changes"]) <= {"same", "read"}
    assert observer.checkpoint() == baseline and writer.export() == current
    (work / "restore.json").write_bytes(saved)
    writer.restore(work / "restore.json")
    destination = tmp_path / "recovered-config.json"
    r.publish(destination, configuration)
    restored = writer.export()
    assert destination.read_bytes() == configuration
    assert destination.stat().st_mode & 0o777 == 0o600
    after = local("after", restored, env["PULUMI_CONFIG_PASSPHRASE"])
    after.key_check()
    assert after.verified_deployment_sha256 == observer.verified_deployment_sha256
    for stage in (after.refresh, after.compare):
        assert set(stage()["resource_changes"]) <= {"same", "read"}
    assert writer.export() == restored
    # Verify the selected immutable three-file restic snapshot, not a filesystem copy.
    restic = recovery_rehearsal._tool(ROOT, "restic")
    repository = tmp_path / "repository"
    password = tmp_path / "password"
    password.write_text("synthetic-backup-password")
    restic_env = dict(
        RESTIC_REPOSITORY=str(repository),
        RESTIC_PASSWORD_FILE=str(password),
        RESTIC_CACHE_DIR=str(tmp_path / "cache"),
        GOMAXPROCS="2",
    )

    def restic_run(args):
        result = subprocess.run(
            [str(restic), *args], env=restic_env, capture_output=True, timeout=60
        )
        assert result.returncode == 0, result.stderr.decode()
        return result.stdout

    restic_run(["init"])
    repository_id = json.loads(restic_run(["cat", "config"]))["id"]
    capture = tmp_path / "capture"
    capture.mkdir()
    manifest = b'{"schema_version":2}'
    for name, raw in (
        ("manifest.json", manifest),
        ("checkpoint.json", saved),
        ("stack-config.json", configuration),
    ):
        (capture / name).write_bytes(raw)
    summaries = [
        json.loads(line) for line in restic_run(["backup", "--json", str(capture)]).splitlines()
    ]
    snapshot = next(v["snapshot_id"] for v in summaries if v.get("message_type") == "summary")
    monkeypatch.setattr(r.backup, "executable", lambda root: restic)
    retrieved = tmp_path / "retrieval"
    retrieved.mkdir()
    r.retrieve(
        ROOT,
        dict(repository=str(repository)),
        dict(
            restore_receipt=json.dumps(
                dict(snapshot_id=snapshot, repository_id=repository_id)
            ).encode(),
            restore_manifest=manifest,
            restore_checkpoint=saved,
            restore_configuration=configuration,
        ),
        retrieved,
        password.read_text(),
        time.monotonic() + 60,
    )


@pytest.mark.operation_integration
@OPT_IN
def test_checkpoint_import_never_creates_a_missing_stack(tmp_path):
    # Existing closed engine must reject missing target before importing even valid empty state.
    cli = recovery_rehearsal._tool(ROOT, "pulumi")
    (tmp_path / "backend").mkdir()
    (tmp_path / "Pulumi.yaml").write_text('{"name":"free-infrastructure","runtime":"python"}')
    path = tmp_path / "restore.json"
    path.write_text('{"version":3,"deployment":{"resources":[]}}')
    env = dict(
        HOME=str(tmp_path),
        PULUMI_HOME=str(tmp_path / "home"),
        PULUMI_BACKEND_URL=(tmp_path / "backend").as_uri(),
        PULUMI_CONFIG_PASSPHRASE="synthetic-long-passphrase",
        PULUMI_SKIP_UPDATE_CHECK="true",
    )
    result = subprocess.run(
        [str(cli), "stack", "import", "--stack", STACK, "--file", str(path), "--non-interactive"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert not list((tmp_path / "backend").rglob("cloudflare-edge.json"))
