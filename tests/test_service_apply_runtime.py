"""Real process/RPC transport plus disposable-engine checks, never cloud service apply."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
import test_oci
import test_oci_dependency
import test_preview_runtime as fixtures
from infra_program import operation_runtime as operation
from infra_program import preview_runtime as preview

ROOT = Path(__file__).resolve().parents[1]
config = test_oci.config
OPT_IN = pytest.mark.skipif(
    os.environ.get("RUN_OPERATION_INTEGRATION") != "1", reason="opt-in apply transport/engine"
)


@pytest.mark.operation_integration
@OPT_IN
@pytest.mark.parametrize("fault", [None, "exit", "timeout", "incomplete"])
def test_synthetic_apply_transport_reaps_and_discards_private_output(
    tmp_path, monkeypatch, capsys, fault
):
    root, archive, work = fixtures.prepared.__wrapped__(tmp_path, monkeypatch)
    cli = preview.cli_runtime(root, archive, work / "bin")
    env = fixtures.environment(work)
    adapter = operation.Runtime(
        cli, work, env, "organization/free-infrastructure/cloudflare-edge", ROOT / "policies"
    )
    (work / "plan.json").write_bytes(b"synthetic-plan")
    (work / "case.json").write_text(json.dumps({"fault": fault}))
    real = operation.subprocess.Popen
    processes = []

    def launch(argv, **options):
        assert argv[0] == str(cli.binary) and options["env"] == env
        process = real(
            [sys.executable, str(ROOT / "tests/fixtures/service_apply_cli.py"), *argv[1:]],
            **options,
        )
        processes.append(process)
        return process

    monkeypatch.setattr(operation.subprocess, "Popen", launch)
    adapter.select()
    assert adapter.checkpoint() == hashlib.sha256(b"synthetic-checkpoint").hexdigest()
    if fault == "timeout":
        adapter.deadline = time.monotonic() + 0.5
    if fault:
        with pytest.raises((ValueError, subprocess.TimeoutExpired)):
            adapter.operation(preview=False)
    else:
        assert adapter.operation(preview=True) == {"same": 1}
        assert adapter.operation(preview=False) == {"same": 1}
    assert all(p.poll() is not None for p in processes)
    assert "SYNTHETIC_PRIVATE_OUTPUT" not in str(capsys.readouterr())


@pytest.mark.operation_integration
@OPT_IN
@pytest.mark.parametrize("unit", ["cloudflare-edge", "oci-network"])
def test_real_cli_policy_plan_and_update_events(tmp_path, config, unit):
    source = ROOT / ".infra/tools/pulumi"
    pin = json.loads((ROOT / "config/toolchain.json").read_bytes())["tools"]["pulumi"]
    assert (
        hashlib.sha256((source / "pulumi").read_bytes()).hexdigest()
        == pin["assets"]["linux-x64"]["binary_sha256"]
    )
    work = tmp_path / "work"
    (work / "bin").mkdir(parents=True)
    for path in source.iterdir():
        if path.is_file():
            shutil.copy2(path, work / "bin" / path.name)
    files = tuple(
        (p.name, p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
        for p in (work / "bin").iterdir()
    )
    cli = preview.CliRuntime(work / "bin/pulumi", files, preview._PERMIT)
    backend = tmp_path / "backend"
    backend.mkdir()
    env = dict(
        HOME=str(work),
        PULUMI_HOME=str(work / "home"),
        PULUMI_BACKEND_URL=backend.as_uri(),
        PULUMI_CONFIG_PASSPHRASE="synthetic-passphrase-long-enough",
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
    (work / "Pulumi.yaml").write_text(
        json.dumps(
            dict(
                name="free-infrastructure",
                runtime=dict(name="python", options={"virtualenv": sys.prefix}),
            )
        )
    )
    (work / "__main__.py").write_text('import pulumi\npulumi.export("fixture", "synthetic")\n')
    if unit == "oci-network":
        outputs = test_oci_dependency.committed(config)
        (work / "__main__.py").write_text(
            "import pulumi\n"
            + "\n".join(
                "pulumi.export(" + repr(k) + ", " + repr(v) + ")" for k, v in outputs.items()
            )
        )
    (work / "stack.yaml").write_text('{"config":{}}')
    for args in (
        ["stack", "init", unit, "--secrets-provider", "passphrase"],
        [
            "preview",
            "--stack",
            unit,
            "--save-plan",
            str(work / "plan.json"),
            "--config-file",
            str(work / "stack.yaml"),
            "--policy-pack",
            str(ROOT / "policies"),
        ],
    ):
        subprocess.run(
            [str(cli.binary), *args, "--non-interactive"],
            cwd=work,
            env=env,
            capture_output=True,
            check=True,
            timeout=120,
        )
    stack = "organization/free-infrastructure/" + unit
    if unit == "cloudflare-edge":
        operation.validate_plan((work / "plan.json").read_bytes(), stack, pin["version"])
    adapter = operation.Runtime(cli, work, env, stack, ROOT / "policies")
    adapter.select()
    before = adapter.checkpoint()
    assert adapter.operation(preview=True).get("create") == 1
    assert adapter.operation(preview=False).get("create") == 1
    assert adapter.checkpoint() != before

    if unit == "oci-network":
        from infra_program.oci.dependencies import validate_network

        checkpoint, observed = adapter.network_outputs()
        assert checkpoint == adapter.checkpoint()
        assert observed == outputs
        validate_network(observed, config, outputs["network"]["account_id"])
        # Probe the pinned engine's saved-plan shape for the actual read-only reference.
        (work / "__main__.py").write_text(
            "import pulumi\n"
            'pulumi.StackReference("fixture-network-reference", '
            'stack_name="organization/free-infrastructure/oci-network", '
            "opts=pulumi.ResourceOptions(protect=True))\n"
        )
        for command in (
            ["stack", "init", "oci-oke", "--secrets-provider", "passphrase"],
            [
                "preview",
                "--stack",
                "oci-oke",
                "--save-plan",
                str(work / "reference-plan.json"),
                "--policy-pack",
                str(ROOT / "policies"),
            ],
        ):
            completed = subprocess.run(
                [str(cli.binary), *command, "--non-interactive"],
                cwd=work,
                env=env,
                capture_output=True,
                check=False,
                timeout=120,
            )
            assert completed.returncode == 0, completed.stdout.decode() + completed.stderr.decode()
        resources = json.loads((work / "reference-plan.json").read_bytes())["resourcePlans"]
        kinds = {r["goal"]["type"] for r in resources.values()}
        assert kinds == {"pulumi:pulumi:Stack", "pulumi:providers:pulumi"}
        provider = next(
            r for r in resources.values() if r["goal"]["type"] == "pulumi:providers:pulumi"
        )
        assert provider["goal"]["name"] == "default" and provider["goal"]["protect"] is False
