"""Pinned SDK transport and real local engine compatibility, with distinct evidence levels."""

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest
import semver
import yaml
from infra_core.backend import qualification_environment
from pulumi import automation as auto

ROOT = Path(__file__).resolve().parents[1]
PIN = json.loads((ROOT / "config/toolchain.json").read_text())["tools"]["pulumi"]["version"]
OPT_IN = pytest.mark.skipif(
    os.environ.get("RUN_OPERATION_INTEGRATION") != "1",
    reason="explicit disposable operation protocol opt-in",
)


class BoundedCommand(auto.PulumiCommand):
    """Test-only launch boundary; never used by a repository executor."""

    def __init__(self, argv, env):
        self.argv, self.env = argv, env
        self.version = semver.VersionInfo.parse(PIN)
        self.timeout = 120
        self.processes = []

    def run(self, args, cwd, additional_env, on_output=None, on_error=None):
        process = subprocess.Popen(
            [*self.argv, "--non-interactive", *args],
            cwd=cwd,
            env=self.env | dict(additional_env),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self.processes.append(process)
        try:
            stdout, stderr = process.communicate(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
            raise RuntimeError("synthetic operation deadline exceeded") from None
        self.last_output = stdout + stderr
        result = auto.CommandResult(stdout, stderr, process.returncode)
        if process.returncode:
            # Synthetic diagnostics must not escape a failed protocol boundary.
            raise RuntimeError("operation protocol command failed")
        return result


def workspace(path, command):
    path.mkdir(exist_ok=True)
    return auto.LocalWorkspace(
        work_dir=str(path), pulumi_home=command.env["PULUMI_HOME"], pulumi_command=command
    )


@pytest.mark.operation_integration
@OPT_IN
def test_sdk_saved_plan_update_event_and_import_transport(tmp_path):
    env = qualification_environment({"PATH": os.environ["PATH"]}, tmp_path / "home", local=True)
    command = BoundedCommand([sys.executable, str(ROOT / "tests/fixtures/operation_cli.py")], env)
    stack = auto.Stack.select("synthetic", workspace(tmp_path, command))
    case = tmp_path / "case.json"
    case.write_text("{}")
    plan = tmp_path / "plan.json"
    events = []
    stack.preview(plan=str(plan), refresh=False, on_event=events.append)
    assert plan.read_text() == "synthetic plan"
    assert any(e.summary_event and e.summary_event.resource_changes for e in events)
    assert all(not hasattr(e.summary_event, "is_preview") for e in events if e.summary_event)
    events.clear()
    result = stack.up(plan=str(plan), refresh=False, show_secrets=False, on_event=events.append)
    assert result.summary.result == "succeeded"
    assert any(e.summary_event and e.summary_event.resource_changes for e in events)
    resources = [
        {
            "type": "synthetic:index:Resource",
            "name": "fixture",
            "id": "id-1",
            "parent": "owner",
            "provider": "provider",
        }
    ]
    names = {"owner": "urn:synthetic:owner", "provider": "urn:synthetic:provider"}
    case.write_text(json.dumps({"mapping": {"resources": resources, "nameTable": names}}))
    result = stack.import_resources(
        resources=resources, name_table=names, protect=True, generate_code=False, show_secrets=False
    )
    assert result.summary.result == "succeeded"
    calls = [json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()]
    assert any(c[0] == "up" and "--plan" in c and "--refresh" not in c for c in calls)
    assert all(p.poll() == 0 for p in command.processes)


@pytest.mark.operation_integration
@OPT_IN
@pytest.mark.parametrize("fault", ["fail", "hang"])
def test_synthetic_failure_and_interruption_reap_process(tmp_path, fault):
    env = qualification_environment({"PATH": os.environ["PATH"]}, tmp_path / "home", local=True)
    command = BoundedCommand([sys.executable, str(ROOT / "tests/fixtures/operation_cli.py")], env)
    stack = auto.Stack.select("synthetic", workspace(tmp_path, command))
    (tmp_path / "case.json").write_text(json.dumps({fault: True}))
    command.timeout = 1 if fault == "hang" else 30
    with pytest.raises(RuntimeError) as error:
        stack.preview(plan=str(tmp_path / "plan.json"), refresh=False)
    assert "SYNTHETIC_PRIVATE_FAILURE" not in str(error.value)
    assert all(p.poll() is not None for p in command.processes)


@pytest.mark.operation_integration
@OPT_IN
def test_real_engine_plan_update_and_checkpoint_roundtrip(tmp_path):
    cli = ROOT / ".infra/tools/pulumi/pulumi"
    env = qualification_environment(
        {"PATH": os.environ["PATH"], "HOME": str(tmp_path)}, tmp_path / "home", local=True
    )
    version = subprocess.run(
        [str(cli), "version"], env=env, capture_output=True, text=True, check=True, timeout=15
    )
    assert version.stdout.strip() == "v" + PIN
    backend = tmp_path / "backend"
    backend.mkdir()
    env["PULUMI_BACKEND_URL"] = backend.as_uri()
    command = BoundedCommand([str(cli)], env)
    project = tmp_path / "project"
    project.mkdir()
    (project / "Pulumi.yaml").write_text(
        json.dumps(
            dict(
                name="operation-protocol",
                runtime=dict(name="python", options={"virtualenv": sys.prefix}),
            )
        )
    )
    program = project / "__main__.py"
    source = (
        "import pulumi\n"
        'r = pulumi.ComponentResource("synthetic:index:Fixture", "fixture")\n'
        'r.register_outputs({"value": "one"})\n'
        'pulumi.export("fixture_secret", pulumi.Output.secret("synthetic-private-value"))\n'
    )
    program.write_text(source)
    ws = workspace(project, command)
    stack = auto.Stack.create("synthetic", ws)
    plan = project / "plan.json"
    events = []
    stack.preview(plan=str(plan), refresh=False, on_event=events.append)
    assert plan.is_file()
    assert any(e.summary_event and e.summary_event.resource_changes for e in events)
    events.clear()
    stack.up(plan=str(plan), refresh=False, show_secrets=False, on_event=events.append)
    assert any(e.summary_event and e.summary_event.resource_changes for e in events)
    # SDK export_stack forces --show-secrets: it is NOT the encrypted backup API.
    encrypted = command.run(["stack", "export", "--stack", stack.name], str(project), {})
    assert "synthetic-private-value" not in encrypted.stdout
    checkpoint = stack.export_stack()
    assert "synthetic-private-value" in json.dumps(checkpoint.deployment)
    resources = checkpoint.deployment["resources"]
    assert any(r["type"] == "synthetic:index:Fixture" for r in resources)
    stack.import_stack(checkpoint)
    assert stack.export_stack().deployment["resources"] == resources
    # An empty/no-change plan must reject an added resource rather than execute it.
    stack.preview(plan=str(plan), refresh=False)
    program.write_text(source + 'pulumi.ComponentResource("synthetic:index:Extra", "extra")\n')
    with pytest.raises(RuntimeError, match="protocol command failed"):
        stack.up(plan=str(plan), refresh=False, show_secrets=False)
    assert "plan" in command.last_output.lower()
    assert not any(
        r["type"] == "synthetic:index:Extra" for r in stack.export_stack().deployment["resources"]
    )
    assert all(p.poll() is not None for p in command.processes)


def test_ci_requires_opt_in_operation_protocol_gate():
    config = yaml.load((ROOT / ".github/workflows/verify.yml").read_text(), Loader=yaml.BaseLoader)
    job = config["jobs"]["verify"]
    step = next(s for s in job["steps"] if s.get("env", {}).get("RUN_OPERATION_INTEGRATION"))
    assert step["env"]["RUN_OPERATION_INTEGRATION"] == "1"
    assert "-m operation_integration" in step["run"] and "if" not in step
    assert "secrets." not in json.dumps(step)
