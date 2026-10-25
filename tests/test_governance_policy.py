"""Mandatory policy enforcement with no provider plugins or cloud resources."""

import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from infra_core.backend import qualification_environment
from infra_program import governance
from pulumi_policy import EnforcementLevel

ROOT = Path(__file__).resolve().parents[1]


def test_policy_pack_is_mandatory(monkeypatch):
    monkeypatch.setattr(governance, "PolicyPack", lambda **kwargs: kwargs)
    pack = governance.policy_pack()
    assert pack["enforcement_level"] == EnforcementLevel.MANDATORY
    assert pack["policies"][0].enforcement_level == EnforcementLevel.MANDATORY


@pytest.mark.backend_integration
@pytest.mark.skipif(
    os.environ.get("RUN_PULUMI_LOCAL_QUALIFICATION") != "1", reason="explicit local-backend opt-in"
)
def test_real_pulumi_preview_blocks_unclassified_resource():
    # Match qualification isolation with an invocation-specific temporary backend.
    with tempfile.TemporaryDirectory(prefix="gov-") as directory:
        _preview(Path(directory))


def _preview(tmp_path):
    env = qualification_environment(dict(os.environ), tmp_path / "home", local=True)
    # Policy-host handshake/output must not depend on redirected stream buffering.
    env["PYTHONUNBUFFERED"] = "1"
    project = tmp_path / "project"
    project.mkdir()
    (project / "Pulumi.yaml").write_text(
        json.dumps(
            {
                "name": "governance-synthetic-test",
                "runtime": {"name": "python", "options": {"virtualenv": sys.prefix}},
            }
        )
    )
    # ComponentResource needs no provider and cannot create a cloud resource.
    (project / "__main__.py").write_text(
        "import pulumi\n"
        'component = pulumi.ComponentResource("synthetic:index:Unreviewed", "blocked")\n'
        "component.register_outputs({})\n"
    )
    backend = tmp_path / "backend"
    backend.mkdir()

    def run(args, *, success=True):
        process = subprocess.Popen(
            ["pulumi", *args, "--non-interactive", "--color=never"],
            cwd=project,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            start_new_session=sys.platform != "win32",
        )
        try:
            stdout, stderr = process.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    capture_output=True,
                    check=False,
                    timeout=15,
                )
            else:
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=15)
            pytest.fail("Synthetic Pulumi command timed out:\n" + stdout + stderr)
        result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        if success:
            assert result.returncode == 0, result.stdout + result.stderr
        return result

    run(["login", backend.as_uri()])
    run(["stack", "init", "synthetic", "--secrets-provider", "passphrase"])
    run(["preview", "--stack", "synthetic"])
    result = run(
        [
            "preview",
            "--stack",
            "synthetic",
            "--policy-pack",
            str(ROOT / "policies"),
        ],
        success=False,
    )
    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "GOV022" in output, output
    assert "mandatory" in output.lower(), output
