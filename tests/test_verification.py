"""CLI and orchestration regression tests, without external binaries or credentials."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from infra_core import cli, verification
from infra_core.repository import find_repository

ROOT = Path(__file__).resolve().parents[1]


def test_repository_discovery_from_nested_directory():
    assert find_repository(ROOT / "packages/infra-core/src") == ROOT


def test_repository_discovery_outside_checkout(tmp_path):
    with pytest.raises(RuntimeError, match="--root"):
        find_repository(tmp_path)


def test_installed_console_entrypoint_from_nested_directory():
    # Exercise the installed console script without assuming a Windows/POSIX suffix.
    script = Path(sys.executable).parent / ("infra.exe" if sys.platform == "win32" else "infra")
    result = subprocess.run(
        [str(script), "check"],
        cwd=ROOT / "terraform",
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "PASS: HCL architecture" in result.stdout


def test_cli_propagates_failure(monkeypatch, capsys):
    def fail(root, *, scope):
        raise RuntimeError("deliberate verification failure")

    monkeypatch.setattr(cli, "verify", fail)
    assert cli.main(["--root", str(ROOT), "verify"]) == 1
    assert "FAIL: deliberate verification failure" in capsys.readouterr().err


def test_cli_rejects_provisioning_commands():
    with pytest.raises(SystemExit) as error:
        cli.main(["apply"])
    assert error.value.code == 2


def test_validation_environment_strips_credentials_and_overrides():
    env = verification.validation_environment(
        {
            "PATH": "tools",
            "AWS_ACCESS_KEY_ID": "secret",
            "oci_private_key": "secret",
            "TF_CLI_ARGS_init": "-upgrade",
            "TG_CONFIG": "elsewhere",
            "PULUMI_ACCESS_TOKEN": "secret",
            "TERRAGRUNT_TFPATH": "untrusted",
            "TF_VAR_private_key": "real-key",
        }
    )
    assert env["PATH"] == "tools"
    assert "secret" not in env.values()
    assert env["TF_VAR_private_key"] == "VALIDATION_ONLY_NOT_A_KEY"
    for key in ("TF_CLI_ARGS_init", "TG_CONFIG", "TERRAGRUNT_TFPATH", "PULUMI_ACCESS_TOKEN"):
        assert key not in env


def test_command_runner_propagates_failures_and_bounds_execution():
    with pytest.raises(subprocess.CalledProcessError) as error:
        verification.run([sys.executable, "-c", "raise SystemExit(9)"], ROOT)
    assert error.value.returncode == 9


def test_python_scope_does_not_require_infrastructure_tools(monkeypatch, capsys):
    calls = []

    def record(args, root, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(verification, "run", record)
    verification.verify(ROOT, scope="python")
    assert all(args[0] == sys.executable for args in calls)
    assert [args[2] for args in calls] == ["ruff", "ruff", "mypy", "pytest"]
    pytest_args = calls[-1]
    scratch = Path(pytest_args[pytest_args.index("--basetemp") + 1]).parent
    assert f"cache_dir={scratch / 'cache'}" in pytest_args
    assert not scratch.exists()
    assert "infrastructure not checked" in capsys.readouterr().out


def test_failed_python_gate_stops_before_provider_initialization(monkeypatch):
    calls = []

    def fail(args, root, **kwargs):
        calls.append(args)
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(verification, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        verification.verify(ROOT)
    assert len(calls) == 1


@pytest.mark.parametrize("unexpected_path", [None, "../../escape.tf"])
def test_verification_materializes_only_approved_files_in_temporary_copy(
    monkeypatch, unexpected_path
):
    generated = {
        name: {"path": name, "contents": "# synthetic rendered configuration\n"}
        for name in verification.GENERATED
    }
    if unexpected_path:
        generated["bad"] = {"path": unexpected_path, "contents": "invalid"}
    initialized = []
    rendered = []

    def record(args, root, **kwargs):
        output = ""
        if args[0] in verification.VERSIONS and args[1] == "--version":
            output = "v" + verification.VERSIONS[args[0]]
        elif args[:2] == ["terragrunt", "render"]:
            rendered.append(root)
            output = json.dumps({"generate": generated})
        elif args[:2] == ["terraform", "init"]:
            initialized.append(root)
            assert root != ROOT / "terraform/01-infrastructure"
            assert args == [
                "terraform",
                "init",
                "-backend=false",
                "-input=false",
                "-lockfile=readonly",
            ]
            assert all(
                (root / name).read_text().startswith("# synthetic")
                for name in verification.GENERATED
            )
            assert kwargs["env"]["TF_VAR_private_key"] == "VALIDATION_ONLY_NOT_A_KEY"
        return subprocess.CompletedProcess(args, 0, stdout=output)

    monkeypatch.setattr(verification, "run", record)
    if unexpected_path:
        with pytest.raises(RuntimeError, match="ARCH009"):
            verification.verify(ROOT)
        assert not initialized
    else:
        verification.verify(ROOT)
        assert len(initialized) == 1
    assert len(rendered) == 1
    assert not rendered[0].exists()
