"""CLI and verification regression tests, without cloud credentials."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from infra_core import cli, verification
from infra_core.repository import find_repository

ROOT = Path(__file__).resolve().parents[1]


def test_repository_discovery_from_nested_directory():
    assert find_repository(ROOT / "packages/infra-core/src") == ROOT


def test_repository_discovery_outside_checkout():
    with tempfile.TemporaryDirectory(prefix="infra-outside-") as directory:
        with pytest.raises(RuntimeError, match="--root"):
            find_repository(Path(directory))


def test_installed_console_entrypoint_from_nested_directory():
    script = Path(sys.executable).parent / ("infra.exe" if sys.platform == "win32" else "infra")
    result = subprocess.run(
        [str(script), "backend", "inspect"],
        cwd=ROOT / "packages/infra-program",
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert json.loads(result.stdout)["deployment_enabled"] is False


def test_cli_propagates_failure(monkeypatch, capsys):
    def fail(root):
        raise RuntimeError("deliberate verification failure")

    monkeypatch.setattr(cli, "verify", fail)
    assert cli.main(["--root", str(ROOT), "verify"]) == 1
    assert "FAIL: deliberate verification failure" in capsys.readouterr().err


@pytest.mark.parametrize(
    "args", [["apply"], ["check"], ["report"], ["verify", "--scope", "python"]]
)
def test_cli_rejects_removed_or_unsupported_commands(args):
    with pytest.raises(SystemExit) as error:
        cli.main(args)
    assert error.value.code == 2


def test_command_runner_propagates_failures_and_bounds_execution():
    with pytest.raises(subprocess.CalledProcessError) as error:
        verification.run([sys.executable, "-c", "raise SystemExit(9)"], ROOT)
    assert error.value.returncode == 9


def test_verification_runs_secret_gate_before_python_tools(monkeypatch, capsys):
    checked = []
    monkeypatch.setattr(verification, "check_secrets", lambda root: checked.append(root))
    calls = []

    def record(args, root, **kwargs):
        calls.append(args)
        output = "packages/infra-program/Pulumi.yaml\0" if args[0] == "git" else ""
        return subprocess.CompletedProcess(args, 0, stdout=output)

    monkeypatch.setattr(verification, "run", record)
    verification.verify(ROOT)
    assert checked == [ROOT]
    assert calls[0] == ["git", "ls-files", "-z"]
    assert all(args[0] == sys.executable for args in calls[1:])
    assert [args[2] for args in calls[1:]] == ["ruff", "ruff", "mypy", "pytest"]
    pytest_args = calls[-1]
    scratch = Path(pytest_args[pytest_args.index("--basetemp") + 1]).parent
    assert f"cache_dir={scratch / 'cache'}" in pytest_args
    assert not scratch.exists()
    assert "No live provider" in capsys.readouterr().out


def test_failed_gate_stops_before_tests(monkeypatch):
    monkeypatch.setattr(verification, "check_secrets", lambda root: None)
    calls = []

    def fail(args, root, **kwargs):
        calls.append(args)
        if args[0] == "git":
            return subprocess.CompletedProcess(args, 0, stdout="")
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(verification, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        verification.verify(ROOT)
    assert len(calls) == 2
    assert calls[-1][2:] == ["ruff", "check", "."]


@pytest.mark.parametrize(
    "artifact",
    [
        ".infra/qualification.json",
        ".pulumi/state.json",
        ".venv/credentials.json",
        "Pulumi.production.yaml",
        "backup.checkpoint.json",
        "signing.key",
        "external.tfstate",
        ".terraform/credentials.json",
        ".terragrunt-cache/checkpoint.json",
        "backend.tf",
    ],
)
def test_private_artifacts_fail_before_running_python_tools(monkeypatch, artifact):
    calls = []

    def record(args, root, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=artifact + "\0")

    monkeypatch.setattr(verification, "run", record)
    with pytest.raises(RuntimeError, match="SECRET002"):
        verification.verify(ROOT)
    assert calls == [["git", "ls-files", "-z"]]
