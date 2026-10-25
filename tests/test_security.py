"""Real workflow mutations and fail-closed tool/protocol tests; no workflow execution."""

import shutil
import subprocess
from pathlib import Path

import pytest
from infra_core import cli, security, verification

ROOT = Path(__file__).resolve().parents[1]
VALID = """name: Synthetic
on: [push]
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: echo harmless
"""


@pytest.fixture
def workflow(tmp_path):
    path = tmp_path / ".github/workflows/check.yml"
    path.parent.mkdir(parents=True)
    path.write_text(VALID)
    return path


def test_real_linter_accepts_repository_and_cli(capsys):
    assert cli.main(["--root", str(ROOT), "security", "workflows"]) == 0
    assert "no workflow steps executed" in capsys.readouterr().out


@pytest.mark.parametrize("suffix", [".yml", ".yaml"])
@pytest.mark.parametrize(
    "source,kind",
    [
        (VALID.replace("runs-on:", "runs-oon:"), "syntax-check"),
        (VALID.replace("echo harmless", "echo ${{ nonexistent.context }}"), "expression"),
        (VALID.replace("    steps:", "    needs: missing-job\n    steps:"), "job-needs"),
        ("name: [unterminated", "syntax-check"),
    ],
)
def test_real_linter_rejects_workflow_mutations(workflow, source, kind, suffix):
    workflow.unlink()
    workflow = workflow.with_suffix(suffix)
    workflow.write_text(source)
    # Repository-local ignores cannot weaken the explicit gate configuration.
    (workflow.parents[1] / "actionlint.yaml").write_text("paths:\n  '**':\n    ignore: ['.*']\n")
    with pytest.raises(RuntimeError, match="WORKFLOW001") as error:
        security.check_workflows(workflow.parents[2], tool_root=ROOT)
    assert kind in str(error.value)
    assert "echo" not in str(error.value) and "nonexistent" not in str(error.value)


@pytest.mark.parametrize("mode", ["missing", "modified"])
def test_untrusted_executable_is_never_run(tmp_path, monkeypatch, mode):
    (tmp_path / "config").mkdir()
    shutil.copyfile(ROOT / "config/toolchain.json", tmp_path / "config/toolchain.json")
    if mode == "modified":
        path = tmp_path / ".infra/tools/actionlint" / security.workflow_linter(ROOT).name
        path.parent.mkdir(parents=True)
        path.write_bytes(b"not the pinned executable")
    monkeypatch.setattr(security.subprocess, "run", lambda *a, **k: pytest.fail("executed"))
    with pytest.raises(RuntimeError, match="WORKFLOW001"):
        security.workflow_linter(tmp_path)


@pytest.mark.parametrize("code", [1, 2, 3, 17])
def test_all_tool_failures_hide_raw_diagnostics(workflow, monkeypatch, code):
    def fail(args, **kwargs):
        assert kwargs["timeout"] == 60 and kwargs["cwd"] == workflow.parents[2]
        assert "-shellcheck=" in args and "-pyflakes=" in args
        config = Path(args[args.index("-config-file") + 1])
        assert config.read_text() == "{}\n"
        return subprocess.CompletedProcess(args, code, "synthetic-sensitive-value", "private error")

    monkeypatch.setattr(security.subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="raw diagnostics suppressed") as error:
        security.check_workflows(workflow.parents[2], tool_root=ROOT)
    assert "synthetic-sensitive-value" not in str(error.value)
    assert "private error" not in str(error.value)


@pytest.mark.parametrize(
    "error", [OSError("private detail"), subprocess.TimeoutExpired("secret", 60)]
)
def test_launch_and_timeout_fail_closed(workflow, monkeypatch, error):
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(security.subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="could not complete") as failure:
        security.check_workflows(workflow.parents[2], tool_root=ROOT)
    assert "secret" not in str(failure.value) and "private detail" not in str(failure.value)


def test_empty_workflow_inventory_fails(tmp_path):
    with pytest.raises(RuntimeError, match="no workflow files"):
        security.check_workflows(tmp_path, tool_root=ROOT)


def test_workflow_failure_stops_the_shared_gate_before_python_tools(monkeypatch):
    for name in ("check_tracked_artifacts", "check_secrets", "check_fitness"):
        monkeypatch.setattr(verification, name, lambda root: None)

    def fail(root):
        raise RuntimeError("WORKFLOW001: deliberate failure")

    monkeypatch.setattr(verification, "check_workflows", fail)
    monkeypatch.setattr(verification, "run", lambda *a, **k: pytest.fail("ran Python tools"))
    with pytest.raises(RuntimeError, match="WORKFLOW001"):
        verification.verify(ROOT)


def test_workflow_cli_propagates_failure(monkeypatch, capsys):
    def fail(root):
        raise RuntimeError("WORKFLOW001: deliberate failure")

    monkeypatch.setattr(cli, "check_workflows", fail)
    assert cli.main(["--root", str(ROOT), "security", "workflows"]) == 1
    assert "WORKFLOW001" in capsys.readouterr().err
