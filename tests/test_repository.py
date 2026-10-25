"""Credential-free workflow and shared verification contracts."""

import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_workflow_runs_the_same_gate_on_both_platforms_without_credentials():
    workflow = (ROOT / ".github/workflows/verify.yml").read_text()
    config = yaml.load(workflow, Loader=yaml.BaseLoader)
    assert set(config["on"]) == {"pull_request", "push", "workflow_call"}
    assert config["permissions"] == {"contents": "read"}
    assert "secrets." not in workflow
    assert "environment:" not in workflow
    job = config["jobs"]["verify"]
    assert set(job["strategy"]["matrix"]["os"]) == {"ubuntu-24.04", "windows-2025"}
    assert "if" not in job
    steps = job["steps"]
    runs = {step.get("run"): step for step in steps if "run" in step}
    for command in (
        "uv sync --locked --all-groups",
        "uv build --all-packages",
        "uv run --locked infra verify",
    ):
        assert command in runs and "if" not in runs[command]
    setup = {s["uses"].split("@")[0]: s for s in steps if "uses" in s}
    assert set(setup) == {"actions/checkout", "astral-sh/setup-uv", "pulumi/actions"}
    assert setup["actions/checkout"]["with"]["persist-credentials"] == "false"
    root_config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert setup["astral-sh/setup-uv"]["with"]["version"] == root_config["tool"]["uv"][
        "required-version"
    ].removeprefix("==")
    foundation = tomllib.loads((ROOT / "config/pulumi.toml").read_text())
    assert setup["pulumi/actions"]["with"]["pulumi-version"] == foundation["pulumi_version"]
    integration = next(s for s in steps if s.get("env", {}).get("RUN_PULUMI_LOCAL_QUALIFICATION"))
    assert "-m backend_integration" in integration["run"]


def test_hook_uses_the_complete_verification_gate():
    config = yaml.load((ROOT / ".pre-commit-config.yaml").read_text(), Loader=yaml.BaseLoader)
    hook = config["repos"][0]["hooks"][0]
    assert hook["entry"] == "uv run --locked infra verify"
    assert hook["pass_filenames"] == "false" and hook["always_run"] == "true"
