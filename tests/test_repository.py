"""Credential-free workflow and shared verification contracts."""

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_workflow_runs_the_linux_gate_without_credentials():
    workflow = (ROOT / ".github/workflows/verify.yml").read_text()
    config = yaml.load(workflow, Loader=yaml.BaseLoader)
    assert_credential_free(config)
    job = config["jobs"]["verify"]
    assert set(job["strategy"]["matrix"]["os"]) == {"ubuntu-24.04"}
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
    assert set(setup) == {"actions/checkout"}
    assert setup["actions/checkout"]["with"]["fetch-depth"] == "0"
    install = next(s for s in steps if s.get("name") == "Install checksum-verified tools")
    assert install["shell"] == "bash"
    assert install["run"] == "python3 .github/scripts/install-tools.py"
    assert steps.index(install) < steps.index(runs["uv sync --locked --all-groups"])
    assert setup["actions/checkout"]["with"]["persist-credentials"] == "false"
    integration = next(s for s in steps if s.get("env", {}).get("RUN_PULUMI_LOCAL_QUALIFICATION"))
    assert "-m backend_integration" in integration["run"]


def test_hook_uses_the_complete_verification_gate():
    config = yaml.load((ROOT / ".pre-commit-config.yaml").read_text(), Loader=yaml.BaseLoader)
    hook = config["repos"][0]["hooks"][0]
    assert hook["entry"] == "uv run --locked infra verify"
    assert hook["pass_filenames"] == "false" and hook["always_run"] == "true"


def assert_action_pins(document, pins):
    if isinstance(document, dict):
        if "uses" in document:
            reference = document["uses"]
            if reference.startswith("./"):
                assert (ROOT / reference).is_file()
            else:
                action, sha = reference.rsplit("@", 1)
                assert re.fullmatch(r"[0-9a-f]{40}", sha)
                assert pins[action] == sha
        for value in document.values():
            assert_action_pins(value, pins)
    elif isinstance(document, list):
        for value in document:
            assert_action_pins(value, pins)


def assert_credential_free(config):
    assert set(config["on"]) == {"pull_request", "push", "workflow_call"}
    assert config["permissions"] == {"contents": "read"}
    assert "secrets." not in str(config)
    assert "environment" not in str(config)


def test_all_workflow_actions_use_reviewed_immutable_commits():
    pins = json.loads((ROOT / "config/toolchain.json").read_text())["actions"]
    for path in sorted(
        set((ROOT / ".github").rglob("*.yml")) | set((ROOT / ".github").rglob("*.yaml"))
    ):
        assert_action_pins(yaml.load(path.read_text(), Loader=yaml.BaseLoader), pins)


@pytest.mark.parametrize(
    "reference", ["actions/checkout@v4", "actions/checkout@main", "actions/checkout@" + "0" * 40]
)
def test_mutable_or_unreviewed_action_references_fail(reference):
    pins = json.loads((ROOT / "config/toolchain.json").read_text())["actions"]
    with pytest.raises(AssertionError):
        assert_action_pins({"uses": reference}, pins)


@pytest.mark.parametrize("change", ["token", "environment", "trigger", "permissions"])
def test_unsafe_verification_workflow_mutations_fail(change):
    config = yaml.load((ROOT / ".github/workflows/verify.yml").read_text(), Loader=yaml.BaseLoader)
    if change == "token":
        config["jobs"]["verify"]["env"] = {"TOKEN": "${{ secrets.CLOUD_TOKEN }}"}
    elif change == "environment":
        config["jobs"]["verify"]["environment"] = "production"
    elif change == "trigger":
        config["on"]["pull_request_target"] = {}
    else:
        config["permissions"]["contents"] = "write"
    with pytest.raises(AssertionError):
        assert_credential_free(config)
