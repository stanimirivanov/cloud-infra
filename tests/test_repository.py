"""Regression tests for state/generation boundaries and CI gate wiring."""

import shutil
import tempfile
import tomllib
from pathlib import Path

import yaml
from infra_core.policy import check_repository
from infra_core.verification import VERSIONS

ROOT = Path(__file__).resolve().parents[1]


class TestRepository:
    def mutated_repository(self, relative_path, before, after, rule):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "terraform", root / "terraform")
            (root / "tests").mkdir()
            shutil.copy2(ROOT / "tests/public_ingress_baseline.json", root / "tests")
            path = root / relative_path
            text = path.read_text()
            assert before in text
            path.write_text(text.replace(before, after))
            assert any(e.startswith(rule + ":") for e in check_repository(root))

    def test_generated_path_escape(self):
        self.mutated_repository(
            "terraform/root.hcl",
            'path      = "provider.tf"',
            'path      = "../../provider.tf"',
            "ARCH009",
        )

    def test_child_hook(self):
        self.mutated_repository(
            "terraform/01-infrastructure/terragrunt.hcl",
            'include "root"',
            'locals { x = "extra" }\ninclude "root"',
            "ARCH011",
        )

    def test_root_shell_execution(self):
        self.mutated_repository(
            "terraform/root.hcl",
            'region                  = "eu-frankfurt-1"',
            'region = run_cmd("unexpected-program")',
            "ARCH012",
        )

    def test_repository_generation_baseline(self):
        assert check_repository(ROOT) == []

    def test_workflow_gate_and_pins(self):
        workflow = (ROOT / ".github/workflows/verify.yml").read_text()
        config = yaml.load(workflow, Loader=yaml.BaseLoader)
        assert set(config["on"]) == {"pull_request", "push", "workflow_call"}
        assert config["permissions"] == {"contents": "read"}
        assert "secrets." not in workflow
        assert "environment:" not in workflow
        steps = config["jobs"]["verify"]["steps"]
        job = config["jobs"]["verify"]
        assert set(job["strategy"]["matrix"]["os"]) == {"ubuntu-24.04", "windows-2025"}
        assert "if" not in job
        runs = {step.get("run"): step for step in steps if "run" in step}
        assert "uv sync --locked --all-groups" in runs
        assert "uv build --all-packages" in runs
        root_config = tomllib.loads((ROOT / "pyproject.toml").read_text())
        setup_uv = next(s for s in steps if s.get("uses", "").startswith("astral-sh/setup-uv@"))
        assert setup_uv["with"]["version"] == root_config["tool"]["uv"][
            "required-version"
        ].removeprefix("==")
        assert runs["uv run --locked infra verify"]["if"] == "runner.os == 'Linux'"
        assert runs["uv run --locked infra verify --scope python"]["if"] == "runner.os == 'Windows'"
        assert runs["uv sync --locked --all-groups"].get("if") is None
        setup = {s["uses"].split("@")[0]: s.get("with", {}) for s in steps if "uses" in s}
        assert setup["hashicorp/setup-terraform"]["terraform_version"] == VERSIONS["terraform"]
        assert setup["autero1/action-terragrunt"]["terragrunt-version"] == VERSIONS["terragrunt"]
        deploy = yaml.load(
            (ROOT / ".github/workflows/terraform.yml").read_text(), Loader=yaml.BaseLoader
        )
        assert deploy["jobs"]["apply"]["needs"] == "verify"
        deploy_steps = deploy["jobs"]["apply"]["steps"]
        reporter = next(
            step for step in deploy_steps if step.get("name", "").startswith("Reconcile")
        )
        assert reporter["run"] == "uv run --locked infra report --directory terraform"
        assert reporter["working-directory"] == "."
        assert reporter["if"] == "always()"
        assert "script:" not in (ROOT / ".github/workflows/terraform.yml").read_text()
        assert deploy["jobs"]["recover"]["if"] == "failure() && needs.apply.result == 'failure'"
        assert deploy["jobs"]["verify"]["uses"] == "./.github/workflows/verify.yml"
        tools = yaml.load(
            (ROOT / ".github/actions/setup-tools/action.yml").read_text(), Loader=yaml.BaseLoader
        )
        assert tools["runs"]["steps"][0]["with"]["terraform_version"] == VERSIONS["terraform"]
        assert tools["runs"]["steps"][1]["with"]["terragrunt-version"] == VERSIONS["terragrunt"]
