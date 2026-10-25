"""Regression tests for state/generation boundaries and CI gate wiring."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from policy import check_repository  # noqa: E402
from verify import VERSIONS  # noqa: E402


class RepositoryTests(unittest.TestCase):
    def mutated_repository(self, relative_path, before, after, rule):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "terraform", root / "terraform")
            (root / "tests").mkdir()
            shutil.copy2(ROOT / "tests/public_ingress_baseline.json", root / "tests")
            path = root / relative_path
            text = path.read_text()
            self.assertIn(before, text)
            path.write_text(text.replace(before, after))
            self.assertTrue(any(e.startswith(rule + ":") for e in check_repository(root)))

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
        self.assertEqual(check_repository(ROOT), [])

    def test_workflow_gate_and_pins(self):
        workflow = (ROOT / ".github/workflows/verify.yml").read_text()
        config = yaml.load(workflow, Loader=yaml.BaseLoader)
        self.assertEqual(set(config["on"]), {"pull_request", "push", "workflow_call"})
        self.assertEqual(config["permissions"], {"contents": "read"})
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("environment:", workflow)
        self.assertNotIn("if:", workflow)
        steps = config["jobs"]["verify"]["steps"]
        self.assertIn({"run": "python scripts/verify.py"}, steps)
        setup = {s["uses"].split("@")[0]: s.get("with", {}) for s in steps if "uses" in s}
        self.assertEqual(
            setup["hashicorp/setup-terraform"]["terraform_version"], VERSIONS["terraform"]
        )
        self.assertEqual(
            setup["autero1/action-terragrunt"]["terragrunt-version"], VERSIONS["terragrunt"]
        )
        deploy = yaml.load(
            (ROOT / ".github/workflows/terraform.yml").read_text(), Loader=yaml.BaseLoader
        )
        self.assertEqual(deploy["jobs"]["apply"]["needs"], "verify")
        self.assertEqual(
            deploy["jobs"]["recover"]["if"], "failure() && needs.apply.result == 'failure'"
        )
        self.assertEqual(deploy["jobs"]["verify"]["uses"], "./.github/workflows/verify.yml")
        tools = yaml.load(
            (ROOT / ".github/actions/setup-tools/action.yml").read_text(), Loader=yaml.BaseLoader
        )
        self.assertEqual(
            tools["runs"]["steps"][0]["with"]["terraform_version"], VERSIONS["terraform"]
        )
        self.assertEqual(
            tools["runs"]["steps"][1]["with"]["terragrunt-version"], VERSIONS["terragrunt"]
        )


if __name__ == "__main__":
    unittest.main()
