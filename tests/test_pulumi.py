"""Pulumi SDK smoke test and disabled program guard; no backend or provider plugin."""

import json
import os
import subprocess
import sys

import pytest
from infra_program.__main__ import main


def test_program_cannot_provision():
    with pytest.raises(RuntimeError, match="Provisioning is not enabled"):
        main()


def test_pulumi_mock_runtime_uses_the_shared_python_environment(tmp_path):
    # Isolate Pulumi global runtime settings from other tests and any user configuration.
    script = tmp_path / "mock_program.py"
    script.write_text(
        """
import json
import pulumi
from infra_core.config import Provider

class OfflineMocks(pulumi.runtime.Mocks):
    def new_resource(self, args):
        raise AssertionError("No resources should be registered in the development foundation")
    def call(self, args):
        raise AssertionError("No provider calls should run")

pulumi.runtime.set_mocks(OfflineMocks(), project="harness-test", stack="offline", preview=True)

@pulumi.runtime.test
def verify_output():
    def check(value):
        assert value == "oci"
        print(json.dumps({"provider": value, "project": pulumi.get_project()}))
    return pulumi.Output.from_input(Provider.OCI.value).apply(check)

verify_output()
""",
        encoding="utf-8",
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(("PULUMI_", "OCI_", "AWS_", "TF_", "TG_"))
    }
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert json.loads(result.stdout) == {"provider": "oci", "project": "harness-test"}
