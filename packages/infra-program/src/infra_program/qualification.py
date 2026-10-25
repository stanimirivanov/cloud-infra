"""Synthetic secret output for backend qualification; never declares cloud resources."""

import os
import time
from pathlib import Path

import pulumi


def main() -> None:
    if pulumi.get_project() != "backend-qualification" or not pulumi.get_stack().startswith(
        "qualification-"
    ):
        raise RuntimeError("qualification program requires an isolated qualification identity")
    if hold := os.environ.get("INFRA_QUALIFICATION_HOLD"):
        marker = Path(hold)
        marker.with_suffix(".ready").touch()
        deadline = time.monotonic() + 60
        while not marker.with_suffix(".release").exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("qualification lock holder timed out")
            time.sleep(0.1)
    pulumi.export("sentinel", pulumi.Config().require_secret("sentinel"))
