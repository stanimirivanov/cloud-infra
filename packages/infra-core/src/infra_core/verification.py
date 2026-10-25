"""Credential-free Python and tracked-artifact verification; no provider or state operations."""

import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from infra_core.fitness import check_fitness


def run(
    args: Sequence[str], root: Path, *, capture: bool = False
) -> subprocess.CompletedProcess[str]:
    print("+ " + " ".join(args), flush=True)
    return subprocess.run(
        args,
        cwd=root,
        check=True,
        text=True,
        timeout=300,
        stdout=subprocess.PIPE if capture else None,
    )


def check_tracked_artifacts(root: Path) -> None:
    tracked = (run(["git", "ls-files", "-z"], root, capture=True).stdout or "").split("\0")
    for name in tracked:
        path = Path(name)
        if (
            path.name in {"backend.tf", "provider.tf", "common_variables.tf"}
            or any(
                part in path.parts
                for part in (".terraform", ".terragrunt-cache", ".venv", ".pulumi", ".infra")
            )
            or path.suffix in {".pem", ".key", ".tfstate", ".tfplan", ".tfvars"}
            or name.endswith((".tfstate.backup", ".tfvars.json", ".checkpoint.json"))
            or (
                path.name.startswith("Pulumi.")
                and path.name != "Pulumi.yaml"
                and path.suffix == ".yaml"
            )
        ):
            raise RuntimeError(f"SECRET002: untrack private/sensitive artifact: {name}")


def verify(root: Path) -> None:
    check_tracked_artifacts(root)
    check_fitness(root)
    for args in (
        ["ruff", "check", "."],
        ["ruff", "format", "--check", "."],
        ["mypy"],
    ):
        run([sys.executable, "-m", *args], root)
    # Keep pytest output/cache isolated from other checkouts and verification runs.
    with tempfile.TemporaryDirectory(prefix="infra-python-") as directory:
        scratch = Path(directory)
        run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--basetemp",
                str(scratch / "tests"),
                "-o",
                f"cache_dir={scratch / 'cache'}",
            ],
            root,
        )
    print("PASS: private artifacts, architecture, documentation, lint, format, types and tests")
    print("No live provider, billing or deployed-state checks were performed.")
