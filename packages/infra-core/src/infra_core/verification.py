"""Credential-free verification. The checkout is never initialized or deployed."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from infra_core.policy import GENERATED, check_repository

VERSIONS = {"terraform": "1.15.8", "terragrunt": "0.97.2"}


def run(
    args: Sequence[str], root: Path, *, env: Mapping[str, str] | None = None, capture: bool = False
) -> subprocess.CompletedProcess[str]:
    print("+ " + " ".join(args), flush=True)
    return subprocess.run(
        args,
        cwd=root,
        env=env,
        check=True,
        text=True,
        timeout=300,
        stdout=subprocess.PIPE if capture else None,
    )


def check_architecture(root: Path) -> None:
    errors = check_repository(root)
    if errors:
        raise RuntimeError("\n".join(errors))


def validation_environment(source: Mapping[str, str]) -> dict[str, str]:
    env = {
        k: v
        for k, v in source.items()
        if not k.upper().startswith(("AWS_", "OCI_", "TF_", "TG_", "TERRAGRUNT_", "PULUMI_"))
    }
    env.update(
        {
            f"TF_VAR_{name}": value
            for name, value in {
                "tenancy_ocid": "ocid1.tenancy.oc1..validation",
                "user_ocid": "ocid1.user.oc1..validation",
                "fingerprint": "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
                "private_key": "VALIDATION_ONLY_NOT_A_KEY",
                "region": "eu-frankfurt-1",
                "compartment_ocid": "ocid1.compartment.oc1..validation",
            }.items()
        }
    )
    env.update(TF_IN_AUTOMATION="true", TG_NON_INTERACTIVE="true")
    return env


def verify_python(root: Path) -> None:
    for args in (
        ["ruff", "check", "."],
        ["ruff", "format", "--check", "."],
        ["mypy"],
    ):
        run([sys.executable, "-m", *args], root)
    # Avoid ambient pytest directories shared by other checkouts or execution users.
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


def verify(root: Path, *, scope: str = "all") -> None:
    if scope in ("all", "python"):
        verify_python(root)
    if scope == "python":
        print("PASS: Python lint, format, types and tests (infrastructure not checked)")
        return
    for tool, version in VERSIONS.items():
        output = run([tool, "--version"], root, capture=True).stdout or ""
        if not re.search(rf"\bv?{re.escape(version)}\b", output):
            raise RuntimeError(f"Install {tool} {version}; found: {output.strip()}")
    check_architecture(root)
    tracked = (run(["git", "ls-files", "-z"], root, capture=True).stdout or "").split("\0")
    for name in tracked:
        path = Path(name)
        if (
            path.name in GENERATED
            or any(part in path.parts for part in (".terraform", ".terragrunt-cache", ".venv"))
            or path.suffix in {".pem", ".key", ".tfstate", ".tfplan", ".tfvars"}
            or name.endswith((".tfstate.backup", ".tfvars.json"))
        ):
            raise RuntimeError(f"SECRET002: untrack generated/sensitive artifact: {name}")
    run(["terraform", "fmt", "-check", "-recursive", "terraform"], root)
    run(["terragrunt", "hcl", "fmt", "--check", "--working-dir", "terraform"], root)
    env = validation_environment(os.environ)
    with tempfile.TemporaryDirectory(prefix="oke-verify-") as directory:
        work = Path(directory) / "terraform"
        shutil.copytree(
            root / "terraform",
            work,
            ignore=shutil.ignore_patterns(
                ".terraform", ".terragrunt-cache", "*.tfstate*", "*.tfvars", "*.tfplan"
            ),
        )
        unit = work / "01-infrastructure"
        result = run(
            ["terragrunt", "render", "--json", "--disable-dependent-modules"],
            unit,
            env=env,
            capture=True,
        )
        config = json.loads(result.stdout)
        for generator in config["generate"].values():
            filename = generator["path"]
            if filename not in GENERATED:
                raise RuntimeError(f"ARCH009: unapproved generated path: {filename}")
            (unit / filename).write_text(generator["contents"], encoding="utf-8")
        run(
            ["terraform", "init", "-backend=false", "-input=false", "-lockfile=readonly"],
            unit,
            env=env,
        )
        run(["terraform", "validate", "-no-color"], unit, env=env)
    print("PASS: lint, format, types, tests, architecture, render and Terraform schema validation")
