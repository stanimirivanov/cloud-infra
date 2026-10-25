"""Single local, hook and CI entry point. Never contacts OCI or the state backend."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from policy import GENERATED, check_repository

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = {"terraform": "1.15.8", "terragrunt": "0.97.2"}


def run(args, cwd=ROOT, env=None, capture=False):
    print("+ " + " ".join(map(str, args)), flush=True)
    return subprocess.run(
        args, cwd=cwd, env=env, check=True, text=True, stdout=subprocess.PIPE if capture else None
    )


def main():
    for tool, version in VERSIONS.items():
        output = run([tool, "--version"], capture=True).stdout
        if not re.search(rf"\bv?{re.escape(version)}\b", output):
            raise RuntimeError(f"Install {tool} {version}; found: {output.strip()}")
    run([sys.executable, "-m", "ruff", "check", "scripts", "tests"])
    run([sys.executable, "-m", "ruff", "format", "--check", "scripts", "tests"])
    run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])
    errors = check_repository(ROOT)
    if errors:
        raise RuntimeError("\n".join(errors))
    tracked = run(["git", "ls-files", "-z"], capture=True).stdout.split("\0")
    for name in tracked:
        path = Path(name)
        if (
            path.name in GENERATED
            or any(part in path.parts for part in (".terraform", ".terragrunt-cache", ".venv"))
            or path.suffix in {".pem", ".key", ".tfstate", ".tfplan", ".tfvars"}
            or name.endswith((".tfstate.backup", ".tfvars.json"))
        ):
            raise RuntimeError(f"SECRET002: untrack generated/sensitive artifact: {name}")
    run(["terraform", "fmt", "-check", "-recursive", "terraform"])
    run(["terragrunt", "hcl", "fmt", "--check", "--working-dir", "terraform"])
    # Do not inherit cloud credentials, Terraform CLI overrides or Terragrunt overrides.
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith(("AWS_", "OCI_", "TF_", "TG_", "TERRAGRUNT_"))
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
    with tempfile.TemporaryDirectory(prefix="oke-verify-") as directory:
        work = Path(directory) / "terraform"
        shutil.copytree(
            ROOT / "terraform",
            work,
            ignore=shutil.ignore_patterns(
                ".terraform", ".terragrunt-cache", "*.tfstate*", "*.tfvars", "*.tfplan"
            ),
        )
        unit = work / "01-infrastructure"
        # Rendering evaluates real Terragrunt includes/functions but does not init/apply.
        result = run(
            ["terragrunt", "render", "--json", "--disable-dependent-modules"],
            cwd=unit,
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
            cwd=unit,
            env=env,
        )
        run(["terraform", "validate", "-no-color"], cwd=unit, env=env)
    print("PASS: lint, policy tests, architecture, formatting, render and schema validation")


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, RuntimeError, ValueError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
