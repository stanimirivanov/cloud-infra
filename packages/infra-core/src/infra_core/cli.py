"""Safe repository CLI. No provisioning or state mutation commands are exposed."""

import argparse
import os
import subprocess
import sys
from collections.abc import Sequence
from importlib.metadata import version
from pathlib import Path

from infra_core.reporting import render_report
from infra_core.repository import find_repository
from infra_core.verification import check_architecture, verify


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="infra", description=__doc__)
    parser.add_argument("--version", action="version", version=version("infra-core"))
    parser.add_argument("--root", type=Path, help="checkout root or a directory within it")
    commands = parser.add_subparsers(dest="command", required=True)
    verifier = commands.add_parser("verify", help="run the credential-free harness")
    verifier.add_argument("--scope", choices=("all", "python"), default="all")
    commands.add_parser("check", help="run the focused HCL architecture policies")
    reporter = commands.add_parser("report", help="render legacy Terragrunt execution reports")
    reporter.add_argument("--directory", type=Path, default=Path("terraform"))
    args = parser.parse_args(argv)
    try:
        root = find_repository(args.root)
        if args.command == "verify":
            verify(root, scope=args.scope)
        elif args.command == "report":
            markdown = render_report(root / args.directory)
            if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
                with Path(summary).open("a", encoding="utf-8") as stream:
                    stream.write(markdown)
            print(markdown, end="")
        else:
            check_architecture(root)
            print("PASS: HCL architecture policies")
    except (subprocess.SubprocessError, RuntimeError, ValueError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0
