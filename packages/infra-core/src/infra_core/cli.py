"""Safe repository CLI. No provisioning or state mutation commands are exposed."""

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from importlib.metadata import version
from pathlib import Path

from infra_core.backend import QualificationError, qualify, validate_receipt
from infra_core.foundation import deny_deployment, load_foundation
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
    backend = commands.add_parser("backend", help="inspect or explicitly qualify backend behavior")
    backend_commands = backend.add_subparsers(dest="backend_command", required=True)
    backend_commands.add_parser("inspect", help="show configuration and disabled deployment state")
    qualifier = backend_commands.add_parser(
        "qualify", help="write only a generated qualification stack"
    )
    qualifier.add_argument("--allow-backend-writes", action="store_true")
    qualifier.add_argument(
        "--local-test", action="store_true", help="isolated filesystem backend, not OCI evidence"
    )
    qualifier.add_argument("--receipt", type=Path, default=Path(".infra/qualification.json"))
    receipt_check = backend_commands.add_parser(
        "check-receipt", help="check OCI evidence freshness/binding"
    )
    receipt_check.add_argument("--receipt", type=Path, default=Path(".infra/qualification.json"))
    for operation in ("preview", "deploy"):
        deployment = commands.add_parser(
            operation, help="readiness check; resource operations are disabled"
        )
        deployment.add_argument("--unit", required=True)
    args = parser.parse_args(argv)
    try:
        root = find_repository(args.root)
        if args.command == "backend":
            config = load_foundation(root)
            if args.backend_command == "inspect":
                print(
                    json.dumps(
                        {
                            "backend": config.backend.url(),
                            "configuration_sha256": config.digest,
                            "pulumi_version": config.pulumi_version,
                            "units": [unit.name for unit in config.units],
                            "deployment_enabled": False,
                        },
                        indent=2,
                    )
                )
            elif args.backend_command == "qualify":
                if not args.allow_backend_writes:
                    raise QualificationError("qualification requires --allow-backend-writes")
                destination = (root / args.receipt).resolve()
                if not destination.is_relative_to(root.resolve() / ".infra"):
                    raise ValueError(
                        "qualification receipts must stay in the checkout's .infra directory"
                    )
                # Never leave stale successful evidence after a failed retry.
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.unlink(missing_ok=True)
                receipt = qualify(
                    config, local=args.local_test, allow_writes=args.allow_backend_writes
                )
                destination.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
                print(f"PASS: {receipt['kind']} backend qualified; resource deployment disabled")
            else:
                validate_receipt(
                    config, json.loads((root / args.receipt).read_text(encoding="utf-8"))
                )
                print("PASS: OCI receipt binding/freshness only; deployment remains disabled")
        elif args.command in ("preview", "deploy"):
            deny_deployment(load_foundation(root), args.unit)
        elif args.command == "verify":
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
