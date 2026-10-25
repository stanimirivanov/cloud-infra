"""Safe repository CLI. No provisioning or state mutation commands are exposed."""

import argparse
import json
import os
import subprocess
import sys
import tomllib
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
    governance = commands.add_parser(
        "governance", help="account-wide cost preflight; no deployment"
    )
    governance_commands = governance.add_subparsers(dest="governance_command", required=True)
    auditor = governance_commands.add_parser(
        "audit", help="audit normalized proposed changes against account evidence"
    )
    auditor.add_argument("--account", type=Path, required=True)
    auditor.add_argument("--inventory", type=Path, required=True)
    auditor.add_argument("--plan", type=Path, required=True)
    inventory = governance_commands.add_parser("inventory", help="read-only OCI tenancy scan")
    inventory.add_argument("--account", type=Path, required=True)
    inventory.add_argument("--oci-config", type=Path, required=True)
    inventory.add_argument("--oci-profile", default="DEFAULT")
    inventory.add_argument("--usage", type=Path)
    inventory.add_argument("--output", type=Path, default=Path(".infra/inventory.json"))
    oci = commands.add_parser("oci", help="render a pure OCI component proposal; no provider calls")
    oci_commands = oci.add_subparsers(dest="oci_command", required=True)
    oci_proposal = oci_commands.add_parser(
        "proposal", help="render the complete disabled OCI graph"
    )
    oci_proposal.add_argument("--config", type=Path, required=True)
    oci_proposal.add_argument("--account-id", required=True)
    kubernetes = commands.add_parser("kubernetes", help="offline namespace/workload governance")
    kube_commands = kubernetes.add_subparsers(dest="kubernetes_command", required=True)
    kube_render = kube_commands.add_parser("render", help="render disabled namespace controls")
    kube_render.add_argument("--config", type=Path, required=True)
    kube_audit = kube_commands.add_parser(
        "audit", help="check full bundle against cluster evidence"
    )
    for name in ("config", "inventory", "resources"):
        kube_audit.add_argument("--" + name, type=Path, required=True)
    cutover = commands.add_parser("cutover", help="offline evidence checks; never an executor")
    cutover_commands = cutover.add_subparsers(dest="cutover_command", required=True)
    cutover_check = cutover_commands.add_parser(
        "check", help="check pinned private review artifacts"
    )
    cutover_check.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        root = find_repository(args.root)
        if args.command == "cutover":
            from infra_core.cutover import check

            print(
                json.dumps(
                    check(root, json.loads((root / args.evidence).read_text(encoding="utf-8"))),
                    indent=2,
                )
            )
        elif args.command == "kubernetes":
            from infra_core.kubernetes.audit import audit as audit_kubernetes
            from infra_core.kubernetes.config import load_config as load_kubernetes
            from infra_core.kubernetes.resources import render

            kube_config = load_kubernetes(root / args.config)
            result_kube = (
                render(kube_config)
                if args.kubernetes_command == "render"
                else audit_kubernetes(
                    kube_config,
                    json.loads((root / args.inventory).read_text(encoding="utf-8")),
                    json.loads((root / args.resources).read_text(encoding="utf-8")),
                )
            )
            print(json.dumps(result_kube, indent=2))
        elif args.command == "oci":
            from infra_core.oci.config import load_config
            from infra_core.oci.graph import foundation_graph, proposal

            config_oci = load_config(root / args.config)
            print(
                json.dumps(
                    proposal(foundation_graph(config_oci), args.account_id, config_oci.region),
                    indent=2,
                )
            )
        elif args.command == "governance":
            from infra_core.governance.audit import audit
            from infra_core.inventory.oci import OCIReader, collect

            with (root / args.account).open("rb") as stream:
                account = tomllib.load(stream)
            if args.governance_command == "audit":
                with (root / "config/quotas/profiles.toml").open("rb") as stream:
                    profiles = tomllib.load(stream)["profiles"]
                profile = profiles.get(account.get("profile"), {})
                result = audit(
                    account,
                    profile,
                    json.loads((root / args.inventory).read_text(encoding="utf-8")),
                    json.loads((root / args.plan).read_text(encoding="utf-8")),
                )
                print(json.dumps(result, sort_keys=True, indent=2))
            else:
                if account.get("provider") != "oci":
                    raise ValueError("GOV006: only the OCI read-only collector is implemented")
                destination = (root / args.output).resolve()
                if not destination.is_relative_to(root.resolve() / ".infra"):
                    raise ValueError("GOV003: inventory output must stay under .infra")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.unlink(missing_ok=True)
                usage = json.loads((root / args.usage).read_text()) if args.usage else None
                try:
                    reader = OCIReader(
                        str((root / args.oci_config).resolve()),
                        args.oci_profile,
                        account["account_id"],
                    )
                    snapshot = collect(
                        reader, account["account_id"], account["home_region"], usage=usage
                    )
                except Exception:
                    raise ValueError(
                        "GOV040: OCI collection failed; inspect credentials/permissions privately"
                    ) from None
                destination.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
                print(
                    "Collected supported OCI families; "
                    "monthly usage/entitlement still require audit"
                )
        elif args.command == "backend":
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
