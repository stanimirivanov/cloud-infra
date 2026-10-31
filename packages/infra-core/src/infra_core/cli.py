"""Repository CLI; explicit protected adapters own any resource execution."""

import argparse
import json
import subprocess
import sys
import tomllib
from collections.abc import Callable, Sequence
from importlib.metadata import version
from pathlib import Path

from infra_core.backend import QualificationError, qualify, validate_receipt
from infra_core.backend_posture import (
    capture_posture,
    envelope_path,
    read_posture_pair,
    validate_posture_evidence,
)
from infra_core.foundation import deny_deployment, load_foundation
from infra_core.repository import find_repository
from infra_core.security import check_workflows
from infra_core.verification import verify


def build_parser() -> argparse.ArgumentParser:
    """Describe the CLI without running commands or accessing infrastructure."""
    parser = argparse.ArgumentParser(prog="infra", description=__doc__)
    parser.add_argument("--version", action="version", version=version("infra-core"))
    parser.add_argument("--root", type=Path, help="checkout root or a directory within it")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify", help="run the credential-free Python and artifact checks")
    providers = commands.add_parser("providers", help="inspect repository provider capabilities")
    provider_commands = providers.add_subparsers(dest="provider_command", required=True)
    provider_inspect = provider_commands.add_parser("inspect", help="read-only capability report")
    provider_inspect.add_argument("--provider", help="select a known provider, e.g. oci or gcp")
    readiness = commands.add_parser(
        "readiness", help="read-only acceptance assertions; no authority"
    )
    readiness.add_argument(
        "--unit",
        required=True,
        choices=["oci-network", "oci-oke", "cloudflare-edge", "supabase-database"],
    )
    readiness.add_argument("--evidence", type=Path, required=True)
    security = commands.add_parser("security", help="security sensors and read-only collection")
    security_commands = security.add_subparsers(dest="security_command", required=True)
    security_commands.add_parser("workflows", help="check workflow syntax with verified actionlint")
    administration_collect = security_commands.add_parser(
        "collect-administration", help="read-only GitHub settings checks; no setting changes"
    )
    administration_collect.add_argument(
        "--output", type=Path, default=Path(".infra/administration.json")
    )
    administration_check = security_commands.add_parser(
        "check-administration", help="offline GitHub settings snapshot consistency"
    )
    administration_check.add_argument("--evidence", type=Path, required=True)
    enrollment = security_commands.add_parser(
        "check-enrollment", help="read-only trust and runner enrollment gaps; no authority"
    )
    enrollment.add_argument("--evidence", type=Path)
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
    qualifier.add_argument(
        "--account-id", help="independently reviewed OCI tenancy; required remotely"
    )
    qualifier.add_argument("--posture", type=Path, default=Path(".infra/backend-posture.json"))
    qualifier.add_argument("--receipt", type=Path, default=Path(".infra/qualification.json"))
    receipt_check = backend_commands.add_parser(
        "check-receipt", help="check OCI evidence freshness/binding"
    )
    receipt_check.add_argument("--receipt", type=Path, default=Path(".infra/qualification.json"))
    posture_check = backend_commands.add_parser(
        "check-posture", help="validate read-only OCI bucket evidence"
    )
    posture_check.add_argument("--account-id", required=True)
    posture_check.add_argument("--evidence", type=Path, default=Path(".infra/backend-posture.json"))
    posture_collect = backend_commands.add_parser(
        "collect-posture", help="read-only OCI bucket metadata scan"
    )
    posture_collect.add_argument("--account-id", required=True)
    posture_collect.add_argument("--oci-config", type=Path, required=True)
    posture_collect.add_argument("--oci-profile", default="DEFAULT")
    posture_collect.add_argument("--output", type=Path, default=Path(".infra/backend-posture.json"))
    backend_readiness = backend_commands.add_parser(
        "check-readiness", help="offline backend readiness gaps; no activation authority"
    )
    backend_readiness.add_argument("--account-id", required=True)
    backend_readiness.add_argument("--evidence", type=Path)
    for operation in ("preview", "deploy"):
        deployment = commands.add_parser(
            operation, help="readiness check; resource operations are disabled"
        )
        deployment.add_argument("--unit", required=True)
        if operation == "preview":
            deployment.add_argument("--commit", help="independently approved full commit SHA")
            deployment.add_argument("--request", type=Path, help="explicit private preview request")
    governance = commands.add_parser(
        "governance", help="account-wide cost preflight; no deployment"
    )
    governance_commands = governance.add_subparsers(dest="governance_command", required=True)
    account_readiness = governance_commands.add_parser(
        "check-readiness", help="offline account evidence; no activation authority"
    )
    account_readiness.add_argument("--unit", required=True)
    account_readiness.add_argument("--account-id", required=True)
    account_readiness.add_argument("--evidence", type=Path)
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
    kube_staging = kube_commands.add_parser(
        "check-staging", help="offline OKE staging inputs; activation pending"
    )
    for name in ("config", "oci-config", "network-outputs", "inventory", "resources"):
        kube_staging.add_argument("--" + name, type=Path, required=True)
    for name in ("account-id", "cluster-id"):
        kube_staging.add_argument("--" + name, required=True)
    backup = commands.add_parser(
        "backup", help="explicit encrypted pair backup; no resource operations"
    )
    backup_commands = backup.add_subparsers(dest="backup_command", required=True)
    backup_readiness = backup_commands.add_parser(
        "check-readiness", help="offline independent-backup evidence; no restore authority"
    )
    for name in ("unit", "repository-id", "recovery-host-id"):
        backup_readiness.add_argument("--" + name, required=True)
    backup_readiness.add_argument("--evidence", type=Path)
    recovery_staging = backup_commands.add_parser(
        "check-recovery", help="offline pair compatibility; recovery pending"
    )
    recovery_staging.add_argument("--unit", required=True)
    for name in (
        "current-checkpoint",
        "current-configuration",
        "restore-checkpoint",
        "restore-configuration",
    ):
        recovery_staging.add_argument("--" + name, type=Path, required=True)
    backup_capture = backup_commands.add_parser(
        "capture", help="write to an existing local repository"
    )
    for name in ("request", "checkpoint", "config", "repository", "password-file"):
        backup_capture.add_argument("--" + name, type=Path, required=True)
    backup_capture.add_argument("--repository-id", required=True)
    backup_capture.add_argument("--exported-at", required=True)
    backup_capture.add_argument("--allow-backup-write", action="store_true", required=True)
    rehearsal = backup_commands.add_parser(
        "rehearse", help="isolated local restore/readback rehearsal"
    )
    for name in ("policy", "receipt", "repository", "password-file", "passphrase-file", "output"):
        rehearsal.add_argument("--" + name, type=Path, required=True)
    rehearsal.add_argument("--allow-local-writes", action="store_true", required=True)
    operations = commands.add_parser("operations", help="offline operation request inspection")
    operation_commands = operations.add_subparsers(dest="operations_command", required=True)
    writer_readiness = operation_commands.add_parser(
        "check-readiness", help="offline writer-exclusion evidence; never a fence"
    )
    writer_readiness.add_argument("--unit", required=True)
    writer_readiness.add_argument("--writers", type=Path, required=True)
    writer_readiness.add_argument("--evidence", type=Path)
    operation_inspect = operation_commands.add_parser(
        "inspect", help="validate request; no authority"
    )
    operation_input = operation_inspect.add_mutually_exclusive_group(required=True)
    operation_input.add_argument("--request", type=Path)
    operation_input.add_argument("--journal", type=Path)
    ownership = commands.add_parser("ownership", help="offline ownership preparation; no authority")
    ownership_commands = ownership.add_subparsers(dest="ownership_command", required=True)
    ownership_prepare = ownership_commands.add_parser(
        "prepare", help="check frozen writers and checkpoint-bound mapping"
    )
    ownership_prepare.add_argument("--evidence", type=Path, required=True)
    cutover = commands.add_parser("cutover", help="offline evidence checks; never an executor")
    cutover_commands = cutover.add_subparsers(dest="cutover_command", required=True)
    cutover_check = cutover_commands.add_parser(
        "check", help="check pinned private review artifacts"
    )
    cutover_check.add_argument("--evidence", type=Path, required=True)
    cutover_handoff = cutover_commands.add_parser(
        "handoff", help="separate signed owner admission; no writer activation"
    )
    cutover_handoff.add_argument("--evidence", type=Path, required=True)
    cutover_handoff.add_argument("--actor", required=True)
    cutover_handoff.add_argument("--environment", required=True)
    services = commands.add_parser(
        "services", help="service preflight and explicit read-only collection"
    )
    services_commands = services.add_subparsers(dest="services_command", required=True)
    service_audit = services_commands.add_parser(
        "audit", help="validate and render additive proposal"
    )
    service_audit.add_argument("--config", type=Path, required=True)
    service_audit.add_argument("--evidence", type=Path, required=True)
    collection = services_commands.add_parser(
        "collect-cloudflare", help="explicit read-only zone evidence; no deployment authority"
    )
    for name in ("config", "review", "token-file", "output"):
        collection.add_argument("--" + name, type=Path, required=True)
    staging = services_commands.add_parser(
        "check-staging", help="offline Supabase inputs; activation pending"
    )
    for name in ("account-id", "scope-id"):
        staging.add_argument("--" + name, required=True)
    for name in ("config", "evidence", "encrypted-configuration"):
        staging.add_argument("--" + name, type=Path, required=True)
    service_apply = commands.add_parser("apply", help="explicit protected single-unit update")
    service_apply.add_argument(
        "--unit",
        choices=["cloudflare-edge", "supabase-database", "oci-network", "oci-oke"],
        required=True,
    )
    for name in ("commit", "actor", "environment"):
        service_apply.add_argument("--" + name, required=True)
    for name in ("bundle", "journal"):
        service_apply.add_argument("--" + name, type=Path, required=True)
    mode = service_apply.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--allow-resource-writes", action="store_true")
    resource_import = commands.add_parser(
        "resource-import", help="explicit protected OCI resource import"
    )
    resource_import.add_argument("--unit", choices=["oci-network", "oci-oke"], required=True)
    for name in ("commit", "actor", "environment"):
        resource_import.add_argument("--" + name, required=True)
    for name in ("bundle", "journal"):
        resource_import.add_argument("--" + name, type=Path, required=True)
    import_mode = resource_import.add_mutually_exclusive_group(required=True)
    import_mode.add_argument("--check", action="store_true")
    import_mode.add_argument("--allow-resource-writes", action="store_true")
    drift = commands.add_parser("drift", help="isolated read-only observation; no remediation")
    drift.add_argument(
        "--unit",
        choices=["oci-network", "oci-oke", "cloudflare-edge", "supabase-database"],
        required=True,
    )
    for name in ("commit", "actor", "environment"):
        drift.add_argument("--" + name, required=True)
    for name in ("bundle", "journal"):
        drift.add_argument("--" + name, type=Path, required=True)
    drift_mode = drift.add_mutually_exclusive_group(required=True)
    drift_mode.add_argument("--check", action="store_true")
    drift_mode.add_argument("--allow-local-writes", action="store_true")
    monitoring = commands.add_parser("monitoring", help="offline operational observations")
    monitoring_commands = monitoring.add_subparsers(dest="monitoring_command", required=True)
    monitor_readiness = monitoring_commands.add_parser(
        "check-readiness", help="offline durable-state checks; activation pending"
    )
    for name in ("unit", "binding-sha256"):
        monitor_readiness.add_argument("--" + name, required=True)
    monitor_readiness.add_argument("--heartbeat-seconds", type=int, required=True)
    findings = monitoring_commands.add_parser(
        "findings", help="read captured cost/capacity evidence"
    )
    findings.add_argument("--evidence", type=Path, required=True)
    health = monitoring_commands.add_parser(
        "health", help="bounded endpoint and recorded OKE health"
    )
    health.add_argument("--evidence", type=Path, required=True)
    health_mode = health.add_mutually_exclusive_group(required=True)
    health_mode.add_argument("--check", action="store_true")
    health_mode.add_argument("--observe", action="store_true")
    recovery = commands.add_parser(
        "state-recovery", help="explicit checkpoint recovery; writers remain frozen"
    )
    recovery.add_argument(
        "--unit",
        choices=["oci-network", "oci-oke", "cloudflare-edge", "supabase-database"],
        required=True,
    )
    for name in ("commit", "actor", "environment"):
        recovery.add_argument("--" + name, required=True)
    for name in ("bundle", "journal"):
        recovery.add_argument("--" + name, type=Path, required=True)
    recovery_mode = recovery.add_mutually_exclusive_group(required=True)
    recovery_mode.add_argument("--check", action="store_true")
    recovery_mode.add_argument("--allow-state-writes", action="store_true")
    return parser


def _posture_commit(root: Path) -> str:
    from infra_core.cutover import repository_state

    try:
        commit, clean = repository_state(root)
    except (OSError, subprocess.SubprocessError):
        raise ValueError("BACKEND006: cannot establish checkout identity") from None
    if not clean:
        raise ValueError("BACKEND006: posture requires a clean reviewed checkout")
    return commit


def main(
    argv: Sequence[str] | None = None,
    *,
    preview: Callable[[Path, argparse.Namespace], None] | None = None,
    apply: Callable[[Path, argparse.Namespace], None] | None = None,
    resource_import: Callable[[Path, argparse.Namespace], None] | None = None,
    drift: Callable[[Path, argparse.Namespace], None] | None = None,
    state_recovery: Callable[[Path, argparse.Namespace], None] | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = find_repository(args.root)
        if args.command == "providers":
            from infra_core.provider_capabilities import inspect as inspect_providers

            print(json.dumps(inspect_providers(root, args.provider), indent=2))
        elif args.command == "readiness":
            from infra_core.readiness import check as check_readiness

            result = check_readiness(root, args.evidence, unit=args.unit)
            print(json.dumps(result, sort_keys=True))
            return 0 if result["status"] == "accepted" else 1
        elif args.command == "security":
            if args.security_command == "workflows":
                check_workflows(root)
                print("PASS: workflow syntax/expressions; no workflow steps executed")
            elif args.security_command == "check-enrollment":
                from infra_core.enrollment import check as check_enrollment

                print(json.dumps(check_enrollment(root, args.evidence), sort_keys=True))
                return 1  # Independent enrollment remains pending even with valid observations.
            else:
                from infra_core.administration import MAX_BYTES, private_path
                from infra_core.administration import check as check_administration
                from infra_core.administration import collect as collect_administration

                if args.security_command == "collect-administration":
                    destination = private_path(root, args.output)
                    if destination.exists():
                        raise ValueError("ADMIN001: use a new private output path; no overwrite")
                    payload = collect_administration(root)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with destination.open("xb") as stream:
                        stream.write(payload)
                    print("PASS: administrative observations saved; operations remain disabled")
                else:
                    with private_path(root, args.evidence).open("rb") as stream:
                        payload = stream.read(MAX_BYTES + 1)
                    print(json.dumps(check_administration(root, payload), indent=2))
        elif args.command == "services" and args.services_command == "collect-cloudflare":
            from infra_core.service_collection import collect_cloudflare

            collect_cloudflare(root, args.config, args.review, args.token_file, args.output)
            print(
                "PASS: Cloudflare evidence collected; entitlement remains independently reviewed; "
                "deployment disabled"
            )
        elif args.command == "services" and args.services_command == "check-staging":
            from infra_core.supabase_staging import check as check_supabase_staging

            result = check_supabase_staging(
                root,
                args.config,
                args.evidence,
                args.encrypted_configuration,
                account_id=args.account_id,
                scope_id=args.scope_id,
            )
            print(json.dumps(result, sort_keys=True))
            return 1  # Staging consistency does not complete operational acceptance.
        elif args.command == "services":
            from infra_core.governance.contracts import mapping
            from infra_core.service_evidence import (
                read_service_pair,
                reviewed_commit,
                validate_service_evidence,
            )

            commit = reviewed_commit(root)
            service_config = mapping(
                json.loads((root / args.config).read_text(encoding="utf-8")), "service proposal"
            )
            payload, envelope = read_service_pair(root / args.evidence)
            with (root / "config/quotas/profiles.toml").open("rb") as stream:
                service_profiles = tomllib.load(stream)["profiles"]
            service_profile = service_profiles.get(
                str(service_config.get("provider")) + "-free", {}
            )
            result = validate_service_evidence(
                service_config, service_profile, payload, envelope, commit=commit
            )
            if reviewed_commit(root) != commit:
                raise ValueError("EXT023: checkout changed during service audit")
            print(json.dumps(result, indent=2))
        elif args.command == "backup" and args.backup_command == "check-recovery":
            from infra_core.recovery_staging import check as check_recovery_staging

            print(
                json.dumps(
                    check_recovery_staging(
                        root,
                        unit=args.unit,
                        current_checkpoint=args.current_checkpoint,
                        current_configuration=args.current_configuration,
                        restore_checkpoint=args.restore_checkpoint,
                        restore_configuration=args.restore_configuration,
                    ),
                    sort_keys=True,
                )
            )
        elif args.command == "backup" and args.backup_command == "check-readiness":
            from infra_core.backup_readiness import check as check_backup_readiness

            result = check_backup_readiness(
                root,
                args.evidence,
                unit=args.unit,
                repository_id=args.repository_id,
                recovery_host_id=args.recovery_host_id,
            )
            print(json.dumps(result, sort_keys=True))
            return 1  # Independent storage and custody acceptance remains pending.
        elif args.command == "backup" and args.backup_command == "rehearse":
            from infra_core.recovery_rehearsal import rehearse

            result = rehearse(
                root,
                root / args.policy,
                root / args.receipt,
                args.repository,
                root / args.password_file,
                root / args.passphrase_file,
                root / args.output,
            )
            print(json.dumps(result, indent=2))
            if not result["objectives_met"]:
                return 1
        elif args.command == "backup":
            from infra_core.backup import capture

            capture(
                root,
                root / args.request,
                root / args.checkpoint,
                root / args.config,
                args.repository,
                args.repository_id,
                root / args.password_file,
                args.exported_at,
            )
            print("PASS: encrypted pair snapshot stored; no resource operation authorized")
        elif args.command == "operations" and args.operations_command == "check-readiness":
            from infra_core.writer_readiness import check as check_writer_readiness

            result = check_writer_readiness(root, args.writers, args.evidence, unit=args.unit)
            print(json.dumps(result, sort_keys=True))
            return 1  # Distributed writer exclusion remains an independent acceptance gate.
        elif args.command == "operations":
            from infra_core.operations import inspect, inspect_journal

            result = (
                inspect(root / args.request)
                if args.request is not None
                else inspect_journal(root / args.journal)
            )
            print(json.dumps(result, indent=2))
        elif args.command == "ownership":
            from infra_core.ownership import inspect as inspect_ownership

            print(json.dumps(inspect_ownership(root, args.evidence), indent=2))
        elif args.command == "cutover":
            from infra_core.cutover import check

            if args.cutover_command == "handoff":
                # Bound/redact the private index through the handoff transport adapter.
                from infra_core.ownership_handoff import inspect as inspect_handoff

                print(
                    json.dumps(
                        inspect_handoff(
                            root, args.evidence, actor=args.actor, environment=args.environment
                        ),
                        indent=2,
                    )
                )
            else:
                print(
                    json.dumps(
                        check(root, json.loads((root / args.evidence).read_text(encoding="utf-8"))),
                        indent=2,
                    )
                )
        elif args.command == "kubernetes" and args.kubernetes_command == "check-staging":
            from infra_core.oke_staging import check as check_oke_staging

            print(
                json.dumps(
                    check_oke_staging(
                        root,
                        args.config,
                        args.oci_config,
                        args.network_outputs,
                        args.inventory,
                        args.resources,
                        account_id=args.account_id,
                        cluster_id=args.cluster_id,
                    ),
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
        elif args.command == "governance" and args.governance_command == "check-readiness":
            from infra_core.account_readiness import check as check_account_readiness

            result = check_account_readiness(
                root, args.evidence, unit=args.unit, account_id=args.account_id
            )
            print(json.dumps(result, sort_keys=True))
            return 1  # Independent live entitlement and IAM review remains pending.
        elif args.command == "governance":
            from infra_core.governance.audit import audit
            from infra_core.inventory.oci import OCIReader, collect
            from infra_core.inventory_evidence import (
                capture_inventory,
                read_inventory_pair,
                reviewed_commit,
                validate_inventory_evidence,
            )

            with (root / args.account).open("rb") as stream:
                account = tomllib.load(stream)
            if args.governance_command == "audit":
                with (root / "config/quotas/profiles.toml").open("rb") as stream:
                    profiles = tomllib.load(stream)["profiles"]
                profile = profiles.get(account.get("profile"), {})
                commit = reviewed_commit(root)
                payload, envelope = read_inventory_pair(root / args.inventory)
                result = audit(
                    account,
                    profile,
                    validate_inventory_evidence(account, profile, payload, envelope, commit=commit),
                    json.loads((root / args.plan).read_text(encoding="utf-8")),
                )
                if reviewed_commit(root) != commit:
                    raise ValueError("GOV043: checkout changed during inventory audit")
                print(json.dumps(result, sort_keys=True, indent=2))
            else:
                if account.get("provider") != "oci":
                    raise ValueError("GOV006: only the OCI read-only collector is implemented")
                destination = (root / args.output).resolve()
                if not destination.is_relative_to(root.resolve() / ".infra"):
                    raise ValueError("GOV003: inventory output must stay under .infra")
                destination.parent.mkdir(parents=True, exist_ok=True)
                sidecar = envelope_path(destination)
                destination.unlink(missing_ok=True)
                sidecar.unlink(missing_ok=True)
                try:
                    commit = reviewed_commit(root)
                    with (root / "config/quotas/profiles.toml").open("rb") as stream:
                        profiles = tomllib.load(stream)["profiles"]
                    profile = profiles.get(account.get("profile"), {})
                    usage = json.loads((root / args.usage).read_text()) if args.usage else None
                    reader = OCIReader(
                        str((root / args.oci_config).resolve()),
                        args.oci_profile,
                        account["account_id"],
                    )
                    snapshot = collect(
                        reader, account["account_id"], account["home_region"], usage=usage
                    )
                    payload, envelope = capture_inventory(account, profile, snapshot, commit=commit)
                    if reviewed_commit(root) != commit:
                        raise ValueError("GOV043: checkout changed during inventory collection")
                    destination.write_bytes(payload)
                    sidecar.write_bytes(envelope)
                except Exception:
                    destination.unlink(missing_ok=True)
                    sidecar.unlink(missing_ok=True)
                    raise ValueError(
                        "GOV040: collection/binding failed; inspect inputs/permissions privately"
                    ) from None
                print(
                    "Collected supported OCI families; "
                    "monthly usage/entitlement still require audit"
                )
        elif args.command == "backend":
            config = load_foundation(root)
            if args.backend_command == "check-readiness":
                from infra_core.backend_readiness import check as check_backend_readiness

                print(
                    json.dumps(
                        check_backend_readiness(root, args.evidence, account_id=args.account_id),
                        sort_keys=True,
                    )
                )
                return 1  # Independent backend acceptance remains pending.
            elif args.backend_command == "collect-posture":
                from infra_core.inventory.oci import OCIReader

                destination = (root / args.output).resolve()
                if not destination.is_relative_to(root / ".infra"):
                    raise ValueError("BACKEND001: posture output must stay under .infra")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.unlink(missing_ok=True)
                sidecar = envelope_path(destination)
                sidecar.unlink(missing_ok=True)
                commit = _posture_commit(root)
                try:
                    reader = OCIReader(
                        str((root / args.oci_config).resolve()), args.oci_profile, args.account_id
                    )
                    posture = reader.backend_posture(config)
                except Exception:
                    raise ValueError(
                        "BACKEND005: OCI posture collection failed; inspect credentials privately"
                    ) from None
                payload, envelope = capture_posture(
                    config, posture, account_id=args.account_id, commit=commit
                )
                if _posture_commit(root) != commit:
                    raise ValueError("BACKEND006: checkout changed during posture collection")
                try:
                    destination.write_bytes(payload)
                    sidecar.write_bytes(envelope)
                except OSError:
                    destination.unlink(missing_ok=True)
                    sidecar.unlink(missing_ok=True)
                    raise ValueError("BACKEND006: posture pair publication failed") from None
                print("PASS: read-only backend posture collected; deployment disabled")
            elif args.backend_command == "check-posture":
                payload, envelope = read_posture_pair(root / args.evidence)
                print(
                    json.dumps(
                        validate_posture_evidence(
                            config,
                            payload,
                            envelope,
                            account_id=args.account_id,
                            commit=_posture_commit(root),
                        )
                    )
                )
            elif args.backend_command == "inspect":
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
                payload, envelope, commit = None, None, None
                if not args.local_test:
                    if not args.account_id:
                        raise ValueError("BACKEND006: remote qualification requires --account-id")
                    commit = _posture_commit(root)
                    payload, envelope = read_posture_pair(root / args.posture)
                receipt = qualify(
                    config,
                    local=args.local_test,
                    allow_writes=args.allow_backend_writes,
                    posture=payload,
                    posture_envelope=envelope,
                    account_id=args.account_id,
                    commit=commit,
                )
                destination.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
                print(f"PASS: {receipt['kind']} backend qualified; resource deployment disabled")
            else:
                validate_receipt(
                    config, json.loads((root / args.receipt).read_text(encoding="utf-8"))
                )
                print("PASS: OCI receipt binding/freshness only; deployment remains disabled")
        elif args.command == "monitoring" and args.monitoring_command == "check-readiness":
            from infra_core.monitoring_readiness import check as check_monitoring_readiness

            result = check_monitoring_readiness(
                root,
                unit=args.unit,
                binding_sha256=args.binding_sha256,
                heartbeat_seconds=args.heartbeat_seconds,
            )
            print(json.dumps(result, sort_keys=True))
            return 1 if result["gaps"] else 0
        elif args.command == "monitoring":
            from infra_core.operational_findings import check as check_findings

            if args.monitoring_command == "health":
                from infra_core.health import check as check_health

                result = check_health(root, args.evidence, network=args.observe)
                print(json.dumps(result, sort_keys=True))
                return 0 if result["status"] == "healthy" else 1
            result = check_findings(root, args.evidence)
            print(json.dumps(result, sort_keys=True))
            return 1 if result["status"] == "unknown" else 0
        elif args.command == "state-recovery":
            if state_recovery is None:
                raise ValueError("RESTORE001: explicit recovery composition required")
            state_recovery(root, args)
        elif args.command == "drift":
            if drift is None:
                raise ValueError("DRIFT001: explicit observation composition required")
            drift(root, args)
        elif args.command == "resource-import":
            if resource_import is None:
                raise ValueError("IMPORT001: explicit resource import composition is required")
            resource_import(root, args)
        elif args.command == "apply":
            if apply is None:
                raise ValueError("APPLY001: explicit service apply composition is required")
            apply(root, args)
        elif args.command == "preview" and preview is not None:
            preview(root, args)
        elif args.command in ("preview", "deploy"):
            deny_deployment(load_foundation(root), args.unit)
        elif args.command == "verify":
            verify(root)
    except (subprocess.SubprocessError, RuntimeError, ValueError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0
