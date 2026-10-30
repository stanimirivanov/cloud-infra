"""Composition entry point; offline commands do not import the Pulumi runtime."""

import argparse
import os
from collections.abc import Sequence
from pathlib import Path

from infra_core.cli import main as core_main


def _preview(root: Path, args: argparse.Namespace) -> None:
    from infra_program.preview_orchestration import execute

    execute(root, args)


def _apply(root: Path, args: argparse.Namespace) -> None:
    _operation(root, args, False)


def _import(root: Path, args: argparse.Namespace) -> None:
    _operation(root, args, True)


def _operation(root: Path, args: argparse.Namespace, importing: bool) -> None:
    from infra_program.operation_runtime import require

    if importing:
        from infra_program.import_driver import execute
    elif args.unit in {"oci-network", "oci-oke"}:
        from infra_program.oci_apply import execute
    else:
        from infra_program.service_apply import execute

    require(
        os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_SHA") == args.commit
        and bool(args.actor)
        and args.actor
        == os.environ.get("GITHUB_ACTOR")
        == os.environ.get("GITHUB_REPOSITORY_OWNER")
        and args.environment == args.unit + ("-import" if importing else "-apply")
    )

    def credentials() -> dict[str, str]:
        names = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "PULUMI_CONFIG_PASSPHRASE"}
        if args.unit in {"oci-network", "oci-oke"}:
            names |= {"OCI_USER_OCID", "OCI_FINGERPRINT", "OCI_PRIVATE_KEY_PATH"}
        if "AWS_SESSION_TOKEN" in os.environ:
            names.add("AWS_SESSION_TOKEN")
        return {name: os.environ[name] for name in names}

    execute(root, args, credentials)


def _drift(root: Path, args: argparse.Namespace) -> None:
    from infra_core.drift_results import require

    from infra_program.drift import execute

    require(
        os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_SHA") == args.commit
        and bool(args.actor)
        and args.actor
        == os.environ.get("GITHUB_ACTOR")
        == os.environ.get("GITHUB_REPOSITORY_OWNER")
        and args.environment == args.unit + "-monitor"
    )

    def credentials() -> dict[str, str]:
        names = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "PULUMI_CONFIG_PASSPHRASE"}
        if args.unit.startswith("oci-"):
            names |= {"OCI_USER_OCID", "OCI_FINGERPRINT", "OCI_PRIVATE_KEY_PATH"}
        if "AWS_SESSION_TOKEN" in os.environ:
            names.add("AWS_SESSION_TOKEN")
        return {name: os.environ[name] for name in names}

    execute(root, args, credentials)


def _recovery(root: Path, args: argparse.Namespace) -> None:
    from infra_core.recovery_contracts import require

    from infra_program.recovery_driver import execute

    require(
        os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_SHA") == args.commit
        and bool(args.actor)
        and args.actor
        == os.environ.get("GITHUB_ACTOR")
        == os.environ.get("GITHUB_REPOSITORY_OWNER")
        and args.environment == args.unit + "-recovery"
    )

    def credentials() -> dict[str, str]:
        names = {
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "RECOVERY_PASSPHRASE",
            "RECOVERY_BACKUP_PASSWORD",
        }
        if args.unit.startswith("oci-"):
            names |= {"OCI_USER_OCID", "OCI_FINGERPRINT", "OCI_PRIVATE_KEY_PATH"}
        if os.environ.get("AWS_SESSION_TOKEN"):
            names.add("AWS_SESSION_TOKEN")
        return {name: os.environ[name] for name in names}

    execute(root, args, credentials)


def main(argv: Sequence[str] | None = None) -> int:
    return core_main(
        argv,
        preview=_preview,
        apply=_apply,
        resource_import=_import,
        drift=_drift,
        state_recovery=_recovery,
    )
