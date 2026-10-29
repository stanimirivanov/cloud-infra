"""Explicit, disabled-by-default service apply; owned inputs and no automatic retries."""

import argparse
import hashlib
import tomllib
from pathlib import Path
from typing import Any

from infra_core import administration, operation_admission, operations
from infra_core.backend import validate_receipt
from infra_core.backend_posture import validate_posture_evidence
from infra_core.foundation import load_foundation
from infra_core.preview_contracts import describe_preview

from infra_program import preview_driver as preview
from infra_program.operation_runtime import MESSAGE, require, validate_plan
from infra_program.preview_orchestration import _private
from infra_program.preview_program import ServicePreviewContext

NAMES = {
    "operation",
    "approval",
    "operator",
    "approver",
    "backup_receipt",
    "backup_manifest",
    "environment",
    "plan",
    "encrypted_configuration",
    "proposal",
    "evidence",
    "envelope",
    "qualification",
    "posture",
    "posture_envelope",
}
APPROVAL = {
    "operation",
    "approval",
    "operator",
    "approver",
    "backup_receipt",
    "backup_manifest",
    "environment",
}


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _enabled(root: Path) -> None:
    value = operations.read_json(root / "config/service-apply.json")
    require(
        value == {"schema_version": 1, "enabled": True}
        and type(value["schema_version"]) is int
        and value["enabled"] is True
    )


def _service(
    root: Path, unit: str, commit: str, raw: dict[str, bytes]
) -> tuple[ServicePreviewContext, bytes]:
    _enabled(root)
    require(unit in {"cloudflare-edge", "supabase-database"})
    foundation = load_foundation(root)
    context = ServicePreviewContext(
        foundation,
        describe_preview(foundation, unit, commit),
        commit,
        preview._json(raw["proposal"], operations.MAX_BYTES),
        tomllib.loads((root / "config/quotas/profiles.toml").read_text())["profiles"][
            "cloudflare-free" if unit == "cloudflare-edge" else "supabase-free"
        ],
        raw["evidence"],
        raw["envelope"],
    )
    preview._contract(root, context)
    _, artifacts, _ = preview._prepare(root, context, raw["encrypted_configuration"], None)
    preview._versions(root, context, artifacts)
    validate_plan(raw["plan"], context.contract.stack_identity, foundation.pulumi_version)
    plans = preview._json(raw["plan"], operations.MAX_BYTES)["resourcePlans"]
    expected_graph = {
        ("pulumi:pulumi:Stack", foundation.project + "-" + unit),
        ("infrastructure:services:Independent", unit),
        ("pulumi:providers:" + context.proposal["provider"], unit + "-provider"),
    }
    expected_graph.update((r["type"], unit + "-" + r["key"]) for r in context.proposal["resources"])
    require(
        len(plans) == len(expected_graph)
        and {(r["goal"]["type"], r["goal"]["name"]) for r in plans.values()} == expected_graph
    )
    validate_receipt(foundation, preview._json(raw["qualification"], operations.MAX_BYTES))
    return context, preview._encoded(
        {
            "inputs": {n: _hash(raw[n]) for n in sorted(NAMES - APPROVAL)},
            "profile": _hash(preview._encoded(context.profile)),
            "foundation": foundation.digest,
        }
    )


def _admit(
    root: Path,
    args: argparse.Namespace,
    bundle: dict[str, Any],
    raw: dict[str, bytes],
    journal: bytes,
) -> tuple[ServicePreviewContext, dict[str, str]]:
    context, inputs = _service(root, args.unit, args.commit, raw)
    validate_posture_evidence(
        context.foundation,
        raw["posture"],
        raw["posture_envelope"],
        account_id=bundle["backend_account_id"],
        commit=args.commit,
    )
    value = operations.request(preview._json(raw["operation"], operations.MAX_BYTES))
    require(
        value["operation"] == "apply"
        and value["unit"] == args.unit
        and value["commit"] == args.commit
    )
    entries = operations._validate(administration._json(journal, array=True)["items"])
    expected = dict(
        actor=args.actor,
        environment=args.environment,
        commit=args.commit,
        configuration_sha256=_hash(raw["encrypted_configuration"]),
        checkpoint_sha256=value["checkpoint_sha256"],
        plan_sha256=_hash(raw["plan"]),
        journal_head=operations.digest(entries[-1]),
    )
    # Include backend scope in the execution-specific signed profile.
    inputs = preview._encoded(
        {"service": _hash(inputs), "backend_account_id": bundle["backend_account_id"]}
    )
    operation_admission.admit(
        root,
        request=raw["operation"],
        approval=raw["approval"],
        signatures={role: raw[role] for role in ("operator", "approver")},
        backup_receipt=raw["backup_receipt"],
        backup_manifest=raw["backup_manifest"],
        environment=raw["environment"],
        journal=journal,
        context=expected,
        execution_inputs=inputs,
    )
    return context, expected


def _load(root: Path, args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, bytes], bytes]:
    _enabled(root)
    require(args.unit in {"cloudflare-edge", "supabase-database"})
    require(_private(root, args.journal) == root / ".infra/operations" / (args.unit + ".json"))
    bundle = operations.read_json(_private(root, args.bundle))
    require(
        set(bundle)
        == {
            "schema_version",
            "paths",
            "backend_account_id",
            "cli_archive",
            "provider_home",
            "output",
        }
        and type(bundle["schema_version"]) is int
        and bundle["schema_version"] == 1
        and set(bundle["paths"]) == NAMES
    )
    raw = {
        n: preview._read(_private(root, p), operations.MAX_BYTES)
        for n, p in bundle["paths"].items()
    }
    require(sum(len(v) for v in raw.values()) <= 4 * 1024 * 1024)
    journal = preview._read(_private(root, args.journal), operations.MAX_BYTES)
    output = _private(root, bundle["output"])
    require(not output.exists() and output.parent.is_dir())
    return bundle, raw, journal


def _current_environment(root: Path, args: argparse.Namespace, raw: dict[str, bytes]) -> None:
    policy = operations.read_json(root / "config/operations-policy.json")
    current = administration.collect_operation_environment(
        root,
        repository=policy["repository"],
        repository_id=policy["repository_id"],
        environment=args.environment,
        commit=args.commit,
    )
    before, after = (
        administration._json(raw["environment"])["responses"],
        administration._json(current)["responses"],
    )
    require(all(before[n] == after[n] for n in ("environment", "branches")))


def check(root: Path, args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, bytes], bytes]:
    """Credential-free preflight; returned frozen inputs are not an execution permit."""
    try:
        root = root.resolve()
        preview._checkout(root)
        bundle, raw, journal = _load(root, args)
        _admit(root, args, bundle, raw, journal)
        _current_environment(root, args, raw)
        return bundle, raw, journal
    except Exception:
        raise ValueError(MESSAGE) from None
