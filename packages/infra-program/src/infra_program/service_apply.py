"""Explicit, disabled-by-default service apply; owned inputs and no automatic retries."""

import argparse
import fcntl
import hashlib
import os
import shutil
import sys
import tempfile
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pulumi
from infra_core import administration, operation_admission, operations
from infra_core.backend import validate_receipt
from infra_core.backend_posture import validate_posture_evidence
from infra_core.foundation import load_foundation
from infra_core.preview_contracts import describe_preview
from infra_core.provider_tools import (
    materialize_home,
    verified_environment,
    verified_supabase_environment,
)

from infra_program import preview_driver as preview
from infra_program.operation_runtime import MESSAGE, Runtime, require, validate_plan
from infra_program.preview_orchestration import _private
from infra_program.preview_program import NetworkPreviewContext, ServicePreviewContext
from infra_program.preview_runtime import cli_runtime
from infra_program.services.configuration import register_services_from_config

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


def _enabled(
    root: Path, oci: bool = False, importing: bool = False, *, unit: str | None = None
) -> None:
    value = operations.read_json(
        root
        / (
            "config/resource-import.json"
            if importing
            else "config/oci-apply.json"
            if oci
            else "config/service-apply.json"
        )
    )
    require(type(oci) is bool and type(importing) is bool and (not importing or oci))
    units = {"oci-network", "oci-oke"} if oci else {"cloudflare-edge", "supabase-database"}
    require(
        type(value) is dict
        and set(value) == {"schema_version", "units"}
        and type(value["schema_version"]) is int
        and value["schema_version"] == 2
        and type(value["units"]) is dict
        and set(value["units"]) == units
        and all(type(enabled) is bool for enabled in value["units"].values())
        and unit in units
        and value["units"][unit] is True
    )


def _service(
    root: Path, unit: str, commit: str, raw: dict[str, bytes]
) -> tuple[ServicePreviewContext, bytes]:
    _enabled(root, unit=unit)
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
    oci: bool = False,
    importing: bool = False,
) -> tuple[preview.Context, dict[str, str]]:
    context: preview.Context
    if importing:
        from infra_program.import_driver import prepare as prepare_import

        context, inputs = prepare_import(root, args.unit, args.commit, raw, journal)
    elif oci:
        from infra_program.oci_apply import prepare

        context, inputs = prepare(root, args.unit, args.commit, raw)
    else:
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
        value["operation"] == ("import" if importing else "apply")
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


def _names(oci: bool, unit: str, importing: bool = False) -> set[str]:
    if importing:
        from infra_program.import_driver import names

        return names(unit)
    if oci:
        from infra_program.oci_apply import names

        return names(unit)
    require(unit in {"cloudflare-edge", "supabase-database"})
    return NAMES


def _load(
    root: Path, args: argparse.Namespace, oci: bool = False, importing: bool = False
) -> tuple[dict[str, Any], dict[str, bytes], bytes]:
    _enabled(root, oci, importing, unit=args.unit)
    names = _names(oci, args.unit, importing)
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
        and set(bundle["paths"]) == names
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


def check(
    root: Path, args: argparse.Namespace, oci: bool = False, importing: bool = False
) -> tuple[dict[str, Any], dict[str, bytes], bytes]:
    """Credential-free preflight; returned frozen inputs are not an execution permit."""
    try:
        root = root.resolve()
        require(not importing or oci)
        preview._checkout(root)
        bundle, raw, journal = _load(root, args, oci, importing)
        _admit(root, args, bundle, raw, journal, oci, importing)
        _current_environment(root, args, raw)
        return bundle, raw, journal
    except Exception:
        raise ValueError(MESSAGE) from None


def execute(
    root: Path,
    args: argparse.Namespace,
    credentials: Callable[[], dict[str, str]],
    oci: bool = False,
    importing: bool = False,
) -> None:
    """Trusted caller establishes protected execution and durable journal custody first."""
    try:
        root = root.resolve()
        bundle, raw, journal = check(root, args, oci, importing)
        if args.check:
            return
        require(args.allow_resource_writes)
        path = _private(root, args.journal)
        lock = path.with_name(path.name + ".apply.lock")
        with os.fdopen(os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600), "a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            require(preview._read(path, operations.MAX_BYTES) == journal)
            _run(root, args, bundle, raw, journal, credentials, oci, importing)
    except Exception:
        raise ValueError(MESSAGE) from None


def _run(
    root: Path,
    args: argparse.Namespace,
    bundle: dict[str, Any],
    raw: dict[str, bytes],
    journal: bytes,
    credentials: Callable[[], dict[str, str]],
    oci: bool = False,
    importing: bool = False,
) -> None:
    context, expected = _admit(root, args, bundle, raw, journal, oci, importing)
    value = operations.request(preview._json(raw["operation"], operations.MAX_BYTES))
    path = _private(root, args.journal)
    _current_environment(root, args, raw)
    head = operations.journal(root, path, value, "admitted", predecessor=expected["journal_head"])
    started, finished = False, False
    try:
        with tempfile.TemporaryDirectory(prefix="apply-", dir=root / ".infra") as directory:
            work = Path(directory)
            cli = cli_runtime(root, _private(root, bundle["cli_archive"]), work / "bin")
            env = materialize_home(
                root,
                _private(root, bundle["provider_home"]),
                work / "home",
                supabase=args.unit == "supabase-database",
            )
            uv_source = _private(root, ".infra/tools/uv/uv")
            uv_hash = operations.read_json(root / "config/toolchain.json")["tools"]["uv"]["assets"][
                "linux-x64"
            ]["binary_sha256"]
            require(_hash(uv_source.read_bytes()) == uv_hash)
            uv_dir = work / "uv-bin"
            uv_dir.mkdir()
            shutil.copyfile(uv_source, uv_dir / "uv")
            (uv_dir / "uv").chmod(0o755)
            require(_hash((uv_dir / "uv").read_bytes()) == uv_hash)
            private = credentials()
            required = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "PULUMI_CONFIG_PASSPHRASE"}
            if oci:
                required |= {"OCI_USER_OCID", "OCI_FINGERPRINT", "OCI_PRIVATE_KEY_PATH"}
                key = _private(root, private["OCI_PRIVATE_KEY_PATH"])
                key_bytes = preview._read(key, 65536)
                require(bool(key_bytes))
                (work / "oci-key.pem").write_bytes(key_bytes)
                (work / "oci-key.pem").chmod(0o600)
                private["OCI_PRIVATE_KEY_PATH"] = str(work / "oci-key.pem")
            require(
                required <= set(private) <= required | {"AWS_SESSION_TOKEN"}
                and all(type(v) is str and bool(v) for v in private.values())
                and len(private["PULUMI_CONFIG_PASSPHRASE"]) >= 20
            )
            env.update(private)
            env.update(
                HOME=str(work),
                TMP=str(work),
                TEMP=str(work),
                TMPDIR=str(work),
                PATH=os.pathsep.join(
                    (
                        str(Path(sys.executable).parent),
                        str(work / "bin"),
                        str(uv_dir),
                    )
                ),
                PULUMI_BACKEND_URL=context.foundation.backend.url(),
                PULUMI_DEBUG_COMMANDS="true",
                PULUMI_SKIP_UPDATE_CHECK="true",
                AWS_EC2_METADATA_DISABLED="true",
                UV_OFFLINE="1",
                PIP_NO_INDEX="1",
                UV_CACHE_DIR=str(work / "uv-cache"),
            )
            owned = {
                "policy.json": preview._policy_configuration(context),
                "stack.yaml": raw["encrypted_configuration"],
                "plan.json": raw["plan"],
                "Pulumi.yaml": preview._encoded(
                    {
                        "name": context.foundation.project,
                        "runtime": {"name": "python", "options": {"virtualenv": sys.prefix}},
                    }
                ),
                "__main__.py": (
                    b"from infra_program.service_apply import program_from_request\n"
                    b"program_from_request()\n"
                ),
            }
            for name, content in owned.items():
                (work / name).write_bytes(content)
            if oci:
                owned["oci-key.pem"] = key_bytes
            if importing:
                from infra_program.import_driver import ImportRuntime, import_file

                owned["import.json"] = import_file(raw)
                (work / "import.json").write_bytes(owned["import.json"])
                runtime: Runtime = ImportRuntime(
                    cli, work, env, context.contract.stack_identity, root / "policies", context, raw
                )
            else:
                runtime = Runtime(
                    cli, work, env, context.contract.stack_identity, root / "policies"
                )

            def dependency() -> None:
                if oci and args.unit == "oci-oke":
                    from infra_program.oci_apply import confirm_dependency

                    if importing:
                        confirm_dependency(runtime, context, raw, True)
                    else:
                        confirm_dependency(runtime, context, raw)

            def confirm() -> None:
                require(operations.inspect_journal(path)["head"] == head)
                require(
                    all(
                        preview._read(_private(root, bundle["paths"][n]), operations.MAX_BYTES) == v
                        for n, v in raw.items()
                    )
                )
                require(all((work / n).read_bytes() == v for n, v in owned.items()))
                _admit(root, args, bundle, raw, journal, oci, importing)
                dependency()
                cli.verify()
                require(_hash((uv_dir / "uv").read_bytes()) == uv_hash)
                (
                    verified_supabase_environment
                    if args.unit == "supabase-database"
                    else verified_environment
                )(root, work / "home")

            def bootstrap() -> None:
                owned["apply.json"] = preview._encoded(
                    dict(
                        oci=oci,
                        importing=importing,
                        root=str(root),
                        unit=args.unit,
                        commit=args.commit,
                        actor=args.actor,
                        environment=args.environment,
                        journal=str(path),
                        journal_head=head,
                        journal_snapshot=journal.hex(),
                        bundle=bundle,
                        raw={n: v.hex() for n, v in raw.items()},
                    )
                )
                (work / "apply.json").write_bytes(owned["apply.json"])

            runtime.select()
            dependency()
            require(runtime.checkpoint() == expected["checkpoint_sha256"])
            bootstrap()
            runtime.operation(preview=True)
            confirm()
            _current_environment(root, args, raw)
            require(runtime.checkpoint() == expected["checkpoint_sha256"])
            head = operations.journal(root, path, value, "running", predecessor=head)
            bootstrap()
            confirm()
            started = True
            changes = runtime.operation(preview=False)
            confirm()
            extra: dict[str, Any] = {}
            if oci and args.unit == "oci-network":
                from infra_program.oci_apply import network_result

                extra = network_result(runtime, context)
            if importing:
                extra["checkpoint_sha256"] = runtime.checkpoint()
                require(extra["checkpoint_sha256"] == runtime.verified_checkpoint_sha256)
                extra["post_import_equivalent"] = True
            head = operations.journal(root, path, value, "succeeded", predecessor=head)
            finished = True
            output = _private(root, bundle["output"])
            with os.fdopen(
                os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
            ) as stream:
                stream.write(
                    preview._encoded(
                        dict(
                            **extra,
                            schema_version=1,
                            operation_id=value["operation_id"],
                            status="succeeded",
                            resource_changes=changes,
                            journal_head=head,
                            approval_sha256=_hash(raw["approval"]),
                            plan_sha256=_hash(raw["plan"]),
                        )
                    )
                )
    except Exception:
        # A launched update can partially mutate state even when its diagnostics look benign.
        if not finished:
            operations.journal(
                root, path, value, "indeterminate" if started else "failed", predecessor=head
            )
        raise


def program_from_request() -> None:
    try:
        data = preview._json(
            preview._read(Path("apply.json"), preview.REQUEST_LIMIT), preview.REQUEST_LIMIT
        )
        root = Path(data["root"])
        preview._checkout(root)
        raw = {n: bytes.fromhex(v) for n, v in data["raw"].items()}
        oci = data.get("oci", False)
        importing = data.get("importing", False)
        require(type(oci) is bool and type(importing) is bool and (not importing or oci))
        require(
            set(raw) == _names(oci, data["unit"], importing)
            and operations.inspect_journal(Path(data["journal"]))["head"] == data["journal_head"]
        )
        require(
            Path("plan.json").read_bytes() == raw["plan"]
            and Path("stack.yaml").read_bytes() == raw["encrypted_configuration"]
        )
        args = argparse.Namespace(
            unit=data["unit"],
            commit=data["commit"],
            actor=data["actor"],
            environment=data["environment"],
        )
        context, _ = _admit(
            root, args, data["bundle"], raw, bytes.fromhex(data["journal_snapshot"]), oci, importing
        )
        require(Path(data["journal"]) == root / ".infra/operations" / (args.unit + ".json"))
        require(Path("policy.json").read_bytes() == preview._policy_configuration(context))
        identity = f"{pulumi.get_organization()}/{pulumi.get_project()}/{pulumi.get_stack()}"
        dry_run = pulumi.runtime.is_dry_run()
        require(identity == context.contract.stack_identity and type(dry_run) is bool)
        stage = operations.inspect_journal(Path(data["journal"]))["state"]
        if importing:
            # The import command never runs a resource program. Its before/after
            # policy previews are the only admitted child executions.
            require(dry_run is True and stage in {"admitted", "running"})
        else:
            require(stage == ("admitted" if dry_run else "running"))
        if oci:
            from infra_program.oci_apply import register

            require(isinstance(context, NetworkPreviewContext))
            assert isinstance(context, NetworkPreviewContext)
            register(context)
            return
        require(isinstance(context, ServicePreviewContext))
        assert isinstance(context, ServicePreviewContext)
        register_services_from_config(
            context.proposal,
            context.evidence,
            context.profile,
            envelope=context.envelope,
            commit=context.expected_commit,
        )
    except Exception:
        raise ValueError(MESSAGE) from None
