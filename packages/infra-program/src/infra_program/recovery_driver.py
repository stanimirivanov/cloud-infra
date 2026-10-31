"""Default-disabled checkpoint recovery; frozen writers and no resource operations."""

import argparse
import fcntl
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infra_core import administration, backup, operation_admission, operations
from infra_core import recovery_contracts as c
from infra_core.backend_posture import validate_posture_evidence
from infra_core.drift_results import parse
from infra_core.network_outputs import validate_network
from infra_core.provider_tools import (
    materialize_home,
    verified_environment,
    verified_supabase_environment,
)

from infra_program import drift
from infra_program import preview_driver as preview
from infra_program import service_apply as shared
from infra_program.operation_runtime import Runtime
from infra_program.preview_orchestration import _private
from infra_program.preview_program import NetworkPreviewContext
from infra_program.preview_runtime import CliRuntime, cli_runtime

require = c.require
BASE = shared.NAMES | {
    "current_checkpoint",
    "restore_checkpoint",
    "restore_configuration",
    "restore_manifest",
    "restore_receipt",
    "restore_policy",
    "rehearsal",
    "freeze",
    "credential_review",
}
OWNER = {
    "owner_decision",
    "owner_approval",
    "owner_operator",
    "owner_approver",
    "owner_subject",
    "owner_checkpoint",
}


def names(unit: str) -> set[str]:
    require(unit in {"oci-network", "oci-oke", "cloudflare-edge", "supabase-database"})
    return (
        BASE
        | ({"account", "peer_checkpoint"} | OWNER if unit.startswith("oci-") else set())
        | ({"dependency_outputs"} if unit == "oci-oke" else set())
    )


def _peer(raw: dict[str, bytes], unit: str) -> dict[str, Any] | None:
    if not unit.startswith("oci-"):
        return None
    peer = "oci-network" if unit == "oci-oke" else "oci-oke"
    value = parse(raw["peer_checkpoint"])
    require(value["version"] == 3 and not value["deployment"].get("pending_operations"))
    backup._encrypted(value)
    resources = value["deployment"]["resources"]
    require(
        bool(resources)
        and all(
            r["urn"].startswith("urn:pulumi:" + peer + "::free-infrastructure::") for r in resources
        )
        and sum(r["type"] == "pulumi:pulumi:Stack" for r in resources) == 1
    )
    return value


def admit(
    root: Path,
    args: argparse.Namespace,
    bundle: dict[str, Any],
    raw: dict[str, bytes],
    journal: bytes,
) -> preview.Context:
    gate = operations.read_json(root / "config/state-recovery.json")
    require(
        type(gate.get("schema_version")) is int
        and gate == dict(schema_version=1, enabled=True)
        and gate["enabled"] is True
    )
    require(set(raw) == names(args.unit))
    request = operations.request(parse(raw["operation"]))
    require(
        request["operation"] == "recovery"
        and request["unit"] == args.unit
        and request["commit"] == args.commit
        and request["checkpoint_sha256"] == c.digest(raw["current_checkpoint"])
        and request["configuration_sha256"] == c.digest(raw["encrypted_configuration"])
    )
    require(raw["plan"] == c.plan(raw, bundle["configuration_destination"]))
    destination = _private(root, bundle["configuration_destination"])
    require(
        destination
        == root / ".infra/recovery/configs" / args.unit / (request["operation_id"] + ".json")
    )
    current = c.pair(raw["current_checkpoint"], raw["encrypted_configuration"], args.unit)
    restored = c.pair(raw["restore_checkpoint"], raw["restore_configuration"], args.unit)
    context = drift._context(
        root,
        args.unit,
        args.commit,
        dict(raw, encrypted_configuration=raw["restore_configuration"]),
    )
    for key in ("current_checkpoint", "restore_checkpoint"):
        drift._checkpoint(root, context, raw[key])
    require(c.identities(current) == c.identities(restored))
    c.unchanged_resources(current, restored)
    peer = _peer(raw, args.unit)
    if args.unit.startswith("oci-"):
        assert isinstance(context, NetworkPreviewContext)
        if args.unit == "oci-oke":
            assert peer is not None
            output = next(
                r["outputs"]
                for r in peer["deployment"]["resources"]
                if r["type"] == "pulumi:pulumi:Stack"
            )
            require(output == parse(raw["dependency_outputs"]))
            validate_network(output, context.configuration, context.account["account_id"])
        else:
            roots = [
                next(
                    r
                    for r in state["deployment"]["resources"]
                    if r["type"] == "pulumi:pulumi:Stack"
                )
                for state in (current, restored)
            ]
            require(roots[0]["outputs"] == roots[1]["outputs"])
            validate_network(
                roots[0]["outputs"], context.configuration, context.account["account_id"]
            )
    c.freeze(raw, args.unit)
    c.restore_evidence(raw, args.unit, backup.host_id())
    c.owner(
        raw,
        args.unit,
        journal,
        context.foundation.digest,
        (root / "config/operations-policy.json").read_bytes(),
    )
    review = parse(raw["credential_review"])
    require(
        set(review)
        == {
            "schema_version",
            "unit",
            "checkpoint_sha256",
            "configuration_sha256",
            "read_only_scopes_reviewed",
            "historical_provider_credentials_reviewed",
            "provider_identity_sha256",
            "reviewed_at",
            "expires_at",
        }
        and type(review["schema_version"]) is int
        and review["schema_version"] == 1
        and review["unit"] == args.unit
        and review["checkpoint_sha256"] == c.digest(raw["restore_checkpoint"])
        and review["configuration_sha256"] == c.digest(raw["restore_configuration"])
        and review["read_only_scopes_reviewed"] is True
        and review["historical_provider_credentials_reviewed"] is True
    )
    require(
        operations._hash(review["provider_identity_sha256"])
        if args.unit.startswith("oci-")
        else review["provider_identity_sha256"] is None
    )
    now = datetime.now(UTC)
    require(
        operations._time(review["reviewed_at"])
        <= now
        < operations._time(review["expires_at"])
        <= operations._time(request["expires_at"])
        and (now - operations._time(review["reviewed_at"])).total_seconds() <= 900
    )
    validate_posture_evidence(
        context.foundation,
        raw["posture"],
        raw["posture_envelope"],
        account_id=bundle["backend_account_id"],
        commit=args.commit,
    )
    entries = operations._validate(administration._json(journal, array=True)["items"])
    binding = preview._encoded(
        dict(
            adapter="state-recovery-v1",
            inputs={n: c.digest(raw[n]) for n in sorted(names(args.unit) - shared.APPROVAL)},
            foundation=context.foundation.digest,
            profile=operations.digest(context.profile),
            backend_account_id=bundle["backend_account_id"],
            repository=str(backup._path(Path(bundle["repository"]))),
            configuration_destination=bundle["configuration_destination"],
        )
    )
    operation_admission.admit(
        root,
        request=raw["operation"],
        approval=raw["approval"],
        signatures={r: raw[r] for r in ("operator", "approver")},
        backup_receipt=raw["backup_receipt"],
        backup_manifest=raw["backup_manifest"],
        environment=raw["environment"],
        journal=journal,
        context=dict(
            actor=args.actor,
            environment=args.environment,
            commit=args.commit,
            configuration_sha256=c.digest(raw["encrypted_configuration"]),
            checkpoint_sha256=c.digest(raw["current_checkpoint"]),
            plan_sha256=c.digest(raw["plan"]),
            journal_head=operations.digest(entries[-1]),
        ),
        execution_inputs=binding,
    )
    return context


def check(root: Path, args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, bytes], bytes]:
    try:
        root = root.resolve()
        preview._checkout(root)
        require(_private(root, args.journal) == root / ".infra/operations" / (args.unit + ".json"))
        bundle = parse(preview._read(_private(root, args.bundle), operations.MAX_BYTES))
        require(
            set(bundle)
            == {
                "schema_version",
                "paths",
                "backend_account_id",
                "cli_archive",
                "provider_home",
                "repository",
                "configuration_destination",
                "output",
            }
            and type(bundle["schema_version"]) is int
            and bundle["schema_version"] == 1
            and set(bundle["paths"]) == names(args.unit)
        )
        raw = {
            n: preview._read(_private(root, p), operations.MAX_BYTES)
            for n, p in bundle["paths"].items()
        }
        require(sum(map(len, raw.values())) <= 12 * operations.MAX_BYTES)
        journal = preview._read(_private(root, args.journal), operations.MAX_BYTES)
        require(Path(bundle["repository"]).is_absolute())
        repository = backup._path(Path(bundle["repository"]))
        require(
            repository.is_absolute()
            and repository.is_dir()
            and not repository.is_relative_to(root)
            and not root.is_relative_to(repository)
        )
        for key in ("configuration_destination", "output"):
            path = _private(root, bundle[key])
            require(not path.exists() and path.parent.is_dir())
        admit(root, args, bundle, raw, journal)
        shared._current_environment(root, args, raw)
        return bundle, raw, journal
    except Exception:
        raise ValueError(c.MESSAGE) from None


class Writer:
    """Only encrypted export and checkpoint restore; never a resource or force command."""

    def __init__(
        self,
        cli: CliRuntime,
        work: Path,
        env: dict[str, str],
        stack: str,
        deadline: float,
        backend: str,
    ):
        require(env["PULUMI_BACKEND_URL"] == backend and not any(k.startswith("OCI_") for k in env))
        self.transport = Runtime(
            cli, work, env, stack, Path(__file__).resolve().parents[4] / "policies"
        )
        self.transport.deadline = deadline
        self.backend = backend

    def _backend(self) -> None:
        require(self.transport.env["PULUMI_BACKEND_URL"] == self.backend)

    def export(self, stack: str | None = None) -> bytes:
        self._backend()
        stack = stack or self.transport.stack
        require(
            stack == self.transport.stack
            or (
                self.transport.stack.endswith(("/oci-network", "/oci-oke"))
                and stack
                in {
                    "organization/free-infrastructure/oci-network",
                    "organization/free-infrastructure/oci-oke",
                }
            )
        )
        path = self.transport.work / "export.json"
        path.unlink(missing_ok=True)
        self.transport._run(["stack", "export", "--file", str(path), "--stack", stack])
        return preview._read(path, operations.MAX_BYTES)

    def restore(self, path: Path) -> None:
        self._backend()
        require(
            path == self.transport.work / "restore.json"
            and path.is_file()
            and not path.is_symlink()
        )
        self.transport._run(
            ["stack", "import", "--stack", self.transport.stack, "--file", str(path)]
        )


class Observer(drift.LocalObserver):
    def key_check(self) -> None:
        self._local()
        path = self.work / "key-check.json"
        path.write_bytes((self.work / "stack.yaml").read_bytes())
        path.chmod(0o600)
        original = self._transport.env["PULUMI_CONFIG_PASSPHRASE"]
        wrong = secrets.token_urlsafe(32)
        require(wrong != original)

        def run(args: list[str], key: str, *, reject: bool = False) -> bytes:
            self._local()
            self._transport.cli.verify()
            remaining = self._transport.deadline - time.monotonic()
            require(remaining > 0)
            result = subprocess.run(
                [str(self._transport.cli.binary), *args, "--non-interactive", "--color=never"],
                cwd=self.work,
                env=dict(self._transport.env, PULUMI_CONFIG_PASSPHRASE=key),
                capture_output=True,
                timeout=min(30, remaining),
                check=False,
            )
            self._transport.cli.verify()
            if reject:
                require(
                    result.returncode in (1, 255)
                    and b"incorrect passphrase" in result.stderr.lower()
                )
            else:
                require(result.returncode == 0 and len(result.stdout) <= operations.MAX_BYTES)
            return result.stdout

        command = [
            "config",
            "set",
            "recovery-key-check",
            "synthetic-recovery-key-check",
            "--secret",
            "--stack",
            self._transport.stack,
            "--config-file",
            str(path),
        ]
        run(command, wrong, reject=True)
        run(command, original)
        values = parse(
            run(
                [
                    "config",
                    "--json",
                    "--show-secrets",
                    "--stack",
                    self._transport.stack,
                    "--config-file",
                    str(path),
                ],
                original,
            )
        )
        require(
            any(
                type(v) is dict
                and v.get("secret") is True
                and v.get("value") == "synthetic-recovery-key-check"
                for v in values.values()
            )
        )
        parse(
            run(
                [
                    "config",
                    "--json",
                    "--show-secrets",
                    "--stack",
                    self._transport.stack,
                    "--config-file",
                    str(self.work / "stack.yaml"),
                ],
                original,
            )
        )
        self.verified_deployment_sha256 = c.deployment_digest(
            parse(
                run(
                    ["stack", "export", "--show-secrets", "--stack", self._transport.stack],
                    original,
                )
            )
        )


def retrieve(
    root: Path,
    bundle: dict[str, Any],
    raw: dict[str, bytes],
    work: Path,
    password: str,
    deadline: float,
) -> None:
    binary = backup.executable(root)
    password_path = work / "backup-password"
    password_path.write_text(password)
    password_path.chmod(0o600)
    env = dict(
        RESTIC_REPOSITORY=str(backup._path(Path(bundle["repository"]))),
        RESTIC_PASSWORD_FILE=str(password_path),
        RESTIC_CACHE_DIR=str(work / "cache"),
        GOMAXPROCS="2",
    )

    def run(args: list[str]) -> bytes:
        require(binary == backup.executable(root) and deadline > time.monotonic())
        result = subprocess.run(
            [str(binary), "--no-lock", *args],
            env=env,
            capture_output=True,
            timeout=min(60, deadline - time.monotonic()),
            check=False,
        )
        require(result.returncode == 0 and binary == backup.executable(root))
        return result.stdout

    receipt = parse(raw["restore_receipt"])
    require(parse(run(["cat", "config"]))["id"] == receipt["repository_id"])
    nodes = [parse(v) for v in run(["ls", "--json", receipt["snapshot_id"]]).splitlines()]
    require(all(n.get("type") in {None, "dir", "file"} for n in nodes))
    files = [n for n in nodes if n.get("type") == "file"]
    expected = {
        "manifest.json": raw["restore_manifest"],
        "checkpoint.json": raw["restore_checkpoint"],
        "stack-config.json": raw["restore_configuration"],
    }
    require(len(files) == 3 and {Path(n["path"]).name for n in files} == set(expected))
    for node in files:
        value = expected[Path(node["path"]).name]
        require(type(node["size"]) is int and node["size"] == len(value) <= operations.MAX_BYTES)
        require(run(["dump", receipt["snapshot_id"], node["path"]]) == value)


def publish(path: Path, raw: bytes) -> None:
    with os.fdopen(
        os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600), "wb"
    ) as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _recover(
    root: Path,
    args: argparse.Namespace,
    bundle: dict[str, Any],
    raw: dict[str, bytes],
    journal: bytes,
    credentials: Callable[[], dict[str, str]],
) -> dict[str, Any]:
    context = admit(root, args, bundle, raw, journal)
    value = operations.request(parse(raw["operation"]))
    path = _private(root, args.journal)
    shared._current_environment(root, args, raw)
    original_head = operations.digest(
        operations._validate(administration._json(journal, array=True)["items"])[-1]
    )
    head = operations.journal(root, path, value, "admitted", predecessor=original_head)
    started_at = datetime.now(UTC).isoformat()
    began = time.monotonic()
    deadline = began + 300
    launched = False
    published = False
    verified_hash = None
    status = "failed"
    try:
        policy = c.restore_evidence(raw, args.unit, backup.host_id())
        deadline = began + min(300, policy["restore_objective_seconds"])
        with tempfile.TemporaryDirectory(
            prefix="state-recovery-", dir=root / ".infra"
        ) as directory:
            work = Path(directory)
            source_work = work / "source"
            source_work.mkdir(mode=0o700)
            cli = cli_runtime(root, _private(root, bundle["cli_archive"]), work / "bin")
            env = materialize_home(
                root,
                _private(root, bundle["provider_home"]),
                work / "home",
                supabase=args.unit == "supabase-database",
            )
            uv = _private(root, ".infra/tools/uv/uv")
            pin = operations.read_json(root / "config/toolchain.json")["tools"]["uv"]["assets"][
                "linux-x64"
            ]["binary_sha256"]
            require(c.digest(uv.read_bytes()) == pin)
            (work / "uv-bin").mkdir()
            shutil.copyfile(uv, work / "uv-bin/uv")
            (work / "uv-bin/uv").chmod(0o755)
            env.update(
                HOME=str(work),
                TMP=str(work),
                TMPDIR=str(work),
                TEMP=str(work),
                PATH=os.pathsep.join(
                    (str(Path(sys.executable).parent), str(work / "bin"), str(work / "uv-bin"))
                ),
                PULUMI_DEBUG_COMMANDS="true",
                PULUMI_SKIP_UPDATE_CHECK="true",
                UV_OFFLINE="1",
                PIP_NO_INDEX="1",
                UV_CACHE_DIR=str(work / "uv-cache"),
            )
            private = dict(credentials())
            required = {
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "RECOVERY_PASSPHRASE",
                "RECOVERY_BACKUP_PASSWORD",
            }
            if args.unit.startswith("oci-"):
                required |= {"OCI_USER_OCID", "OCI_FINGERPRINT", "OCI_PRIVATE_KEY_PATH"}
            require(
                required <= set(private) <= required | {"AWS_SESSION_TOKEN"}
                and all(type(v) is str and bool(v) for v in private.values())
                and len(private["RECOVERY_PASSPHRASE"]) >= 20
            )
            review = parse(raw["credential_review"])
            key = None
            if args.unit.startswith("oci-"):
                require(
                    review["provider_identity_sha256"]
                    == operations.digest(
                        {k: private[k] for k in ("OCI_USER_OCID", "OCI_FINGERPRINT")}
                    )
                )
                key = preview._read(_private(root, private["OCI_PRIVATE_KEY_PATH"]), 65536)
                (work / "oci-key.pem").write_bytes(key)
                (work / "oci-key.pem").chmod(0o600)
                private["OCI_PRIVATE_KEY_PATH"] = str(work / "oci-key.pem")
            retrieve(root, bundle, raw, work, private["RECOVERY_BACKUP_PASSWORD"], deadline)
            env.update({k: v for k, v in private.items() if k.startswith("OCI_")})
            env["PULUMI_CONFIG_PASSPHRASE"] = private["RECOVERY_PASSPHRASE"]
            source_env = {k: v for k, v in env.items() if not k.startswith("OCI_")}
            source_env.update({k: v for k, v in private.items() if k.startswith("AWS_")})
            source_env.update(
                PULUMI_BACKEND_URL=context.foundation.backend.url(),
                PULUMI_HOME=str(source_work / "home"),
                HOME=str(source_work),
                AWS_EC2_METADATA_DISABLED="true",
            )
            project = preview._encoded(
                dict(
                    name=context.foundation.project,
                    runtime=dict(name="python", options=dict(virtualenv=sys.prefix)),
                )
            )
            (source_work / "Pulumi.yaml").write_bytes(project)
            (source_work / "restore.json").write_bytes(raw["restore_checkpoint"])
            (source_work / "restore.json").chmod(0o600)
            writer = Writer(
                cli,
                source_work,
                source_env,
                context.contract.stack_identity,
                deadline,
                context.foundation.backend.url(),
            )
            _, artifacts, _ = preview._prepare(
                root, context, raw["restore_configuration"], raw.get("dependency_outputs")
            )
            owned = dict(
                **{
                    "Pulumi.yaml": project,
                    "stack.yaml": raw["restore_configuration"],
                    "policy.json": preview._policy_configuration(context),
                    "context.json": preview._request(
                        root, context, artifacts, raw.get("dependency_outputs")
                    ),
                    "__main__.py": (
                        b"from infra_program.preview_driver import program_from_request\n"
                        b"program_from_request()\n"
                    ),
                }
            )
            locals_: list[Path] = []
            destination = _private(root, bundle["configuration_destination"])

            def confirm() -> None:
                require(
                    time.monotonic() < deadline and operations.inspect_journal(path)["head"] == head
                )
                require(
                    all(
                        preview._read(_private(root, bundle["paths"][n]), operations.MAX_BYTES) == v
                        for n, v in raw.items()
                    )
                )
                require(
                    (source_work / "restore.json").read_bytes() == raw["restore_checkpoint"]
                    and (source_work / "Pulumi.yaml").read_bytes() == project
                    and c.digest((work / "uv-bin/uv").read_bytes()) == pin
                )
                for local in locals_:
                    require(all((local / n).read_bytes() == v for n, v in owned.items()))
                if published:
                    require(destination.read_bytes() == raw["restore_configuration"])
                else:
                    require(not destination.exists())
                if key is not None:
                    require((work / "oci-key.pem").read_bytes() == key)
                cli.verify()
                (
                    verified_supabase_environment
                    if args.unit == "supabase-database"
                    else verified_environment
                )(root, work / "home")
                admit(root, args, bundle, raw, journal)

            def source_matches(expected: bytes) -> None:
                require(writer.export() == expected)
                if args.unit.startswith("oci-"):
                    peer = "oci-network" if args.unit == "oci-oke" else "oci-oke"
                    require(
                        writer.export("organization/free-infrastructure/" + peer)
                        == raw["peer_checkpoint"]
                    )

            def reconcile(checkpoint: bytes, name: str) -> str:
                local = work / name
                local.mkdir(mode=0o700)
                for n, data in owned.items():
                    (local / n).write_bytes(data)
                    (local / n).chmod(0o600)
                locals_.append(local)
                observer = Observer(cli, local, env, context.contract.stack_identity, deadline)
                observer.load(args.unit, checkpoint)
                if args.unit == "oci-oke":
                    peer = parse(raw["peer_checkpoint"])
                    peer["deployment"]["resources"] = [
                        r
                        for r in peer["deployment"]["resources"]
                        if r["type"] == "pulumi:pulumi:Stack"
                    ]
                    observer.load("oci-network", preview._encoded(peer))
                baseline = observer.checkpoint()
                observer.key_check()
                confirm()
                for stage in (observer.refresh, observer.compare):
                    report = stage()
                    require(set(report["resource_changes"]) <= {"same", "read"})
                    confirm()
                require(observer.checkpoint() == baseline)
                return observer.verified_deployment_sha256

            confirm()
            source_matches(raw["current_checkpoint"])
            before_digest = reconcile(raw["restore_checkpoint"], "before")
            confirm()
            shared._current_environment(root, args, raw)
            source_matches(raw["current_checkpoint"])
            head = operations.journal(root, path, value, "running", predecessor=head)
            confirm()
            launched = True
            writer.restore(source_work / "restore.json")
            publish(destination, raw["restore_configuration"])
            published = True
            confirm()
            restored = writer.export()
            drift._checkpoint(root, context, restored)
            require(reconcile(restored, "after") == before_digest)
            confirm()
            shared._current_environment(root, args, raw)
            source_matches(restored)
            require(time.monotonic() - began <= policy["restore_objective_seconds"])
            verified_hash = c.digest(restored)
            status = "succeeded"
    except Exception:
        status = "indeterminate" if launched else "failed"
    head = operations.journal(root, path, value, status, predecessor=head)
    report = dict(
        schema_version=1,
        kind="state-recovery",
        operation_id=value["operation_id"],
        unit=args.unit,
        commit=args.commit,
        status=status,
        started_at=started_at,
        completed_at=datetime.now(UTC).isoformat(),
        restore_seconds=time.monotonic() - began,
        expected_current_checkpoint_sha256=value["checkpoint_sha256"],
        snapshot_id=parse(raw["restore_receipt"])["snapshot_id"],
        restore_checkpoint_sha256=c.digest(raw["restore_checkpoint"]),
        restored_checkpoint_sha256=verified_hash,
        configuration_sha256=c.digest(raw["restore_configuration"]),
        configuration_published=published,
        reconciliation_verified=status == "succeeded",
        journal_head=head,
        approval_sha256=c.digest(raw["approval"]),
        writer_release_authorized=False,
        resource_operations_authorized=False,
        freeze_release_attempted=False,
    )
    publish(_private(root, bundle["output"]), preview._encoded(report))
    return report


def execute(
    root: Path, args: argparse.Namespace, credentials: Callable[[], dict[str, str]]
) -> None:
    try:
        root = root.resolve()
        bundle, raw, journal = check(root, args)
        if args.check:
            return
        require(args.allow_state_writes)
        path = _private(root, args.journal)
        lock = (
            _private(root, ".infra/operations/oci-dependency.apply.lock")
            if args.unit.startswith("oci-")
            else path.with_name(path.name + ".apply.lock")
        )
        with os.fdopen(os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600), "a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            require(preview._read(path, operations.MAX_BYTES) == journal)
            report = _recover(root, args, bundle, raw, journal, credentials)
        print("RECOVERY: " + report["status"] + "; writers remain frozen")
        require(report["status"] == "succeeded")
    except Exception:
        raise ValueError(c.MESSAGE) from None
