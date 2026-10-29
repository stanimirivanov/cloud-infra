"""Default-disabled isolated refresh previews; no authoritative writes or remediation."""

import argparse
import fcntl
import os
import shutil
import sys
import tempfile
import time
import tomllib
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from infra_core import administration, operation_admission, operations
from infra_core import drift_results as results
from infra_core.backend import validate_receipt
from infra_core.backend_posture import validate_posture_evidence
from infra_core.backup import ENCRYPTED_VALUE_SIGNATURE, SIGNATURE
from infra_core.foundation import load_foundation
from infra_core.network_outputs import validate_network
from infra_core.oci.config import parse_config
from infra_core.oci.graph import network_graph, oke_graph
from infra_core.preview_contracts import describe_preview
from infra_core.provider_tools import (
    materialize_home,
    verified_environment,
    verified_supabase_environment,
)

from infra_program import preview_driver as preview
from infra_program import service_apply as shared
from infra_program.operation_runtime import Runtime
from infra_program.preview_orchestration import _private
from infra_program.preview_program import (
    NetworkPreviewContext,
    OkePreviewContext,
    ServicePreviewContext,
)
from infra_program.preview_runtime import CliRuntime, cli_runtime

require = results.require
BASE = shared.NAMES | {"checkpoint", "credential_review"}


def names(unit: str) -> set[str]:
    require(unit in results.UNITS)
    return (
        BASE
        | ({"account"} if unit.startswith("oci-") else set())
        | ({"dependency_outputs", "network_checkpoint"} if unit == "oci-oke" else set())
    )


def _enabled(root: Path) -> None:
    policy = operations.read_json(root / "config/drift.json")
    require(
        type(policy.get("schema_version")) is int
        and policy == {"schema_version": 1, "enabled": True}
        and policy["enabled"] is True
    )


def _context(root: Path, unit: str, commit: str, raw: dict[str, bytes]) -> preview.Context:
    foundation = load_foundation(root)
    contract = describe_preview(foundation, unit, commit)
    profiles = tomllib.loads((root / "config/quotas/profiles.toml").read_text())["profiles"]
    context: preview.Context
    if unit.startswith("oci-"):
        account = preview._json(raw["account"], operations.MAX_BYTES)
        cls = OkePreviewContext if unit == "oci-oke" else NetworkPreviewContext
        context = cls(
            foundation,
            contract,
            commit,
            parse_config(preview._json(raw["proposal"], operations.MAX_BYTES)),
            account,
            profiles[account["profile"]],
            raw["evidence"],
            raw["envelope"],
        )
    else:
        context = ServicePreviewContext(
            foundation,
            contract,
            commit,
            preview._json(raw["proposal"], operations.MAX_BYTES),
            profiles["cloudflare-free" if unit == "cloudflare-edge" else "supabase-free"],
            raw["evidence"],
            raw["envelope"],
        )
    preview._contract(root, context)
    context, artifacts, _ = preview._prepare(
        root, context, raw["encrypted_configuration"], raw.get("dependency_outputs")
    )
    preview._versions(root, context, artifacts)
    validate_receipt(foundation, preview._json(raw["qualification"], operations.MAX_BYTES))
    return context


def specification(context: preview.Context) -> dict[str, dict[str, Any]]:
    unit = context.contract.unit
    prefix = f"urn:pulumi:{unit}::free-infrastructure::"
    root = prefix + "pulumi:pulumi:Stack::free-infrastructure-" + unit
    specs = {root: dict(type="pulumi:pulumi:Stack", parent="", provider="", protect=False)}

    def add(urn: str, kind: str, parent: str, provider: str = "", protect: bool = True) -> None:
        specs[urn] = dict(type=kind, parent=parent, provider=provider, protect=protect)

    if isinstance(context, ServicePreviewContext):
        kind = "infrastructure:services:Independent"
        component = prefix + kind + "::" + unit
        provider = (
            prefix
            + kind
            + "$pulumi:providers:"
            + context.proposal["provider"]
            + "::"
            + unit
            + "-provider"
        )
        add(component, kind, root)
        add(provider, "pulumi:providers:" + context.proposal["provider"], component)
        for item in context.proposal["resources"]:
            add(
                prefix + kind + "$" + item["type"] + "::" + unit + "-" + item["key"],
                item["type"],
                component,
                provider,
            )
    else:
        cfg = context.configuration
        kind = "infrastructure:oci:" + ("Oke" if unit == "oci-oke" else "Network")
        component = prefix + kind + "::" + cfg.name + ("-oke" if unit == "oci-oke" else "-network")
        provider = prefix + "pulumi:providers:oci::" + cfg.name + "-provider"
        add(component, kind, root)
        add(provider, "pulumi:providers:oci", root)
        for item in oke_graph(cfg) if unit == "oci-oke" else network_graph(cfg):
            add(
                prefix + kind + "$" + item.kind + "::" + cfg.name + "-" + item.key,
                item.kind,
                component,
                provider,
            )
        if unit == "oci-oke":
            builtin = prefix + "pulumi:providers:pulumi::default"
            add(builtin, "pulumi:providers:pulumi", root, protect=False)
            add(
                prefix + "pulumi:pulumi:StackReference::" + cfg.name + "-network-reference",
                "pulumi:pulumi:StackReference",
                root,
                builtin,
            )
    return specs


def _checkpoint(root: Path, context: preview.Context, raw: bytes) -> dict[str, dict[str, Any]]:
    records = results.checkpoint(raw, context.contract.unit, specification(context))
    pins = operations.read_json(root / "config/provider-toolchain.json")
    for record in records.values():
        kind = record["type"]
        if not kind.startswith("pulumi:providers:"):
            continue
        fields = record.get("inputs", {})
        provider = kind.split(":")[-1]
        if provider == "pulumi":
            require(fields == {})
            continue
        version = (
            pins["downstream"]["version"]
            if provider == "supabase"
            else pins["providers"][provider]["version"]
        )
        require(
            fields.get("version", version) == version and fields.get("pluginDownloadURL", "") == ""
        )
        allowed = {"version", "pluginDownloadURL", "__defaults"}
        if provider == "oci":
            assert isinstance(context, NetworkPreviewContext)
            require(
                fields.get("region") == context.configuration.region
                and fields.get("tenancyOcid") == context.account["account_id"]
            )
            allowed |= {"region", "tenancyOcid"}
        else:
            token, endpoint = (
                ("apiToken", "baseUrl") if provider == "cloudflare" else ("accessToken", "endpoint")
            )
            require(
                fields.get(endpoint)
                == (
                    "https://api.cloudflare.com/client/v4"
                    if provider == "cloudflare"
                    else "https://api.supabase.com"
                )
            )
            for properties in (fields, record.get("outputs", {})):
                if token in properties:
                    secret = properties[token]
                    require(
                        type(secret) is dict
                        and secret.get(SIGNATURE) == ENCRYPTED_VALUE_SIGNATURE
                        and set(secret) == {SIGNATURE, "ciphertext"}
                    )
            require(token in fields)
            allowed |= {token, endpoint}
        require(set(fields) <= allowed)
    return records


def _admit(
    root: Path,
    args: argparse.Namespace,
    bundle: dict[str, Any],
    raw: dict[str, bytes],
    journal: bytes,
) -> preview.Context:
    require(raw["plan"] == results.plan(args.unit))
    context = _context(root, args.unit, args.commit, raw)
    _checkpoint(root, context, raw["checkpoint"])
    if args.unit == "oci-oke":
        assert isinstance(context, OkePreviewContext)
        dependency = results.parse(raw["network_checkpoint"])
        require(
            dependency["version"] == 3 and not dependency["deployment"].get("pending_operations")
        )
        from infra_core.backup import _encrypted

        _encrypted(dependency)
        roots = [
            r for r in dependency["deployment"]["resources"] if r["type"] == "pulumi:pulumi:Stack"
        ]
        require(
            len(roots) == 1
            and roots[0]["urn"]
            == (
                "urn:pulumi:oci-network::free-infrastructure::pulumi:pulumi:Stack::"
                "free-infrastructure-oci-network"
            )
            and roots[0]["outputs"] == results.parse(raw["dependency_outputs"])
        )
        validate_network(roots[0]["outputs"], context.configuration, context.account["account_id"])
    value = operations.request(results.parse(raw["operation"]))
    require(
        value["operation"] == "monitor"
        and value["unit"] == args.unit
        and value["commit"] == args.commit
        and value["checkpoint_sha256"] == shared._hash(raw["checkpoint"])
    )
    validate_posture_evidence(
        context.foundation,
        raw["posture"],
        raw["posture_envelope"],
        account_id=bundle["backend_account_id"],
        commit=args.commit,
    )
    review = results.parse(raw["credential_review"])
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
    )
    require(
        type(review["schema_version"]) is int
        and review["schema_version"] == 1
        and review["unit"] == args.unit
        and review["checkpoint_sha256"] == value["checkpoint_sha256"]
        and review["configuration_sha256"] == value["configuration_sha256"]
        and review["read_only_scopes_reviewed"] is True
        and review["historical_provider_credentials_reviewed"] is True
        and (
            operations._hash(review["provider_identity_sha256"])
            if args.unit.startswith("oci-")
            else review["provider_identity_sha256"] is None
        )
    )
    now = datetime.now(UTC)
    require(
        operations._time(review["reviewed_at"])
        <= now
        < operations._time(review["expires_at"])
        <= operations._time(value["expires_at"])
        and (now - operations._time(review["reviewed_at"])).total_seconds() <= 900
    )
    entries = operations._validate(administration._json(journal, array=True)["items"])
    expected = dict(
        actor=args.actor,
        environment=args.environment,
        commit=args.commit,
        configuration_sha256=shared._hash(raw["encrypted_configuration"]),
        checkpoint_sha256=value["checkpoint_sha256"],
        plan_sha256=shared._hash(raw["plan"]),
        journal_head=operations.digest(entries[-1]),
    )
    binding = preview._encoded(
        dict(
            adapter="isolated-drift-v1",
            inputs={n: shared._hash(raw[n]) for n in sorted(names(args.unit) - shared.APPROVAL)},
            foundation=context.foundation.digest,
            profile=shared._hash(preview._encoded(context.profile)),
            backend_account_id=bundle["backend_account_id"],
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
        context=expected,
        execution_inputs=binding,
    )
    return context


def check(root: Path, args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, bytes], bytes]:
    try:
        root = root.resolve()
        _enabled(root)
        preview._checkout(root)
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
            and set(bundle["paths"]) == names(args.unit)
        )
        raw = {
            n: preview._read(_private(root, p), operations.MAX_BYTES)
            for n, p in bundle["paths"].items()
        }
        require(sum(map(len, raw.values())) <= 6 * operations.MAX_BYTES)
        journal = preview._read(_private(root, args.journal), operations.MAX_BYTES)
        output = _private(root, bundle["output"])
        require(not output.exists() and output.parent.is_dir())
        _admit(root, args, bundle, raw, journal)
        shared._current_environment(root, args, raw)
        return bundle, raw, journal
    except Exception:
        raise ValueError(results.MESSAGE) from None


class SourceReader:
    def __init__(
        self, cli: CliRuntime, work: Path, env: dict[str, str], stack: str, deadline: float
    ):
        self._transport = Runtime(
            cli, work, env, stack, Path(__file__).resolve().parents[4] / "policies"
        )
        self._transport.deadline = deadline
        self.work = work

    def export(self, stack: str) -> bytes:
        require(
            stack == self._transport.stack
            or (
                self._transport.stack.endswith("/oci-oke")
                and stack == "organization/free-infrastructure/oci-network"
            )
        )
        path = self.work / "source.json"
        path.unlink(missing_ok=True)
        self._transport._run(["stack", "export", "--file", str(path), "--stack", stack])
        require(path.stat().st_size <= operations.MAX_BYTES)
        path.chmod(0o600)
        return preview._read(path, operations.MAX_BYTES)


class LocalObserver:
    def __init__(
        self, cli: CliRuntime, work: Path, env: dict[str, str], stack: str, deadline: float
    ):
        self.work = work
        self.backend = work / "backend"
        self.backend.mkdir(mode=0o700)
        require(not self.backend.is_symlink() and self.backend.resolve().parent == work.resolve())
        local = dict(env, PULUMI_BACKEND_URL=self.backend.as_uri())
        require(not any(k.startswith("AWS_") for k in local))
        self._transport = Runtime(
            cli, work, local, stack, Path(__file__).resolve().parents[4] / "policies"
        )
        self._transport.deadline = deadline

    def _local(self) -> None:
        uri = urlparse(self._transport.env["PULUMI_BACKEND_URL"])
        require(
            uri.scheme == "file"
            and uri.netloc == ""
            and Path(unquote(uri.path)).resolve() == self.backend.resolve()
            and not self.backend.is_symlink()
        )

    def load(self, unit: str, raw: bytes) -> None:
        self._local()
        require(
            unit == self._transport.stack.split("/")[-1]
            or (self._transport.stack.endswith("/oci-oke") and unit == "oci-network")
        )
        path = self.work / (unit + "-checkpoint.json")
        path.write_bytes(raw)
        path.chmod(0o600)
        self._transport._run(["stack", "init", unit, "--secrets-provider", "passphrase"])
        self._transport._run(
            [
                "stack",
                "import",
                "--stack",
                "organization/free-infrastructure/" + unit,
                "--file",
                str(path),
            ]
        )

    def checkpoint(self) -> str:
        self._local()
        return self._transport.checkpoint()

    def refresh(self) -> dict[str, Any]:
        self._local()
        args = [
            "refresh",
            "--preview-only",
            "--run-program",
            "--stack",
            self._transport.stack,
            "--config-file",
            str(self.work / "stack.yaml"),
            "--parallel",
            "1",
            "--suppress-outputs",
            "--suppress-progress",
        ]
        return results.summarize(
            self._transport._capture(args), refresh=True, policy=str(self._transport.policy)
        )

    def compare(self) -> dict[str, Any]:
        self._local()
        args = [
            "preview",
            "--refresh=false",
            "--stack",
            self._transport.stack,
            "--config-file",
            str(self.work / "stack.yaml"),
            "--policy-pack",
            str(self._transport.policy),
            "--parallel",
            "1",
            "--suppress-outputs",
            "--suppress-progress",
        ]
        return results.summarize(
            self._transport._capture(args), refresh=False, policy=str(self._transport.policy)
        )


def _observe(
    root: Path,
    args: argparse.Namespace,
    bundle: dict[str, Any],
    raw: dict[str, bytes],
    journal: bytes,
    credentials: Callable[[], dict[str, str]],
) -> dict[str, Any]:
    context = _admit(root, args, bundle, raw, journal)
    value = operations.request(results.parse(raw["operation"]))
    path = _private(root, args.journal)
    shared._current_environment(root, args, raw)
    head = operations.journal(
        root,
        path,
        value,
        "admitted",
        predecessor=operations.digest(
            operations._validate(administration._json(journal, array=True)["items"])[-1]
        ),
    )
    started = datetime.now(UTC).isoformat()
    deadline = time.monotonic() + 300
    source_same: bool | None = None
    local_same: bool | None = None
    refresh = comparison = None
    error: str | None = None
    source: SourceReader | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="drift-", dir=root / ".infra") as directory:
            work = Path(directory)
            local = work / "local"
            local.mkdir(mode=0o700)
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
            require(shared._hash(uv.read_bytes()) == pin)
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
                PULUMI_CONFIG_PASSPHRASE="",
                UV_OFFLINE="1",
                PIP_NO_INDEX="1",
                UV_CACHE_DIR=str(work / "uv-cache"),
            )
            private = dict(credentials())
            required = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "PULUMI_CONFIG_PASSPHRASE"}
            if args.unit.startswith("oci-"):
                required |= {"OCI_USER_OCID", "OCI_FINGERPRINT", "OCI_PRIVATE_KEY_PATH"}
            require(
                required <= set(private) <= required | {"AWS_SESSION_TOKEN"}
                and all(type(v) is str and bool(v) for v in private.values())
                and len(private["PULUMI_CONFIG_PASSPHRASE"]) >= 20
            )
            if args.unit.startswith("oci-"):
                key = preview._read(_private(root, private["OCI_PRIVATE_KEY_PATH"]), 65536)
                (work / "oci-key.pem").write_bytes(key)
                (work / "oci-key.pem").chmod(0o600)
                private["OCI_PRIVATE_KEY_PATH"] = str(work / "oci-key.pem")
            review = results.parse(raw["credential_review"])
            if args.unit.startswith("oci-"):
                require(
                    review["provider_identity_sha256"]
                    == operations.digest(
                        {k: private[k] for k in ("OCI_USER_OCID", "OCI_FINGERPRINT")}
                    )
                )
            else:
                require(review["provider_identity_sha256"] is None)
            env.update({k: v for k, v in private.items() if not k.startswith("AWS_")})
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
            _, artifacts, _ = preview._prepare(
                root, context, raw["encrypted_configuration"], raw.get("dependency_outputs")
            )
            owned = {
                "Pulumi.yaml": project,
                "stack.yaml": raw["encrypted_configuration"],
                "context.json": preview._request(
                    root, context, artifacts, raw.get("dependency_outputs")
                ),
                "__main__.py": (
                    b"from infra_program.preview_driver import program_from_request\n"
                    b"program_from_request()\n"
                ),
            }
            for name, data in owned.items():
                (local / name).write_bytes(data)
                (local / name).chmod(0o600)
            source = SourceReader(
                cli, source_work, source_env, context.contract.stack_identity, deadline
            )
            observer = LocalObserver(
                cli, local, env, context.contract.stack_identity, deadline - 60
            )

            def confirm() -> None:
                nonlocal error
                if not all(
                    preview._read(_private(root, bundle["paths"][n]), operations.MAX_BYTES) == v
                    for n, v in raw.items()
                ):
                    error = "inputs_changed"
                    raise ValueError(results.MESSAGE)
                require(
                    operations.inspect_journal(path)["head"] == head
                    and all((local / n).read_bytes() == v for n, v in owned.items())
                )
                require(shared._hash((work / "uv-bin/uv").read_bytes()) == pin)
                (
                    verified_supabase_environment
                    if args.unit == "supabase-database"
                    else verified_environment
                )(root, work / "home")
                if args.unit.startswith("oci-"):
                    require((work / "oci-key.pem").read_bytes() == key)
                cli.verify()
                _admit(root, args, bundle, raw, journal)

            def sources() -> bool:
                same = source.export(context.contract.stack_identity) == raw["checkpoint"]
                if args.unit == "oci-oke":
                    same = (
                        source.export("organization/free-infrastructure/oci-network")
                        == raw["network_checkpoint"]
                        and same
                    )
                return same

            try:
                confirm()
                source_same = sources()
                if not source_same:
                    error = "source_changed"
                    raise ValueError(results.MESSAGE)
                observer.load(args.unit, raw["checkpoint"])
                if args.unit == "oci-oke":
                    # Project only the verified dependency root; no providers or resources.
                    dependency = results.parse(raw["network_checkpoint"])
                    dependency["deployment"]["resources"] = [
                        r
                        for r in dependency["deployment"]["resources"]
                        if r["type"] == "pulumi:pulumi:Stack"
                    ]
                    observer.load("oci-network", preview._encoded(dependency))
                baseline = observer.checkpoint()
                head = operations.journal(root, path, value, "running", predecessor=head)
                confirm()
                shared._current_environment(root, args, raw)
                refresh = observer.refresh()
                confirm()
                comparison = observer.compare()
                confirm()
                local_same = observer.checkpoint() == baseline
                if not local_same:
                    error = "local_state_changed"
            except Exception:
                error = error or "observation_failed"
            finally:
                try:
                    source_same = sources()
                    if not source_same:
                        error = "source_changed"
                except Exception:
                    source_same = None
                    error = "source_unavailable"
    except Exception:
        error = error or "observation_failed"
    report = results.result(
        request=value,
        started_at=started,
        completed_at=datetime.now(UTC).isoformat(),
        source_unchanged=source_same,
        local_unchanged=local_same,
        refresh=refresh,
        comparison=comparison,
        error=error,
    )
    state = (
        "succeeded"
        if report["status"] != "unknown"
        else "failed"
        if source_same is True and local_same is not False
        else "indeterminate"
    )
    # Setup can fail while still admitted; preserve the actual transition graph.
    if operations.inspect_journal(path)["state"] == "admitted" and state == "indeterminate":
        state = "failed"
    report["journal_head"] = operations.journal(root, path, value, state, predecessor=head)
    report["approval_sha256"] = shared._hash(raw["approval"])
    report["observation_inputs_sha256"] = operations.digest(
        {n: shared._hash(raw[n]) for n in sorted(names(args.unit) - shared.APPROVAL)}
    )
    output = _private(root, bundle["output"])
    with os.fdopen(os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as stream:
        stream.write(preview._encoded(report))
        stream.flush()
        os.fsync(stream.fileno())
    return report


def execute(
    root: Path, args: argparse.Namespace, credentials: Callable[[], dict[str, str]]
) -> None:
    try:
        root = root.resolve()
        bundle, raw, journal = check(root, args)
        if args.check:
            return
        require(args.allow_local_writes)
        path = _private(root, args.journal)
        lock = (
            _private(root, ".infra/operations/oci-dependency.apply.lock")
            if args.unit.startswith("oci-")
            else path.with_name(path.name + ".apply.lock")
        )
        with os.fdopen(os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600), "a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            require(preview._read(path, operations.MAX_BYTES) == journal)
            report = _observe(root, args, bundle, raw, journal, credentials)
        print("OBSERVATION: " + report["status"])
        require(report["status"] != "unknown")
    except Exception:
        raise ValueError(results.MESSAGE) from None
