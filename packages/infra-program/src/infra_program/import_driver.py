"""Explicit protected OCI import; no generated code, source release or automatic retry."""

import argparse
import fcntl
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from infra_core import operations, ownership
from infra_core.oci.config import FoundationConfig, parse_config
from infra_core.oci.graph import Resource, network_graph, oke_graph

from infra_program import oci_apply
from infra_program import preview_driver as preview
from infra_program import service_apply as driver
from infra_program.oci.dependencies import validate_network
from infra_program.operation_runtime import MESSAGE, Runtime, require, validate_events
from infra_program.preview_orchestration import _private
from infra_program.preview_program import NetworkPreviewContext
from infra_program.preview_runtime import CliRuntime


def names(unit: str) -> set[str]:
    return oci_apply.names(unit) | {"ownership", "target_checkpoint"}


def _document(raw: dict[str, bytes]) -> dict[str, Any]:
    return preview._json(raw["ownership"], operations.MAX_BYTES)


def _graph(raw: dict[str, bytes]) -> tuple[FoundationConfig, tuple[Resource, ...]]:
    cfg = parse_config(preview._json(raw["proposal"], operations.MAX_BYTES))
    unit = _document(raw)["target_stack"].split("/")[-1]
    return cfg, oke_graph(cfg) if unit == "oci-oke" else network_graph(cfg)


def _identities(raw: dict[str, bytes]) -> tuple[str, str]:
    doc, (cfg, _) = _document(raw), _graph(raw)
    unit = doc["target_stack"].split("/")[-1]
    prefix = f"urn:pulumi:{unit}::free-infrastructure::"
    kind = "infrastructure:oci:" + ("Oke" if unit == "oci-oke" else "Network")
    parent = prefix + kind + "::" + cfg.name + ("-oke" if unit == "oci-oke" else "-network")
    return parent, prefix + "pulumi:providers:oci::" + cfg.name + "-provider"


def import_file(raw: dict[str, bytes]) -> bytes:
    """Generate a closed one-unit import file solely from the reviewed mapping."""
    doc, (_, graph) = _document(raw), _graph(raw)
    specs = {r.key: r for r in graph}
    parent, provider = _identities(raw)
    return preview._encoded(
        dict(
            resources=[
                dict(
                    type=specs[e["logical_key"]].kind,
                    name=e["pulumi_name"],
                    id=e["id"],
                    parent="owner",
                    provider="provider",
                )
                for e in doc["entries"]
                if e["operation"] == "import"
            ],
            nameTable={"owner": parent, "provider": provider},
        )
    )


def _target_metadata(root: Path, raw: dict[str, bytes]) -> dict[str, dict[str, Any]]:
    doc = _document(raw)
    checkpoint = raw["target_checkpoint"]
    require(ownership._read(root, doc["artifacts"]["target_checkpoint"])[1] == checkpoint)
    records = ownership._target(checkpoint, doc["target_stack"])
    parent, provider = _identities(raw)
    require(parent in records and provider in records and bool(records[provider].get("id")))
    # Import must use existing explicit metadata; never bootstrap it through resource creation.
    if doc["target_stack"].endswith("/oci-oke"):
        cfg, _ = _graph(raw)
        prefix = "urn:pulumi:oci-oke::free-infrastructure::"
        require(
            prefix + "pulumi:pulumi:StackReference::" + cfg.name + "-network-reference" in records
            and prefix + "pulumi:providers:pulumi::default" in records
        )
    return records


def prepare(
    root: Path, unit: str, commit: str, raw: dict[str, bytes], journal: bytes
) -> tuple[NetworkPreviewContext, bytes]:
    driver._enabled(root, True, True, unit=unit)
    require(set(raw) == names(unit))
    doc = _document(raw)
    result = ownership.prepare(root, doc, prepared_journal=journal)
    require(result["unit"] == unit and type(result["imports"]) is int and result["imports"] > 0)
    for reference, name in (
        ("request", "operation"),
        ("configuration", "proposal"),
        ("encrypted_configuration", "encrypted_configuration"),
    ):
        require(ownership._read(root, doc["artifacts"][reference])[1] == raw[name])
    context, _ = oci_apply.prepare(
        root, unit, commit, {n: raw[n] for n in oci_apply.names(unit)}, True
    )
    before = _target_metadata(root, raw)
    parent, provider = _identities(raw)
    plans = preview._json(raw["plan"], operations.MAX_BYTES)["resourcePlans"]
    entries = {e["pulumi_name"]: e for e in doc["entries"]}
    for value in plans.values():
        goal = value["goal"]
        if goal["type"].startswith("oci:"):
            entry = entries[goal["name"]]
            require(value["steps"] == (["create"] if entry["operation"] == "import" else ["same"]))
            require(
                goal.get("provider") == provider + "::" + before[provider]["id"]
                and goal.get("parent") == parent
            )
        else:
            require(value["steps"] == ["same"])
    require(len(import_file(raw)) <= operations.MAX_BYTES)
    if unit == "oci-network":
        roots = [r for r in before.values() if r["type"] == "pulumi:pulumi:Stack"]
        validate_network(
            roots[0].get("outputs"), context.configuration, context.account["account_id"]
        )
        expected = {e["logical_key"]: e["id"] for e in doc["entries"]}
        require(all(expected[k] == v for k, v in roots[0]["outputs"]["network"]["ids"].items()))
    return context, preview._encoded(
        dict(
            adapter="oci-import-v1",
            inputs={n: driver._hash(raw[n]) for n in sorted(names(unit) - driver.APPROVAL)},
            ownership_binding=result["binding_sha256"],
            import_file_sha256=driver._hash(import_file(raw)),
            profile_sha256=driver._hash(preview._encoded(context.profile)),
            foundation_sha256=context.foundation.digest,
        )
    )


def validate_imported(
    checkpoint: bytes, context: NetworkPreviewContext, raw: dict[str, bytes]
) -> None:
    """Check state identity/protection; a separate policy preview establishes equivalence."""
    records = ownership._target(checkpoint, context.contract.stack_identity)
    cfg, graph = _graph(raw)
    specs = {r.key: r for r in graph}
    parent, provider = _identities(raw)
    doc = _document(raw)
    prefix = "urn:pulumi:" + context.contract.unit + "::free-infrastructure::"
    kind = "infrastructure:oci:" + ("Oke" if context.contract.unit == "oci-oke" else "Network")
    expected = set()
    require(parent in records and provider in records)
    original = ownership._target(raw["target_checkpoint"], doc["target_stack"])
    require(records[provider].get("id") == original[provider].get("id"))
    require(
        records[parent].get("protect") is True
        and records[provider].get("protect") is True
        and records[provider].get("inputs", {}).get("region") == cfg.region
    )
    for entry in doc["entries"]:
        urn = prefix + kind + "$" + specs[entry["logical_key"]].kind + "::" + entry["pulumi_name"]
        expected.add(urn)
        record = records[urn]
        require(
            record.get("id") == entry["id"]
            and record.get("protect") is True
            and record.get("parent") == parent
            and record.get("provider") == provider + "::" + records[provider]["id"]
        )
    require({urn for urn, r in records.items() if r["type"].startswith("oci:")} == expected)


class ImportRuntime(Runtime):
    def __init__(
        self,
        cli: CliRuntime,
        work: Path,
        env: dict[str, str],
        stack: str,
        policy: Path,
        context: preview.Context,
        raw: dict[str, bytes],
    ):
        super().__init__(cli, work, env, stack, policy)
        require(isinstance(context, NetworkPreviewContext))
        assert isinstance(context, NetworkPreviewContext)
        self.context, self.raw = context, raw

    def operation(self, *, preview: bool) -> dict[str, int]:
        if preview:
            changes = super().operation(preview=True)
            require(
                set(changes) <= {"same", "read", "create"}
                and changes.get("create", 0) == len(preview_imports(self.raw))
            )
            return changes
        path = self.work / "import.json"
        require(path.read_bytes() == import_file(self.raw))
        events = self._capture(
            [
                "import",
                "--yes",
                "--skip-preview",
                "--file",
                str(path),
                "--protect=true",
                "--generate-code=false",
                "--parallel",
                "1",
                "--stack",
                self.stack,
                "--config-file",
                str(self.work / "stack.yaml"),
                "--suppress-outputs",
                "--suppress-progress",
            ]
        )
        require(path.read_bytes() == import_file(self.raw))
        changes = validate_events(events, preview=False, policy=self.policy, importing=True)
        require(
            set(changes) <= {"same", "read", "import"}
            and changes.get("import", 0) == len(preview_imports(self.raw))
        )
        post = self.checkpoint()
        validate_imported((self.work / "current.json").read_bytes(), self.context, self.raw)
        equivalent = super().operation(preview=True)
        require(set(equivalent) <= {"same", "read"} and self.checkpoint() == post)
        self.verified_checkpoint_sha256 = post
        return changes


def preview_imports(raw: dict[str, bytes]) -> list[dict[str, Any]]:
    return [e for e in _document(raw)["entries"] if e["operation"] == "import"]


def execute(
    root: Path, args: argparse.Namespace, credentials: Callable[[], dict[str, str]]
) -> None:
    try:
        root = root.resolve()
        driver._enabled(root, True, True, unit=args.unit)
        require(args.unit in oci_apply.UNITS)
        if args.check:
            driver.check(root, args, True, True)
            return
        lock = _private(root, ".infra/operations/oci-dependency.apply.lock")
        require(lock.parent.is_dir())
        with os.fdopen(os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600), "a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            driver.execute(root, args, credentials, True, True)
    except Exception:
        raise ValueError(MESSAGE) from None
