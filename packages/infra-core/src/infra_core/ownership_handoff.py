"""Signed paired-OCI owner admission; never edits state or activates a writer."""

import math
import re
import tomllib
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from infra_core import administration, operation_admission, operations, ownership
from infra_core.cutover import repository_state
from infra_core.foundation import load_foundation
from infra_core.governance.audit import audit
from infra_core.inventory_evidence import validate_inventory_evidence
from infra_core.network_outputs import network_digest, validate_network
from infra_core.oci.config import FoundationConfig, parse_config
from infra_core.oci.graph import network_graph, oke_graph, proposal
from infra_core.preview_contracts import describe_preview
from infra_core.preview_results import POLICY_SOURCES, validate_preview_result
from infra_core.review_signatures import verify_payload

PAYLOAD_TYPE = "application/vnd.cloud-infra.ownership-handoff.v1+json"
MESSAGE = "HANDOFF001: owner admission rejected; diagnostics withheld"
UNIT_INPUTS = {
    "preparation",
    "prepared_journal",
    "journal",
    "import_receipt",
    "checkpoint",
    "released_source",
    "preview",
    "preview_inputs",
    "backup_request",
    "backup_manifest",
    "backup_receipt",
    "recovery_policy",
    "recovery_receipt",
}
ARTIFACTS = {
    "configuration",
    "network_outputs",
    "release",
    "freeze",
    "environment",
    "approval",
    "operator",
    "approver",
} | {prefix + "_" + name for prefix in ("network", "oke") for name in UNIT_INPUTS}
EXCLUDED = {"approval", "operator", "approver"}


def _number(value: Any) -> float:
    ownership._require(type(value) in {int, float} and math.isfinite(value) and value >= 0)
    return float(value)


def scope_digest(document: dict[str, Any], raw: dict[str, bytes]) -> str:
    """Review subject for release/freeze observations; independent of those reports."""
    return operations.digest(
        dict(
            handoff_id=document["handoff_id"],
            commit=document["commit"],
            artifacts={
                n: ownership._hash(v)
                for n, v in sorted(raw.items())
                if n not in EXCLUDED | {"release", "freeze", "environment"}
            },
        )
    )


def _preview(
    root: Path,
    prefix: str,
    raw: dict[str, bytes],
    cfg: FoundationConfig,
    now: datetime,
    commit: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    unit = "oci-" + prefix
    package = ownership._fields(
        ownership._json(raw[prefix + "_preview_inputs"]), {"checkpoint_sha256", "artifacts"}
    )
    ownership._require(package["checkpoint_sha256"] == ownership._hash(raw[prefix + "_checkpoint"]))
    artifacts = {n: bytes.fromhex(v) for n, v in package["artifacts"].items()}
    foundation = load_foundation(root)
    contract = describe_preview(foundation, unit, commit)
    receipt = validate_preview_result(raw[prefix + "_preview"], contract, artifacts, now=now)
    ownership._require(set(receipt["resource_changes"]) <= {"same", "read"})
    for role, path in (
        ("toolchain", "config/toolchain.json"),
        ("provider_toolchain", "config/provider-toolchain.json"),
    ):
        ownership._require(artifacts[role] == (root / path).read_bytes())
    expected_policy = operations.encoded(
        {p: ownership._hash((root / p).read_bytes()) for p in POLICY_SOURCES}
    )
    ownership._require(artifacts["policy"] == expected_policy)
    payload = ownership._fields(
        ownership._json(artifacts["proposal"]), {"configuration", "stack_configuration"}
    )
    ownership._require(payload["configuration"] == ownership._json(operations.encoded(asdict(cfg))))
    account = ownership._json(artifacts["account"])
    profile = tomllib.loads((root / "config/quotas/profiles.toml").read_text())["profiles"][
        account["profile"]
    ]
    ownership._require(
        artifacts["profile"] == operations.encoded(profile) and account["home_region"] == cfg.region
    )
    inventory = validate_inventory_evidence(
        account,
        profile,
        artifacts["evidence"],
        artifacts["envelope"],
        commit=contract.commit_sha,
        now=now,
    )
    ownership._require(
        operations._time(inventory["collection_completed_at"])
        <= operations._time(receipt["started_at"])
    )
    graph = network_graph(cfg) if prefix == "network" else oke_graph(cfg)
    audit(
        account,
        profile,
        inventory,
        proposal(graph, account["account_id"], cfg.region, units=(unit,)),
        now=now,
    )
    if prefix == "oke":
        ownership._require(
            ownership._json(artifacts["dependency_outputs"])
            == ownership._json(raw["network_outputs"])
        )
    return receipt, dict(account=account, stack_configuration=payload["stack_configuration"])


def _recovery(
    prefix: str,
    raw: dict[str, bytes],
    request: dict[str, Any],
    imported_at: datetime,
    now: datetime,
) -> datetime:
    def get(name: str) -> dict[str, Any]:
        value = ownership._json(raw[prefix + "_" + name])
        ownership._require(type(value) is dict)
        assert isinstance(value, dict)
        return value

    backup_request = operations.request(get("backup_request"))
    manifest, receipt, settings, rehearsal = (
        get(n) for n in ("backup_manifest", "backup_receipt", "recovery_policy", "recovery_receipt")
    )
    ownership._require(
        backup_request["operation"] == "recovery"
        and backup_request["unit"] == request["unit"]
        and backup_request["commit"] == request["commit"]
        and backup_request["operation_id"] != request["operation_id"]
    )
    ownership._require(
        type(manifest["schema_version"]) is int
        and manifest["schema_version"] == 2
        and type(receipt["schema_version"]) is int
        and receipt["schema_version"] == 1
    )
    checkpoint = ownership._hash(raw[prefix + "_checkpoint"])
    ownership._require(
        manifest["operation_id"] == backup_request["operation_id"]
        and manifest["request_sha256"] == operations.digest(backup_request)
        and manifest["unit"] == request["unit"]
        and manifest["stack"] == "organization/free-infrastructure/" + request["unit"]
        and manifest["commit"] == request["commit"]
        and manifest["checkpoint_sha256"] == backup_request["checkpoint_sha256"] == checkpoint
        and manifest["configuration_sha256"]
        == backup_request["configuration_sha256"]
        == request["configuration_sha256"]
    )
    ownership._require(
        receipt["manifest_sha256"] == ownership._hash(raw[prefix + "_backup_manifest"])
        and receipt["repository_id"] == manifest["repository_id"]
        and all(
            operations._hash(receipt[n])
            for n in ("manifest_sha256", "snapshot_id", "repository_id")
        )
    )
    ownership._fields(
        settings,
        {
            "schema_version",
            "max_backup_age_seconds",
            "restore_objective_seconds",
            "require_independent_host",
        },
    )
    ownership._require(
        type(settings["schema_version"]) is int
        and settings["schema_version"] == 1
        and settings["require_independent_host"] is True
        and _number(settings["max_backup_age_seconds"]) > 0
        and _number(settings["restore_objective_seconds"]) > 0
    )
    ownership._require(
        type(rehearsal["schema_version"]) is int
        and rehearsal["schema_version"] == 2
        and rehearsal["policy_sha256"] == ownership._hash(operations.encoded(settings))
    )
    for name in (
        "unit",
        "stack",
        "operation_id",
        "checkpoint_sha256",
        "configuration_sha256",
        "source_host_id",
    ):
        ownership._require(rehearsal[name] == manifest[name])
    ownership._require(
        rehearsal["manifest_sha256"] == receipt["manifest_sha256"]
        and rehearsal["snapshot_id"] == receipt["snapshot_id"]
        and rehearsal["kind"] == "off-host"
        and operations._hash(rehearsal["source_host_id"])
        and operations._hash(rehearsal["recovery_host_id"])
        and rehearsal["source_host_id"] != rehearsal["recovery_host_id"]
    )
    ownership._require(
        all(
            rehearsal[n] is True
            for n in ("objectives_met", "wrong_key_rejected", "correct_key_readback")
        )
        and rehearsal["execution_authorized"] is False
    )
    exported, captured, completed, start, end = [
        operations._time(v)
        for v in (
            manifest["source_exported_at"],
            manifest["captured_at"],
            receipt["completed_at"],
            rehearsal["started_at"],
            rehearsal["completed_at"],
        )
    ]
    ownership._require(
        imported_at <= exported <= captured <= completed <= start <= end <= now
        and captured < operations._time(backup_request["expires_at"])
    )
    ownership._require(
        (now - exported).total_seconds() <= settings["max_backup_age_seconds"]
        and _number(rehearsal["backup_age_seconds"]) <= settings["max_backup_age_seconds"]
        and _number(rehearsal["restore_seconds"]) <= settings["restore_objective_seconds"]
        and abs((end - start).total_seconds() - rehearsal["restore_seconds"]) <= 1
    )
    return end


def _unit(
    root: Path,
    prefix: str,
    raw: dict[str, bytes],
    cfg: FoundationConfig,
    commit: str,
    now: datetime,
    read: Callable[[dict[str, Any]], bytes],
) -> dict[str, Any]:
    unit = "oci-" + prefix
    preparation = ownership._json(raw[prefix + "_preparation"])
    ownership._fields(
        preparation, {"schema_version", "source", "target_stack", "entries", "artifacts"}
    )
    ownership._require(
        type(preparation["schema_version"]) is int
        and preparation["schema_version"] == 1
        and preparation["target_stack"] == "organization/free-infrastructure/" + unit
    )
    original = {
        n: read(ref)
        for n, ref in ownership._fields(preparation["artifacts"], ownership.ARTIFACTS).items()
        if n != "journal"
    }
    ownership._require(original["configuration"] == raw["configuration"])
    request = operations.request(ownership._json(original["request"]))
    ownership._require(
        request["operation"] == "import"
        and request["unit"] == unit
        and request["commit"] == commit
        and request["configuration_sha256"] == ownership._hash(original["encrypted_configuration"])
        and request["checkpoint_sha256"] == ownership._hash(original["target_checkpoint"])
    )
    prepared = raw[prefix + "_prepared_journal"]
    ref = preparation["artifacts"]["journal"]
    ownership._require(
        root / ref["path"] == root / ".infra/operations" / (unit + ".json")
        and ref["sha256"] == ownership._hash(prepared)
    )
    before_entries = operations._validate(ownership._json(prepared))
    entries = operations._validate(ownership._json(raw[prefix + "_journal"]))
    ownership._require(
        bool(before_entries)
        and before_entries[-1]["state"] == "prepared"
        and before_entries[-1]["request"] == request
        and entries[: len(before_entries)] == before_entries
        and [e["state"] for e in entries[len(before_entries) :]]
        == ["admitted", "running", "succeeded"]
    )
    imported_at = operations._time(entries[-1]["at"])
    ownership._require(imported_at <= now)
    receipt = ownership._json(raw[prefix + "_import_receipt"])
    ownership._require(
        type(receipt["schema_version"]) is int
        and receipt["schema_version"] == 1
        and receipt["status"] == "succeeded"
        and receipt["post_import_equivalent"] is True
        and receipt["operation_id"] == request["operation_id"]
        and receipt["journal_head"] == operations.digest(entries[-1])
        and receipt["checkpoint_sha256"] == ownership._hash(raw[prefix + "_checkpoint"])
        and operations._hash(receipt["approval_sha256"])
        and operations._hash(receipt["plan_sha256"])
    )
    counts = receipt["resource_changes"]
    ownership._require(
        type(counts) is dict
        and set(counts) <= {"same", "read", "import"}
        and all(type(v) is int and v >= 0 for v in counts.values())
    )
    graph = network_graph(cfg) if prefix == "network" else oke_graph(cfg)
    ownership._fields(
        preparation["source"], {"engine", "backend_sha256", "workspace", "lineage", "serial"}
    )
    ownership._require(
        preparation["source"]["engine"] == "terraform"
        and operations._hash(preparation["source"]["backend_sha256"])
        and type(preparation["source"]["serial"]) is int
        and str(UUID(preparation["source"]["lineage"])) == preparation["source"]["lineage"]
    )
    ownership._text(preparation["source"]["workspace"])
    settings = ownership._fields(
        ownership._json(original["encrypted_configuration"]), {"encryptionsalt", "config"}
    )
    ownership._require(
        type(settings["encryptionsalt"]) is str
        and settings["encryptionsalt"].startswith("v1:")
        and len(settings["encryptionsalt"]) > 3
        and settings["config"] == {}
    )
    source = ownership._source(original["source_checkpoint"], preparation["source"])
    initial_target = ownership._target(original["target_checkpoint"], preparation["target_stack"])
    imports = ownership._mapping(preparation["entries"], graph, cfg, source, initial_target, unit)
    ownership._require(imports > 0 and counts.get("import") == imports)
    frozen = ownership._json(original["freeze"])
    ownership._fields(
        frozen,
        {
            "schema_version",
            "phase",
            "binding_sha256",
            "complete",
            "other_writers_reviewed",
            "active_operations",
            "frozen_at",
            "checkpointed_at",
            "observed_at",
            "expires_at",
            "reviewed_by",
            "writers",
        },
    )
    ownership._require(type(frozen["schema_version"]) is int and frozen["schema_version"] == 1)
    ownership._text(frozen["reviewed_by"])
    original_writers = frozen["writers"]
    ownership._require(type(original_writers) is list and len(original_writers) == 2)
    known = set()
    for writer in original_writers:
        ownership._fields(writer, {"engine", "identity_sha256", "frozen", "active_operations"})
        ownership._require(
            writer["frozen"] is True
            and type(writer["active_operations"]) is int
            and writer["active_operations"] == 0
        )
        known.add((writer["engine"], writer["identity_sha256"]))
    ownership._require(
        known
        == {
            ("terraform", operations.digest(preparation["source"])),
            ("pulumi", operations.digest(preparation["target_stack"])),
        }
    )
    frozen_at = operations._time(frozen["frozen_at"])
    ownership._require((operations._time(entries[-3]["at"]) - frozen_at).total_seconds() <= 900)
    ownership._require(
        frozen["phase"] == "writers-frozen"
        and frozen["complete"] is True
        and frozen["other_writers_reviewed"] is True
        and type(frozen["active_operations"]) is int
        and frozen["active_operations"] == 0
    )
    binding = ownership.preparation_binding(
        preparation,
        request,
        original,
        foundation_sha256=load_foundation(root).digest,
        journal_head=operations.digest(before_entries[-1]),
    )
    ownership._require(
        frozen["binding_sha256"] == binding
        and operations._time(before_entries[-1]["at"])
        <= frozen_at
        <= operations._time(frozen["checkpointed_at"])
        <= operations._time(frozen["observed_at"])
        <= operations._time(entries[-3]["at"])
        <= operations._time(entries[-2]["at"])
        <= imported_at
        <= operations._time(frozen["expires_at"])
        <= operations._time(request["expires_at"])
    )
    released_state = ownership._json(raw[prefix + "_released_source"])
    ownership._require(
        type(released_state["serial"]) is int
        and released_state["serial"] > preparation["source"]["serial"]
    )
    released = ownership._source(
        raw[prefix + "_released_source"],
        dict(preparation["source"], serial=released_state["serial"]),
    )
    ownership._require(
        all(
            e["terraform_address"] is None or e["terraform_address"] not in released
            for e in preparation["entries"]
        )
    )
    target = ownership._target(raw[prefix + "_checkpoint"], preparation["target_stack"])
    retained = [
        dict(e, operation="same", owner="pulumi", terraform_address=None)
        for e in preparation["entries"]
    ]
    ownership._mapping(retained, graph, cfg, released, target, unit)
    provider = (
        "urn:pulumi:"
        + unit
        + "::free-infrastructure::pulumi:providers:oci::"
        + cfg.name
        + "-provider"
    )
    ownership._require(initial_target[provider]["id"] == target[provider]["id"])
    recovery_end = _recovery(prefix, raw, request, imported_at, now)
    preview, preview_scope = _preview(root, prefix, raw, cfg, now, commit)
    ownership._require(
        preview_scope["stack_configuration"] == ownership._json(original["encrypted_configuration"])
    )
    return dict(
        imported_at=imported_at,
        running_at=operations._time(entries[-2]["at"]),
        frozen_at=frozen_at,
        recovery_end=recovery_end,
        preview=preview,
        source_identity=operations.digest(preparation["source"]),
        source_scope=operations.digest(
            {n: v for n, v in preparation["source"].items() if n != "serial"}
        ),
        source_serial=preparation["source"]["serial"],
        source_checkpoint_sha256=ownership._hash(original["source_checkpoint"]),
        released_checkpoint_sha256=ownership._hash(raw[prefix + "_released_source"]),
        checkpoint=target,
        count=len(graph),
        receipt=receipt,
        request_id=request["operation_id"],
        backup_id=ownership._json(raw[prefix + "_backup_request"])["operation_id"],
        account=preview_scope["account"],
    )


def check(
    root: Path, document: object, *, actor: str, environment: str, now: datetime | None = None
) -> dict[str, object]:
    try:
        return _check(
            root.resolve(),
            ownership._json(operations.encoded(document)),
            actor,
            environment,
            now or datetime.now(UTC),
        )
    except Exception:
        raise ValueError(MESSAGE) from None


def _check(
    root: Path, data: dict[str, Any], actor: str, environment: str, now: datetime
) -> dict[str, object]:
    settings_raw = (root / "config/ownership-handoff.json").read_bytes()
    settings = ownership._fields(
        ownership._json(settings_raw), {"schema_version", "enabled", "max_evidence_age_seconds"}
    )
    ownership._require(
        type(settings["schema_version"]) is int
        and settings["schema_version"] == 1
        and settings["enabled"] is True
        and 0 < _number(settings["max_evidence_age_seconds"]) <= 900
        and now.utcoffset() == timedelta(0)
    )
    policy_raw = (root / "config/operations-policy.json").read_bytes()
    policy, reviewers = operation_admission._policy(policy_raw)
    ownership._require(
        policy["environments"]["handoff/oci"] == environment
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}", actor) is not None
    )
    ownership._fields(data, {"schema_version", "handoff_id", "commit", "artifacts"})
    ownership._require(
        type(data["schema_version"]) is int
        and data["schema_version"] == 1
        and str(UUID(data["handoff_id"])) == data["handoff_id"]
        and repository_state(root) == (data["commit"], True)
    )
    captured: list[tuple[dict[str, Any], bytes]] = []

    def read(ref: dict[str, Any]) -> bytes:
        _, content = ownership._read(root, ref)
        captured.append((ref, content))
        ownership._require(sum(len(v) for _, v in captured) <= 12 * operations.MAX_BYTES)
        return content

    refs = ownership._fields(data["artifacts"], ARTIFACTS)
    raw = {n: read(ref) for n, ref in refs.items()}
    ownership._require(
        all(
            root / refs[p + "_journal"]["path"]
            == root / ".infra/operations" / ("oci-" + p + ".json")
            for p in ("network", "oke")
        )
    )
    cfg = parse_config(ownership._json(raw["configuration"]))
    units = {p: _unit(root, p, raw, cfg, data["commit"], now, read) for p in ("network", "oke")}
    ownership._require(units["network"]["imported_at"] <= units["oke"]["running_at"])
    ownership._require(
        all(
            (now - state["recovery_end"]).total_seconds() <= settings["max_evidence_age_seconds"]
            for state in units.values()
        )
    )
    if units["network"]["source_scope"] == units["oke"]["source_scope"]:
        ownership._require(
            units["network"]["released_checkpoint_sha256"]
            == units["oke"]["released_checkpoint_sha256"]
        )
        if units["network"]["source_serial"] == units["oke"]["source_serial"]:
            ownership._require(
                units["network"]["source_checkpoint_sha256"]
                == units["oke"]["source_checkpoint_sha256"]
            )
    identifiers = {units[p][k] for p in ("network", "oke") for k in ("request_id", "backup_id")}
    ownership._require(len(identifiers) == 4 and data["handoff_id"] not in identifiers)
    outputs = ownership._json(raw["network_outputs"])
    validate_network(outputs, cfg, units["network"]["account"]["account_id"])
    ownership._require(
        units["network"]["account"]["account_id"] == units["oke"]["account"]["account_id"]
    )
    roots = [
        r for r in units["network"]["checkpoint"].values() if r["type"] == "pulumi:pulumi:Stack"
    ]
    ownership._require(
        roots[0].get("outputs") == outputs
        and units["network"]["receipt"]["dependency_outputs_sha256"] == network_digest(outputs)
    )
    reference = units["oke"]["checkpoint"][
        "urn:pulumi:oci-oke::free-infrastructure::pulumi:pulumi:StackReference::"
        + cfg.name
        + "-network-reference"
    ]
    ownership._require(
        reference["outputs"]["outputs"] == outputs
        and reference["outputs"]["secretOutputNames"] == []
    )
    scope = scope_digest(data, raw)
    release = ownership._fields(
        ownership._json(raw["release"]),
        {
            "schema_version",
            "handoff_id",
            "scope_sha256",
            "source_released",
            "source_writer_disabled",
            "completed_at",
        },
    )
    ownership._require(
        type(release["schema_version"]) is int
        and release["schema_version"] == 1
        and release["handoff_id"] == data["handoff_id"]
        and release["scope_sha256"] == scope
        and release["source_released"] is True
        and release["source_writer_disabled"] is True
    )
    released_at = operations._time(release["completed_at"])
    frozen = ownership._fields(
        ownership._json(raw["freeze"]),
        {
            "schema_version",
            "handoff_id",
            "scope_sha256",
            "complete",
            "continuous_freeze",
            "other_writers_reviewed",
            "live_equivalence_reviewed",
            "observed_at",
            "expires_at",
            "writers",
        },
    )
    ownership._require(
        type(frozen["schema_version"]) is int
        and frozen["schema_version"] == 1
        and frozen["handoff_id"] == data["handoff_id"]
        and frozen["scope_sha256"] == scope
        and all(
            frozen[k] is True
            for k in (
                "complete",
                "continuous_freeze",
                "other_writers_reviewed",
                "live_equivalence_reviewed",
            )
        )
    )
    observed, expiry = (
        operations._time(frozen["observed_at"]),
        operations._time(frozen["expires_at"]),
    )
    ownership._require(
        released_at <= observed <= now < expiry
        and (now - released_at).total_seconds() <= settings["max_evidence_age_seconds"]
    )
    writers = frozen["writers"]
    ownership._require(
        type(writers) is list
        and len(writers) == 2
        and {w["unit"] for w in writers} == {"oci-network", "oci-oke"}
    )
    for writer in writers:
        ownership._fields(
            writer,
            {
                "unit",
                "source_identity_sha256",
                "source_active",
                "target_active",
                "active_operations",
                "frozen_at",
            },
        )
        prefix = writer["unit"].removeprefix("oci-")
        state = units[prefix]
        ownership._require(
            writer["source_identity_sha256"] == state["source_identity"]
            and writer["source_active"] is False
            and writer["target_active"] is False
            and type(writer["active_operations"]) is int
            and writer["active_operations"] == 0
            and operations._time(writer["frozen_at"])
            <= state["frozen_at"]
            <= state["imported_at"]
            <= state["recovery_end"]
            <= released_at
            <= operations._time(state["preview"]["started_at"])
            <= operations._time(state["preview"]["completed_at"])
            <= observed
        )
    administration.validate_operation_environment(
        raw["environment"],
        repository=policy["repository"],
        repository_id=policy["repository_id"],
        environment=environment,
        commit=data["commit"],
        now=now,
    )
    admin_start = operations._time(ownership._json(raw["environment"])["started_at"])
    ownership._require(released_at <= admin_start)
    approval = ownership._json(raw["approval"])
    expected = dict(
        schema_version=1,
        handoff_id=data["handoff_id"],
        actor=actor,
        environment=environment,
        commit=data["commit"],
        evidence_sha256=operations.digest(
            {n: ownership._hash(v) for n, v in sorted(raw.items()) if n not in EXCLUDED}
        ),
        handoff_policy_sha256=ownership._hash(settings_raw),
        operation_policy_sha256=ownership._hash(policy_raw),
        foundation_sha256=load_foundation(root).digest,
    )
    ownership._require(
        set(approval) == set(expected) | {"issued_at", "expires_at"}
        and all(type(approval[k]) is type(v) and approval[k] == v for k, v in expected.items())
    )
    issued, until = (
        operations._time(approval["issued_at"]),
        operations._time(approval["expires_at"]),
    )
    ownership._require(
        max(observed, operations._time(ownership._json(raw["environment"])["completed_at"]))
        <= issued
        <= now
        < until
        <= expiry
        and (until - issued).total_seconds()
        <= min(policy["max_approval_age_seconds"], settings["max_evidence_age_seconds"])
    )
    principals = [
        verify_payload(role, raw["approval"], raw[role], reviewers, payload_type=PAYLOAD_TYPE)
        for role in ("operator", "approver")
    ]
    ownership._require(
        len(set(p.casefold() for p in principals)) == 2
        and actor.casefold() not in {p.casefold() for p in principals}
    )
    for ref, content in captured:
        ownership._require(ownership._read(root, ref)[1] == content)
    ownership._require(
        (root / "config/operations-policy.json").read_bytes() == policy_raw
        and (root / "config/ownership-handoff.json").read_bytes() == settings_raw
        and repository_state(root) == (data["commit"], True)
    )
    return dict(
        schema_version=1,
        handoff_id=data["handoff_id"],
        status="target-owner-admitted",
        admitted_owner="pulumi",
        observed_active_writer="none",
        target_owner_admitted=True,
        next_transition="target-writer-activation-review",
        approval_sha256=ownership._hash(raw["approval"]),
        expires_at=approval["expires_at"],
        resources=sum(v["count"] for v in units.values()),
        resource_execution_authorized=False,
        writer_activation_authorized=False,
        cutover_authorized=False,
    )


def inspect(root: Path, path: Path, *, actor: str, environment: str) -> dict[str, object]:
    """Bounded immutable private-index CLI adapter; no receipt or state writes."""
    try:
        root = root.resolve()
        path = root / path
        ownership._require(
            path.is_relative_to(root / ".infra") and path.resolve().is_relative_to(root / ".infra")
        )
        ownership._require(not any(p.is_symlink() for p in (path, *path.parents)))
        with path.open("rb") as stream:
            raw = stream.read(operations.MAX_BYTES + 1)
        from infra_core.cutover import handoff

        result = handoff(root, ownership._json(raw), actor=actor, environment=environment)
        ownership._require(
            ownership._read(root, {"path": str(path), "sha256": ownership._hash(raw)})[1] == raw
        )
        return result
    except Exception:
        raise ValueError(MESSAGE) from None
