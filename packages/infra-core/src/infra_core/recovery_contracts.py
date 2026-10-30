"""Frozen recovery scope, encrypted pairs and historical owner provenance; no execution."""

import json
import math
from datetime import UTC, datetime, timedelta
from typing import Any

from infra_core import backup, operation_admission, operations, ownership_handoff
from infra_core.drift_results import parse
from infra_core.review_signatures import verify_payload

MESSAGE = "RESTORE001: recovery prerequisite or reconciliation rejected; diagnostics withheld"


def require(value: bool) -> None:
    if not value:
        raise ValueError(MESSAGE)


def digest(raw: bytes) -> str:
    return operation_admission._hash(raw)


def pair(checkpoint: bytes, configuration: bytes, unit: str) -> dict[str, Any]:
    state, config = parse(checkpoint), parse(configuration)
    require(type(state["version"]) is int and state["version"] == 3)
    deployment = state["deployment"]
    require(
        not deployment.get("pending_operations")
        and deployment["secrets_providers"]["type"] == "passphrase"
    )
    salt = deployment["secrets_providers"]["state"]["salt"]
    require(
        type(salt) is str
        and bool(salt)
        and set(config) == {"encryptionsalt", "config"}
        and config["encryptionsalt"] == salt
        and type(config["config"]) is dict
    )
    for value in config["config"].values():
        require(
            type(value) is dict
            and set(value) == {"secure"}
            and type(value["secure"]) is str
            and value["secure"].startswith("v1:")
        )
    backup._encrypted(state)
    resources = deployment["resources"]
    require(type(resources) is list and bool(resources))
    prefix = "urn:pulumi:" + unit + "::free-infrastructure::"
    require(
        all(r["urn"].startswith(prefix) and not r.get("delete") for r in resources)
        and sum(r["type"] == "pulumi:pulumi:Stack" for r in resources) == 1
        and len({r["urn"] for r in resources}) == len(resources)
    )
    return state


def identities(state: dict[str, Any]) -> dict[str, Any]:
    return {
        r["urn"]: {k: r.get(k) for k in ("type", "id", "parent", "provider", "protect", "custom")}
        for r in state["deployment"]["resources"]
    }


def unchanged_resources(current: dict[str, Any], restored: dict[str, Any]) -> None:
    # Provider Read cannot prove write-only secret fields. Never roll their recorded
    # properties back just because the provider's refresh happens to be a no-op.
    def properties(state: dict[str, Any]) -> dict[str, Any]:
        return {
            r["urn"]: {k: r.get(k) for k in ("inputs", "outputs")}
            for r in state["deployment"]["resources"]
            if r["type"].startswith(("oci:", "cloudflare:", "supabase:"))
        }

    require(properties(current) == properties(restored))


def deployment_digest(value: dict[str, Any]) -> str:
    """Hash locally decrypted state without retaining plaintext or engine manifest."""
    require(value.get("version") == 3 and type(value.get("deployment")) is dict)
    return operations.digest({k: v for k, v in value["deployment"].items() if k != "manifest"})


def subject(raw: dict[str, bytes]) -> str:
    names = {
        "operation",
        "current_checkpoint",
        "encrypted_configuration",
        "restore_checkpoint",
        "restore_configuration",
        "restore_manifest",
        "restore_receipt",
        "proposal",
        "credential_review",
    }
    return operations.digest({name: digest(raw[name]) for name in sorted(names)})


def plan(raw: dict[str, bytes], destination: str) -> bytes:
    return operations.encoded(
        dict(
            schema_version=1,
            operation="state-recovery",
            subject_sha256=subject(raw),
            configuration_destination=destination,
            resource_operations=False,
            writer_release=False,
        )
    )


def freeze(raw: dict[str, bytes], unit: str, *, now: datetime | None = None) -> None:
    now = now or datetime.now(UTC)
    request = operations.request(parse(raw["operation"]))
    value = parse(raw["freeze"])
    require(
        set(value)
        == {"schema_version", "subject_sha256", "frozen_at", "observed_at", "expires_at", "writers"}
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["subject_sha256"] == subject(raw)
    )
    frozen, observed, expiry = (
        operations._time(value[k]) for k in ("frozen_at", "observed_at", "expires_at")
    )
    current = operations._time(parse(raw["backup_manifest"])["source_exported_at"])
    require(
        frozen <= current <= observed <= now < expiry <= operations._time(request["expires_at"])
        and (now - observed).total_seconds() <= 900
    )
    units = {"oci-network", "oci-oke"} if unit.startswith("oci-") else {unit}
    require(type(value["writers"]) is dict and set(value["writers"]) == units)
    for record in value["writers"].values():
        require(
            type(record) is dict
            and record
            == dict(owner="pulumi", source_active=False, target_active=False, active_operations=0)
            and type(record["active_operations"]) is int
            and record["source_active"] is False
            and record["target_active"] is False
        )


def restore_evidence(
    raw: dict[str, bytes], unit: str, host: str, *, now: datetime | None = None
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    manifest, receipt, policy, rehearsal = (
        parse(raw[k])
        for k in ("restore_manifest", "restore_receipt", "restore_policy", "rehearsal")
    )
    require(
        set(policy)
        == {
            "schema_version",
            "max_backup_age_seconds",
            "restore_objective_seconds",
            "require_independent_host",
        }
        and type(policy["schema_version"]) is int
        and policy["schema_version"] == 1
        and policy["require_independent_host"] is True
    )
    for key in ("max_backup_age_seconds", "restore_objective_seconds"):
        require(
            type(policy[key]) in {int, float} and math.isfinite(policy[key]) and policy[key] > 0
        )
    require(policy["restore_objective_seconds"] <= 300)
    require(
        type(manifest["schema_version"]) is int
        and manifest["schema_version"] == 2
        and manifest["unit"] == unit
        and manifest["stack"] == "organization/free-infrastructure/" + unit
        and manifest["checkpoint_sha256"] == digest(raw["restore_checkpoint"])
        and manifest["configuration_sha256"] == digest(raw["restore_configuration"])
        and operations._hash(manifest["source_host_id"])
        and manifest["source_host_id"] != host
    )
    require(
        type(receipt["schema_version"]) is int
        and receipt["schema_version"] == 1
        and receipt["manifest_sha256"] == digest(raw["restore_manifest"])
        and receipt["repository_id"] == manifest["repository_id"]
        and all(
            operations._hash(receipt[k])
            for k in ("snapshot_id", "manifest_sha256", "repository_id")
        )
    )
    exported, captured, backed, start, end = (
        operations._time(v)
        for v in (
            manifest["source_exported_at"],
            manifest["captured_at"],
            receipt["completed_at"],
            rehearsal["started_at"],
            rehearsal["completed_at"],
        )
    )
    require(
        exported <= captured <= backed <= start <= end <= now
        and (now - exported).total_seconds() <= policy["max_backup_age_seconds"]
    )
    require(
        type(rehearsal["schema_version"]) is int
        and rehearsal["schema_version"] == 2
        and rehearsal["kind"] == "off-host"
        and rehearsal["recovery_host_id"] == host
        and rehearsal["policy_sha256"] == operations.digest(policy)
        and rehearsal["snapshot_id"] == receipt["snapshot_id"]
        and rehearsal["manifest_sha256"] == receipt["manifest_sha256"]
        and rehearsal["execution_authorized"] is False
    )
    for key in (
        "unit",
        "stack",
        "operation_id",
        "configuration_sha256",
        "checkpoint_sha256",
        "source_host_id",
    ):
        require(rehearsal[key] == manifest[key])
    for key in ("objectives_met", "wrong_key_rejected", "correct_key_readback"):
        require(rehearsal[key] is True)
    age, duration = rehearsal["backup_age_seconds"], rehearsal["restore_seconds"]
    require(
        type(age) in {int, float}
        and math.isfinite(age)
        and 0 <= age <= policy["max_backup_age_seconds"]
        and type(duration) in {int, float}
        and math.isfinite(duration)
        and 0 <= duration <= policy["restore_objective_seconds"]
        and abs((end - start).total_seconds() - duration) <= 1
    )
    return policy


def owner(
    raw: dict[str, bytes], unit: str, journal: bytes, foundation: str, root_policy: bytes
) -> None:
    """Authenticate historical scope, not replay an expired writer-admission decision."""
    entries = operations._validate(json.loads(journal))
    action = "import" if unit.startswith("oci-") else "apply"
    require(
        any(
            e["state"] == "succeeded"
            and e["request"]["unit"] == unit
            and e["request"]["operation"] == action
            for e in entries[:-1]
        )
    )
    if not unit.startswith("oci-"):
        return
    approval, decision, subject_map = (
        parse(raw[k]) for k in ("owner_approval", "owner_decision", "owner_subject")
    )
    policy, reviewers = operation_admission._policy(root_policy)
    require(
        set(subject_map) == {"schema_version", "artifacts"}
        and type(subject_map["schema_version"]) is int
        and subject_map["schema_version"] == 1
        and set(subject_map["artifacts"])
        == ownership_handoff.ARTIFACTS - ownership_handoff.EXCLUDED
        and all(operations._hash(v) for v in subject_map["artifacts"].values())
    )
    require(
        set(approval)
        == {
            "schema_version",
            "handoff_id",
            "actor",
            "environment",
            "commit",
            "evidence_sha256",
            "handoff_policy_sha256",
            "operation_policy_sha256",
            "foundation_sha256",
            "issued_at",
            "expires_at",
        }
        and type(approval["schema_version"]) is int
        and approval["schema_version"] == 1
        and approval["evidence_sha256"] == operations.digest(subject_map["artifacts"])
        and approval["operation_policy_sha256"] == digest(root_policy)
        and approval["foundation_sha256"] == foundation
        and approval["environment"] == policy["environments"]["handoff/oci"]
    )
    issued, expiry = (operations._time(approval[k]) for k in ("issued_at", "expires_at"))
    require(
        timedelta(0) < expiry - issued <= timedelta(seconds=900) and issued <= datetime.now(UTC)
    )
    principals = [
        verify_payload(
            role,
            raw["owner_approval"],
            raw["owner_" + role],
            reviewers,
            payload_type=ownership_handoff.PAYLOAD_TYPE,
        )
        for role in ("operator", "approver")
    ]
    require(
        len({p.casefold() for p in principals}) == 2
        and approval["actor"].casefold() not in {p.casefold() for p in principals}
    )
    require(
        decision["status"] == "target-owner-admitted"
        and decision["target_owner_admitted"] is True
        and decision["admitted_owner"] == "pulumi"
        and decision["observed_active_writer"] == "none"
        and decision["handoff_id"] == approval["handoff_id"]
        and decision["expires_at"] == approval["expires_at"]
        and decision["approval_sha256"] == digest(raw["owner_approval"])
        and all(
            decision[k] is False
            for k in (
                "resource_execution_authorized",
                "writer_activation_authorized",
                "cutover_authorized",
            )
        )
    )
    key = "network_checkpoint" if unit == "oci-network" else "oke_checkpoint"
    require(subject_map["artifacts"][key] == digest(raw["owner_checkpoint"]))
    require(
        identities(parse(raw["owner_checkpoint"])) == identities(parse(raw["restore_checkpoint"]))
    )
