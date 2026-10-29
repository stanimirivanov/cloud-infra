"""Offline signed operation preflight; never issue authority, consume a request or execute."""

import base64
import hashlib
import math
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infra_core import administration, operations, review_signatures
from infra_core.cutover import repository_state

PAYLOAD_TYPE = "application/vnd.cloud-infra.operation-approval.v1+json"
ROLES = {"operator", "approver"}
CONTEXT = {
    "actor",
    "environment",
    "commit",
    "configuration_sha256",
    "checkpoint_sha256",
    "plan_sha256",
    "journal_head",
}


def require(value: bool) -> None:
    if not value:
        raise ValueError("ADMIT001: operation approval or admission binding rejected")


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _policy(raw: bytes) -> tuple[dict[str, Any], tuple[review_signatures.Reviewer, ...]]:
    require(len(raw) <= review_signatures.MAX_POLICY_BYTES)
    value = administration._json(raw)
    require(
        set(value)
        == {
            "schema_version",
            "enabled",
            "repository",
            "repository_id",
            "max_approval_age_seconds",
            "max_backup_age_seconds",
            "environments",
            "reviewers",
        }
    )
    require(
        type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["enabled"] is True
    )
    require(
        type(value["repository"]) is str
        and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value["repository"]) is not None
    )
    require(type(value["repository_id"]) is int and value["repository_id"] > 0)
    for field in ("max_approval_age_seconds", "max_backup_age_seconds"):
        bound = value[field]
        require(type(bound) in (int, float) and math.isfinite(bound) and bound > 0)
    require(value["max_approval_age_seconds"] <= 900)
    require(type(value["environments"]) is dict and bool(value["environments"]))
    require(type(value["reviewers"]) is list and 2 <= len(value["reviewers"]) <= 16)
    reviewers = []
    for item in value["reviewers"]:
        require(type(item) is dict and set(item) == {"principal", "public_key", "roles"})
        require(
            type(item["principal"]) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}", item["principal"]) is not None
        )
        require(
            type(item["roles"]) is list
            and bool(item["roles"])
            and all(type(role) is str for role in item["roles"])
            and len(set(item["roles"])) == len(item["roles"])
            and set(item["roles"]) <= ROLES
        )
        key = base64.b64decode(item["public_key"], validate=True)
        require(len(key) == 32)
        reviewers.append(
            review_signatures.Reviewer(item["principal"], key, frozenset(item["roles"]))
        )
    require(
        len({r.key for r in reviewers}) == len(reviewers)
        and len({r.principal.casefold() for r in reviewers}) == len(reviewers)
    )
    return value, tuple(reviewers)


def admit(
    root: Path,
    *,
    request: bytes,
    approval: bytes,
    signatures: dict[str, bytes],
    backup_receipt: bytes,
    backup_manifest: bytes,
    environment: bytes,
    journal: bytes,
    context: dict[str, str],
    now: datetime | None = None,
    execution_inputs: bytes | None = None,
) -> dict[str, Any]:
    """Caller supplies independent current context, never expectations from the approval.

    A prepared journal can be checked repeatedly. Executors must recheck and atomically
    transition it before admitting credentials; this diagnostic result is not a token.
    """
    try:
        head, clean = repository_state(root)
        require(clean and head == context["commit"])
        policy_raw = (root / "config/operations-policy.json").read_bytes()
        result = _admit(
            policy_raw,
            request,
            approval,
            signatures,
            backup_receipt,
            backup_manifest,
            environment,
            journal,
            context,
            now or datetime.now(UTC),
            execution_inputs,
        )
        require(repository_state(root) == (head, True))
        return result
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        OverflowError,
        RecursionError,
    ):
        raise ValueError("ADMIT001: operation approval or admission binding rejected") from None


def _admit(
    policy_raw: bytes,
    request_raw: bytes,
    approval_raw: bytes,
    signatures: dict[str, bytes],
    receipt_raw: bytes,
    manifest_raw: bytes,
    environment_raw: bytes,
    journal_raw: bytes,
    context: dict[str, str],
    now: datetime,
    execution_inputs: bytes | None = None,
) -> dict[str, Any]:
    policy, reviewers = _policy(policy_raw)
    require(set(context) == CONTEXT and all(type(v) is str for v in context.values()))
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}", context["actor"]) is not None)
    value = operations.request(administration._json(request_raw))
    require(
        value["commit"] == context["commit"]
        and value["configuration_sha256"] == context["configuration_sha256"]
        and value["checkpoint_sha256"] == context["checkpoint_sha256"]
    )
    for field in ("configuration_sha256", "checkpoint_sha256", "plan_sha256", "journal_head"):
        require(operations._hash(context[field]))
    require(
        policy["environments"][value["operation"] + "/" + value["unit"]] == context["environment"]
    )
    entries = operations._validate(administration._json(journal_raw, array=True)["items"])
    require(
        bool(entries)
        and entries[-1]["state"] == "prepared"
        and entries[-1]["request"] == value
        and operations.digest(entries[-1]) == context["journal_head"]
    )
    receipt, manifest = administration._json(receipt_raw), administration._json(manifest_raw)
    require(
        type(receipt["schema_version"]) is int
        and receipt["schema_version"] == 1
        and type(manifest["schema_version"]) is int
        and manifest["schema_version"] == 2
    )
    require(
        receipt["manifest_sha256"] == _hash(manifest_raw)
        and receipt["repository_id"] == manifest["repository_id"]
        and manifest["operation_id"] == value["operation_id"]
        and manifest["unit"] == value["unit"]
        and manifest["stack"] == "organization/free-infrastructure/" + value["unit"]
        and manifest["request_sha256"] == operations.digest(value)
        and manifest["commit"] == value["commit"]
        and manifest["configuration_sha256"] == value["configuration_sha256"]
        and manifest["checkpoint_sha256"] == value["checkpoint_sha256"]
    )
    require(operations._hash(receipt["snapshot_id"]) and operations._hash(receipt["repository_id"]))
    exported = operations._time(manifest["source_exported_at"])
    require(
        exported
        <= operations._time(manifest["captured_at"])
        <= operations._time(receipt["completed_at"])
        <= now
        and 0 <= (now - exported).total_seconds() <= policy["max_backup_age_seconds"]
    )
    administration.validate_operation_environment(
        environment_raw,
        repository=policy["repository"],
        repository_id=policy["repository_id"],
        environment=context["environment"],
        commit=context["commit"],
        now=now,
    )
    approval = administration._json(approval_raw)
    expected = dict(
        schema_version=2 if execution_inputs is not None else 1,
        operation_id=value["operation_id"],
        **context,
        request_sha256=_hash(request_raw),
        policy_sha256=_hash(policy_raw),
        backup_sha256=_hash(receipt_raw),
        environment_sha256=_hash(environment_raw),
    )
    if execution_inputs is not None:
        require(
            type(execution_inputs) is bytes and 0 < len(execution_inputs) <= operations.MAX_BYTES
        )
        expected["execution_inputs_sha256"] = _hash(execution_inputs)
    require(
        set(approval) == set(expected) | {"issued_at", "expires_at"}
        and all(approval[k] == v for k, v in expected.items())
        and type(approval["schema_version"]) is int
    )
    issued, expiry = (
        operations._time(approval["issued_at"]),
        operations._time(approval["expires_at"]),
    )
    require(
        issued <= now < expiry <= operations._time(value["expires_at"])
        and (expiry - issued).total_seconds() <= policy["max_approval_age_seconds"]
    )
    require(
        operations._time(receipt["completed_at"]) <= issued
        and operations._time(administration._json(environment_raw)["completed_at"]) <= issued
        and operations._time(entries[-1]["at"]) <= issued
    )
    require(set(signatures) == ROLES)
    principals = [
        review_signatures.verify_payload(
            role, approval_raw, signatures[role], reviewers, payload_type=PAYLOAD_TYPE
        )
        for role in sorted(ROLES)
    ]
    require(
        len(set(principals)) == 2
        and context["actor"].casefold() not in {p.casefold() for p in principals}
    )
    return dict(
        schema_version=1,
        admission_verified=True,
        execution_authorized=False,
        operation_id=value["operation_id"],
        approval_sha256=_hash(approval_raw),
        journal_head=context["journal_head"],
        expires_at=approval["expires_at"],
    )
