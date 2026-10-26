"""Offline DSSE/Ed25519 verification against repository-enrolled public keys only."""

import base64
import json
import re
import tomllib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from infra_core.cutover_evidence import REPORTS
from infra_core.evidence import MAX_ENVELOPE_BYTES
from infra_core.governance.contracts import GovernanceError, fields, require

PAYLOAD_TYPE = "application/vnd.in-toto+json"
MAX_POLICY_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 96 * 1024


@dataclass(frozen=True)
class Reviewer:
    principal: str
    key: bytes
    roles: frozenset[str]


def preauth(payload: bytes) -> bytes:
    """DSSE v1 PAE for the fixed application-specific in-toto payload type."""
    kind = PAYLOAD_TYPE.encode("ascii")
    return (
        b"DSSEv1 "
        + str(len(kind)).encode()
        + b" "
        + kind
        + b" "
        + str(len(payload)).encode()
        + b" "
        + payload
    )


def _decode(value: object, maximum: int) -> bytes:
    require(
        isinstance(value, str) and len(value) <= 4 * ((maximum + 2) // 3),
        "CUT010",
        "invalid signature encoding",
    )
    assert isinstance(value, str)
    decoded = base64.b64decode(value, altchars=b"-_", validate=True)
    require(len(decoded) <= maximum, "CUT010", "decoded signature field exceeds limit")
    return decoded


def parse_policy(payload: bytes) -> tuple[Reviewer, ...]:
    """A disabled, empty or ambiguous policy never authenticates any reviewer."""
    require(
        type(payload) is bytes and len(payload) <= MAX_POLICY_BYTES,
        "CUT009",
        "reviewer policy must be bounded immutable bytes",
    )
    try:
        data = fields(
            tomllib.loads(payload.decode("utf-8")),
            {"schema_version", "enabled", "reviewers"},
            "reviewer policy",
        )
        require(
            type(data["schema_version"]) is int
            and data["schema_version"] == 1
            and data["enabled"] is True,
            "CUT009",
            "reviewer policy is disabled or unsupported",
        )
        values = data["reviewers"]
        require(
            isinstance(values, list) and 1 <= len(values) <= 16,
            "CUT009",
            "one to sixteen enrolled reviewer keys required",
        )
        reviewers = []
        seen = set()
        for value in values:
            item = fields(value, {"principal", "public_key", "roles"}, "reviewer key")
            principal, roles = item["principal"], item["roles"]
            require(
                isinstance(principal, str)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}", principal) is not None
                and isinstance(roles, list)
                and bool(roles)
                and all(isinstance(role, str) for role in roles)
                and len(set(roles)) == len(roles)
                and set(roles) <= REPORTS,
                "CUT009",
                "invalid reviewer principal or role permissions",
            )
            key = _decode(item["public_key"], 32)
            require(len(key) == 32 and key not in seen, "CUT009", "ambiguous or invalid public key")
            seen.add(key)
            reviewers.append(Reviewer(principal, key, frozenset(roles)))
        return tuple(reviewers)
    except (ValueError, TypeError, RecursionError):
        raise GovernanceError("CUT009: invalid or disabled reviewer trust policy") from None


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        require(key not in result, "CUT010", "duplicate signature JSON field")
        result[key] = value
    return result


def verify_review(
    role: str,
    envelope: bytes,
    signature: bytes,
    reviewers: tuple[Reviewer, ...],
) -> str:
    """Authenticate a key holder; keyid is an untrusted hint and never selects identity."""
    require(
        role in REPORTS
        and type(envelope) is bytes
        and len(envelope) <= MAX_ENVELOPE_BYTES
        and type(signature) is bytes
        and len(signature) <= MAX_SIGNATURE_BYTES,
        "CUT010",
        "invalid bounded review signature input",
    )
    try:
        data = fields(
            json.loads(signature.decode("utf-8"), object_pairs_hook=_object),
            {"payload", "payloadType", "signatures"},
            "DSSE envelope",
        )
        require(
            data["payloadType"] == PAYLOAD_TYPE
            and isinstance(data["signatures"], list)
            and len(data["signatures"]) == 1,
            "CUT010",
            "unsupported DSSE profile",
        )
        signed = data["signatures"][0]
        require(
            isinstance(signed, dict) and "sig" in signed and set(signed) <= {"keyid", "sig"},
            "CUT010",
            "invalid DSSE signature fields",
        )
        require(
            isinstance(signed.get("keyid", ""), str) and len(signed.get("keyid", "")) <= 256,
            "CUT010",
            "invalid untrusted key hint",
        )
        payload = _decode(data["payload"], MAX_ENVELOPE_BYTES)
        sig = _decode(signed["sig"], 64)
        require(payload == envelope and len(sig) == 64, "CUT010", "signed payload differs")
    except (ValueError, TypeError, RecursionError):
        raise GovernanceError("CUT010: invalid review signature envelope") from None
    message = preauth(payload)
    for reviewer in reviewers:
        if role not in reviewer.roles:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(reviewer.key).verify(sig, message)
        except (InvalidSignature, ValueError, UnsupportedAlgorithm):
            continue
        return reviewer.principal
    raise GovernanceError("CUT010: no authorized reviewer key verified the signature")
