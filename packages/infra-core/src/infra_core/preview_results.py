"""Unsigned preview observations: byte consistency and policy signals, never authority."""

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn

from infra_core.evidence import MAX_ARTIFACT_BYTES, MAX_TOTAL_BYTES
from infra_core.preview_contracts import PreviewContract

POLICY_SOURCES = (
    "policies/__main__.py",
    "policies/PulumiPolicy.yaml",
    "packages/infra-program/src/infra_program/governance.py",
    "uv.lock",
    ".python-version",
    "packages/infra-program/src/infra_program/preview_driver.py",
    "packages/infra-program/src/infra_program/preview_runtime.py",
)

PACK = "always-free-governance"
RULE = "reviewed-resource-costs"
MAX_EVENT_BYTES = 256 * 1024
MAX_EVENTS = 10_000
MAX_RESULT_BYTES = 64 * 1024
WINDOW = timedelta(minutes=15)
OPERATIONS = set(
    (
        "same create update delete replace create-replacement delete-replaced read "
        "read-replacement discard discard-replaced remove-pending-replace"
    ).split()
)
_FIXED = {
    "schema_version": 1,
    "operation": "preview",
    "status": "succeeded",
    "deployment_authorized": False,
    "cutover_authorized": False,
}
_EVENTS = set(
    (
        "cancelEvent stdoutEvent diagnosticEvent preludeEvent summaryEvent resourcePreEvent "
        "resOutputsEvent policyLoadEvent progressEvent policyAnalyzeSummaryEvent "
        "policyAnalyzeStackSummaryEvent policyRemediateSummaryEvent"
    ).split()
)


def _require(condition: bool, code: str = "PREVIEW003") -> None:
    if not condition:
        raise ValueError(code + ": invalid or incomplete preview evidence")


def _reject(*args: Any) -> NoReturn:
    raise ValueError("PREVIEW003: invalid or incomplete preview evidence")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _parse(data: bytes, limit: int) -> dict[str, Any]:
    _require(type(data) is bytes and 0 < len(data) <= limit)
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_object, parse_constant=_reject)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("PREVIEW003: invalid or incomplete preview evidence") from None
    _require(type(value) is dict)
    assert isinstance(value, dict)
    return value


def _digest(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _scope(contract: PreviewContract, artifacts: Mapping[str, bytes]) -> dict[str, Any]:
    _require(type(contract) is PreviewContract and contract.preview_enabled is True)
    names = {
        "proposal",
        "profile",
        "evidence",
        "envelope",
        "toolchain",
        "provider_toolchain",
        "policy",
    }
    if contract.unit.startswith("oci-"):
        names.add("account")
    if contract.unit == "oci-oke":
        names.add("dependency_outputs")
    _require(isinstance(artifacts, Mapping) and set(artifacts) == names)
    _require(all(type(v) is bytes and 0 < len(v) <= MAX_ARTIFACT_BYTES for v in artifacts.values()))
    _require(sum(len(v) for v in artifacts.values()) <= MAX_TOTAL_BYTES)
    return dict(
        _FIXED,
        unit=contract.unit,
        stack_identity=contract.stack_identity,
        commit_sha=contract.commit_sha,
        configuration_sha256=contract.configuration_sha256,
        preview_contract_sha256=contract.digest,
        inputs={k: hashlib.sha256(artifacts[k]).hexdigest() for k in sorted(names)},
    )


def _counts(value: Any) -> None:
    _require(type(value) is dict and bool(value) and set(value) <= OPERATIONS)
    _require(all(type(v) is int and 0 <= v <= MAX_EVENTS for v in value.values()))
    _require(0 < sum(value.values()) <= MAX_EVENTS)


def preview_input_digests(
    contract: PreviewContract, artifacts: Mapping[str, bytes]
) -> dict[str, str]:
    """Validate/bind captured inputs before execution as well as during receipt validation."""
    digests: dict[str, str] = _scope(contract, artifacts)["inputs"]
    return digests


def _time(value: Any) -> datetime:
    _require(type(value) is str and len(value) <= 64)
    try:
        parsed = datetime.fromisoformat(value)
        _require(parsed.utcoffset() is not None)
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        raise ValueError("PREVIEW003: invalid or incomplete preview evidence") from None


def validate_preview_result(
    encoded: bytes,
    contract: PreviewContract,
    artifacts: Mapping[str, bytes],
    *,
    now: datetime,
) -> dict[str, Any]:
    """Validate against independent expectations; a forged matching receipt is still unsigned."""
    data, expected = _parse(encoded, MAX_RESULT_BYTES), _scope(contract, artifacts)
    _require(
        set(data)
        == set(expected)
        | {
            "started_at",
            "completed_at",
            "resource_changes",
            "policy",
            "events_sha256",
            "event_count",
        }
    )
    _require(all(type(data[k]) is type(v) and data[k] == v for k, v in expected.items()))
    _require(isinstance(now, datetime) and now.utcoffset() is not None)
    start, end = _time(data["started_at"]), _time(data["completed_at"])
    _require(timedelta(0) <= end - start <= WINDOW and timedelta(0) <= now - end <= WINDOW)
    _counts(data["resource_changes"])
    _require(
        _digest(data["events_sha256"])
        and type(data["event_count"]) is int
        and 3 <= data["event_count"] <= MAX_EVENTS
    )
    policy = data["policy"]
    _require(
        type(policy) is dict
        and set(policy)
        == {"pack", "source_sha256", "version_sha256", "passed_checks", "violations"}
    )
    _require(
        policy["pack"] == PACK
        and policy["source_sha256"] == expected["inputs"]["policy"]
        and _digest(policy["version_sha256"])
        and type(policy["passed_checks"]) is int
        and 0 < policy["passed_checks"] <= data["event_count"]
        and type(policy["violations"]) is int
        and policy["violations"] == 0
    )
    return data


def create_preview_result(
    contract: PreviewContract,
    artifacts: Mapping[str, bytes],
    events: Iterable[bytes],
    *,
    exit_code: int,
    started_at: str,
    completed_at: str,
    now: datetime,
) -> bytes:
    """Consume bounded CLI wire records, discard private content, emit canonical success bytes.

    SDK SummaryEvent drops isPreview/result and positive policy analysis events;
    callers must preserve the CLI 3.272.0 wire observations instead of synthesizing them.
    """
    data = _scope(contract, artifacts)
    _require(type(exit_code) is int and exit_code == 0, "PREVIEW004")
    start_second = int(_time(started_at).timestamp())
    end_second = int(_time(completed_at).timestamp())
    digest, total, count, sequence, checks = hashlib.sha256(), 0, 0, -1, 0
    summary: dict[str, Any] | None = None
    terminal = False
    for raw in events:
        count += 1
        _require(not terminal and count <= MAX_EVENTS, "PREVIEW004")
        event = _parse(raw, MAX_EVENT_BYTES)
        total += len(raw)
        _require(total <= MAX_TOTAL_BYTES, "PREVIEW004")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
        seq = event.get("sequence")
        _require(type(seq) is int and seq > sequence, "PREVIEW004")
        assert isinstance(seq, int)
        sequence = seq
        stamp = event.get("timestamp")
        _require(type(stamp) is int and start_second <= stamp <= end_second, "PREVIEW004")
        kinds = set(event) - {"sequence", "timestamp"}
        _require(len(kinds) == 1 and kinds <= _EVENTS, "PREVIEW004")
        kind = next(iter(kinds))
        body = event[kind]
        _require(type(body) is dict, "PREVIEW004")
        if kind == "diagnosticEvent":
            severity = body.get("severity")
            _require(
                type(severity) is str and severity in {"debug", "info", "info#err", "warning"},
                "PREVIEW004",
            )
        elif kind.startswith("policy") and kind != "policyLoadEvent":
            _require(
                summary is None
                and body.get("policyPackName") == PACK
                and body.get("failed", []) == [],
                "PREVIEW004",
            )
            if kind == "policyAnalyzeSummaryEvent":
                _require(body.get("passed") == [RULE], "PREVIEW004")
                checks += 1
            else:
                _require(body.get("passed", []) == [], "PREVIEW004")
        elif kind == "summaryEvent":
            _require(
                summary is None
                and body.get("maybeCorrupt") is False
                and body.get("isPreview") is True
                and body.get("result") == "succeeded",
                "PREVIEW004",
            )
            _counts(body.get("resourceChanges"))
            packs = body.get("PolicyPacks")
            _require(
                type(packs) is dict
                and set(packs) == {PACK}
                and type(packs[PACK]) is str
                and len(packs[PACK]) <= 128,
                "PREVIEW004",
            )
            try:
                version_digest = hashlib.sha256(packs[PACK].encode()).hexdigest()
            except UnicodeError:
                _reject()
            summary = body
        elif kind == "cancelEvent":
            _require(body == {} and summary is not None, "PREVIEW004")
            terminal = True
    _require(terminal and summary is not None and checks > 0, "PREVIEW004")
    assert summary is not None
    data.update(
        started_at=started_at,
        completed_at=completed_at,
        resource_changes=summary["resourceChanges"],
        event_count=count,
        events_sha256=digest.hexdigest(),
        policy={
            "pack": PACK,
            "source_sha256": data["inputs"]["policy"],
            "version_sha256": version_digest,
            "passed_checks": checks,
            "violations": 0,
        },
    )
    encoded = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()
    validate_preview_result(encoded, contract, artifacts, now=now)
    return encoded
