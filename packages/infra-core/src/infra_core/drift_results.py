"""Pure bounded drift evidence: unknown never means clean or remediation authority."""

import hashlib
import json
from datetime import timedelta
from typing import Any

from infra_core import backup, operations
from infra_core.preview_results import _EVENTS, MAX_EVENT_BYTES, MAX_EVENTS, OPERATIONS, PACK, RULE

UNITS = {"oci-network", "oci-oke", "cloudflare-edge", "supabase-database"}
MESSAGE = "DRIFT001: isolated observation rejected; diagnostics withheld"
ERRORS = {
    "observation_failed",
    "inputs_changed",
    "source_changed",
    "source_unavailable",
    "local_state_changed",
}


def require(value: bool) -> None:
    if not value:
        raise ValueError(MESSAGE)


def parse(raw: bytes) -> dict[str, Any]:
    require(type(raw) is bytes and 0 < len(raw) <= operations.MAX_BYTES)
    value = json.loads(raw, object_pairs_hook=operations._pairs)
    json.dumps(value, allow_nan=False)
    require(type(value) is dict)
    assert isinstance(value, dict)
    return value


def plan(unit: str) -> bytes:
    require(unit in UNITS)
    return operations.encoded(
        dict(
            schema_version=1,
            operation="isolated-drift",
            unit=unit,
            refresh="preview-only-run-program",
            compare="policy-preview",
            remediation=False,
        )
    )


def checkpoint(
    raw: bytes, unit: str, expected: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    require(unit in UNITS)
    state = parse(raw)
    require(type(state["version"]) is int and state["version"] == 3)
    deployment = state["deployment"]
    require(not deployment.get("pending_operations"))
    crypto = deployment["secrets_providers"]
    require(
        crypto["type"] == "passphrase"
        and type(crypto["state"]["salt"]) is str
        and bool(crypto["state"]["salt"])
    )
    backup._encrypted(state)
    resources = deployment["resources"]
    require(type(resources) is list and len(resources) == len(expected))
    indexed = {r["urn"]: r for r in resources}
    require(len(indexed) == len(resources) and set(indexed) == set(expected))
    prefix = f"urn:pulumi:{unit}::free-infrastructure::"
    for urn, spec in expected.items():
        record = indexed[urn]
        require(
            urn.startswith(prefix) and record["type"] == spec["type"] and not record.get("delete")
        )
        require(
            record.get("parent", "")
            in (
                {spec["parent"], ""}
                if spec["parent"].endswith("free-infrastructure-" + unit)
                else {spec["parent"]}
            )
        )
        if spec["protect"]:
            require(record.get("protect") is True)
        if spec["provider"]:
            provider = indexed[spec["provider"]]
            require(
                type(provider.get("id")) is str
                and bool(provider["id"])
                and record.get("provider") == spec["provider"] + "::" + provider["id"]
            )
        if record["type"].startswith(("oci:", "cloudflare:", "supabase:")):
            require(type(record.get("id")) is str and bool(record["id"]))
    return indexed


def summarize(records: list[bytes], *, refresh: bool, policy: str) -> dict[str, Any]:
    require(0 < len(records) <= MAX_EVENTS)
    previous, terminal, passed = -1, False, 0
    summary = None
    total = 0
    for raw in records:
        require(len(raw) <= MAX_EVENT_BYTES)
        total += len(raw)
        require(total <= 4 * operations.MAX_BYTES)
        event = parse(raw)
        require(not terminal and type(event["sequence"]) is int and event["sequence"] > previous)
        previous = event["sequence"]
        kinds = set(event) - {"sequence", "timestamp"}
        require(len(kinds) == 1 and kinds <= _EVENTS)
        kind = next(iter(kinds))
        body = event[kind]
        require(type(body) is dict)
        if kind == "diagnosticEvent":
            require(body.get("severity") in {"debug", "info", "info#err", "warning"})
        elif kind.startswith("policy") and kind != "policyLoadEvent":
            require(
                not refresh and body.get("policyPackName") == PACK and body.get("failed", []) == []
            )
            if kind == "policyAnalyzeSummaryEvent":
                require(body.get("passed") == [RULE])
                passed += 1
        elif kind == "summaryEvent":
            require(
                summary is None
                and body.get("isPreview") is True
                and body.get("result") == "succeeded"
                and body.get("maybeCorrupt") is False
            )
            packs = body["PolicyPacks"]
            require(
                type(packs) is dict
                and set(packs) == (set() if refresh else {PACK + "|local|" + policy})
            )
            require(all(type(v) is str and 0 < len(v) <= 128 for v in packs.values()))
            counts = body["resourceChanges"]
            require(
                type(counts) is dict
                and bool(counts)
                and set(counts) <= OPERATIONS
                and all(type(v) is int and 0 <= v <= MAX_EVENTS for v in counts.values())
                and 0 < sum(counts.values()) <= MAX_EVENTS
            )
            summary = counts
        elif kind == "cancelEvent":
            require(summary is not None and body == {})
            terminal = True
    require(terminal and summary is not None and (refresh or passed > 0))
    return dict(
        resource_changes=summary,
        events_sha256=hashlib.sha256(b"\n".join(records)).hexdigest(),
        event_count=len(records),
        policy_checks=passed,
    )


def result(
    *,
    request: dict[str, Any],
    started_at: str,
    completed_at: str,
    source_unchanged: bool | None,
    local_unchanged: bool | None,
    refresh: dict[str, Any] | None,
    comparison: dict[str, Any] | None,
    error: str | None,
) -> dict[str, Any]:
    value = operations.request(request)
    require(value["operation"] == "monitor")
    start, end = operations._time(started_at), operations._time(completed_at)
    require(
        timedelta(0) <= end - start and (error is not None or end - start <= timedelta(seconds=305))
    )
    require(type(source_unchanged) is bool or source_unchanged is None)
    require(type(local_unchanged) is bool or local_unchanged is None)
    require(error is None or error in ERRORS)
    for stage in (refresh, comparison):
        if stage is not None:
            require(
                type(stage) is dict
                and set(stage)
                == {"resource_changes", "events_sha256", "event_count", "policy_checks"}
            )
            counts = stage["resource_changes"]
            require(
                type(counts) is dict
                and bool(counts)
                and set(counts) <= OPERATIONS
                and all(type(v) is int and 0 <= v <= MAX_EVENTS for v in counts.values())
                and 0 < sum(counts.values()) <= MAX_EVENTS
            )
            require(
                operations._hash(stage["events_sha256"])
                and type(stage["event_count"]) is int
                and 2 <= stage["event_count"] <= MAX_EVENTS
                and type(stage["policy_checks"]) is int
                and stage["policy_checks"] >= 0
            )
    if comparison is not None:
        require(comparison["policy_checks"] > 0)
    complete = (
        error is None
        and source_unchanged is True
        and local_unchanged is True
        and refresh is not None
        and comparison is not None
    )
    status = "unknown"
    if complete:
        assert refresh is not None and comparison is not None
        changed = any(
            v > 0 and k not in {"same", "read"}
            for stage in (refresh, comparison)
            for k, v in stage["resource_changes"].items()
        )
        status = "drifted" if changed else "clean"
    else:
        require(error is not None)
    return dict(
        schema_version=1,
        kind="isolated-drift",
        operation_id=value["operation_id"],
        unit=value["unit"],
        commit=value["commit"],
        checkpoint_sha256=value["checkpoint_sha256"],
        configuration_sha256=value["configuration_sha256"],
        started_at=started_at,
        completed_at=completed_at,
        status=status,
        source_unchanged=source_unchanged,
        local_checkpoint_unchanged=local_unchanged,
        refresh=refresh,
        comparison=comparison,
        error_code=error,
        remediation_authorized=False,
        production_state_write_authorized=False,
    )
