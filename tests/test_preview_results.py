"""Synthetic wire receipts: fail closed, bind exact inputs and retain no raw diagnostics."""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from infra_core.foundation import load_foundation
from infra_core.preview_contracts import describe_preview
from infra_core.preview_results import (
    MAX_EVENT_BYTES,
    MAX_EVENTS,
    PACK,
    RULE,
    create_preview_result,
    validate_preview_result,
)
from preview_graph_helpers import service_events

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 28, 12, tzinfo=UTC)


def wire(kind, body, sequence):
    return json.dumps(
        {"sequence": sequence, "timestamp": int(NOW.timestamp()), kind: body}
    ).encode()


@pytest.fixture(params=["cloudflare-edge", "supabase-database", "oci-network", "oci-oke"])
def inputs(request):
    foundation = load_foundation(ROOT)
    foundation = replace(
        foundation, units=tuple(replace(u, preview_enabled=True) for u in foundation.units)
    )
    contract = describe_preview(foundation, request.param, "a" * 40)
    names = {
        "proposal",
        "profile",
        "evidence",
        "envelope",
        "toolchain",
        "provider_toolchain",
        "policy",
    }
    if request.param.startswith("oci-"):
        names.add("account")
    if request.param == "oci-oke":
        names.add("dependency_outputs")
    artifacts = {name: ("synthetic " + name).encode() for name in names}
    graph_events = []
    if not request.param.startswith("oci-"):
        provider = "cloudflare" if request.param == "cloudflare-edge" else "supabase"
        configuration = json.loads((ROOT / f"config/{provider}.example.json").read_text())
        artifacts["proposal"] = json.dumps(
            {"configuration": configuration, "stack_configuration": {}}
        ).encode()
        artifacts["provider_toolchain"] = (ROOT / "config/provider-toolchain.json").read_bytes()
        graph_events = service_events(configuration)
    summary = {
        "maybeCorrupt": False,
        "isPreview": True,
        "result": "succeeded",
        "durationSeconds": 1,
        "resourceChanges": {"same": 1, "create": 2},
        "PolicyPacks": {PACK: "local"},
    }
    events = [
        wire("policyAnalyzeSummaryEvent", {"policyPackName": PACK, "passed": [RULE]}, 0),
        wire("summaryEvent", summary, 1),
        wire("cancelEvent", {}, 2),
    ]
    records = graph_events + [
        (
            next(k for k in json.loads(raw) if k.endswith("Event")),
            next(v for k, v in json.loads(raw).items() if k.endswith("Event")),
        )
        for raw in events
    ]
    events = [wire(kind, body, n) for n, (kind, body) in enumerate(records)]
    return contract, artifacts, events


def create(inputs, **changes):
    contract, artifacts, events = inputs
    args = dict(exit_code=0, started_at=NOW.isoformat(), completed_at=NOW.isoformat(), now=NOW)
    args.update(changes)
    return create_preview_result(contract, artifacts, events, **args)


def test_canonical_roundtrip_exact_bindings_and_no_authority(inputs):
    contract, artifacts, _ = inputs
    encoded = create(inputs)
    assert encoded == create(inputs)
    result = validate_preview_result(encoded, contract, artifacts, now=NOW)
    assert result["policy"]["passed_checks"] == 1
    assert result["policy"]["source_sha256"] == result["inputs"]["policy"]
    assert result["deployment_authorized"] is False and result["cutover_authorized"] is False
    for name in artifacts:
        with pytest.raises(ValueError, match="PREVIEW003"):
            validate_preview_result(
                encoded, contract, dict(artifacts, **{name: b"changed"}), now=NOW
            )
    with pytest.raises(ValueError, match="PREVIEW003"):
        validate_preview_result(encoded, replace(contract, commit_sha="b" * 40), artifacts, now=NOW)


@pytest.mark.parametrize(
    "fault",
    (
        "exit no-policy no-summary duplicate-summary no-terminal after-terminal sequence "
        "sequence-bool unknown violation resource-failure diagnostic malformed-diagnostic "
        "failed-analysis wrong-pack old-clock malformed-clock "
        "update canceled corrupt sdk-summary empty-counts bad-count unknown-op missing-pack "
        "duplicate-json invalid-json oversize too-many"
    ).split(),
)
def test_incomplete_or_failed_observations_never_produce_success(inputs, fault):
    contract, artifacts, original = inputs
    events = list(original)
    if fault == "exit":
        with pytest.raises(ValueError, match="PREVIEW004"):
            create(inputs, exit_code=1)
        return
    if fault in {"no-policy", "no-summary", "no-terminal"}:
        del events[{"no-policy": -3, "no-summary": -2, "no-terminal": -1}[fault]]
    elif fault == "duplicate-summary":
        events.insert(2, wire("summaryEvent", json.loads(events[-2])["summaryEvent"], 2))
    elif fault == "after-terminal":
        events.append(wire("stdoutEvent", {"message": "private-message"}, 3))
    elif fault in {"old-clock", "malformed-clock"}:
        data = json.loads(events[0])
        data["timestamp"] = 1 if fault == "old-clock" else True
        events[0] = json.dumps(data).encode()
    elif fault in {"sequence", "sequence-bool"}:
        data = json.loads(events[-2])
        data["sequence"] = 0 if fault == "sequence" else True
        events[-2] = json.dumps(data).encode()
    elif fault in {
        "unknown",
        "violation",
        "resource-failure",
        "diagnostic",
        "malformed-diagnostic",
    }:
        kind = {
            "unknown": "futureEvent",
            "violation": "policyEvent",
            "resource-failure": "resOpFailedEvent",
            "diagnostic": "diagnosticEvent",
            "malformed-diagnostic": "diagnosticEvent",
        }[fault]
        events[0] = wire(
            kind,
            {
                "message": "private-message",
                "severity": [] if fault == "malformed-diagnostic" else "error",
            },
            0,
        )
    elif fault == "failed-analysis":
        events[0] = wire(
            "policyAnalyzeSummaryEvent",
            {"policyPackName": PACK, "passed": [RULE], "failed": [RULE]},
            0,
        )
    elif fault in {"duplicate-json", "invalid-json", "oversize", "too-many"}:
        bad = {
            "duplicate-json": b'{"sequence":0,"sequence":1}',
            "invalid-json": b"private-message",
            "oversize": b"x" * (MAX_EVENT_BYTES + 1),
        }
        events = (
            [wire("stdoutEvent", {}, n) for n in range(MAX_EVENTS + 1)]
            if fault == "too-many"
            else [bad[fault]]
        )
    else:
        summary = json.loads(events[-2])["summaryEvent"]
        changes = {
            "wrong-pack": ("PolicyPacks", {"other": "local"}),
            "update": ("isPreview", False),
            "canceled": ("result", "canceled"),
            "corrupt": ("maybeCorrupt", True),
            "sdk-summary": ("isPreview", None),
            "empty-counts": ("resourceChanges", {}),
            "bad-count": ("resourceChanges", {"create": True}),
            "unknown-op": ("resourceChanges", {"import": 1}),
            "missing-pack": ("PolicyPacks", None),
        }
        key, value = changes[fault]
        if value is None:
            del summary[key]
        else:
            summary[key] = value
        events[-2] = wire("summaryEvent", summary, len(events) - 2)
    with pytest.raises(ValueError, match="PREVIEW00") as error:
        create((contract, artifacts, events))
    assert "private-message" not in str(error.value)


def test_raw_messages_properties_and_versions_are_not_serialized(inputs):
    contract, artifacts, events = inputs
    private = "synthetic-private-content"
    events = [
        wire("stdoutEvent", {"message": private}, 0),
    ] + [
        wire(
            next(k for k in json.loads(raw) if k.endswith("Event")),
            next(v for k, v in json.loads(raw).items() if k.endswith("Event")),
            n + 1,
        )
        for n, raw in enumerate(events)
    ]
    if not contract.unit.startswith("oci-"):
        event = json.loads(events[1])
        event["resourcePreEvent"]["metadata"]["new"]["outputs"] = {"token": private}
        events[1] = json.dumps(event).encode()
    encoded = create((contract, artifacts, events))
    assert private.encode() not in encoded and b'"local"' not in encoded


@pytest.mark.parametrize(
    "field,value",
    [
        ("deployment_authorized", True),
        ("schema_version", True),
        ("cutover_authorized", True),
        ("operation", "update"),
        ("event_count", True),
        ("events_sha256", "invalid"),
        ("extra", "private-message"),
    ],
)
def test_result_tampering_is_rejected(inputs, field, value):
    contract, artifacts, _ = inputs
    result = json.loads(create(inputs))
    result[field] = value
    with pytest.raises(ValueError, match="PREVIEW003"):
        validate_preview_result(json.dumps(result).encode(), contract, artifacts, now=NOW)


def test_clocks_disabled_contract_and_missing_bindings_fail(inputs):
    contract, artifacts, events = inputs
    for changes in (
        {"now": NOW - timedelta(seconds=1)},
        {"now": NOW + timedelta(minutes=16)},
        {"started_at": NOW.replace(tzinfo=None).isoformat()},
        {"started_at": (NOW - timedelta(minutes=16)).isoformat()},
    ):
        with pytest.raises(ValueError, match="PREVIEW003"):
            create(inputs, **changes)
    for bad in (
        dict(artifacts, unexpected=b"bytes"),
        {k: v for k, v in artifacts.items() if k != "policy"},
    ):
        with pytest.raises(ValueError, match="PREVIEW003"):
            create((contract, bad, events))
    with pytest.raises(ValueError, match="PREVIEW003"):
        create((replace(contract, preview_enabled=False), artifacts, events))


def test_aggregate_stream_budget_stops_consumption(inputs, monkeypatch):
    import infra_core.preview_results as results

    monkeypatch.setattr(results, "MAX_TOTAL_BYTES", 4096)
    contract, artifacts, _ = inputs
    consumed = []

    def events():
        for n in range(100):
            consumed.append(n)
            yield wire("stdoutEvent", {"message": "x" * 1000}, n)

    with pytest.raises(ValueError, match="PREVIEW004"):
        create((contract, artifacts, events()))
    assert len(consumed) < 10


@pytest.mark.parametrize("inputs", ["cloudflare-edge", "supabase-database"], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        "missing-child",
        "missing-provider",
        "missing-output",
        "duplicate",
        "extra-resource",
        "wrong-type",
        "wrong-parent",
        "wrong-provider",
        "provider-id",
        "external",
        "wrong-protect",
        "wrong-custom",
        "changed-input",
        "missing-input",
        "unknown-input",
        "extra-input",
        "array-inputs",
        "bool-input",
        "plaintext-secret",
        "endpoint",
        "version",
        "new-urn",
        "pending-delete",
        "init-error",
        "unknown-state",
        "late-substitution",
        "replace",
        "metadata-provider",
    ],
)
def test_service_graph_mismatches_fail_without_private_diagnostics(inputs, fault):
    contract, artifacts, raw = inputs
    events = [json.loads(record) for record in raw]
    child = events[6]["resourcePreEvent"]["metadata"]
    provider = events[4]["resourcePreEvent"]["metadata"]
    if fault == "missing-child":
        del events[6:8]
    elif fault == "missing-provider":
        del events[4:6]
    elif fault == "missing-output":
        del events[7]
    elif fault == "duplicate":
        events.insert(7, json.loads(json.dumps(events[6])))
    elif fault == "extra-resource":
        child["urn"] += "-extra"
    elif fault in {"wrong-type", "wrong-parent", "wrong-provider", "wrong-protect", "wrong-custom"}:
        field = fault.removeprefix("wrong-")
        child["new"][field] = False if field in {"protect", "custom"} else "private-substitution"
    elif fault in {"changed-input", "missing-input", "unknown-input", "extra-input", "bool-input"}:
        props = child["new"]["inputs"]
        field = "ttl" if contract.unit == "cloudflare-edge" else "legacyApiKeysEnabled"
        if fault == "missing-input":
            del props[field]
        elif fault == "extra-input":
            props["paidAddon"] = "private-substitution"
        else:
            props[field] = {
                "changed-input": "private-substitution",
                "unknown-input": "04da6b54-80e4-46f7-96ec-b56ff0331ba9",
                "bool-input": True if field == "ttl" else 0,
            }[fault]
    elif fault == "array-inputs":
        child["new"]["inputs"] = list(child["new"]["inputs"].items())
    elif fault == "plaintext-secret":
        token = "apiToken" if contract.unit == "cloudflare-edge" else "accessToken"
        provider["new"]["inputs"][token] = "private-substitution"
    elif fault == "endpoint":
        field = "baseUrl" if contract.unit == "cloudflare-edge" else "endpoint"
        provider["new"]["inputs"][field] = "private-substitution"
    elif fault == "version":
        provider["new"]["inputs"]["version"] = "unreviewed"
    elif fault == "provider-id":
        child["new"]["provider"] = child["provider"] = (
            child["provider"].rsplit("::", 1)[0] + "::other-id"
        )
    elif fault == "external":
        child["new"]["external"] = True
    elif fault == "new-urn":
        child["new"]["urn"] += "-other"
    elif fault == "pending-delete":
        child["new"]["delete"] = True
    elif fault == "init-error":
        child["new"]["initErrors"] = ["private-substitution"]
    elif fault == "unknown-state":
        child["new"] = None
    elif fault == "late-substitution":
        events[7]["resOutputsEvent"]["metadata"]["new"]["inputs"]["name"] = "private-substitution"
    elif fault == "replace":
        child["op"] = "replace"
    else:
        child["provider"] = "other"
    for n, event in enumerate(events):
        event["sequence"] = n
    with pytest.raises(ValueError, match="PREVIEW009") as error:
        create((contract, artifacts, [json.dumps(event).encode() for event in events]))
    assert "private-substitution" not in str(error.value)


@pytest.mark.parametrize("inputs", ["cloudflare-edge", "supabase-database"], indirect=True)
def test_two_child_graph_stamp_and_legacy_receipt_rejection(inputs):
    contract, artifacts, raw = inputs
    proposal = json.loads(artifacts["proposal"])
    second = json.loads(json.dumps(proposal["configuration"]["resources"][0]))
    second["key"] = "second"
    second["props"]["name"] = (
        "second.example.com" if contract.unit == "cloudflare-edge" else "second-db"
    )
    proposal["configuration"]["resources"].append(second)
    artifacts["proposal"] = json.dumps(proposal).encode()
    bodies = service_events(proposal["configuration"]) + [
        (
            next(k for k in json.loads(record) if k.endswith("Event")),
            next(v for k, v in json.loads(record).items() if k.endswith("Event")),
        )
        for record in raw[-3:]
    ]
    receipt = json.loads(
        create((contract, artifacts, [wire(k, v, n) for n, (k, v) in enumerate(bodies)]))
    )
    assert receipt["schema_version"] == 2
    assert receipt["service_graph"]["resource_count"] == 5
    assert len(receipt["service_graph"]["sha256"]) == 64
    for fault in ("schema", "digest", "count"):
        changed = json.loads(json.dumps(receipt))
        if fault == "schema":
            changed["schema_version"] = 1
        elif fault == "digest":
            changed["service_graph"]["sha256"] = "0" * 64
        else:
            changed["service_graph"]["resource_count"] = 4
        with pytest.raises(ValueError, match="PREVIEW003"):
            validate_preview_result(json.dumps(changed).encode(), contract, artifacts, now=NOW)
