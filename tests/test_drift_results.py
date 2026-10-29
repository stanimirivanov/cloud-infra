"""Bounded observations never infer health from missing or failed provider reads."""

import json
from copy import deepcopy

import pytest
from infra_core import drift_results as d
from infra_core import operations

NOW = "2026-10-29T00:00:00+00:00"
REQUEST = dict(
    schema_version=1,
    operation_id="12345678-1234-4234-8234-123456789abc",
    operation="monitor",
    unit="cloudflare-edge",
    commit="a" * 40,
    configuration_sha256="b" * 64,
    checkpoint_sha256="c" * 64,
    expires_at="2026-10-29T00:05:00+00:00",
    expected_predecessor=None,
)


def events(refresh=True, changes=None):
    values = (
        []
        if refresh
        else [
            dict(policyAnalyzeSummaryEvent=dict(policyPackName=d.PACK, passed=[d.RULE], failed=[]))
        ]
    )
    values += [
        dict(
            summaryEvent=dict(
                isPreview=True,
                result="succeeded",
                maybeCorrupt=False,
                resourceChanges=changes or {"same": 2},
                PolicyPacks={} if refresh else {d.PACK + "|local|/policy": "0.0.1"},
            )
        ),
        dict(cancelEvent={}),
    ]
    return [operations.encoded(dict(sequence=i, timestamp=1, **v)) for i, v in enumerate(values)]


def observation(**kw):
    args = dict(
        request=REQUEST,
        started_at=NOW,
        completed_at=NOW,
        source_unchanged=True,
        local_unchanged=True,
        refresh=d.summarize(events(), refresh=True, policy="/policy"),
        comparison=d.summarize(events(False), refresh=False, policy="/policy"),
        error=None,
    )
    args.update(kw)
    return d.result(**args)


@pytest.mark.parametrize("stage", ["refresh", "comparison"])
@pytest.mark.parametrize("change", sorted(d.OPERATIONS - {"same", "read"}))
def test_live_and_configuration_differences_are_drift(stage, change):
    sample = d.summarize(
        events(stage == "refresh", {change: 1}), refresh=stage == "refresh", policy="/policy"
    )
    assert observation(**{stage: sample})["status"] == "drifted"


def test_complete_unchanged_observation_is_clean_without_authority():
    value = observation()
    assert value["status"] == "clean"
    assert value["remediation_authorized"] is value["production_state_write_authorized"] is False
    assert value["checkpoint_sha256"] == REQUEST["checkpoint_sha256"]


@pytest.mark.parametrize("error", sorted(d.ERRORS))
@pytest.mark.parametrize("field", ["source_unchanged", "local_unchanged", "refresh", "comparison"])
def test_incomplete_observation_is_unknown(field, error):
    assert observation(**{field: None, "error": error})["status"] == "unknown"
    with pytest.raises(ValueError):
        observation(**{field: None})


@pytest.mark.parametrize(
    "fault",
    [
        "truncated",
        "error",
        "update",
        "duplicate",
        "reordered",
        "extra",
        "policy",
        "failed-policy",
        "corrupt",
        "operation",
        "bool-count",
        "empty",
        "huge",
        "nan",
        "late-event",
    ],
)
@pytest.mark.parametrize("refresh", [True, False])
def test_untrusted_event_stream_cannot_be_clean(fault, refresh):
    raw = events(refresh)
    parsed = [json.loads(v) for v in raw]
    summary = next(v["summaryEvent"] for v in parsed if "summaryEvent" in v)
    if fault == "truncated":
        parsed.pop()
    elif fault == "error":
        parsed.insert(
            0, dict(sequence=-1, diagnosticEvent=dict(severity="error", message="PRIVATE"))
        )
    elif fault == "update":
        summary["isPreview"] = False
    elif fault == "duplicate":
        parsed.insert(-1, deepcopy(parsed[-2]))
    elif fault == "reordered":
        parsed[-1]["sequence"] = -1
    elif fault == "extra":
        parsed[0]["newEvent"] = {}
    elif fault == "policy":
        summary["PolicyPacks"] = {"foreign": "1"}
    elif fault == "failed-policy":
        parsed.insert(
            0,
            dict(
                sequence=-1,
                policyAnalyzeSummaryEvent=dict(
                    policyPackName=d.PACK, passed=[d.RULE], failed=[d.RULE]
                ),
            ),
        )
    elif fault == "corrupt":
        summary["maybeCorrupt"] = True
    elif fault == "operation":
        summary["resourceChanges"] = {"import": 1}
    elif fault == "bool-count":
        summary["resourceChanges"] = {"same": True}
    elif fault == "empty":
        summary["resourceChanges"] = {}
    elif fault == "huge":
        summary["private"] = "x" * d.MAX_EVENT_BYTES
    elif fault == "nan":
        raw[0] = b'{"sequence":0,"timestamp":NaN,"cancelEvent":{}}'
    elif fault == "late-event":
        parsed.append(dict(sequence=99, stdoutEvent={}))
    if fault != "nan":
        raw = [operations.encoded(v) for v in parsed]
    with pytest.raises((ValueError, KeyError)):
        d.summarize(raw, refresh=refresh, policy="/policy")


def test_raw_properties_are_not_in_report_and_duplicate_keys_rejected():
    raw = events()
    raw.insert(
        0,
        operations.encoded(
            dict(
                sequence=-1,
                resOutputsEvent=dict(metadata=dict(new=dict(outputs=dict(token="PRIVATE")))),
            )
        ),
    )
    raw = [operations.encoded(dict(json.loads(v), sequence=i)) for i, v in enumerate(raw)]
    result = d.summarize(raw, refresh=True, policy="/policy")
    assert b"PRIVATE" not in operations.encoded(result)
    with pytest.raises(ValueError):
        d.parse(b'{"a":1,"a":2}')


def test_elapsed_time_and_action_are_bounded():
    with pytest.raises(ValueError):
        observation(completed_at="2026-10-29T00:06:00+00:00")
    with pytest.raises(ValueError):
        observation(request=dict(REQUEST, operation="apply"))
    assert (
        observation(completed_at="2026-10-29T00:06:00+00:00", error="observation_failed")["status"]
        == "unknown"
    )
