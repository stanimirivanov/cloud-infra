"""Closed saved-plan graph and event verdicts for the service operation runtime."""

import json
from pathlib import Path

import pytest
from infra_program import operation_runtime as runtime

ROOT = Path(__file__).resolve().parents[1]


def plan(unit="cloudflare-edge", full=False):
    prefix = f"urn:pulumi:{unit}::free-infrastructure::"
    goals = {
        prefix + "pulumi:pulumi:Stack::root": dict(
            steps=["same"],
            goal=dict(
                type="pulumi:pulumi:Stack", name="free-infrastructure-" + unit, protect=False
            ),
        )
    }
    if full:
        component = prefix + "infrastructure:services:Independent::" + unit
        kind = "cloudflare" if unit == "cloudflare-edge" else "supabase"
        provider = (
            prefix
            + "infrastructure:services:Independent$pulumi:providers:"
            + kind
            + "::"
            + unit
            + "-provider"
        )
        resource_type = runtime.DNS if kind == "cloudflare" else runtime.PROJECT
        child = (
            prefix + "infrastructure:services:Independent$" + resource_type + "::" + unit + "-app"
        )
        goals[component] = dict(
            steps=["same"],
            goal=dict(type="infrastructure:services:Independent", name=unit, protect=True),
        )
        goals[provider] = dict(
            steps=["same"],
            goal=dict(
                type="pulumi:providers:" + kind,
                name=unit + "-provider",
                parent=component,
                protect=True,
            ),
        )
        goals[child] = dict(
            steps=["same"],
            goal=dict(
                type=resource_type,
                name=unit + "-app",
                parent=component,
                provider=provider + "::fixture-id",
                protect=True,
            ),
        )
    return dict(manifest={"version": "v3.272.0"}, resourcePlans=goals)


@pytest.mark.parametrize(
    "fault",
    ["delete", "replace", "create-replacement", "wrong-stack", "version", "protect", "type"],
)
def test_unsafe_saved_plan_is_rejected(fault):
    value = plan()
    resource = next(iter(value["resourcePlans"].values()))
    if fault in {"delete", "replace", "create-replacement"}:
        resource["steps"] = [fault]
    elif fault == "wrong-stack":
        value["resourcePlans"] = {"urn:foreign": resource}
    elif fault == "version":
        value["manifest"]["version"] = "v0.0.0"
    elif fault == "protect":
        resource["goal"] = {"type": "infrastructure:services:Independent", "protect": False}
    else:
        resource["goal"]["type"] = "unreviewed:index:Type"
    with pytest.raises(ValueError):
        runtime.validate_plan(
            json.dumps(value).encode(),
            "organization/free-infrastructure/cloudflare-edge",
            "3.272.0",
        )


@pytest.mark.parametrize("preview", [True, False])
@pytest.mark.parametrize("fault", [None, "delete", "mode", "policy", "terminal", "diagnostic"])
def test_event_verdict_requires_complete_non_destructive_policy_success(preview, fault):
    bodies = [
        ("policyAnalyzeSummaryEvent", dict(policyPackName=runtime.PACK, passed=[runtime.RULE])),
        (
            "summaryEvent",
            dict(
                isPreview=preview,
                result="succeeded",
                maybeCorrupt=False,
                resourceChanges={"same": 1},
                PolicyPacks={runtime.PACK + "|local|" + str(ROOT / "policies"): "0.0.1"},
            ),
        ),
        ("cancelEvent", {}),
    ]
    if fault == "delete":
        bodies[1][1]["resourceChanges"] = {"delete": 1}
    elif fault == "mode":
        bodies[1][1]["isPreview"] = not preview
    elif fault == "policy":
        bodies[0][1]["failed"] = ["violation"]
    elif fault == "terminal":
        bodies.pop()
    elif fault == "diagnostic":
        bodies.insert(0, ("diagnosticEvent", {"severity": "error"}))
    records = [
        json.dumps(dict(sequence=i, timestamp=1, **{kind: body})).encode()
        for i, (kind, body) in enumerate(bodies)
    ]
    if fault:
        with pytest.raises(ValueError):
            runtime.validate_events(records, preview=preview, policy=ROOT / "policies")
    else:
        assert runtime.validate_events(records, preview=preview, policy=ROOT / "policies") == {
            "same": 1
        }


@pytest.mark.parametrize("unit", ["cloudflare-edge", "supabase-database"])
@pytest.mark.parametrize("fault", [None, "parent", "provider", "protect"])
def test_parented_provider_urns_are_bound_to_the_approved_graph(unit, fault):
    value = plan(unit, full=True)
    child = list(value["resourcePlans"].values())[-1]["goal"]
    if fault:
        child[fault] = False if fault == "protect" else "foreign"
        with pytest.raises(ValueError):
            runtime.validate_plan(
                json.dumps(value).encode(), "organization/free-infrastructure/" + unit, "3.272.0"
            )
    else:
        runtime.validate_plan(
            json.dumps(value).encode(), "organization/free-infrastructure/" + unit, "3.272.0"
        )
