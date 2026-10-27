"""Management observations cannot manufacture usage, database samples or membership."""

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import test_services as fixtures
from infra_core import service_evidence as se
from infra_core.governance.contracts import GovernanceError
from infra_core.inventory import supabase as sb
from infra_core.provider_evidence import record_observation

ACCOUNT, ORG, PROJECT, COMMIT = "synthetic-account", "example-org", "a" * 20, "b" * 40
PATH = f"/v1/organizations/{ORG}/projects?offset=0&limit=100"


def projects(items, count=None, offset=0):
    return {
        "projects": items,
        "pagination": {
            "count": len(items) if count is None else count,
            "limit": 100,
            "offset": offset,
        },
    }


@pytest.fixture
def network(monkeypatch):
    state = SimpleNamespace(
        calls=[],
        denied=None,
        age=timedelta(0),
        replies={
            "/v1/profile": {"gotrue_id": ACCOUNT, "primary_email": "private@example.com"},
            "/v1/organizations": [
                {"id": "org-id", "slug": ORG},
                {"id": "paid-id", "slug": "paid-org"},
            ],
            f"/v1/organizations/{ORG}": {"id": "org-id", "plan": "free"},
            "/v1/organizations/paid-org": {"id": "paid-id", "plan": "pro"},
            f"/v1/organizations/{ORG}/entitlements": {
                "entitlements": [{"feature": {"key": "project_pausing"}, "hasAccess": True}]
            },
            PATH: projects(
                [
                    {
                        "ref": PROJECT,
                        "status": "INACTIVE",
                        "is_branch": False,
                        "databases": [{"disk_volume_size_gb": 99}],
                    }
                ]
            ),
        },
    )

    def get(provider, target, *, token):
        assert provider == "supabase" and token == "synthetic-token"
        state.calls.append(target)
        if state.denied == target:
            raise PermissionError("private-token")
        reply = state.replies[target]
        body = reply if isinstance(reply, bytes) else json.dumps(reply).encode()
        clock = datetime.now(UTC) - state.age
        return record_observation(provider, target.encode(), body, started=clock, finished=clock)

    monkeypatch.setattr(sb, "observe_get", get)
    return state


def collect():
    return sb.collect_management(ACCOUNT, (ORG, "paid-org"), token="synthetic-token")


@pytest.fixture
def supplement():
    config, data, profile = fixtures.service.__wrapped__(SimpleNamespace(param="supabase"))
    data["resources"] = [{"id": PROJECT, "scope_id": ORG, "database_mb": "100"}]
    wrapper = {
        "schema_version": 1,
        "classification": "supplemental-operator-observations",
        "evidence": data,
        "database_observations": [
            {
                "id": PROJECT,
                "scope_id": ORG,
                "as_of": data["collection_started_at"],
                "source": "synthetic DB observation",
            }
        ],
    }
    return config, profile, wrapper


def capture(collection, supplement):
    config, profile, wrapper = supplement
    return se.capture_supabase_evidence(
        config, profile, collection, json.dumps(wrapper).encode(), commit=COMMIT
    )


def test_paused_project_and_supplement_round_trip_existing_evidence(network, supplement):
    collection = collect()
    before = deepcopy(supplement)
    payload, envelope = capture(collection, supplement)
    data = json.loads(payload)
    assert len(collection.projects) == 1 and collection.free_organizations == (ORG,)
    assert data["resources"][0]["database_mb"] == "100"  # Never derive from provisioned disk GB.
    assert data["usage"] == supplement[2]["evidence"]["usage"]
    assert data["verified_at"] == supplement[2]["evidence"]["verified_at"]
    assert "supplemental-operator-observations sha256=" in data["source"]
    assert b"private@example.com" not in payload and supplement == before
    assert (
        se.validate_service_evidence(*supplement[:2], payload, envelope, commit=COMMIT)[
            "deployment_authorized"
        ]
        is False
    )
    assert not any("paid-org/projects" in target for target in network.calls)


@pytest.mark.parametrize(
    "change", ["user", "missing-org", "duplicate-org", "unknown-plan", "entitlements"]
)
def test_scope_and_entitlement_gaps_fail_closed(network, change):
    if change == "user":
        network.replies["/v1/profile"]["gotrue_id"] = "other"
    elif change == "missing-org":
        network.replies["/v1/organizations"].pop()
    elif change == "duplicate-org":
        network.replies["/v1/organizations"][1] = network.replies["/v1/organizations"][0]
    elif change == "unknown-plan":
        network.replies[f"/v1/organizations/{ORG}"].pop("plan")
    else:
        network.replies[f"/v1/organizations/{ORG}/entitlements"] = {}
    with pytest.raises(GovernanceError):
        collect()


@pytest.mark.parametrize("fault", [None, "total", "offset", "duplicate"])
def test_unfiltered_offset_pagination_and_changed_or_duplicate_pages(network, fault):
    network.replies[PATH] = projects(
        [{"ref": f"{i:020d}", "is_branch": False} for i in range(100)], 101
    )
    last = projects([{"ref": "z" * 20, "is_branch": False}], 101, 100)
    if fault == "total":
        last["pagination"]["count"] = 102
    if fault == "offset":
        last["pagination"]["offset"] = 0
    if fault == "duplicate":
        last["projects"][0]["ref"] = "0" * 20
    network.replies[f"/v1/organizations/{ORG}/projects?offset=100&limit=100"] = last
    if fault:
        with pytest.raises(GovernanceError):
            collect()
    else:
        assert len(collect().projects) == 101
    assert all("search=" not in path and "statuses=" not in path for path in network.calls)


@pytest.mark.parametrize("bound", ["MAX_CALLS", "MAX_BYTES", "MAX_PROJECTS"])
def test_collection_budgets_fail_without_partial_results(network, monkeypatch, bound):
    monkeypatch.setattr(sb, bound, 0)
    with pytest.raises(GovernanceError):
        collect()


def test_denied_or_stale_observations_do_not_create_evidence(network):
    network.denied = PATH
    with pytest.raises(GovernanceError, match="raw details withheld") as error:
        collect()
    assert "private-token" not in str(error.value)
    network.denied, network.age = None, timedelta(minutes=16)
    with pytest.raises(GovernanceError, match="clocks"):
        collect()


@pytest.mark.parametrize(
    "fault",
    [
        "classification",
        "metric",
        "coverage",
        "storage-float",
        "sample",
        "sample-clock",
        "project",
        "review",
    ],
)
def test_supplements_cannot_hide_unknown_data_or_restamp_sources(network, supplement, fault):
    wrapper = supplement[2]
    if fault == "classification":
        wrapper["classification"] = "automated-billing-proof"
    elif fault == "metric":
        wrapper["evidence"]["usage"].pop("mau")
    elif fault == "coverage":
        wrapper["evidence"]["usage"]["egress_mb"]["covered_through"] = "1970-01-01T00:00:00+00:00"
    elif fault == "storage-float":
        wrapper["evidence"]["usage"]["storage_gb_hours"]["value"] = 0.1
    elif fault == "sample":
        wrapper["database_observations"] = []
    elif fault == "sample-clock":
        wrapper["database_observations"][0]["as_of"] = "1970-01-01T00:00:00+00:00"
    elif fault == "project":
        wrapper["evidence"]["resources"] = []
    else:
        wrapper["evidence"]["verified"] = False
    with pytest.raises(GovernanceError):
        capture(collect(), supplement)


def test_target_must_remain_observed_free(network, supplement):
    with pytest.raises(GovernanceError):
        capture(replace(collect(), free_organizations=()), supplement)


def test_free_projects_outside_target_org_cannot_be_omitted(network, supplement):
    network.replies["/v1/organizations/paid-org"]["plan"] = "free"
    network.replies["/v1/organizations/paid-org/entitlements"] = network.replies[
        f"/v1/organizations/{ORG}/entitlements"
    ]
    network.replies["/v1/organizations/paid-org/projects?offset=0&limit=100"] = projects(
        [{"ref": "z" * 20, "is_branch": False}]
    )
    collection = collect()
    assert len(collection.projects) == 2
    with pytest.raises(GovernanceError, match="every observed Free project"):
        capture(collection, supplement)
