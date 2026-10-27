"""Cloudflare collection must preserve scope, full record counts and independent review."""

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import test_services as fixtures
from infra_core import service_evidence as se
from infra_core.governance.contracts import GovernanceError
from infra_core.inventory import cloudflare as cf
from infra_core.provider_evidence import record_observation

ACCOUNT, ZONE, COMMIT = "b" * 32, "a" * 32, "c" * 40


def record(index, name="old.example.com", kind="TXT"):
    return {"id": f"{index:032x}", "name": name, "type": kind, "content": "private-record-content"}


def page(items, total=None, number=1):
    total = len(items) if total is None else total
    return {
        "success": True,
        "errors": [],
        "result": items,
        "result_info": {
            "page": number,
            "per_page": 100,
            "count": len(items),
            "total_count": total,
            "total_pages": max(1, (total + 99) // 100),
        },
    }


@pytest.fixture
def network(monkeypatch):
    state = SimpleNamespace(
        calls=[],
        age=timedelta(0),
        replies=[
            {
                "success": True,
                "errors": [],
                "result": {
                    "id": ZONE,
                    "account": {"id": ACCOUNT},
                    "name": "example.com",
                    "status": "active",
                    "plan": {"legacy_id": "free"},
                },
            },
            page(
                [
                    record(1),
                    record(2, "_sip._tcp.example.com", "SRV"),
                    record(3, "*.example.com", "A"),
                ]
            ),
        ],
    )

    def get(provider, target, *, token):
        assert provider == "cloudflare" and token == "synthetic-token"
        state.calls.append(target)
        reply = state.replies.pop(0)
        body = reply if isinstance(reply, bytes) else json.dumps(reply).encode()
        clock = datetime.now(UTC) - state.age
        return record_observation(provider, target.encode(), body, started=clock, finished=clock)

    monkeypatch.setattr(cf, "observe_get", get)
    return state


def collect():
    return cf.collect_zone(ACCOUNT, ZONE, "example.com", token="synthetic-token")


@pytest.fixture
def reviewed():
    config, evidence, profile = fixtures.service.__wrapped__(SimpleNamespace(param="cloudflare"))
    config["account_id"] = evidence["account_id"] = ACCOUNT
    keys = {
        "account_id",
        "scope_id",
        "scope_name",
        "profile_revision",
        "verified",
        "verified_at",
        "plan",
        "other_services_reviewed",
        "source",
    }
    review = {key: evidence[key] for key in keys} | {"schema_version": 1}
    review["verified_at"] = (datetime.now(UTC) - timedelta(days=5)).isoformat()
    return config, profile, review


def test_all_record_types_and_original_clocks_round_trip_existing_envelope(network, reviewed):
    collection = collect()
    config, profile, review = reviewed
    original = deepcopy(reviewed)
    payload, envelope = se.capture_cloudflare_evidence(
        config, profile, collection, review, commit=COMMIT
    )
    report = se.validate_service_evidence(config, profile, payload, envelope, commit=COMMIT)
    data = json.loads(payload)
    assert report["deployment_authorized"] is False and len(data["resources"]) == 3
    assert {r["type"] for r in data["resources"]} == {"TXT", "SRV", "A"}
    assert data["verified_at"] == review["verified_at"]
    assert (
        data["collection_started_at"]
        == collection.observations[0].collection_started_at.isoformat()
    )
    assert (
        data["collection_completed_at"]
        == collection.observations[-1].collection_finished_at.isoformat()
    )
    assert b"private-record-content" not in payload and b"synthetic-token" not in payload
    assert reviewed == original and network.calls == [
        f"/client/v4/zones/{ZONE}",
        f"/client/v4/zones/{ZONE}/dns_records?page=1&per_page=100",
    ]


@pytest.mark.parametrize("changed_total", [False, True])
def test_multiple_pages_are_unfiltered_and_fully_counted(network, changed_total):
    network.replies[1:] = [
        page([record(i) for i in range(1, 101)], 101),
        page([record(101)], 101, 2),
    ]
    if changed_total:
        network.replies[2]["result_info"]["total_count"] = 102
        with pytest.raises(GovernanceError, match="CF003"):
            collect()
        return
    assert len(collect().records) == 101
    assert network.calls[-1].endswith("?page=2&per_page=100")


@pytest.mark.parametrize(
    "change",
    [{"id": "c" * 32}, {"account": {"id": "c" * 32}}, {"name": "other.com"}, {"status": "pending"}],
)
def test_independent_zone_scope_must_match(network, change):
    network.replies[0]["result"].update(change)
    with pytest.raises(GovernanceError, match="CF001"):
        collect()
    assert len(network.calls) == 1


@pytest.mark.parametrize(
    "key,value",
    [
        ("page", 2),
        ("per_page", 20),
        ("count", 0),
        ("total_count", 4),
        ("total_pages", 2),
        ("total_count", True),
    ],
)
def test_missing_or_inconsistent_pagination_fails(network, key, value):
    network.replies[1]["result_info"][key] = value
    with pytest.raises(GovernanceError, match="CF003"):
        collect()


@pytest.mark.parametrize("change", [{"id": f"{1:032x}"}, {"name": "outside.com"}, {"type": ""}])
def test_duplicate_or_invalid_records_fail(network, change):
    network.replies[1]["result"][1].update(change)
    with pytest.raises(GovernanceError, match="CF004"):
        collect()


@pytest.mark.parametrize(
    "body",
    [
        b'{"success":true,"success":false}',
        b'{"private":',
        b"[]",
        b'{"success":false,"errors":["private-token"]}',
    ],
)
def test_api_failures_and_bad_json_are_sanitized(network, body):
    network.replies[0] = body
    with pytest.raises(GovernanceError) as error:
        collect()
    assert "private-token" not in str(error.value)


@pytest.mark.parametrize("bound", ["MAX_PAGES", "MAX_RECORDS", "MAX_BYTES"])
def test_budgets_fail_without_partial_evidence(network, monkeypatch, bound):
    monkeypatch.setattr(cf, bound, 0)
    with pytest.raises(GovernanceError):
        collect()


def test_stale_clocks_and_empty_zone(network):
    network.age = timedelta(minutes=16)
    with pytest.raises(GovernanceError, match="CF005"):
        collect()
    network.age = timedelta(0)
    network.replies.insert(
        0,
        {
            "success": True,
            "errors": [],
            "result": {
                "id": ZONE,
                "account": {"id": ACCOUNT},
                "name": "example.com",
                "status": "active",
            },
        },
    )
    network.replies[1] = page([])
    assert collect().records == ()


@pytest.mark.parametrize(
    "change",
    [
        {"verified": False},
        {"other_services_reviewed": False},
        {"plan": "paid"},
        {"account_id": "other"},
        {"scope_id": "other"},
        {"scope_name": "other.com"},
        {"profile_revision": 999},
        {"source": None},
    ],
)
def test_api_success_cannot_supply_entitlement_or_override_review(network, reviewed, change):
    config, profile, review = reviewed
    with pytest.raises(GovernanceError):
        se.capture_cloudflare_evidence(config, profile, collect(), review | change, commit=COMMIT)


def test_paid_api_plan_contradiction_blocks_free_review(network, reviewed):
    collection = replace(collect(), reported_plan="pro")
    config, profile, review = reviewed
    with pytest.raises(GovernanceError, match="CF001"):
        se.capture_cloudflare_evidence(config, profile, collection, review, commit=COMMIT)
