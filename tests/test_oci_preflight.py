"""OCI library gates bind immutable observations before invoking trusted callbacks."""

from copy import deepcopy
from datetime import timedelta

import pytest
import test_governance as fixtures
from infra_core.governance.audit import audit
from infra_core.governance.contracts import GovernanceError
from infra_core.inventory_evidence import capture_inventory, validate_inventory_evidence
from infra_program import governance

evidence = fixtures.evidence
COMMIT = "a" * 40
NOW = fixtures.NOW


@pytest.fixture
def bound(evidence, monkeypatch):
    payload, envelope = capture_inventory(*evidence[:3], commit=COMMIT, now=NOW)
    monkeypatch.setattr(
        governance,
        "validate_inventory_evidence",
        lambda *args, **kw: validate_inventory_evidence(*args, **kw, now=NOW),
    )
    monkeypatch.setattr(governance, "audit", lambda *args: audit(*args, now=NOW))
    return payload, envelope


@pytest.mark.parametrize(
    "fault",
    [
        "dictionary",
        "mutable",
        "bytes",
        "envelope",
        "account",
        "profile",
        "region",
        "config",
        "commit",
        "stale",
    ],
)
def test_invalid_binding_never_calls_registration(evidence, bound, monkeypatch, fault):
    payload, envelope = bound
    commit = COMMIT
    if fault == "dictionary":
        payload = evidence[2]
    elif fault == "mutable":
        payload = bytearray(payload)
    elif fault == "bytes":
        payload += b" "
    elif fault == "envelope":
        envelope = b"{}"
    elif fault == "account":
        evidence[0]["account_id"] = "other"
    elif fault == "profile":
        evidence[1]["revision"] += 1
    elif fault == "region":
        evidence[0]["home_region"] = "other"
    elif fault == "config":
        evidence[0]["reservations"]["ocpus"] = 1
    elif fault == "commit":
        commit = "b" * 40
    else:
        monkeypatch.setattr(
            governance,
            "validate_inventory_evidence",
            lambda *a, **kw: validate_inventory_evidence(*a, **kw, now=NOW + timedelta(minutes=16)),
        )
    effects = []
    with pytest.raises(ValueError, match="EVID"):
        governance.preflight(
            *evidence[:2],
            payload,
            evidence[3],
            lambda: effects.append(True),
            envelope=envelope,
            commit=commit,
        )
    assert not effects


@pytest.mark.parametrize("missing", ["envelope", "commit"])
def test_binding_arguments_are_required(evidence, bound, missing):
    payload, envelope = bound
    kwargs = {"envelope": envelope, "commit": COMMIT}
    del kwargs[missing]
    effects = []
    with pytest.raises(TypeError):
        governance.preflight(
            *evidence[:2], payload, evidence[3], lambda: effects.append(True), **kwargs
        )
    assert not effects


@pytest.mark.parametrize("fault", ["eligibility", "usage", "proposal"])
def test_bound_inventory_cannot_replace_accounting_audit(evidence, bound, fault):
    if fault == "eligibility":
        evidence[0]["verified"] = False
    elif fault == "usage":
        evidence[2]["usage"] = None
    else:
        evidence[3]["complete"] = False
    payload, envelope = capture_inventory(*evidence[:3], commit=COMMIT, now=NOW)
    effects = []
    with pytest.raises(GovernanceError, match="GOV"):
        governance.preflight(
            *evidence[:2],
            payload,
            evidence[3],
            lambda: effects.append(True),
            envelope=envelope,
            commit=COMMIT,
        )
    assert not effects


def test_audit_uses_frozen_inputs_and_callback_runs_once_after_success(
    evidence, bound, monkeypatch
):
    payload, envelope = bound
    original = deepcopy(evidence)
    events = []

    def auditing(account, profile, inventory, plan):
        assert not events
        evidence[0]["verified"] = False
        evidence[1]["enabled"] = False
        evidence[3]["units"].clear()
        assert (account, profile, inventory, plan) == original
        result = audit(account, profile, inventory, plan, now=NOW)
        events.append("audited")
        return result

    monkeypatch.setattr(governance, "audit", auditing)
    sentinel = object()

    def register():
        assert events == ["audited"]
        events.append("registered")
        return sentinel

    assert (
        governance.preflight(
            *evidence[:2], payload, evidence[3], register, envelope=envelope, commit=COMMIT
        )
        is sentinel
    )
    assert events == ["audited", "registered"]
