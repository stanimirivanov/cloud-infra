"""Readiness adapters preserve existing account and service audit rejection rules."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import test_governance
import test_services
from infra_core import account_readiness as a
from infra_core import cli, inventory_evidence, service_evidence

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
evidence = test_governance.evidence
service = test_services.service


def setup(root, monkeypatch, unit, configuration, payload, envelope, proposal, now):
    (root / "config/quotas").mkdir(parents=True)
    (root / "config/quotas/profiles.toml").write_bytes(
        (ROOT / "config/quotas/profiles.toml").read_bytes()
    )
    (root / ".infra").mkdir()
    monkeypatch.setattr(a, "repository_state", lambda root: (COMMIT, True))
    (root / ".infra/config.json").write_text(json.dumps(configuration))
    (root / ".infra/observation.json").write_bytes(payload)
    (root / ".infra/observation.json.envelope.json").write_bytes(envelope)
    index = dict(
        schema_version=1,
        unit=unit,
        commit=COMMIT,
        configuration=".infra/config.json",
        observation=".infra/observation.json",
        proposal=None,
    )
    if proposal is not None:
        index["proposal"] = ".infra/proposal.json"
        (root / index["proposal"]).write_text(json.dumps(proposal))
    (root / ".infra/index.json").write_text(json.dumps(index))
    return root, unit, configuration["account_id"], now


@pytest.fixture(params=["oci-network", "oci-oke"])
def oci_bundle(tmp_path, monkeypatch, evidence, request):
    account, profile, inventory, proposal = evidence
    proposal["units"][0]["name"] = request.param
    payload, envelope = inventory_evidence.capture_inventory(
        account, profile, inventory, commit=COMMIT, now=test_governance.NOW
    )
    return setup(
        tmp_path,
        monkeypatch,
        request.param,
        account,
        payload,
        envelope,
        proposal,
        test_governance.NOW,
    )


@pytest.fixture
def service_bundle(tmp_path, monkeypatch, service):
    config, evidence, profile = service
    payload = json.dumps(evidence).encode()
    envelope = service_evidence.capture_service_evidence(config, profile, payload, commit=COMMIT)
    return setup(
        tmp_path, monkeypatch, config["unit"], config, payload, envelope, None, datetime.now(UTC)
    )


def check(bundle, **kwargs):
    root, unit, account, now = bundle
    return a.check(
        root, Path(".infra/index.json"), **(dict(unit=unit, account_id=account, now=now) | kwargs)
    )


def assert_pending(bundle):
    root, _, account, _ = bundle
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = check(bundle)
    assert result["status"] == "pending"
    assert result["account_evidence"] == "account-evidence-consistent"
    assert all(
        result[key] is False
        for key in (
            "account_ready",
            "execution_authorized",
            "activation_authorized",
            "live_controls_verified",
        )
    )
    assert account not in json.dumps(result)
    assert before == {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_oci_valid_evidence_is_not_acceptance(oci_bundle):
    assert_pending(oci_bundle)


def test_service_valid_evidence_is_not_acceptance(service_bundle):
    assert_pending(service_bundle)


def change_observation(bundle, mutate):
    root = bundle[0]
    path = root / ".infra/observation.json"
    data = json.loads(path.read_bytes())
    mutate(data)
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    sidecar = root / ".infra/observation.json.envelope.json"
    envelope = json.loads(sidecar.read_bytes())
    envelope["subject"][0]["digest"]["sha256"] = hashlib.sha256(raw).hexdigest()
    sidecar.write_text(json.dumps(envelope))


@pytest.mark.parametrize(
    "mutation",
    [
        "partial",
        "coverage",
        "usage",
        "account",
        "proposal",
        "unverified",
        "stale",
        "profile",
        "unit",
    ],
)
def test_oci_audit_cannot_be_bypassed(oci_bundle, mutation):
    root, _, _, now = oci_bundle
    if mutation in ("partial", "coverage", "usage", "account"):

        def mutate(data):
            if mutation == "partial":
                data["complete"] = False
            elif mutation == "coverage":
                data["covered_types"] = []
            elif mutation == "usage":
                data["usage"]["values"] = {}
            else:
                data["account_id"] = "other"

        change_observation(oci_bundle, mutate)
    elif mutation in ("proposal", "unit"):
        path = root / ".infra/proposal.json"
        data = json.loads(path.read_bytes())
        if mutation == "proposal":
            data["complete"] = False
        else:
            data["units"][0]["name"] = "other"
        path.write_text(json.dumps(data))
    elif mutation in ("unverified", "profile"):
        path = root / ".infra/config.json"
        data = json.loads(path.read_bytes())
        data["verified" if mutation == "unverified" else "profile_revision"] = (
            False if mutation == "unverified" else 99
        )
        path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="AREADY001"):
        check(oci_bundle, now=now + timedelta(minutes=16) if mutation == "stale" else now)


@pytest.mark.parametrize(
    "mutation",
    ["partial", "unverified", "other-services", "coverage", "billing", "scope", "stale", "usage"],
)
def test_service_audit_cannot_be_bypassed(service_bundle, mutation):
    root, unit, _, now = service_bundle

    def mutate(data):
        if mutation in ("partial", "unverified", "other-services"):
            data[
                {
                    "partial": "complete",
                    "unverified": "verified",
                    "other-services": "other_services_reviewed",
                }[mutation]
            ] = False
        elif mutation == "coverage":
            data["coverage"] = {}
        elif mutation == "billing":
            data["billing_period"] = None if unit == "supabase-database" else {"invalid": True}
        elif mutation == "scope":
            data["scope_id"] = "other"
        elif mutation == "usage":
            data["usage"] = {} if unit == "supabase-database" else {"unknown": 1}

    change_observation(service_bundle, mutate)
    with pytest.raises(ValueError, match="AREADY001"):
        check(service_bundle, now=now + timedelta(minutes=16) if mutation == "stale" else now)


@pytest.mark.parametrize(
    "mutation",
    [
        "escape",
        "symlink",
        "alias",
        "extra",
        "commit",
        "duplicate",
        "large",
        "missing",
        "dirty",
        "account",
    ],
)
def test_private_boundaries(oci_bundle, monkeypatch, mutation):
    root, _, _, _ = oci_bundle
    path = root / ".infra/index.json"
    index = json.loads(path.read_bytes())
    if mutation == "escape":
        index["configuration"] = "../PRIVATE.json"
    elif mutation == "symlink":
        (root / ".infra/link.json").symlink_to(root / ".infra/config.json")
        index["configuration"] = ".infra/link.json"
    elif mutation == "alias":
        index["proposal"] = index["observation"] + ".envelope.json"
    elif mutation == "extra":
        index["extra"] = False
    elif mutation == "commit":
        index["commit"] = "b" * 40
    elif mutation == "dirty":
        monkeypatch.setattr(a, "repository_state", lambda root: (COMMIT, False))
    path.write_text(json.dumps(index))
    if mutation == "duplicate":
        path.write_text('{"schema_version":1,"schema_version":1}')
    elif mutation == "large":
        (root / ".infra/config.json").write_bytes(b" " * (1024 * 1024 + 1))
    elif mutation == "missing":
        (root / ".infra/observation.json.envelope.json").unlink()
    with pytest.raises(
        ValueError,
        match="^AREADY001: account readiness input rejected; private diagnostics withheld$",
    ):
        check(oci_bundle, **({"account_id": "other"} if mutation == "account" else {}))


@pytest.mark.parametrize("changed", ["commit", "profile", "evidence"])
def test_mutation_during_check_rejected(service_bundle, monkeypatch, changed):
    root, _, _, _ = service_bundle
    calls = 0

    def state(root):
        nonlocal calls
        calls += 1
        if calls == 2:
            if changed == "commit":
                return "b" * 40, True
            path = root / (
                "config/quotas/profiles.toml" if changed == "profile" else ".infra/config.json"
            )
            path.write_bytes(path.read_bytes() + b" ")
        return COMMIT, True

    monkeypatch.setattr(a, "repository_state", state)
    with pytest.raises(ValueError, match="AREADY001"):
        check(service_bundle)


def test_cli_missing_evidence_is_pending(oci_bundle, monkeypatch, capsys):
    root, unit, account, _ = oci_bundle
    monkeypatch.setattr(cli, "find_repository", lambda arg: root)
    assert cli.main(["governance", "check-readiness", "--unit", unit, "--account-id", account]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["account_evidence"] == "pending" and result["account_ready"] is False


def test_oci_over_budget_rejected(oci_bundle):
    def mutate(data):
        data["usage"]["values"]["a1_ocpu_hours"] = 1000000

    change_observation(oci_bundle, mutate)
    with pytest.raises(ValueError, match="AREADY001"):
        check(oci_bundle)


@pytest.mark.parametrize("mutation", ["over-budget", "reporting-lag"])
def test_supabase_usage_is_not_zero_filled_or_restamped(service_bundle, mutation):
    if service_bundle[1] != "supabase-database":
        pytest.skip("Cloudflare DNS has no usage meter in this contract")

    def mutate(data):
        if mutation == "over-budget":
            data["usage"]["storage_gb_hours"]["value"] = 1000000
        else:
            data["usage"]["storage_gb_hours"]["covered_through"] = (
                service_bundle[3] - timedelta(hours=1)
            ).isoformat()

    change_observation(service_bundle, mutate)
    with pytest.raises(ValueError, match="AREADY001"):
        check(service_bundle)
