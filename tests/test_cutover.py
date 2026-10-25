"""Private synthetic evidence: full positive chain and tamper/staleness/ownership failures."""

import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from evidence_helpers import recovery_metrics, upgrade_inventory
from infra_core import cli, cutover
from infra_core.foundation import load_foundation
from infra_core.governance.contracts import GovernanceError
from infra_core.governance.resources import CLUSTER, INSTANCE, INVENTORY_TYPES
from infra_core.kubernetes.resources import render
from infra_core.oci.config import FoundationConfig, ImageEvidence
from infra_core.oci.graph import foundation_graph, proposal

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40


def table(name, values):
    return (
        f"[{name}]\n"
        + "\n".join(f"{key} = {json.dumps(value)}" for key, value in values.items())
        + "\n"
    )


@pytest.fixture
def review(tmp_path, monkeypatch, kube_config, kube_inventory):
    root = tmp_path
    (root / "config/quotas").mkdir(parents=True)
    (root / ".infra").mkdir()
    (root / "pyproject.toml").write_text('[project]\nname="oci-oke-infrastructure"\n')
    (root / "config/pulumi.toml").write_bytes((ROOT / "config/pulumi.toml").read_bytes())
    monkeypatch.setattr(cutover, "repository_state", lambda root: (COMMIT, True))
    now = datetime.now(UTC).isoformat()
    profile = {
        "id": "oci-free",
        "revision": 1,
        "provider": "oci",
        "enabled": True,
        "reviewed_at": now,
    }
    profile_text = table("profiles.oci-free", profile)
    profile_text += table(
        "profiles.oci-free.capacity", {"ocpus": 2, "memory_gb": 12, "block_gb": 200}
    )
    profile_text += table(
        "profiles.oci-free.monthly",
        {"a1_ocpu_hours": 1500, "a1_memory_gb_hours": 9000, "block_gb_months": 200},
    )
    (root / "config/quotas/profiles.toml").write_text(profile_text)
    oci = FoundationConfig(
        "fixture",
        kube_config.region,
        "ocid1.compartment.oc1..fixture",
        ("198.51.100.10/32",),
        "ocid1.service.oc1.fra.fixture",
        "all-fra-services-in-oracle-services-network",
        ("fixture:EU-FRANKFURT-1-AD-1",),
        "v1.34.1",
        ("v1.34.1",),
        ImageEvidence(
            "ocid1.image.oc1.eu-frankfurt-1.fixture",
            kube_config.region,
            "aarch64",
            "v1.34.1",
            now,
            "synthetic review",
        ),
    )
    oci_values = asdict(oci)
    image = oci_values.pop("image")
    account = {
        "provider": "oci",
        "account_id": kube_config.account_id,
        "home_region": kube_config.region,
        "profile": "oci-free",
        "profile_revision": 1,
        "verified": True,
        "verified_at": now,
        "other_services_reviewed": True,
    }
    inventory = {
        "schema_version": 1,
        "account_id": kube_config.account_id,
        "provider": "oci",
        "observed_at": now,
        "complete": True,
        "all_regions": True,
        "all_compartments": True,
        "covered_types": sorted(INVENTORY_TYPES),
        "resources": [
            {
                "id": kube_config.cluster_id,
                "type": CLUSTER,
                "region": kube_config.region,
                "owner": None,
                "retained": False,
                "props": {"type": "BASIC_CLUSTER"},
            }
        ]
        + [
            {
                "id": node,
                "type": INSTANCE,
                "region": kube_config.region,
                "owner": None,
                "retained": False,
                "props": {
                    "shape": "VM.Standard.A1.Flex",
                    "shapeConfig": {"ocpus": 1, "memoryInGbs": 6},
                },
            }
            for node in kube_inventory["node_ids"]
        ],
        "usage": {
            "account_id": kube_config.account_id,
            "provider": "oci",
            "month": now[:7],
            "observed_at": now,
            "source": "synthetic usage",
            "values": {"a1_ocpu_hours": 0, "a1_memory_gb_hours": 0, "block_gb_months": 0},
        },
    }
    upgrade_inventory(inventory, account["home_region"])
    graph = foundation_graph(oci)
    entries = [
        {
            "logical_key": item.key,
            "id": kube_config.cluster_id if item.key == "cluster" else "fixture-" + item.key,
            "unit": item.unit,
            "pulumi_name": oci.name + "-" + item.key,
            "pulumi_parent": oci.name + ("-network" if item.unit == "oci-network" else "-oke"),
            "provider_region": oci.region,
            "owner": "terraform",
            "terraform_address": f"oci_fixture.item_{index}",
            "operation": "import",
        }
        for index, item in enumerate(graph)
    ]
    header = {
        "commit": COMMIT,
        "account_id": kube_config.account_id,
        "cluster_id": kube_config.cluster_id,
        "region": kube_config.region,
        "observed_at": now,
        "source": "synthetic offline review",
        "reviewed_by": "synthetic reviewer",
    }
    config = load_foundation(root)
    values = asdict(kube_config)
    namespaces = values.pop("namespaces")
    reserved = values.pop("reserved")
    kube_text = table("cluster", values) + table("reserved", reserved)
    for namespace in namespaces:
        kube_text += "\n" + table("namespaces", namespace).replace("[namespaces]", "[[namespaces]]")
    artifacts = {
        "account": table("account", account).removeprefix("[account]\n") + "\n[reservations]\n",
        "oci_config": table("foundation", oci_values) + table("image", image),
        "kubernetes_config": kube_text,
        "backend_receipt": {
            "schema_version": 2,
            "run_id": "a" * 32,
            "recovery": recovery_metrics(),
            "kind": "oci-s3",
            "configuration_sha256": config.digest,
            "pulumi_version": config.pulumi_version,
            "completed_at": now,
            "deployment_authorized": False,
            "checks": [
                "encrypted-config",
                "encrypted-checkpoint",
                "lock-contention",
                "restore-readback",
                "independent-recovery",
            ],
        },
        "inventory": inventory,
        "kubernetes_inventory": kube_inventory,
        "oci_proposal": {
            "schema_version": 1,
            "account_id": kube_config.account_id,
            "provider": "oci",
            "complete": True,
            "units": [{"name": unit, "changes": []} for unit in ("oci-network", "oci-oke")],
        },
        "kubernetes_resources": render(kube_config),
        "ownership": {
            **header,
            "complete": True,
            "writers_frozen": True,
            "active_operations": 0,
            "entries": entries,
        },
        "preview": {
            **header,
            "complete": True,
            "graph_sha256": cutover.digest(proposal(graph, kube_config.account_id, oci.region)),
            "operations": [
                {key: entry[key] for key in ("logical_key", "id", "unit", "operation")}
                for entry in entries
            ],
        },
        "health": {**header, "checks": sorted(cutover.HEALTH)},
        "rollback": {**header, "checks": sorted(cutover.ROLLBACK)},
    }
    document = {
        "schema_version": 1,
        "commit": COMMIT,
        "account_id": kube_config.account_id,
        "cluster_id": kube_config.cluster_id,
        "region": kube_config.region,
        "configuration_sha256": config.digest,
        "captured_at": now,
        "artifacts": {},
    }

    def write(role, value):
        path = root / ".infra" / (role + (".toml" if isinstance(value, str) else ".json"))
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        document["artifacts"][role] = {
            "path": str(path.relative_to(root)),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    for role, value in artifacts.items():
        write(role, value)
    return root, document, artifacts, write


def test_complete_bundle_is_consistent_but_never_authorizes_cutover(review):
    root, document, _, _ = review
    result = cutover.check(root, document)
    assert result["status"] == "evidence-consistent"
    assert result["deployment_authorized"] is result["cutover_authorized"] is False
    assert "explicit human cutover instruction" in result["remaining_gates"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("commit", "b" * 40),
        ("configuration_sha256", "wrong"),
        ("schema_version", True),
        ("captured_at", (datetime.now(UTC) - timedelta(minutes=16)).isoformat()),
    ],
)
def test_changed_commit_config_and_stale_bundle_fail(review, field, value):
    root, document, _, _ = review
    document[field] = value
    with pytest.raises(GovernanceError, match="CUT001"):
        cutover.check(root, document)


def test_dirty_checkout_is_not_reviewed(review, monkeypatch):
    root, document, _, _ = review
    monkeypatch.setattr(cutover, "repository_state", lambda root: (COMMIT, False))
    with pytest.raises(GovernanceError, match="CUT001"):
        cutover.check(root, document)


def test_missing_tampered_escaped_and_duplicated_artifacts_fail(review):
    root, document, artifacts, write = review
    ref = document["artifacts"]["health"]
    path = root / ref["path"]
    path.write_text("tampered")
    with pytest.raises(GovernanceError, match="CUT002"):
        cutover.check(root, document)
    write("health", artifacts["health"])
    document["artifacts"]["health"]["path"] = "../outside.json"
    with pytest.raises(GovernanceError, match="CUT002"):
        cutover.check(root, document)
    write("health", artifacts["health"])
    document["artifacts"]["health"] = document["artifacts"]["rollback"]
    with pytest.raises(GovernanceError, match="CUT002"):
        cutover.check(root, document)


@pytest.mark.parametrize(
    "role,field,value,code",
    [
        ("ownership", "writers_frozen", False, "CUT005"),
        ("ownership", "active_operations", True, "CUT005"),
        ("ownership", "complete", False, "CUT005"),
        ("ownership", "entries", [], "CUT005"),
        ("preview", "complete", False, "CUT006"),
        ("preview", "graph_sha256", "wrong", "CUT006"),
        ("preview", "operations", [], "CUT006"),
        ("health", "checks", [], "CUT007"),
        ("rollback", "checks", [], "CUT007"),
        ("health", "cluster_id", "wrong", "CUT004"),
        (
            "health",
            "observed_at",
            (datetime.now(UTC) - timedelta(minutes=16)).isoformat(),
            "CUT004",
        ),
    ],
)
def test_incomplete_or_mismatched_reviews_fail(review, role, field, value, code):
    root, document, artifacts, write = review
    artifacts[role][field] = value
    write(role, artifacts[role])
    with pytest.raises(GovernanceError, match=code):
        cutover.check(root, document)


@pytest.mark.parametrize(
    "mutation", ["duplicate-id", "dual-owner", "delete", "wrong-parent", "wrong-cluster"]
)
def test_ownership_ambiguity_and_destructive_operations_fail(review, mutation):
    root, document, artifacts, write = review
    entries = artifacts["ownership"]["entries"]
    if mutation == "duplicate-id":
        entries[1]["id"] = entries[0]["id"]
    elif mutation == "dual-owner":
        entries[0]["owner"] = "terraform-and-pulumi"
    elif mutation == "delete":
        entries[0]["operation"] = "delete"
    elif mutation == "wrong-parent":
        entries[0]["pulumi_parent"] = "unreviewed"
    else:
        next(item for item in entries if item["logical_key"] == "cluster")["id"] = "wrong"
    write("ownership", artifacts["ownership"])
    with pytest.raises(GovernanceError, match="CUT005|CUT006"):
        cutover.check(root, document)


def test_cluster_capacity_must_match_observed_oci_nodes(review):
    root, document, artifacts, write = review
    artifacts["kubernetes_inventory"]["allocatable"]["cpu_m"] = 4000
    write("kubernetes_inventory", artifacts["kubernetes_inventory"])
    with pytest.raises(GovernanceError, match="CUT003"):
        cutover.check(root, document)


def test_backend_local_receipt_and_billing_plan_changes_fail(review):
    root, document, artifacts, write = review
    artifacts["backend_receipt"]["kind"] = "local"
    write("backend_receipt", artifacts["backend_receipt"])
    with pytest.raises(RuntimeError):
        cutover.check(root, document)


def test_cli_returns_only_sanitized_consistency_result(review, capsys):
    root, document, _, _ = review
    evidence = root / ".infra/review.json"
    evidence.write_text(json.dumps(document))
    assert cli.main(["--root", str(root), "cutover", "check", "--evidence", str(evidence)]) == 0
    assert json.loads(capsys.readouterr().out)["cutover_authorized"] is False


def test_artifacts_are_parsed_from_their_hashed_snapshot(review, monkeypatch):
    root, document, _, _ = review
    original = cutover.validate_receipt

    def change_after_capture(*args):
        original(*args)
        (root / document["artifacts"]["oci_config"]["path"]).write_text("changed after capture")

    monkeypatch.setattr(cutover, "validate_receipt", change_after_capture)
    assert cutover.check(root, document)["status"] == "evidence-consistent"
    with pytest.raises(GovernanceError, match="CUT002"):
        cutover.check(root, document)


def test_checkout_change_during_review_fails(review, monkeypatch):
    root, document, _, _ = review
    states = iter([(COMMIT, True), ("b" * 40, True)])
    monkeypatch.setattr(cutover, "repository_state", lambda root: next(states))
    with pytest.raises(GovernanceError, match="CUT001"):
        cutover.check(root, document)
