"""Private synthetic evidence: full positive chain and tamper/staleness/ownership failures."""

import base64
import hashlib
import json
import tomllib
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from evidence_helpers import administration_responses, recovery_metrics, upgrade_inventory
from infra_core import cli, cutover
from infra_core.cutover_evidence import (
    REPORTS,
    SUBJECTS,
    TRUSTED_INPUTS,
    capture_review,
    review_scope,
)
from infra_core.foundation import load_foundation
from infra_core.governance.contracts import GovernanceError
from infra_core.governance.resources import CLUSTER, INSTANCE, INVENTORY_TYPES
from infra_core.inventory_evidence import capture_inventory
from infra_core.kubernetes.resources import render
from infra_core.oci.config import FoundationConfig, ImageEvidence
from infra_core.oci.graph import foundation_graph, proposal
from infra_core.review_signatures import PAYLOAD_TYPE, preauth

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40


def table(name, values):
    return (
        f"[{name}]\n"
        + "\n".join(f"{key} = {json.dumps(value)}" for key, value in values.items())
        + "\n"
    )


def sign_review(key, payload, *, keyid="untrusted-hint"):
    return json.dumps(
        {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode(),
            "signatures": [
                {"keyid": keyid, "sig": base64.b64encode(key.sign(preauth(payload))).decode()}
            ],
        }
    ).encode()


@pytest.fixture
def review(tmp_path, monkeypatch, kube_config, kube_inventory, review_signer):
    root = tmp_path
    (root / "config/quotas").mkdir(parents=True)
    (root / ".infra").mkdir()
    public_key = base64.b64encode(review_signer.public_key().public_bytes_raw()).decode()
    (root / "config/cutover-reviewers.toml").write_text(
        "schema_version = 1\nenabled = true\n[[reviewers]]\n"
        'principal = "synthetic-reviewer"\npublic_key = "'
        + public_key
        + '"\nroles = '
        + json.dumps(sorted(REPORTS))
        + "\n",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text('[project]\nname="oci-oke-infrastructure"\n')
    (root / "config/administration.json").write_bytes(
        (ROOT / "config/administration.json").read_bytes()
    )
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
        "reviewed_by": "synthetic-reviewer",
    }
    config = load_foundation(root)
    values = asdict(kube_config)
    namespaces = values.pop("namespaces")
    reserved = values.pop("reserved")
    kube_text = table("cluster", values) + table("reserved", reserved)
    for namespace in namespaces:
        kube_text += "\n" + table("namespaces", namespace).replace("[namespaces]", "[[namespaces]]")
    administrative_policy = (root / "config/administration.json").read_bytes()
    key_policy = (root / "config/cutover-reviewers.toml").read_bytes()
    administration = {
        "schema_version": 3,
        "commit": COMMIT,
        "policy_sha256": {
            "config/administration.json": hashlib.sha256(administrative_policy).hexdigest(),
            "config/cutover-reviewers.toml": hashlib.sha256(key_policy).hexdigest(),
        },
        "started_at": now,
        "completed_at": now,
        "responses": administration_responses(json.loads(administrative_policy), COMMIT),
    }
    artifacts = {
        "administration": administration,
        "account": table("account", account).removeprefix("[account]\n") + "\n[reservations]\n",
        "oci_config": table("foundation", oci_values) + table("image", image),
        "kubernetes_config": kube_text,
        "backend_receipt": {
            "schema_version": 3,
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
                "wrong-passphrase-rejected",
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
        "schema_version": 5,
        "commit": COMMIT,
        "account_id": kube_config.account_id,
        "cluster_id": kube_config.cluster_id,
        "region": kube_config.region,
        "configuration_sha256": config.digest,
        "captured_at": now,
        "artifacts": {},
    }

    subject_bytes = {}

    def write(role, value, *, rebind=True):
        path = root / ".infra" / (role + (".toml" if isinstance(value, str) else ".json"))
        content = (
            value
            if isinstance(value, bytes)
            else (value if isinstance(value, str) else json.dumps(value)).encode("utf-8")
        )
        path.write_bytes(content)
        if role in SUBJECTS:
            subject_bytes[role] = content
        document["artifacts"][role] = {
            "path": str(path.relative_to(root)),
            "sha256": hashlib.sha256(content).hexdigest(),
        }

        if rebind and SUBJECTS - TRUSTED_INPUTS <= set(document["artifacts"]):
            # Negative-domain fixtures deliberately rebuild bindings and ephemeral signatures.
            # Replay/tamper regressions pass rebind=False to preserve the original review.
            subjects = dict(subject_bytes)
            subjects["quota_profiles"] = (root / "config/quotas/profiles.toml").read_bytes()
            subjects["reviewer_policy"] = (root / "config/cutover-reviewers.toml").read_bytes()
            subjects["administrative_policy"] = (root / "config/administration.json").read_bytes()
            for report in sorted(REPORTS):
                scope = review_scope(
                    report,
                    account_id=kube_config.account_id,
                    region=kube_config.region,
                    cluster_id=kube_config.cluster_id,
                    commit=COMMIT,
                    configuration_sha256=config.digest,
                )
                observed = json.loads(subjects[report])["observed_at"]
                encoded = capture_review(
                    report,
                    subjects,
                    scope=scope,
                    now=datetime.fromisoformat(observed),
                )
                artifacts[report + "_envelope"] = encoded
                write(report + "_envelope", encoded, rebind=False)
                signed = sign_review(review_signer, encoded)
                artifacts[report + "_signature"] = signed
                write(report + "_signature", signed, rebind=False)

    payload, envelope = capture_inventory(
        tomllib.loads(artifacts["account"]),
        tomllib.loads(profile_text)["profiles"]["oci-free"],
        inventory,
        commit=COMMIT,
    )
    for role, value in artifacts.items():
        write(role, payload if role == "inventory" else value)
    artifacts["inventory_envelope"] = envelope
    write("inventory_envelope", envelope)
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
        ("schema_version", 1),
        ("schema_version", 2),
        ("schema_version", 3),
        ("schema_version", 4),
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
            "EVID004",
        ),
    ],
)
def test_incomplete_or_mismatched_reviews_fail(review, role, field, value, code):
    root, document, artifacts, write = review
    artifacts[role][field] = value
    write(role, artifacts[role])
    with pytest.raises(ValueError, match=code):
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
    root, document, _, write = review
    evidence = root / ".infra/review.json"
    evidence.write_text(json.dumps(document))
    assert cli.main(["--root", str(root), "cutover", "check", "--evidence", str(evidence)]) == 0
    assert json.loads(capsys.readouterr().out)["cutover_authorized"] is False
    inventory = root / document["artifacts"]["inventory"]["path"]
    write("inventory", inventory.read_bytes() + b" ")
    evidence.write_text(json.dumps(document))
    assert cli.main(["--root", str(root), "cutover", "check", "--evidence", str(evidence)]) == 1
    output = capsys.readouterr()
    assert "EVID002" in output.err and not output.out


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


@pytest.mark.parametrize("fault", ["role", "file", "oversize", "digest", "alias"])
def test_inventory_sidecar_is_mandatory_bounded_and_hashed(review, fault):
    root, document, _, write = review
    ref = document["artifacts"]["inventory_envelope"]
    path = root / ref["path"]
    if fault == "role":
        del document["artifacts"]["inventory_envelope"]
    elif fault == "file":
        path.unlink()
    elif fault == "oversize":
        write("inventory_envelope", b" " * (cutover.MAX_ENVELOPE_BYTES + 1))
    elif fault == "digest":
        path.write_bytes(b"changed without updating the index")
    else:
        document["artifacts"]["inventory_envelope"] = document["artifacts"]["inventory"]
    with pytest.raises(GovernanceError, match="GOV003|CUT002"):
        cutover.check(root, document)


@pytest.mark.parametrize(
    "fault",
    ["bytes", "account", "region", "unit", "commit", "clock", "stale", "kind", "profile", "config"],
)
def test_rehashed_index_cannot_bypass_inventory_binding(review, fault):
    root, document, artifacts, write = review
    envelope = json.loads(artifacts["inventory_envelope"])
    if fault == "bytes":
        path = root / document["artifacts"]["inventory"]["path"]
        write("inventory", path.read_bytes() + b" ")
    elif fault == "profile":
        path = root / "config/quotas/profiles.toml"
        path.write_text(path.read_text().replace("enabled = true", "enabled = false"))
    elif fault == "config":
        write("account", artifacts["account"] + "ocpus = 1\n")
    elif fault in ("account", "region", "unit", "commit"):
        key = "account_id" if fault == "account" else fault
        envelope["predicate"]["scope"][key] = "b" * 40 if fault == "commit" else "other"
    elif fault == "kind":
        envelope["predicateType"] = "other"
    else:
        age = timedelta(minutes=16) if fault == "stale" else timedelta(seconds=1)
        start = datetime.fromisoformat(artifacts["inventory"]["collection_started_at"])
        envelope["predicate"]["collection_started_at"] = (start - age).isoformat()
    write("inventory_envelope", json.dumps(envelope).encode())
    with pytest.raises(ValueError, match="EVID|GOV043"):
        cutover.check(root, document)


@pytest.mark.parametrize("fault", ["json", "coverage", "usage"])
def test_recomputed_inner_hash_cannot_bypass_inventory_or_billing_checks(review, fault):
    root, document, artifacts, write = review
    inventory = artifacts["inventory"]
    if fault == "json":
        payload = b'{"PRIVATE":'
    else:
        if fault == "coverage":
            inventory["coverage"]["queries"].pop()
        else:
            inventory["usage"] = None
        payload = json.dumps(inventory).encode()
    envelope = json.loads(artifacts["inventory_envelope"])
    envelope["subject"][0]["digest"]["sha256"] = hashlib.sha256(payload).hexdigest()
    write("inventory", payload)
    write("inventory_envelope", json.dumps(envelope).encode())
    with pytest.raises(ValueError, match="GOV") as error:
        cutover.check(root, document)
    assert "PRIVATE" not in str(error.value)


def test_inventory_pair_uses_hashed_snapshot_without_reopening_files(review, monkeypatch):
    root, document, _, _ = review
    original = cutover.validate_receipt

    def change_pair_after_capture(*args):
        original(*args)
        for role in ("inventory", "inventory_envelope"):
            (root / document["artifacts"][role]["path"]).write_bytes(b"changed after capture")

    monkeypatch.setattr(cutover, "validate_receipt", change_pair_after_capture)
    assert cutover.check(root, document)["cutover_authorized"] is False
    with pytest.raises(GovernanceError, match="CUT002"):
        cutover.check(root, document)
