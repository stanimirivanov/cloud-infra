"""Signed recovery contracts and frozen two-phase lifecycle, without provider operations."""

import argparse
import base64
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import test_drift
import test_oci_dependency
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from evidence_helpers import administration_responses
from infra_core import operation_admission as admission
from infra_core import operations, ownership_handoff, review_signatures
from infra_core import recovery_contracts as c
from infra_program import cli
from infra_program import recovery_driver as r

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
config = test_drift.config
case = test_drift.case


def signed(payload, keys, kind):
    return {
        role: operations.encoded(
            dict(
                payloadType=kind,
                payload=base64.b64encode(payload).decode(),
                signatures=[
                    dict(
                        sig=base64.b64encode(
                            key.sign(review_signatures.preauth(payload, kind))
                        ).decode()
                    )
                ],
            )
        )
        for role, key in keys.items()
    }


@pytest.fixture
def prepared(case, tmp_path, monkeypatch):
    context, cfg, _, dependency = case
    unit = context.contract.unit
    (tmp_path / "config").mkdir()
    (tmp_path / "config/provider-toolchain.json").write_bytes(
        (ROOT / "config/provider-toolchain.json").read_bytes()
    )
    (tmp_path / "config/state-recovery.json").write_bytes(
        operations.encoded(dict(schema_version=1, enabled=True))
    )
    keys = {role: Ed25519PrivateKey.generate() for role in ("operator", "approver")}
    policy = dict(
        schema_version=1,
        enabled=True,
        repository="example/infra",
        repository_id=123,
        max_approval_age_seconds=900,
        max_backup_age_seconds=3600,
        environments={"recovery/" + unit: unit + "-recovery", "handoff/oci": "oci-handoff"},
        reviewers=[
            dict(
                principal=role,
                roles=[role],
                public_key=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
            )
            for role, key in keys.items()
        ],
    )
    policy_raw = operations.encoded(policy)
    (tmp_path / "config/operations-policy.json").write_bytes(policy_raw)
    monkeypatch.setattr(admission, "repository_state", lambda root: (COMMIT, True))
    monkeypatch.setattr(r.drift, "_context", lambda *a: context)
    monkeypatch.setattr(r, "validate_posture_evidence", lambda *a, **kw: None)
    monkeypatch.setattr(r.backup, "host_id", lambda: "f" * 64)
    now = datetime.now(UTC)
    earlier = (now - timedelta(seconds=20)).isoformat()
    expires = (now + timedelta(minutes=10)).isoformat()
    state = test_drift.checkpoint(context)
    state["deployment"]["secrets_providers"]["state"]["salt"] = json.loads(cfg)["encryptionsalt"]
    if unit == "oci-network":
        state["deployment"]["resources"][0]["outputs"] = test_oci_dependency.committed(
            context.configuration
        )
    checkpoint = operations.encoded(state)
    current = deepcopy(state)
    current["deployment"]["manifest"] = {"time": "current"}
    raw = {name: b"fixture" for name in r.names(unit)}
    raw.update(
        current_checkpoint=operations.encoded(current),
        encrypted_configuration=cfg,
        restore_checkpoint=checkpoint,
        restore_configuration=cfg,
    )
    value = dict(
        schema_version=1,
        operation_id="12345678-1234-4234-8234-123456789abc",
        operation="recovery",
        unit=unit,
        commit=COMMIT,
        checkpoint_sha256=c.digest(raw["current_checkpoint"]),
        configuration_sha256=c.digest(cfg),
        expires_at=expires,
        expected_predecessor=None,
    )
    path = tmp_path / ".infra/operations" / (unit + ".json")
    prior = dict(
        value,
        operation="import" if unit.startswith("oci-") else "apply",
        operation_id="22345678-1234-4234-8234-123456789abc",
    )
    head = None
    for phase in ("prepared", "admitted", "running", "succeeded"):
        head = operations.journal(tmp_path, path, prior, phase, predecessor=head)
    value["expected_predecessor"] = head
    operations.journal(tmp_path, path, value, "prepared", predecessor=head)
    raw["operation"] = operations.encoded(value)

    def manifest(request, checkpoint_hash):
        return dict(
            schema_version=2,
            unit=unit,
            stack=context.contract.stack_identity,
            operation_id=request["operation_id"],
            commit=COMMIT,
            request_sha256=operations.digest(request),
            configuration_sha256=c.digest(cfg),
            checkpoint_sha256=checkpoint_hash,
            repository_id="d" * 64,
            source_host_id="e" * 64,
            source_exported_at=earlier,
            captured_at=earlier,
        )

    old = dict(value, operation_id="32345678-1234-4234-8234-123456789abc")
    current_manifest = manifest(value, c.digest(raw["current_checkpoint"]))
    restore_manifest = manifest(old, c.digest(checkpoint))
    for prefix, doc in (("backup", current_manifest), ("restore", restore_manifest)):
        raw[prefix + "_manifest"] = operations.encoded(doc)
        raw[prefix + "_receipt"] = operations.encoded(
            dict(
                schema_version=1,
                repository_id="d" * 64,
                manifest_sha256=c.digest(raw[prefix + "_manifest"]),
                snapshot_id=("a" if prefix == "backup" else "b") * 64,
                completed_at=earlier,
            )
        )
    objectives = dict(
        schema_version=1,
        max_backup_age_seconds=3600,
        restore_objective_seconds=120,
        require_independent_host=True,
    )
    raw["restore_policy"] = operations.encoded(objectives)
    raw["rehearsal"] = operations.encoded(
        dict(
            schema_version=2,
            kind="off-host",
            recovery_host_id="f" * 64,
            **{
                k: restore_manifest[k]
                for k in (
                    "unit",
                    "stack",
                    "operation_id",
                    "checkpoint_sha256",
                    "configuration_sha256",
                    "source_host_id",
                )
            },
            policy_sha256=operations.digest(objectives),
            snapshot_id="b" * 64,
            manifest_sha256=c.digest(raw["restore_manifest"]),
            started_at=earlier,
            completed_at=earlier,
            backup_age_seconds=0,
            restore_seconds=0,
            objectives_met=True,
            wrong_key_rejected=True,
            correct_key_readback=True,
            execution_authorized=False,
        )
    )
    raw["credential_review"] = operations.encoded(
        dict(
            schema_version=1,
            unit=unit,
            checkpoint_sha256=c.digest(checkpoint),
            configuration_sha256=c.digest(cfg),
            read_only_scopes_reviewed=True,
            historical_provider_credentials_reviewed=True,
            provider_identity_sha256=operations.digest(
                dict(OCI_USER_OCID="user", OCI_FINGERPRINT="fingerprint")
            )
            if unit.startswith("oci-")
            else None,
            reviewed_at=earlier,
            expires_at=expires,
        )
    )
    if unit.startswith("oci-"):
        peer = deepcopy(state)
        peer_unit = "oci-network" if unit == "oci-oke" else "oci-oke"
        peer["deployment"]["resources"] = [
            dict(
                type="pulumi:pulumi:Stack",
                urn="urn:pulumi:"
                + peer_unit
                + "::free-infrastructure::pulumi:pulumi:Stack::free-infrastructure-"
                + peer_unit,
                outputs=test_oci_dependency.committed(context.configuration)
                if unit == "oci-oke"
                else {},
            )
        ]
        raw["peer_checkpoint"] = operations.encoded(peer)
        raw["owner_checkpoint"] = checkpoint
        artifacts = {n: "e" * 64 for n in ownership_handoff.ARTIFACTS - ownership_handoff.EXCLUDED}
        artifacts["network_checkpoint" if unit == "oci-network" else "oke_checkpoint"] = c.digest(
            checkpoint
        )
        raw["owner_subject"] = operations.encoded(dict(schema_version=1, artifacts=artifacts))
        owner = dict(
            schema_version=1,
            handoff_id="42345678-1234-4234-8234-123456789abc",
            actor="owner",
            environment="oci-handoff",
            commit=COMMIT,
            evidence_sha256=operations.digest(artifacts),
            handoff_policy_sha256="b" * 64,
            operation_policy_sha256=c.digest(policy_raw),
            foundation_sha256=context.foundation.digest,
            issued_at=(now - timedelta(days=1)).isoformat(),
            expires_at=(now - timedelta(days=1) + timedelta(minutes=5)).isoformat(),
        )
        raw["owner_approval"] = operations.encoded(owner)
        raw.update(
            {
                "owner_" + role: proof
                for role, proof in signed(
                    raw["owner_approval"], keys, ownership_handoff.PAYLOAD_TYPE
                ).items()
            }
        )
        raw["owner_decision"] = operations.encoded(
            dict(
                schema_version=1,
                status="target-owner-admitted",
                target_owner_admitted=True,
                admitted_owner="pulumi",
                observed_active_writer="none",
                handoff_id=owner["handoff_id"],
                expires_at=owner["expires_at"],
                approval_sha256=c.digest(raw["owner_approval"]),
                resource_execution_authorized=False,
                writer_activation_authorized=False,
                cutover_authorized=False,
            )
        )
    if dependency is not None:
        raw["dependency_outputs"] = dependency
    raw["freeze"] = operations.encoded(
        dict(
            schema_version=1,
            subject_sha256=c.subject(raw),
            frozen_at=earlier,
            observed_at=earlier,
            expires_at=expires,
            writers={
                u: dict(
                    owner="pulumi", source_active=False, target_active=False, active_operations=0
                )
                for u in ({"oci-network", "oci-oke"} if unit.startswith("oci-") else {unit})
            },
        )
    )
    destination = ".infra/recovery/configs/" + unit + "/" + value["operation_id"] + ".json"
    (tmp_path / destination).parent.mkdir(parents=True)
    raw["plan"] = c.plan(raw, destination)
    responses = administration_responses(
        dict(
            policy,
            environment=unit + "-recovery",
            required_checks=[],
            workflow=dict(id=1, path=".github/workflows/verify.yml"),
        ),
        COMMIT,
    )
    responses["environment"]["can_admins_bypass"] = False
    env = dict(
        schema_version=1,
        commit=COMMIT,
        started_at=earlier,
        completed_at=earlier,
        responses={k: responses[k] for k in ("repository", "branch", "environment", "branches")},
    )
    raw["environment"] = operations.encoded(env)
    bundle = dict(
        schema_version=1,
        paths={},
        backend_account_id="fixture",
        cli_archive=".infra/cli",
        provider_home=".infra/providers",
        repository=str(tmp_path.parent / (tmp_path.name + "-repository")),
        configuration_destination=destination,
        output=".infra/result.json",
    )
    Path(bundle["repository"]).mkdir()
    args = argparse.Namespace(
        unit=unit,
        commit=COMMIT,
        actor="requester",
        environment=unit + "-recovery",
        journal=path,
        bundle=tmp_path / ".infra/bundle.json",
        check=False,
        allow_state_writes=True,
    )
    journal = path.read_bytes()
    captured = []
    real = admission.admit
    monkeypatch.setattr(admission, "admit", lambda *a, **kw: captured.append(kw))
    r.admit(tmp_path, args, bundle, raw, journal)
    monkeypatch.setattr(admission, "admit", real)
    binding = captured[0]["execution_inputs"]
    expected = captured[0]["context"]
    approval = dict(
        schema_version=2,
        operation_id=value["operation_id"],
        **expected,
        request_sha256=c.digest(raw["operation"]),
        policy_sha256=c.digest(policy_raw),
        backup_sha256=c.digest(raw["backup_receipt"]),
        environment_sha256=c.digest(raw["environment"]),
        execution_inputs_sha256=c.digest(binding),
        issued_at=datetime.now(UTC).isoformat(),
        expires_at=expires,
    )
    raw["approval"] = operations.encoded(approval)
    raw.update(signed(raw["approval"], keys, admission.PAYLOAD_TYPE))
    for name, data in raw.items():
        bundle["paths"][name] = ".infra/" + name + ".json"
        (tmp_path / bundle["paths"][name]).write_bytes(data)
    args.bundle.write_text(json.dumps(bundle))
    return tmp_path, args, bundle, raw, journal, context


def test_full_signed_recovery_admission_reuses_context_and_action(prepared):
    root, args, bundle, raw, journal, context = prepared
    assert r.admit(root, args, bundle, raw, journal) == context
    assert operations.inspect_journal(args.journal)["state"] == "prepared"
    changed = dict(
        raw, operation=operations.encoded(dict(json.loads(raw["operation"]), operation="apply"))
    )
    with pytest.raises(ValueError):
        r.admit(root, args, bundle, changed, journal)


def test_admitted_recovery_approval_cannot_be_replayed(prepared):
    root, args, bundle, raw, journal, _ = prepared
    head = operations.inspect_journal(args.journal)["head"]
    operations.journal(
        root, args.journal, json.loads(raw["operation"]), "admitted", predecessor=head
    )
    with pytest.raises(ValueError):
        r.admit(root, args, bundle, raw, args.journal.read_bytes())


@pytest.mark.parametrize(
    "fault",
    [
        "snapshot",
        "scope",
        "key-review",
        "active-writer",
        "freeze-age",
        "rpo",
        "rto",
        "host",
        "owner",
        "props",
    ],
)
def test_changed_frozen_inputs_fail_before_credentials(prepared, fault):
    root, args, bundle, raw, journal, _ = prepared
    if fault == "snapshot":
        raw["restore_checkpoint"] += b" "
    elif fault == "scope":
        value = json.loads(raw["restore_checkpoint"])
        value["deployment"]["resources"][0]["urn"] = "foreign"
        raw["restore_checkpoint"] = operations.encoded(value)
    elif fault == "key-review":
        value = json.loads(raw["credential_review"])
        value["read_only_scopes_reviewed"] = False
        raw["credential_review"] = operations.encoded(value)
    elif fault == "active-writer":
        value = json.loads(raw["freeze"])
        next(iter(value["writers"].values()))["target_active"] = True
        raw["freeze"] = operations.encoded(value)
    elif fault == "freeze-age":
        value = json.loads(raw["freeze"])
        value["observed_at"] = "2020-01-01T00:00:00+00:00"
        raw["freeze"] = operations.encoded(value)
    elif fault in {"rpo", "rto"}:
        value = json.loads(raw["restore_policy"])
        value["max_backup_age_seconds" if fault == "rpo" else "restore_objective_seconds"] = 0
        raw["restore_policy"] = operations.encoded(value)
    elif fault == "host":
        value = json.loads(raw["rehearsal"])
        value["recovery_host_id"] = "0" * 64
        raw["rehearsal"] = operations.encoded(value)
    elif fault == "owner":
        if args.unit.startswith("oci-"):
            raw["owner_operator"] = raw["operator"]
        else:
            entries = json.loads(journal)
            entries[0]["request"]["operation"] = "import"
            journal = operations.encoded(entries)
    else:
        value = json.loads(raw["restore_checkpoint"])
        native = next(
            v
            for v in value["deployment"]["resources"]
            if v["type"].startswith(("oci:", "cloudflare:", "supabase:"))
        )
        native["inputs"] = {"writeOnlySecret": "changed"}
        raw["restore_checkpoint"] = operations.encoded(value)
    with pytest.raises((ValueError, KeyError)):
        r.admit(root, args, bundle, raw, journal)


def test_recorded_secret_properties_cannot_be_rolled_back(case):
    context, *_ = case
    before = test_drift.checkpoint(context)
    after = deepcopy(before)
    native = next(
        v
        for v in after["deployment"]["resources"]
        if v["type"].startswith(("oci:", "cloudflare:", "supabase:"))
    )
    native["outputs"] = {"password": "changed"}
    with pytest.raises(ValueError):
        c.unchanged_resources(before, after)


def test_default_disabled_and_check_never_loads_keys(monkeypatch, tmp_path):
    with pytest.raises(ValueError):
        r.execute(ROOT, argparse.Namespace(), lambda: pytest.fail("keys"))
    monkeypatch.setattr(r, "check", lambda *a: ({}, {}, b"prepared"))
    r.execute(tmp_path, argparse.Namespace(check=True), lambda: pytest.fail("keys"))
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "credentials",
        "snapshot",
        "key",
        "pre-drift",
        "source-change",
        "peer-change",
        "input-change",
        "local-change",
        "restore",
        "publish",
        "post-drift",
        "post-input",
        "state-mismatch",
    ],
)
def test_frozen_lifecycle_outcomes_and_no_compensation(prepared, monkeypatch, fault):
    import hashlib
    from types import SimpleNamespace

    root, args, bundle, raw, journal, context = prepared
    (root / ".infra/tools/uv").mkdir(parents=True)
    (root / ".infra/tools/uv/uv").write_bytes(b"uv")
    (root / "config/toolchain.json").write_text(
        json.dumps(
            dict(
                tools=dict(
                    uv=dict(
                        assets={"linux-x64": dict(binary_sha256=hashlib.sha256(b"uv").hexdigest())}
                    )
                )
            )
        )
    )
    monkeypatch.setattr(r, "admit", lambda *a: context)
    monkeypatch.setattr(r.shared, "_current_environment", lambda *a: None)
    monkeypatch.setattr(r, "cli_runtime", lambda *a: SimpleNamespace(verify=lambda: None))
    monkeypatch.setattr(r, "materialize_home", lambda *a, **kw: {})
    monkeypatch.setattr(r, "verified_environment", lambda *a: None)
    monkeypatch.setattr(r, "verified_supabase_environment", lambda *a: None)
    monkeypatch.setattr(r.preview, "_prepare", lambda *a: (context, {}, None))
    monkeypatch.setattr(r.preview, "_request", lambda *a: b"context")
    events = []

    def retrieve(*a):
        if fault == "snapshot":
            raise ValueError("PRIVATE")

    monkeypatch.setattr(r, "retrieve", retrieve)

    class Writer:
        def __init__(self, cli, work, env, stack, deadline, backend):
            assert "AWS_ACCESS_KEY_ID" in env and not any(k.startswith("OCI_") for k in env)
            assert env["PULUMI_BACKEND_URL"] == backend
            self.restored = False
            self.exports = 0
            self.peers = 0

        def export(self, stack=None):
            if stack is not None:
                self.peers += 1
                return (
                    b"changed"
                    if fault == "peer-change" and self.peers > 1
                    else raw["peer_checkpoint"]
                )
            self.exports += 1
            if fault == "source-change" and not self.restored and self.exports > 1:
                return b"changed"
            return raw["restore_checkpoint"] if self.restored else raw["current_checkpoint"]

        def restore(self, path):
            events.append("restore")
            assert operations.inspect_journal(args.journal)["state"] == "running"
            assert path.read_bytes() == raw["restore_checkpoint"]
            self.restored = True
            if fault == "restore":
                raise ValueError("PRIVATE partial write")

    class Observer:
        def __init__(self, cli, work, env, *a):
            assert not any(k.startswith("AWS_") for k in env)
            self.after = work.name == "after"
            self.count = 0

        def load(self, unit, checkpoint):
            if unit != args.unit:
                assert len(json.loads(checkpoint)["deployment"]["resources"]) == 1

        def checkpoint(self):
            self.count += 1
            return str(self.count) if fault == "local-change" else "baseline"

        def key_check(self):
            self.verified_deployment_sha256 = (
                "changed" if fault == "state-mismatch" and self.after else "verified"
            )
            if fault == "key":
                raise ValueError("PRIVATE incorrect passphrase")

        def refresh(self):
            events.append("after-refresh" if self.after else "before-refresh")
            if fault == "input-change" and not self.after:
                (root / bundle["paths"]["proposal"]).write_bytes(b"changed")
            return dict(
                resource_changes={"update": 1}
                if (fault == "pre-drift" and not self.after)
                or (fault == "post-drift" and self.after)
                else {"same": 2}
            )

        def compare(self):
            if fault == "post-input" and self.after:
                (root / bundle["paths"]["proposal"]).write_bytes(b"changed")
            return dict(resource_changes={"same": 2})

    monkeypatch.setattr(r, "Writer", Writer)
    monkeypatch.setattr(r, "Observer", Observer)
    original = r.publish

    def publish(path, payload):
        if fault == "publish" and path == root / bundle["configuration_destination"]:
            raise OSError("PRIVATE")
        original(path, payload)

    monkeypatch.setattr(r, "publish", publish)

    def credentials():
        assert operations.inspect_journal(args.journal)["state"] == "admitted"
        if fault == "credentials":
            raise ValueError("PRIVATE")
        values = dict(
            AWS_ACCESS_KEY_ID="key",
            AWS_SECRET_ACCESS_KEY="secret",
            RECOVERY_PASSPHRASE="synthetic-long-recovery-passphrase",
            RECOVERY_BACKUP_PASSWORD="password",
        )
        if args.unit.startswith("oci-"):
            path = root / ".infra/key.pem"
            path.write_bytes(b"synthetic-private-key")
            values.update(
                OCI_USER_OCID="user", OCI_FINGERPRINT="fingerprint", OCI_PRIVATE_KEY_PATH=str(path)
            )
        return values

    report = r._recover(root, args, bundle, raw, journal, credentials)
    outcome = (
        "succeeded"
        if fault is None or (fault == "peer-change" and not args.unit.startswith("oci-"))
        else "indeterminate"
        if fault in {"restore", "publish", "post-drift", "post-input", "state-mismatch"}
        else "failed"
    )
    assert report["status"] == operations.inspect_journal(args.journal)["state"] == outcome
    assert (
        report["writer_release_authorized"]
        is report["resource_operations_authorized"]
        is report["freeze_release_attempted"]
        is False
    )
    assert report["reconciliation_verified"] is (outcome == "succeeded")
    assert events.count("restore") == int(outcome in {"succeeded", "indeterminate"})
    assert json.loads((root / bundle["output"]).read_bytes()) == report
    assert "PRIVATE" not in json.dumps(report)
    assert not list((root / ".infra").glob("state-recovery-*"))
    if outcome == "succeeded":
        assert (root / bundle["configuration_destination"]).read_bytes() == raw[
            "restore_configuration"
        ]
        assert events == ["before-refresh", "restore", "after-refresh"]


@pytest.mark.parametrize("fault", [None, "event", "branch", "actor", "commit", "environment"])
def test_cli_requires_explicit_protected_recovery_context(monkeypatch, fault):
    args = argparse.Namespace(
        unit="oci-network", commit=COMMIT, actor="owner", environment="oci-network-recovery"
    )
    for key, value in dict(
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/main",
        GITHUB_SHA=COMMIT,
        GITHUB_ACTOR="owner",
        GITHUB_REPOSITORY_OWNER="owner",
    ).items():
        monkeypatch.setenv(key, value)
    if fault in {"event", "branch", "actor", "commit"}:
        monkeypatch.setenv(
            dict(
                event="GITHUB_EVENT_NAME",
                branch="GITHUB_REF",
                actor="GITHUB_ACTOR",
                commit="GITHUB_SHA",
            )[fault],
            "wrong",
        )
    elif fault == "environment":
        args.environment = "oci-network-apply"
    calls = []
    monkeypatch.setattr(r, "execute", lambda *a: calls.append(a))
    if fault:
        with pytest.raises(ValueError):
            cli._recovery(ROOT, args)
        assert not calls
    else:
        cli._recovery(ROOT, args)
        assert len(calls) == 1


def test_workflow_keeps_cloud_keys_out_of_preflight_and_preserves_journal():
    import yaml

    workflow = yaml.load(
        (ROOT / ".github/workflows/state-recovery.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert (
        workflow["permissions"] == {"contents": "read"}
        and workflow["concurrency"]["cancel-in-progress"] == "false"
    )
    job = workflow["jobs"]["recover"]
    assert job["needs"] == "verify" and job["runs-on"]["group"] == "recovery"
    assert job["steps"][0]["with"]["clean"] == "false"
    preflight = next(s for s in job["steps"] if "--check" in s.get("run", ""))
    assert set(preflight["env"]) == {"GH_TOKEN"}
    assert "writer-release" not in str(workflow) and "--force" not in str(workflow)
