"""Paired signed handoff, real pure validators, and no state/writer side effects."""

import base64
import hashlib
import json
import shutil
import tomllib
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_import_driver
import test_oci
import test_oci_dependency
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from evidence_helpers import administration_responses
from infra_core import cli, cutover, operations, ownership
from infra_core import ownership_handoff as handoff
from infra_core.foundation import load_foundation
from infra_core.inventory_evidence import capture_inventory
from infra_core.network_outputs import network_digest
from infra_core.preview_contracts import describe_preview
from infra_core.preview_results import POLICY_SOURCES, create_preview_result
from infra_core.review_signatures import preauth
from preview_graph_helpers import oci_events

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
config = test_oci.config


@pytest.fixture
def bundle(tmp_path, config, monkeypatch):
    private = tmp_path / ".infra"
    private.mkdir()
    cases = {}
    for prefix in ("network", "oke"):
        directory = private / "captures" / prefix
        directory.mkdir(parents=True)
        cases[prefix] = test_import_driver.case.__wrapped__(
            SimpleNamespace(param="oci-" + prefix), config, directory, monkeypatch
        )
    source = cases["network"].root
    for directory in ("config", "packages", "policies"):
        shutil.copytree(source / directory, tmp_path / directory)
    for filename in ("pyproject.toml", "uv.lock", ".python-version"):
        shutil.copyfile(source / filename, tmp_path / filename)
    now = datetime.now(UTC) + timedelta(seconds=180)

    def stamp(seconds):
        return (now + timedelta(seconds=seconds)).isoformat()

    raw = {}
    paths = {}
    doc = dict(
        schema_version=1,
        handoff_id="52345678-1234-4234-8234-123456789abc",
        commit=COMMIT,
        artifacts={},
    )

    def write(name, value):
        content = value if isinstance(value, bytes) else operations.encoded(value)
        path = paths.get(name, private / (name + ".json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        paths[name] = path
        raw[name] = content
        doc["artifacts"][name] = dict(path=str(path), sha256=hashlib.sha256(content).hexdigest())

    write("configuration", cases["network"].raw["configuration"])
    outputs = test_oci_dependency.committed(config)
    write("network_outputs", outputs)
    for index, (prefix, case) in enumerate(cases.items()):
        initial = case.doc
        source_state = json.loads(case.raw["source_checkpoint"])
        initial["source"].update(
            workspace=prefix, lineage=str(index + 6) + "2345678-1234-4234-8234-123456789abc"
        )
        source_state["lineage"] = initial["source"]["lineage"]
        case.write("source_checkpoint", source_state)
        req = json.loads(case.raw["request"])
        req.update(
            operation_id=str(index + 1) + "2345678-1234-4234-8234-123456789abc",
            expires_at=stamp(300),
        )
        case.write("request", req)
        prepared = [dict(request=req, state="prepared", previous=None, at=stamp(-120))]
        case.write("journal", prepared)
        initial["artifacts"]["journal"]["path"] = ".infra/operations/oci-" + prefix + ".json"
        oldfreeze = json.loads(case.raw["freeze"])
        oldfreeze.update(
            frozen_at=stamp(-110),
            checkpointed_at=stamp(-105),
            observed_at=stamp(-100),
            expires_at=stamp(200),
        )
        oldfreeze["writers"][0]["identity_sha256"] = operations.digest(initial["source"])
        oldfreeze["binding_sha256"] = ownership.preparation_binding(
            initial,
            req,
            case.raw,
            foundation_sha256=load_foundation(tmp_path).digest,
            journal_head=operations.digest(prepared[-1]),
        )
        case.write("freeze", oldfreeze)
        for name, ref in initial["artifacts"].items():
            if name != "journal":
                ref["path"] = str(case.paths[name])
        write(prefix + "_preparation", initial)
        write(prefix + "_prepared_journal", prepared)
        case.inputs["ownership"] = operations.encoded(initial)
        post = json.loads(test_import_driver.imported_checkpoint(case))
        if prefix == "oke":
            reference = next(
                r
                for r in post["deployment"]["resources"]
                if r["type"] == "pulumi:pulumi:StackReference"
            )
            reference["outputs"] = dict(outputs=outputs, secretOutputNames=[])
        write(prefix + "_checkpoint", post)
        started, ended = (-90, -80) if prefix == "network" else (-70, -60)
        entries = list(prepared)
        for stage, second in (
            ("admitted", started - 5),
            ("running", started),
            ("succeeded", ended),
        ):
            entries.append(
                dict(
                    request=req,
                    state=stage,
                    previous=operations.digest(entries[-1]),
                    at=stamp(second),
                )
            )
        paths[prefix + "_journal"] = private / "operations" / ("oci-" + prefix + ".json")
        write(prefix + "_journal", entries)
        receipt = dict(
            schema_version=1,
            operation_id=req["operation_id"],
            status="succeeded",
            resource_changes={"import": len(case.graph)},
            journal_head=operations.digest(entries[-1]),
            approval_sha256="b" * 64,
            plan_sha256="c" * 64,
            post_import_equivalent=True,
            checkpoint_sha256=hashlib.sha256(raw[prefix + "_checkpoint"]).hexdigest(),
        )
        if prefix == "network":
            receipt["dependency_outputs_sha256"] = network_digest(outputs)
        write(prefix + "_import_receipt", receipt)
        released = dict(source_state, serial=8, resources=[])
        write(prefix + "_released_source", released)
        backup_request = dict(
            req,
            operation="recovery",
            operation_id=str(index + 3) + "2345678-1234-4234-8234-123456789abc",
            checkpoint_sha256=receipt["checkpoint_sha256"],
        )
        write(prefix + "_backup_request", backup_request)
        manifest = dict(
            schema_version=2,
            operation_id=backup_request["operation_id"],
            request_sha256=operations.digest(backup_request),
            unit=req["unit"],
            stack=initial["target_stack"],
            commit=COMMIT,
            repository_id="d" * 64,
            configuration_sha256=req["configuration_sha256"],
            checkpoint_sha256=receipt["checkpoint_sha256"],
            source_exported_at=stamp(-58),
            captured_at=stamp(-57),
            source_host_id="e" * 64,
        )
        write(prefix + "_backup_manifest", manifest)
        backup_receipt = dict(
            schema_version=1,
            manifest_sha256=hashlib.sha256(raw[prefix + "_backup_manifest"]).hexdigest(),
            repository_id="d" * 64,
            snapshot_id="f" * 64,
            completed_at=stamp(-56),
        )
        write(prefix + "_backup_receipt", backup_receipt)
        settings = dict(
            schema_version=1,
            max_backup_age_seconds=300,
            restore_objective_seconds=30,
            require_independent_host=True,
        )
        write(prefix + "_recovery_policy", settings)
        rehearsal = dict(
            schema_version=2,
            policy_sha256=hashlib.sha256(operations.encoded(settings)).hexdigest(),
            kind="off-host",
            snapshot_id="f" * 64,
            manifest_sha256=backup_receipt["manifest_sha256"],
            backup_age_seconds=8,
            restore_seconds=5,
            objectives_met=True,
            wrong_key_rejected=True,
            correct_key_readback=True,
            execution_authorized=False,
            unit=req["unit"],
            stack=initial["target_stack"],
            operation_id=backup_request["operation_id"],
            configuration_sha256=req["configuration_sha256"],
            checkpoint_sha256=receipt["checkpoint_sha256"],
            source_host_id="e" * 64,
            recovery_host_id="a" * 64,
            started_at=stamp(-55),
            completed_at=stamp(-50),
        )
        write(prefix + "_recovery_receipt", rehearsal)
        account, _, inventory = test_oci.evidence()
        profile = tomllib.loads((tmp_path / "config/quotas/profiles.toml").read_text())["profiles"][
            "oci-free"
        ]
        observed, envelope = capture_inventory(account, profile, inventory, commit=COMMIT)
        artifacts = dict(
            account=operations.encoded(account),
            profile=operations.encoded(profile),
            evidence=observed,
            envelope=envelope,
            toolchain=(tmp_path / "config/toolchain.json").read_bytes(),
            provider_toolchain=(tmp_path / "config/provider-toolchain.json").read_bytes(),
            policy=operations.encoded(
                {p: hashlib.sha256((tmp_path / p).read_bytes()).hexdigest() for p in POLICY_SOURCES}
            ),
            proposal=operations.encoded(
                dict(
                    configuration=asdict(config),
                    stack_configuration=json.loads(case.raw["encrypted_configuration"]),
                )
            ),
        )
        if prefix == "oke":
            artifacts["dependency_outputs"] = operations.encoded(outputs)
        contract = describe_preview(load_foundation(tmp_path), "oci-" + prefix, COMMIT)

        def event(kind, body, sequence):
            return operations.encoded(
                dict(
                    sequence=sequence,
                    timestamp=int((now - timedelta(seconds=25)).timestamp()),
                    **{kind: body},
                )
            )

        events = [
            event(
                "policyAnalyzeSummaryEvent",
                dict(policyPackName="always-free-governance", passed=["reviewed-resource-costs"]),
                0,
            ),
            event(
                "summaryEvent",
                dict(
                    isPreview=True,
                    result="succeeded",
                    maybeCorrupt=False,
                    resourceChanges={"same": len(case.graph)},
                    PolicyPacks={"always-free-governance": "local"},
                ),
                1,
            ),
            event("cancelEvent", {}, 2),
        ]
        events = [
            event(kind, body, n)
            for n, (kind, body) in enumerate(
                oci_events("oci-" + prefix, config, account, outputs if prefix == "oke" else None)
                + [
                    (
                        next(k for k in json.loads(record) if k.endswith("Event")),
                        next(v for k, v in json.loads(record).items() if k.endswith("Event")),
                    )
                    for record in events
                ]
            )
        ]
        preview = create_preview_result(
            contract,
            artifacts,
            events,
            exit_code=0,
            started_at=stamp(-30),
            completed_at=stamp(-20),
            now=now,
        )
        write(prefix + "_preview", preview)
        write(
            prefix + "_preview_inputs",
            dict(
                checkpoint_sha256=receipt["checkpoint_sha256"],
                artifacts={n: v.hex() for n, v in artifacts.items()},
            ),
        )
    keys = {role: Ed25519PrivateKey.generate() for role in ("operator", "approver")}
    policy = dict(
        schema_version=1,
        enabled=True,
        repository="example/infra",
        repository_id=123,
        max_approval_age_seconds=300,
        max_backup_age_seconds=300,
        environments={"handoff/oci": "oci-handoff"},
        reviewers=[
            dict(
                principal=role,
                roles=[role],
                public_key=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
            )
            for role, key in keys.items()
        ],
    )
    (tmp_path / "config/operations-policy.json").write_bytes(operations.encoded(policy))
    settings = dict(schema_version=1, enabled=True, max_evidence_age_seconds=300)
    (tmp_path / "config/ownership-handoff.json").write_bytes(operations.encoded(settings))
    responses = administration_responses(
        dict(
            policy,
            environment="oci-handoff",
            required_checks=[],
            workflow=dict(id=1, path=".github/workflows/verify.yml"),
        ),
        COMMIT,
    )
    responses["environment"]["can_admins_bypass"] = False
    write(
        "environment",
        dict(
            schema_version=1,
            commit=COMMIT,
            started_at=stamp(-15),
            completed_at=stamp(-5),
            responses={
                n: responses[n] for n in ("repository", "branch", "environment", "branches")
            },
        ),
    )

    def seal():
        scope = handoff.scope_digest(doc, raw)
        write(
            "release",
            dict(
                schema_version=1,
                handoff_id=doc["handoff_id"],
                scope_sha256=scope,
                source_released=True,
                source_writer_disabled=True,
                completed_at=stamp(-40),
            ),
        )
        write(
            "freeze",
            dict(
                schema_version=1,
                handoff_id=doc["handoff_id"],
                scope_sha256=scope,
                complete=True,
                continuous_freeze=True,
                other_writers_reviewed=True,
                live_equivalence_reviewed=True,
                observed_at=stamp(-10),
                expires_at=stamp(120),
                writers=[
                    dict(
                        unit="oci-" + p,
                        source_identity_sha256=operations.digest(c.doc["source"]),
                        source_active=False,
                        target_active=False,
                        active_operations=0,
                        frozen_at=stamp(-115),
                    )
                    for p, c in cases.items()
                ],
            ),
        )
        sign()

    def sign():
        approval = dict(
            schema_version=1,
            handoff_id=doc["handoff_id"],
            actor="requester",
            environment="oci-handoff",
            commit=COMMIT,
            evidence_sha256=operations.digest(
                {
                    n: hashlib.sha256(v).hexdigest()
                    for n, v in sorted(raw.items())
                    if n not in handoff.EXCLUDED
                }
            ),
            handoff_policy_sha256=hashlib.sha256(
                (tmp_path / "config/ownership-handoff.json").read_bytes()
            ).hexdigest(),
            operation_policy_sha256=hashlib.sha256(
                (tmp_path / "config/operations-policy.json").read_bytes()
            ).hexdigest(),
            foundation_sha256=load_foundation(tmp_path).digest,
            issued_at=stamp(-1),
            expires_at=stamp(60),
        )
        write("approval", approval)
        for role, key in keys.items():
            write(
                role,
                dict(
                    payloadType=handoff.PAYLOAD_TYPE,
                    payload=base64.b64encode(raw["approval"]).decode(),
                    signatures=[
                        dict(
                            sig=base64.b64encode(
                                key.sign(preauth(raw["approval"], handoff.PAYLOAD_TYPE))
                            ).decode()
                        )
                    ],
                ),
            )

    seal()
    monkeypatch.setattr(handoff, "repository_state", lambda root: (COMMIT, True))
    return SimpleNamespace(
        root=tmp_path,
        doc=doc,
        raw=raw,
        paths=paths,
        write=write,
        seal=seal,
        sign=sign,
        now=now,
        keys=keys,
        policy=policy,
        cases=cases,
        stamp=stamp,
    )


def test_signed_handoff_admits_owner_without_activating_writers_or_writing(bundle):
    before = {p: p.read_bytes() for p in bundle.root.rglob("*") if p.is_file()}
    result = cutover.handoff(
        bundle.root, bundle.doc, actor="requester", environment="oci-handoff", now=bundle.now
    )
    assert result["target_owner_admitted"] is True and result["observed_active_writer"] == "none"
    assert all(
        result[n] is False
        for n in (
            "resource_execution_authorized",
            "writer_activation_authorized",
            "cutover_authorized",
        )
    )
    assert before == {p: p.read_bytes() for p in before}
    assert "synthetic-id" not in json.dumps(result)
    assert "PRIVATE_CHECKPOINT_SENTINEL" not in json.dumps(result)


def test_default_disabled_handoff_does_not_open_artifacts():
    with pytest.raises(ValueError, match="HANDOFF001"):
        cutover.handoff(ROOT, {}, actor="owner", environment="oci-handoff")


def decide(bundle, **kwargs):
    return cutover.handoff(
        bundle.root,
        bundle.doc,
        actor="requester",
        environment="oci-handoff",
        now=bundle.now,
        **kwargs,
    )


@pytest.mark.parametrize(
    "fault",
    [
        "release-before-freeze",
        "not-released",
        "source-active",
        "target-active",
        "unknown-writer",
        "duplicate-writer",
        "missing-writer",
        "not-continuous",
        "missing-live-review",
        "stale-freeze",
    ],
)
def test_release_and_single_writer_order_cannot_be_waived_by_valid_signatures(bundle, fault):
    role = "release" if fault in {"release-before-freeze", "not-released"} else "freeze"
    value = json.loads(bundle.raw[role])
    if fault == "release-before-freeze":
        value["completed_at"] = bundle.stamp(-115)
    elif fault == "not-released":
        value["source_released"] = False
    elif fault in {"source-active", "target-active"}:
        value["writers"][0][fault.replace("-", "_")] = True
    elif fault == "unknown-writer":
        value["writers"][0]["unit"] = "other"
    elif fault == "duplicate-writer":
        value["writers"][1] = value["writers"][0]
    elif fault == "missing-writer":
        value["writers"].pop()
    elif fault == "not-continuous":
        value["continuous_freeze"] = False
    elif fault == "missing-live-review":
        value["live_equivalence_reviewed"] = False
    else:
        value["expires_at"] = bundle.stamp(-1)
    bundle.write(role, value)
    bundle.sign()
    with pytest.raises(ValueError, match="HANDOFF001"):
        decide(bundle)


@pytest.mark.parametrize(
    "fault",
    [
        "source-owner-remains",
        "renamed-source-owner",
        "changed-target",
        "preview-drift",
        "wrong-network-outputs",
        "same-host",
        "wrong-key",
        "failed-recovery",
        "old-recovery",
        "recovery-scope",
        "RTO",
        "failed-import",
        "indeterminate-import",
        "reversed-imports",
    ],
)
def test_handoff_rejects_changed_scope_drift_recovery_and_partial_import(bundle, fault):
    role = "network_released_source"
    if fault in {"source-owner-remains", "renamed-source-owner"}:
        value = json.loads(bundle.raw[role])
        original = json.loads(bundle.cases["network"].raw["source_checkpoint"])
        value["resources"] = original["resources"]
        if fault == "renamed-source-owner":
            for record in value["resources"]:
                record["name"] += "renamed"
    elif fault == "changed-target":
        role = "oke_checkpoint"
        value = json.loads(bundle.raw[role])
        value["deployment"]["resources"][-1]["id"] = "other"
    elif fault == "preview-drift":
        role = "network_preview"
        value = json.loads(bundle.raw[role])
        value["resource_changes"] = {"update": 1}
    elif fault == "wrong-network-outputs":
        role = "network_outputs"
        value = json.loads(bundle.raw[role])
        value["network"]["ids"]["vcn"] += "other"
    elif fault in {
        "same-host",
        "wrong-key",
        "failed-recovery",
        "old-recovery",
        "recovery-scope",
        "RTO",
    }:
        role = "oke_recovery_receipt"
        value = json.loads(bundle.raw[role])
        field = {
            "same-host": "recovery_host_id",
            "wrong-key": "wrong_key_rejected",
            "failed-recovery": "objectives_met",
            "old-recovery": "schema_version",
            "recovery-scope": "checkpoint_sha256",
            "RTO": "restore_seconds",
        }[fault]
        value[field] = {
            "same-host": value["source_host_id"],
            "wrong-key": False,
            "failed-recovery": False,
            "old-recovery": 1,
            "recovery-scope": "0" * 64,
            "RTO": 31,
        }[fault]
    else:
        role = "network_journal"
        value = json.loads(bundle.raw[role])
        if fault == "reversed-imports":
            value[-1]["at"] = bundle.stamp(-65)
        else:
            value[-1]["state"] = "failed" if fault == "failed-import" else "indeterminate"
        receipt = json.loads(bundle.raw["network_import_receipt"])
        receipt["journal_head"] = operations.digest(value[-1])
        bundle.write("network_import_receipt", receipt)
    bundle.write(role, value)
    bundle.seal()
    with pytest.raises(ValueError, match="HANDOFF001"):
        decide(bundle)


def resign_actual(bundle):
    for role, key in bundle.keys.items():
        bundle.write(
            role,
            dict(
                payloadType=handoff.PAYLOAD_TYPE,
                payload=base64.b64encode(bundle.raw["approval"]).decode(),
                signatures=[
                    dict(
                        sig=base64.b64encode(
                            key.sign(preauth(bundle.raw["approval"], handoff.PAYLOAD_TYPE))
                        ).decode()
                    )
                ],
            ),
        )


@pytest.mark.parametrize(
    "fault", ["wrong-type", "wrong-role", "changed-approval", "expired", "requester-is-signer"]
)
def test_role_bound_signatures_and_expiry(bundle, fault):
    if fault == "wrong-type":
        value = json.loads(bundle.raw["operator"])
        value["payloadType"] = "application/vnd.cloud-infra.operation-approval.v1+json"
        value["signatures"][0]["sig"] = base64.b64encode(
            bundle.keys["operator"].sign(preauth(bundle.raw["approval"], value["payloadType"]))
        ).decode()
        bundle.write("operator", value)
    elif fault == "wrong-role":
        bundle.write("approver", json.loads(bundle.raw["operator"]))
    else:
        value = json.loads(bundle.raw["approval"])
        if fault == "changed-approval":
            value["evidence_sha256"] = "0" * 64
        elif fault == "expired":
            value["expires_at"] = bundle.stamp(-1)
        else:
            value["actor"] = "operator"
        bundle.write("approval", value)
        resign_actual(bundle)
    with pytest.raises(ValueError, match="HANDOFF001"):
        if fault == "requester-is-signer":
            cutover.handoff(
                bundle.root, bundle.doc, actor="operator", environment="oci-handoff", now=bundle.now
            )
        else:
            decide(bundle)


def test_artifacts_and_clean_commit_are_rechecked(bundle, monkeypatch):
    original = handoff._unit

    def change(*args):
        result = original(*args)
        if args[1] == "oke":
            bundle.paths["network_released_source"].write_bytes(b"PRIVATE_CHECKPOINT_SENTINEL")
        return result

    monkeypatch.setattr(handoff, "_unit", change)
    with pytest.raises(ValueError, match="HANDOFF001") as error:
        decide(bundle)
    assert "PRIVATE_CHECKPOINT_SENTINEL" not in str(error.value)


def test_cli_is_read_only_and_existing_diagnostic_stays_false(bundle, monkeypatch, capsys):
    path = bundle.root / ".infra/handoff.json"
    path.write_bytes(operations.encoded(bundle.doc))
    original = handoff.check

    def with_clock(root, document, **kwargs):
        kwargs.pop("now", None)
        return original(root, document, now=bundle.now, **kwargs)

    monkeypatch.setattr(handoff, "check", with_clock)
    before = {p: p.read_bytes() for p in bundle.root.rglob("*") if p.is_file()}
    assert (
        cli.main(
            [
                "--root",
                str(bundle.root),
                "cutover",
                "handoff",
                "--actor",
                "requester",
                "--environment",
                "oci-handoff",
                "--evidence",
                str(path),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["cutover_authorized"] is False and result["target_owner_admitted"] is True
    assert before == {p: p.read_bytes() for p in before}


def test_changed_checkout_at_end_rejects_handoff(bundle, monkeypatch):
    seen = []

    def current(root):
        seen.append(root)
        return COMMIT, len(seen) == 1

    monkeypatch.setattr(handoff, "repository_state", current)
    with pytest.raises(ValueError, match="HANDOFF001"):
        decide(bundle)
    assert len(seen) == 2


def test_shared_source_scope_requires_one_consistent_released_checkpoint(bundle):
    combined = json.loads(bundle.cases["network"].raw["source_checkpoint"])
    combined["resources"] += json.loads(bundle.cases["oke"].raw["source_checkpoint"])["resources"]
    combined["lineage"] = "82345678-1234-4234-8234-123456789abc"
    identity = dict(
        bundle.cases["network"].doc["source"], workspace="shared", lineage=combined["lineage"]
    )
    for prefix, case in bundle.cases.items():
        case.doc["source"] = dict(identity)
        case.write("source_checkpoint", combined)
        frozen = json.loads(case.raw["freeze"])
        frozen["writers"][0]["identity_sha256"] = operations.digest(identity)
        frozen["binding_sha256"] = ownership.preparation_binding(
            case.doc,
            json.loads(case.raw["request"]),
            case.raw,
            foundation_sha256=load_foundation(bundle.root).digest,
            journal_head=operations.digest(
                json.loads(bundle.raw[prefix + "_prepared_journal"])[-1]
            ),
        )
        case.write("freeze", frozen)
        for role in ("source_checkpoint", "freeze"):
            case.doc["artifacts"][role]["path"] = str(case.paths[role])
        bundle.write(prefix + "_preparation", case.doc)
        bundle.write(prefix + "_released_source", dict(combined, serial=8, resources=[]))
    bundle.seal()
    assert decide(bundle)["target_owner_admitted"] is True
    changed = json.loads(bundle.raw["oke_released_source"])
    changed["serial"] = 9
    bundle.write("oke_released_source", changed)
    bundle.seal()
    with pytest.raises(ValueError, match="HANDOFF001"):
        decide(bundle)


def test_long_backup_RPO_cannot_extend_handoff_recovery_freshness(bundle):
    def earlier(value):
        return (datetime.fromisoformat(value) - timedelta(seconds=500)).isoformat()

    case = bundle.cases["network"]
    prepared = json.loads(bundle.raw["network_prepared_journal"])
    prepared[0]["at"] = earlier(prepared[0]["at"])
    case.write("journal", prepared)
    case.doc["artifacts"]["journal"]["path"] = ".infra/operations/oci-network.json"
    frozen = json.loads(case.raw["freeze"])
    for name in ("frozen_at", "checkpointed_at", "observed_at"):
        frozen[name] = earlier(frozen[name])
    frozen["binding_sha256"] = ownership.preparation_binding(
        case.doc,
        json.loads(case.raw["request"]),
        case.raw,
        foundation_sha256=load_foundation(bundle.root).digest,
        journal_head=operations.digest(prepared[-1]),
    )
    case.write("freeze", frozen)
    case.doc["artifacts"]["freeze"]["path"] = str(case.paths["freeze"])
    bundle.write("network_preparation", case.doc)
    bundle.write("network_prepared_journal", prepared)
    journal = json.loads(bundle.raw["network_journal"])
    for index, entry in enumerate(journal):
        entry["at"] = earlier(entry["at"])
        entry["previous"] = operations.digest(journal[index - 1]) if index else None
    bundle.write("network_journal", journal)
    imported = json.loads(bundle.raw["network_import_receipt"])
    imported["journal_head"] = operations.digest(journal[-1])
    bundle.write("network_import_receipt", imported)
    manifest = json.loads(bundle.raw["network_backup_manifest"])
    for name in ("source_exported_at", "captured_at"):
        manifest[name] = earlier(manifest[name])
    bundle.write("network_backup_manifest", manifest)
    backup = json.loads(bundle.raw["network_backup_receipt"])
    backup["completed_at"] = earlier(backup["completed_at"])
    backup["manifest_sha256"] = hashlib.sha256(bundle.raw["network_backup_manifest"]).hexdigest()
    bundle.write("network_backup_receipt", backup)
    policy = json.loads(bundle.raw["network_recovery_policy"])
    policy["max_backup_age_seconds"] = 900
    bundle.write("network_recovery_policy", policy)
    report = json.loads(bundle.raw["network_recovery_receipt"])
    for name in ("started_at", "completed_at"):
        report[name] = earlier(report[name])
    report["manifest_sha256"] = backup["manifest_sha256"]
    report["policy_sha256"] = hashlib.sha256(operations.encoded(policy)).hexdigest()
    bundle.write("network_recovery_receipt", report)
    bundle.seal()
    latest = json.loads(bundle.raw["freeze"])
    next(w for w in latest["writers"] if w["unit"] == "oci-network")["frozen_at"] = bundle.stamp(
        -615
    )
    bundle.write("freeze", latest)
    bundle.sign()
    # The old measurement still satisfies its explicit backup/restore objectives.
    measured = handoff._recovery(
        "network",
        bundle.raw,
        json.loads(case.raw["request"]),
        datetime.fromisoformat(bundle.stamp(-580)),
        bundle.now,
    )
    assert (bundle.now - measured).total_seconds() == 550
    with pytest.raises(ValueError, match="HANDOFF001"):
        decide(bundle)
