"""Operation-bound DSSE approvals with no credential admission or executor."""

import base64
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from evidence_helpers import administration_responses
from infra_core import administration as admin
from infra_core import operation_admission as a
from infra_core import operations as op
from infra_core import review_signatures as sig

NOW = datetime(2026, 10, 29, tzinfo=UTC)
COMMIT = "a" * 40


@pytest.fixture
def admission(tmp_path, monkeypatch):
    monkeypatch.setattr(a, "repository_state", lambda root: (COMMIT, True))
    (tmp_path / "config").mkdir()
    keys = {role: Ed25519PrivateKey.generate() for role in a.ROLES}
    policy = dict(
        schema_version=1,
        enabled=True,
        repository="example/infra",
        repository_id=123,
        max_approval_age_seconds=300,
        max_backup_age_seconds=3600,
        environments={"apply/oci-network": "oci-network-apply"},
        reviewers=[
            dict(
                principal=role,
                roles=[role],
                public_key=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
            )
            for role, key in keys.items()
        ],
    )
    value = dict(
        schema_version=1,
        operation_id="12345678-1234-4234-8234-123456789abc",
        operation="apply",
        unit="oci-network",
        commit=COMMIT,
        configuration_sha256="b" * 64,
        checkpoint_sha256="c" * 64,
        expires_at=(NOW + timedelta(minutes=5)).isoformat(),
        expected_predecessor=None,
    )
    entry = dict(request=value, state="prepared", previous=None, at=NOW.isoformat())
    manifest = dict(
        schema_version=2,
        operation_id=value["operation_id"],
        stack="organization/free-infrastructure/oci-network",
        request_sha256=op.digest(value),
        unit=value["unit"],
        commit=COMMIT,
        repository_id="d" * 64,
        configuration_sha256="b" * 64,
        checkpoint_sha256="c" * 64,
        source_exported_at=NOW.isoformat(),
        captured_at=NOW.isoformat(),
    )
    receipt = dict(
        schema_version=1,
        manifest_sha256=a._hash(op.encoded(manifest)),
        repository_id="d" * 64,
        snapshot_id="e" * 64,
        completed_at=NOW.isoformat(),
    )
    responses = administration_responses(
        dict(
            policy,
            environment="oci-network-apply",
            required_checks=[],
            workflow={"id": 1, "path": ".github/workflows/verify.yml"},
        ),
        COMMIT,
    )
    responses["environment"]["can_admins_bypass"] = False
    environment = dict(
        schema_version=1,
        commit=COMMIT,
        started_at=NOW.isoformat(),
        completed_at=NOW.isoformat(),
        responses={k: responses[k] for k in ("repository", "branch", "environment", "branches")},
    )
    context = dict(
        actor="requester",
        environment="oci-network-apply",
        commit=COMMIT,
        configuration_sha256="b" * 64,
        checkpoint_sha256="c" * 64,
        plan_sha256="f" * 64,
        journal_head=op.digest(entry),
    )

    def inputs(execution_inputs=None):
        receipt["manifest_sha256"] = a._hash(op.encoded(manifest))
        raw = op.encoded(policy)
        (tmp_path / "config/operations-policy.json").write_bytes(raw)
        args = dict(
            request=op.encoded(value),
            backup_receipt=op.encoded(receipt),
            backup_manifest=op.encoded(manifest),
            environment=op.encoded(environment),
            journal=op.encoded([entry]),
            context=deepcopy(context),
            now=NOW,
        )
        approval = dict(
            schema_version=1,
            operation_id=value["operation_id"],
            **context,
            request_sha256=a._hash(args["request"]),
            policy_sha256=a._hash(raw),
            backup_sha256=a._hash(args["backup_receipt"]),
            environment_sha256=a._hash(args["environment"]),
            issued_at=NOW.isoformat(),
            expires_at=value["expires_at"],
        )
        if execution_inputs is not None:
            approval["schema_version"] = 2
            approval["execution_inputs_sha256"] = a._hash(execution_inputs)
        args["approval"] = op.encoded(approval)
        args["signatures"] = {
            role: op.encoded(
                dict(
                    payloadType=a.PAYLOAD_TYPE,
                    payload=base64.b64encode(args["approval"]).decode(),
                    signatures=[
                        dict(
                            sig=base64.b64encode(
                                key.sign(sig.preauth(args["approval"], a.PAYLOAD_TYPE))
                            ).decode()
                        )
                    ],
                )
            )
            for role, key in keys.items()
        }
        return args

    return tmp_path, inputs, policy, environment, entry, context, manifest


def test_valid_preflight_is_idempotent_and_never_authorizes(admission):
    root, inputs, *_ = admission
    args = inputs()
    assert a.admit(root, **args) == a.admit(root, **args)
    assert a.admit(root, **args)["admission_verified"] is True
    assert a.admit(root, **args)["execution_authorized"] is False


@pytest.mark.parametrize(
    "field",
    [
        "actor",
        "environment",
        "commit",
        "configuration_sha256",
        "checkpoint_sha256",
        "plan_sha256",
        "journal_head",
    ],
)
def test_changed_current_context_rejects_approved_inputs(admission, field):
    root, inputs, *_ = admission
    args = inputs()
    args["context"][field] = "changed"
    with pytest.raises(ValueError, match="ADMIT001"):
        a.admit(root, **args)


@pytest.mark.parametrize(
    "fault",
    [
        "disabled",
        "role",
        "role-permission",
        "stale-environment",
        "stale-backup",
        "requester-case",
        "duplicate-key",
        "duplicate-principal",
        "requester",
        "expired",
        "replay",
        "no-reviewer",
        "bypass",
        "missing-bypass",
        "branch",
    ],
)
def test_invalid_signed_inputs_fail_even_when_resigned(admission, fault):
    root, inputs, policy, environment, entry, context, manifest = admission
    if fault == "disabled":
        policy["enabled"] = False
    elif fault == "role":
        policy["reviewers"][0]["roles"] = ["health"]
    elif fault == "role-permission":
        role = policy["reviewers"][0]["roles"][0]
        policy["reviewers"][0]["roles"] = list(a.ROLES - {role})
    elif fault == "stale-environment":
        environment["started_at"] = environment["completed_at"] = (
            NOW - timedelta(minutes=16)
        ).isoformat()
    elif fault == "stale-backup":
        manifest["source_exported_at"] = (NOW - timedelta(hours=2)).isoformat()
    elif fault == "requester-case":
        context["actor"] = policy["reviewers"][0]["principal"].upper()
    elif fault == "duplicate-key":
        policy["reviewers"][1]["public_key"] = policy["reviewers"][0]["public_key"]
    elif fault == "duplicate-principal":
        policy["reviewers"][1]["principal"] = policy["reviewers"][0]["principal"]
    elif fault == "requester":
        context["actor"] = policy["reviewers"][0]["principal"]
    elif fault == "expired":
        entry["request"]["expires_at"] = NOW.isoformat()
    elif fault == "replay":
        pass
    elif fault == "no-reviewer":
        environment["responses"]["environment"]["protection_rules"] = []
    elif fault == "bypass":
        environment["responses"]["environment"]["can_admins_bypass"] = True
    elif fault == "missing-bypass":
        environment["responses"]["environment"].pop("can_admins_bypass")
    elif fault == "branch":
        environment["responses"]["branches"]["branch_policies"][0]["name"] = "feature"
    args = inputs()
    if fault == "replay":
        admitted = dict(
            request=entry["request"],
            state="admitted",
            previous=op.digest(entry),
            at=NOW.isoformat(),
        )
        args["journal"] = op.encoded([entry, admitted])
        args["context"]["journal_head"] = op.digest(admitted)
    with pytest.raises(ValueError, match="ADMIT001"):
        a.admit(root, **args)


@pytest.mark.parametrize(
    "field", ["request", "backup_receipt", "backup_manifest", "environment", "approval"]
)
def test_changed_bytes_are_rejected(admission, field):
    root, inputs, *_ = admission
    args = inputs()
    args[field] += b" "
    with pytest.raises(ValueError, match="ADMIT001"):
        a.admit(root, **args)


def test_distinct_dsse_type_and_wrong_signer_fail(admission):
    root, inputs, *_ = admission
    args = inputs()
    role = "operator"
    signature = json.loads(args["signatures"][role])
    signature["payloadType"] = sig.PAYLOAD_TYPE
    args["signatures"][role] = op.encoded(signature)
    with pytest.raises(ValueError, match="ADMIT001"):
        a.admit(root, **args)
    args = inputs()
    signature = json.loads(args["signatures"][role])
    signature["signatures"][0]["sig"] = base64.b64encode(b"x" * 64).decode()
    args["signatures"][role] = op.encoded(signature)
    with pytest.raises(ValueError, match="ADMIT001"):
        a.admit(root, **args)


def test_fresh_clock_and_clean_head_required(admission, monkeypatch):
    root, inputs, *_ = admission
    args = inputs()
    args["now"] = NOW + timedelta(hours=1)
    with pytest.raises(ValueError, match="ADMIT001"):
        a.admit(root, **args)
    monkeypatch.setattr(a, "repository_state", lambda root: (COMMIT, False))
    with pytest.raises(ValueError, match="ADMIT001"):
        a.admit(root, **inputs())


def test_read_only_environment_collector(admission, monkeypatch):
    root, _, policy, environment, *_ = admission
    replies = iter(environment["responses"].values())
    calls = []

    def get(root, endpoint):
        calls.append(endpoint)
        return next(replies)

    monkeypatch.setattr(admin, "_get", get)
    # Collection supplies its own current clocks, and independently checks the expected scope.
    raw = admin.collect_operation_environment(
        root,
        repository=policy["repository"],
        repository_id=policy["repository_id"],
        environment="oci-network-apply",
        commit=COMMIT,
    )
    assert json.loads(raw)["commit"] == COMMIT and len(calls) == 4
    assert calls[-1].endswith("deployment-branch-policies?per_page=100&page=1")


def test_checkout_change_during_verification_is_rejected(admission, monkeypatch):
    root, inputs, *_ = admission
    states = iter([(COMMIT, True), (COMMIT, False)])
    monkeypatch.setattr(a, "repository_state", lambda root: next(states))
    with pytest.raises(ValueError, match="ADMIT001"):
        a.admit(root, **inputs())


def test_execution_approval_requires_exact_extended_binding(admission):
    root, inputs, *_ = admission
    args = inputs(b"frozen-service-inputs")
    assert a.admit(root, **args, execution_inputs=b"frozen-service-inputs")["admission_verified"]
    for changed in (None, b"changed"):
        with pytest.raises(ValueError, match="ADMIT001"):
            a.admit(root, **args, execution_inputs=changed)
    with pytest.raises(ValueError, match="ADMIT001"):
        a.admit(root, **inputs(), execution_inputs=b"frozen-service-inputs")


def test_import_approval_is_execution_bound_and_not_an_apply_permit(admission):
    root, inputs, policy, environment, entry, context, manifest = admission
    entry["request"]["operation"] = "import"
    context["environment"] = "oci-network-import"
    context["journal_head"] = op.digest(entry)
    policy["environments"] = {"import/oci-network": "oci-network-import"}
    environment["responses"]["environment"]["name"] = "oci-network-import"
    environment["responses"]["environment"]["url"] = (
        "https://api.github.com/repos/example/infra/environments/oci-network-import"
    )
    manifest["request_sha256"] = op.digest(entry["request"])
    binding = b'{"adapter":"oci-import-v1","mapping":"reviewed"}'
    args = inputs(binding)
    args["execution_inputs"] = binding
    assert a.admit(root, **args)["admission_verified"] is True
    args["execution_inputs"] += b"changed"
    with pytest.raises(ValueError):
        a.admit(root, **args)
