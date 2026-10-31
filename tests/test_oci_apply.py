"""Ordered OCI admission, closed graphs and dependency continuity without cloud writes."""

import argparse
import json
import re
import shutil
import tomllib
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pulumi
import pytest
import test_backend
import test_oci
import test_oci_dependency
from infra_core import operations
from infra_core.foundation import load_foundation
from infra_core.inventory_evidence import capture_inventory
from infra_core.oci.graph import network_graph, oke_graph
from infra_core.preview_contracts import describe_preview
from infra_program import oci_apply as apply
from infra_program import service_apply as driver
from infra_program.oci.dependencies import network_digest
from infra_program.preview_program import NetworkPreviewContext, OkePreviewContext

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
config = test_oci.config


def saved_plan(context):
    unit, cfg = context.contract.unit, context.configuration
    prefix = f"urn:pulumi:{unit}::free-infrastructure::"
    root = prefix + "pulumi:pulumi:Stack::free-infrastructure-" + unit
    component_type = "infrastructure:oci:" + ("Oke" if unit == "oci-oke" else "Network")
    component = prefix + component_type + "::fixture-" + ("oke" if unit == "oci-oke" else "network")
    provider = prefix + "pulumi:providers:oci::fixture-provider"
    resources = {}

    def add(urn, resource_type, parent="", **kw):
        resources[urn] = dict(
            steps=["same"],
            goal=dict(
                type=resource_type,
                name=urn.split("::")[-1],
                protect=urn != root,
                parent=parent,
                **kw,
            ),
        )

    add(root, "pulumi:pulumi:Stack")
    add(component, component_type)
    add(provider, "pulumi:providers:oci")
    for item in oke_graph(cfg) if unit == "oci-oke" else network_graph(cfg):
        add(
            prefix + component_type + "$" + item.kind + "::fixture-" + item.key,
            item.kind,
            component,
            provider=provider + "::fixture-id",
        )
    if unit == "oci-oke":
        builtin = prefix + "pulumi:providers:pulumi::default"
        add(builtin, "pulumi:providers:pulumi")
        resources[builtin]["goal"]["protect"] = False
    return dict(
        manifest={"version": "v" + context.foundation.pulumi_version}, resourcePlans=resources
    )


@pytest.fixture(params=["oci-network", "oci-oke"])
def case(request, config, tmp_path):
    for name in (
        *apply.preview.SOURCES,
        "config/pulumi.toml",
        "config/toolchain.json",
        "config/provider-toolchain.json",
        "config/quotas/profiles.toml",
    ):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    path = tmp_path / "config/pulumi.toml"
    path.write_text(path.read_text().replace("preview_enabled = false", "preview_enabled = true"))
    path = tmp_path / "config/quotas/profiles.toml"
    path.write_text(
        re.sub(
            r'reviewed_at = "[^"]+"',
            'reviewed_at = "' + datetime.now(UTC).isoformat() + '"',
            path.read_text(),
        )
    )
    (tmp_path / "config/oci-apply.json").write_text(
        '{"schema_version":2,"units":{"oci-network":true,"oci-oke":true}}'
    )
    unit = request.param
    foundation = load_foundation(tmp_path)
    account, _, inventory = test_oci.evidence()
    profile = tomllib.loads(path.read_text())["profiles"]["oci-free"]
    evidence, envelope = capture_inventory(account, profile, inventory, commit=COMMIT)
    cls = OkePreviewContext if unit == "oci-oke" else NetworkPreviewContext
    context = cls(
        foundation,
        describe_preview(foundation, unit, COMMIT),
        COMMIT,
        config,
        account,
        profile,
        evidence,
        envelope,
    )
    cfg = asdict(config)
    image = cfg.pop("image")
    raw = {n: b"fixture" for n in apply.names(unit)}
    raw.update(
        proposal=json.dumps(dict(foundation=cfg, image=image)).encode(),
        account=json.dumps(account).encode(),
        evidence=evidence,
        envelope=envelope,
        plan=json.dumps(saved_plan(context)).encode(),
        encrypted_configuration=b'{"encryptionsalt":"v1:fixture","config":{}}',
        qualification=json.dumps(test_backend.receipt(foundation)).encode(),
    )
    if unit == "oci-oke":
        journal = tmp_path / ".infra/operations/oci-network.json"
        value = json.loads((ROOT / "config/operations.example.json").read_bytes())
        value.update(commit=COMMIT, expires_at="2099-01-01T00:00:00+00:00")
        head = None
        for state in ("prepared", "admitted", "running", "succeeded"):
            head = operations.journal(tmp_path, journal, value, state, predecessor=head)
        outputs = test_oci_dependency.committed(config)
        raw.update(
            dependency_outputs=json.dumps(outputs).encode(),
            network_journal=journal.read_bytes(),
            network_receipt=json.dumps(
                dict(
                    status="succeeded",
                    operation_id=value["operation_id"],
                    journal_head=head,
                    dependency_outputs_sha256=network_digest(outputs),
                    checkpoint_sha256="c" * 64,
                )
            ).encode(),
        )
    return tmp_path, context, raw


def test_existing_oci_preflight_and_execution_binding(case):
    root, context, raw = case
    result, binding = apply.prepare(root, context.contract.unit, COMMIT, raw)
    assert result.configuration == context.configuration
    assert json.loads(binding)["adapter"] == "oci-apply-v1"
    raw["evidence"] += b" "
    with pytest.raises((ValueError, RuntimeError)):
        apply.prepare(root, context.contract.unit, COMMIT, raw)


@pytest.mark.parametrize(
    "fault",
    [
        "replace",
        "delete",
        "type",
        "parent",
        "provider",
        "protect",
        "missing",
        "foreign-stack",
        "version",
    ],
)
def test_plan_rejects_changes_outside_reviewed_graph(case, fault):
    _, context, raw = case
    plan = json.loads(raw["plan"])
    resources = plan["resourcePlans"]
    child = next(r for r in resources.values() if r["goal"]["type"].startswith("oci:"))
    if fault in {"replace", "delete"}:
        child["steps"] = [fault]
    elif fault in {"parent", "provider", "type"}:
        child["goal"][fault] = "unreviewed"
    elif fault == "protect":
        child["goal"]["protect"] = False
    elif fault == "missing":
        resources.pop(next(iter(resources)))
    elif fault == "foreign-stack":
        key = next(iter(resources))
        resources[key.replace(context.contract.unit, "other")] = resources.pop(key)
    else:
        plan["manifest"]["version"] = "v0.0.0"
    with pytest.raises(ValueError):
        apply.validate_plan(json.dumps(plan).encode(), context)


@pytest.mark.parametrize(
    "fault", ["not-succeeded", "changed-outputs", "wrong-operation", "stale-journal", "checkpoint"]
)
def test_oke_requires_matching_successful_network_and_live_outputs(case, fault):
    root, context, raw = case
    if context.contract.unit != "oci-oke":
        return
    context, _ = apply.prepare(root, context.contract.unit, COMMIT, raw)
    outputs = json.loads(raw["dependency_outputs"])
    if fault == "not-succeeded":
        entries = json.loads(raw["network_journal"])
        raw["network_journal"] = json.dumps(entries[:-1]).encode()
    elif fault == "wrong-operation":
        receipt = json.loads(raw["network_receipt"])
        receipt["operation_id"] = "other"
        raw["network_receipt"] = json.dumps(receipt).encode()
    elif fault == "stale-journal":
        (root / ".infra/operations/oci-network.json").write_bytes(b"[]")
        with pytest.raises(ValueError):
            apply.prepare(root, context.contract.unit, COMMIT, raw)
        return
    elif fault == "changed-outputs":
        outputs["network"]["ids"]["vcn"] += "changed"
    runtime = SimpleNamespace(
        network_outputs=lambda: ("d" * 64 if fault == "checkpoint" else "c" * 64, outputs)
    )
    with pytest.raises(ValueError):
        apply.confirm_dependency(runtime, context, raw)
    assert (
        operations.inspect_journal(root / ".infra/operations/oci-network.json")["state"]
        == "succeeded"
    )


@pytest.mark.parametrize("case", ["oci-oke"], indirect=True)
def test_network_success_is_not_oke_success(case):
    _, context, raw = case
    if context.contract.unit == "oci-oke":
        receipt = apply.dependency(context, raw)
        assert receipt["status"] == "succeeded"
        assert "oke" not in receipt


def test_default_gate_rejects_before_credentials():
    with pytest.raises(ValueError):
        apply.execute(ROOT, argparse.Namespace(), lambda: pytest.fail("credentials"))


@pytest.mark.parametrize("dry_run", [True, False])
@pytest.mark.parametrize("fault", [None, "identity", "journal-mode"])
def test_owned_oci_bootstrap_admits_before_factory(case, monkeypatch, dry_run, fault):
    root, context, raw = case
    unit = context.contract.unit
    value = json.loads((ROOT / "config/operations.example.json").read_bytes())
    value.update(unit=unit, expires_at="2099-01-01T00:00:00+00:00")
    journal = root / ".infra/operations" / (unit + ".json")
    # OKE's network journal is an independent successful operation.
    if journal.exists():
        journal.unlink()
    head = operations.journal(root, journal, value, "prepared", predecessor=None)
    original = journal.read_bytes()
    head = operations.journal(root, journal, value, "admitted", predecessor=head)
    if (not dry_run) != (fault == "journal-mode"):
        head = operations.journal(root, journal, value, "running", predecessor=head)
    for name, content in {
        "plan.json": raw["plan"],
        "stack.yaml": raw["encrypted_configuration"],
        "policy.json": apply.preview._policy_configuration(context),
    }.items():
        (root / name).write_bytes(content)
    data = dict(
        oci=True,
        root=str(root),
        unit=unit,
        commit=COMMIT,
        actor="owner",
        environment=unit + "-apply",
        journal=str(journal),
        journal_head=head,
        journal_snapshot=original.hex(),
        bundle={},
        raw={n: v.hex() for n, v in raw.items()},
    )
    (root / "apply.json").write_text(json.dumps(data))
    monkeypatch.chdir(root)
    monkeypatch.setattr(driver.preview, "_checkout", lambda root: None)
    monkeypatch.setattr(driver, "_admit", lambda *a: (context, {}))
    monkeypatch.setattr(pulumi.runtime, "is_dry_run", lambda: dry_run)
    monkeypatch.setattr(pulumi, "get_organization", lambda: "organization")
    monkeypatch.setattr(pulumi, "get_project", lambda: "free-infrastructure")
    monkeypatch.setattr(pulumi, "get_stack", lambda: "wrong" if fault == "identity" else unit)
    called = []
    monkeypatch.setattr(apply, "register", lambda context: called.append(context))
    if fault:
        with pytest.raises(ValueError):
            driver.program_from_request()
        assert not called
    else:
        driver.program_from_request()
        assert called == [context]


def test_oci_workflow_has_shared_ordering_and_credential_boundary():
    import yaml

    workflow = yaml.load(
        (ROOT / ".github/workflows/oci-apply.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert "inputs.unit" not in workflow["concurrency"]["group"]
    assert workflow["concurrency"]["cancel-in-progress"] == "false"
    job = workflow["jobs"]["apply"]
    assert job["needs"] == "verify" and job["environment"] == "${{ inputs.unit }}-apply"
    assert job["steps"][0]["with"]["clean"] == "false"
    before = next(s for s in job["steps"] if "--check" in s.get("run", ""))
    after = next(s for s in job["steps"] if "--allow-resource-writes" in s.get("run", ""))
    assert set(before["env"]) == {"GH_TOKEN"}
    assert set(after["env"]) >= {"OCI_USER_OCID", "OCI_FINGERPRINT", "OCI_PRIVATE_KEY_PATH"}


def test_shared_oci_lock_surrounds_executor(case, monkeypatch):
    root, context, _ = case
    args = argparse.Namespace(unit=context.contract.unit, check=False)
    (root / ".infra/operations").mkdir(parents=True, exist_ok=True)
    locks = []
    monkeypatch.setattr(apply.fcntl, "flock", lambda fd, flag: locks.append("locked"))

    def execute(root, args, credentials, oci):
        assert locks == ["locked"] and oci is True
        locks.append("executed")

    monkeypatch.setattr(driver, "execute", execute)
    apply.execute(root, args, lambda: pytest.fail("early credentials"))
    assert locks == ["locked", "executed"]


def test_registration_delegates_existing_factories_and_exports(case, monkeypatch):
    _, context, raw = case
    exports, calls = {}, []
    monkeypatch.setattr(pulumi, "export", lambda name, value: exports.update({name: value}))
    if context.contract.unit == "oci-oke":
        from dataclasses import replace

        context = replace(
            context, expected_network_sha256=network_digest(json.loads(raw["dependency_outputs"]))
        )

        class Result:
            def apply(self, callback):
                callback(SimpleNamespace(cluster_id="cluster", node_pool_id="workers"))

        def factory(*args, **kwargs):
            calls.append((args, kwargs))
            return Result()

        monkeypatch.setattr(apply.components, "register_oke", factory)
    else:
        output = json.loads(json.dumps(test_oci_dependency.committed(context.configuration)))[
            "network"
        ]

        def factory(*args, **kwargs):
            calls.append((args, kwargs))
            return SimpleNamespace(outputs=SimpleNamespace(**output))

        monkeypatch.setattr(apply.components, "register_network", factory)
    apply.register(context)
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args == (context.configuration, context.account, context.profile, context.inventory)
    assert kwargs["envelope"] == context.envelope and kwargs["commit"] == COMMIT
    if context.contract.unit == "oci-oke":
        assert kwargs["dependency_stack"] == apply.NETWORK_STACK
        assert kwargs["expected_network_sha256"] == context.expected_network_sha256
        assert set(exports) == {"oke"}
    else:
        assert exports == test_oci_dependency.committed(context.configuration)


@pytest.mark.parametrize(
    "name,properties,allowed",
    [("default", {}, True), ("other", {}, False), ("default", {"endpoint": "other"}, False)],
)
def test_builtin_reference_provider_has_no_cloud_configuration(name, properties, allowed):
    from infra_program import governance

    violations = []
    governance.validate_resource(
        SimpleNamespace(resource_type="pulumi:providers:pulumi", name=name, props=properties),
        lambda message, urn: violations.append(message),
    )
    assert (violations == []) is allowed
