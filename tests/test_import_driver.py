"""Protected import mappings and outcomes; native OCI acceptance remains external."""

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_oci
import test_oci_apply
import test_oci_dependency
import test_ownership
from infra_core import operations, ownership
from infra_program import import_driver as driver
from infra_program import operation_runtime, service_apply

ROOT = Path(__file__).resolve().parents[1]
config = test_oci.config


@pytest.fixture(params=["oci-network", "oci-oke"])
def case(request, config, tmp_path, monkeypatch):
    own = test_ownership.case.__wrapped__(request, config, tmp_path, monkeypatch)
    other = tmp_path / "runtime-fixture"
    other.mkdir()
    _, context, raw = test_oci_apply.case.__wrapped__(request, config, other)
    for directory in ("config", "packages", "policies"):
        shutil.copytree(other / directory, tmp_path / directory, dirs_exist_ok=True)
    for filename in ("uv.lock", ".python-version"):
        shutil.copyfile(other / filename, tmp_path / filename)
    (tmp_path / "config/resource-import.json").write_text('{"schema_version":1,"enabled":true}')
    target = json.loads(own.raw["target_checkpoint"])
    prefix = f"urn:pulumi:{own.unit}::free-infrastructure::"
    kind = "infrastructure:oci:" + ("Network" if own.unit == "oci-network" else "Oke")
    parent = prefix + kind + "::fixture-" + ("network" if own.unit == "oci-network" else "oke")
    provider = prefix + "pulumi:providers:oci::fixture-provider"
    target["deployment"]["resources"].extend(
        [
            dict(urn=parent, type=kind, protect=True),
            dict(
                urn=provider,
                type="pulumi:providers:oci",
                id="fixture-id",
                protect=True,
                inputs={"region": config.region},
            ),
        ]
    )
    if own.unit == "oci-network":
        outputs = test_oci_dependency.committed(config)
        target["deployment"]["resources"][0]["outputs"] = outputs
        source = json.loads(own.raw["source_checkpoint"])
        for entry, record in zip(own.doc["entries"], source["resources"], strict=True):
            if entry["logical_key"] in outputs["network"]["ids"]:
                entry["id"] = outputs["network"]["ids"][entry["logical_key"]]
                record["instances"][0]["attributes"]["id"] = entry["id"]
        own.write("source_checkpoint", source)
    else:
        target["deployment"]["resources"].extend(
            [
                dict(
                    urn=prefix + "pulumi:pulumi:StackReference::fixture-network-reference",
                    type="pulumi:pulumi:StackReference",
                    protect=True,
                    inputs={"name": driver.oci_apply.NETWORK_STACK},
                ),
                dict(
                    urn=prefix + "pulumi:providers:pulumi::default", type="pulumi:providers:pulumi"
                ),
            ]
        )
        path = tmp_path / ".infra/operations/oci-network.json"
        path.write_bytes(raw["network_journal"])
    own.write("target_checkpoint", target)
    request_value = json.loads(own.raw["request"])
    request_value["checkpoint_sha256"] = hashlib.sha256(own.raw["target_checkpoint"]).hexdigest()
    own.write("request", request_value)
    entries = json.loads(own.raw["journal"])
    entries[0]["request"] = request_value
    own.write("journal", entries)
    own.bind()
    raw.update(
        operation=own.raw["request"],
        proposal=own.raw["configuration"],
        encrypted_configuration=own.raw["encrypted_configuration"],
        target_checkpoint=own.raw["target_checkpoint"],
        ownership=operations.encoded(own.doc),
    )
    plan = json.loads(raw["plan"])
    for record in plan["resourcePlans"].values():
        if record["goal"]["type"].startswith("oci:"):
            record["steps"] = ["create"]
    raw["plan"] = operations.encoded(plan)
    own.context, own.inputs = context, raw
    return own


def test_import_preflight_binds_mapping_without_apply_activation(case):
    (case.root / "config/oci-apply.json").write_text('{"schema_version":1,"enabled":false}')
    context, binding = driver.prepare(
        case.root, case.unit, test_ownership.COMMIT, case.inputs, case.raw["journal"]
    )
    assert context.contract.unit == case.unit
    payload = json.loads(binding)
    assert payload["adapter"] == "oci-import-v1"
    file = json.loads(driver.import_file(case.inputs))
    assert len(file["resources"]) == len(case.graph)
    assert all(r["parent"] == "owner" and r["provider"] == "provider" for r in file["resources"])
    assert {r["id"] for r in file["resources"]} == {e["id"] for e in case.doc["entries"]}


@pytest.mark.parametrize(
    "fault",
    [
        "id",
        "duplicate",
        "plan-update",
        "plan-provider",
        "changed-source",
        "changed-target",
        "other-request",
        "missing-parent",
    ],
)
def test_bad_import_inputs_are_rejected_before_credentials(case, fault):
    raw = dict(case.inputs)
    if fault in {"id", "duplicate", "other-request"}:
        doc = json.loads(raw["ownership"])
        if fault == "id":
            doc["entries"][0]["id"] = "other"
        elif fault == "duplicate":
            doc["entries"][1]["id"] = doc["entries"][0]["id"]
        else:
            doc["artifacts"]["request"]["sha256"] = "0" * 64
        raw["ownership"] = operations.encoded(doc)
    elif fault.startswith("plan-"):
        plan = json.loads(raw["plan"])
        entry = next(
            r for r in plan["resourcePlans"].values() if r["goal"]["type"].startswith("oci:")
        )
        if fault == "plan-update":
            entry["steps"] = ["update"]
        else:
            entry["goal"]["provider"] += "other"
        raw["plan"] = operations.encoded(plan)
    elif fault == "changed-source":
        case.paths["source_checkpoint"].write_bytes(b"changed")
    elif fault == "missing-parent":
        target = json.loads(raw["target_checkpoint"])
        target["deployment"]["resources"] = [
            r
            for r in target["deployment"]["resources"]
            if not r["type"].startswith("infrastructure:")
        ]
        raw["target_checkpoint"] = operations.encoded(target)
    else:
        raw["target_checkpoint"] += b" "
    with pytest.raises((ValueError, RuntimeError)):
        driver.prepare(case.root, case.unit, test_ownership.COMMIT, raw, case.raw["journal"])


@pytest.mark.parametrize("stage", ["admitted", "running", "succeeded"])
def test_prepared_journal_continuation_is_only_for_this_operation(case, stage):
    value = json.loads(case.raw["request"])
    head = operations.inspect_journal(case.paths["journal"])["head"]
    for state in ["admitted", "running", "succeeded"]:
        head = operations.journal(case.root, case.paths["journal"], value, state, predecessor=head)
        if state == stage:
            break
    if stage == "succeeded":
        with pytest.raises(ValueError):
            driver.prepare(
                case.root, case.unit, test_ownership.COMMIT, case.inputs, case.raw["journal"]
            )
    else:
        assert (
            driver.prepare(
                case.root, case.unit, test_ownership.COMMIT, case.inputs, case.raw["journal"]
            )[0].contract.unit
            == case.unit
        )
    with pytest.raises(ValueError):
        ownership.prepare(case.root, case.doc)


def imported_checkpoint(case):
    target = json.loads(case.inputs["target_checkpoint"])
    parent, provider = driver._identities(case.inputs)
    prefix = f"urn:pulumi:{case.unit}::free-infrastructure::"
    kind = "infrastructure:oci:" + ("Network" if case.unit == "oci-network" else "Oke")
    for entry, spec in zip(case.doc["entries"], case.graph, strict=True):
        target["deployment"]["resources"].append(
            dict(
                urn=prefix + kind + "$" + spec.kind + "::" + entry["pulumi_name"],
                type=spec.kind,
                id=entry["id"],
                protect=True,
                parent=parent,
                provider=provider + "::fixture-id",
            )
        )
    return operations.encoded(target)


@pytest.mark.parametrize(
    "fault", [None, "wrong-id", "unprotected", "wrong-parent", "wrong-provider", "partial"]
)
def test_imported_checkpoint_requires_every_exact_protected_binding(case, fault):
    value = json.loads(imported_checkpoint(case))
    resource = value["deployment"]["resources"][-1]
    if fault == "partial":
        value["deployment"]["resources"].pop()
    elif fault:
        resource[
            {
                "wrong-id": "id",
                "unprotected": "protect",
                "wrong-parent": "parent",
                "wrong-provider": "provider",
            }[fault]
        ] = False if fault == "unprotected" else "other"
    if fault:
        with pytest.raises((ValueError, KeyError)):
            driver.validate_imported(operations.encoded(value), case.context, case.inputs)
    else:
        driver.validate_imported(operations.encoded(value), case.context, case.inputs)


@pytest.mark.parametrize(
    "fault", [None, "partial", "post-change", "changed-checkpoint", "missing-terminal"]
)
def test_runtime_import_requires_noop_post_preview(case, monkeypatch, fault):
    work = case.root / ".infra/runtime"
    work.mkdir()
    (work / "import.json").write_bytes(driver.import_file(case.inputs))
    runtime = driver.ImportRuntime(
        SimpleNamespace(verify=lambda: None),
        work,
        {},
        case.context.contract.stack_identity,
        ROOT / "policies",
        case.context,
        case.inputs,
    )
    records = [
        operations.encoded(
            dict(
                sequence=0,
                summaryEvent=dict(
                    isPreview=False,
                    result="succeeded",
                    maybeCorrupt=False,
                    resourceChanges={"import": len(case.graph)},
                    PolicyPacks={},
                ),
            )
        ),
        operations.encoded(dict(sequence=1, cancelEvent={})),
    ]
    if fault == "missing-terminal":
        records.pop()
    if fault == "partial":
        checkpoint = json.loads(imported_checkpoint(case))
        checkpoint["deployment"]["resources"].pop()
        after = operations.encoded(checkpoint)
    else:
        after = imported_checkpoint(case)
    calls = []

    def capture(args):
        calls.append("import")
        assert args[0] == "import" and "--protect=true" in args and "--generate-code=false" in args
        assert "--plan" not in args and "--policy-pack" not in args
        return records

    monkeypatch.setattr(runtime, "_capture", capture)

    def checkpoint():
        (work / "current.json").write_bytes(after)
        calls.append("checkpoint")
        return "changed" if fault == "changed-checkpoint" and len(calls) > 3 else "post"

    monkeypatch.setattr(runtime, "checkpoint", checkpoint)

    def preview(*a, **kw):
        calls.append("post-preview")
        return {"update": 1} if fault == "post-change" else {"same": len(case.graph)}

    monkeypatch.setattr(operation_runtime.Runtime, "operation", preview)
    if fault:
        with pytest.raises((ValueError, KeyError)):
            runtime.operation(preview=False)
    else:
        assert runtime.operation(preview=False) == {"import": len(case.graph)}
        assert calls == ["import", "checkpoint", "post-preview", "checkpoint"]


def test_import_is_disabled_before_any_credential_lookup():
    with pytest.raises(ValueError):
        driver.execute(ROOT, argparse.Namespace(), lambda: pytest.fail("credentials"))


@pytest.mark.parametrize("unit", ["oci-network", "oci-oke"])
@pytest.mark.parametrize(
    "fault", [None, "preview", "up", "mutate-preview", "mutate-up", "credentials", "checkpoint"]
)
def test_import_journal_outcomes_and_credential_ordering(tmp_path, monkeypatch, unit, fault):
    import test_service_apply

    test_service_apply.test_apply_journal_and_credential_ordering(
        tmp_path, monkeypatch, unit, fault, True
    )


@pytest.mark.parametrize(
    "stage,dry_run", [("admitted", True), ("running", True), ("running", False)]
)
def test_import_child_is_preview_only_in_owned_journal_stages(case, monkeypatch, stage, dry_run):
    import pulumi

    value = json.loads(case.raw["request"])
    head = operations.inspect_journal(case.paths["journal"])["head"]
    for state in ["admitted", "running"]:
        head = operations.journal(case.root, case.paths["journal"], value, state, predecessor=head)
        if state == stage:
            break
    for name, raw in {
        "plan.json": case.inputs["plan"],
        "stack.yaml": case.inputs["encrypted_configuration"],
    }.items():
        (case.root / name).write_bytes(raw)
    payload = dict(
        oci=True,
        importing=True,
        root=str(case.root),
        unit=case.unit,
        commit=test_ownership.COMMIT,
        actor="owner",
        environment=case.unit + "-import",
        journal=str(case.paths["journal"]),
        journal_head=head,
        journal_snapshot=case.raw["journal"].hex(),
        bundle={},
        raw={n: v.hex() for n, v in case.inputs.items()},
    )
    (case.root / "apply.json").write_bytes(operations.encoded(payload))
    monkeypatch.chdir(case.root)
    monkeypatch.setattr(service_apply.preview, "_checkout", lambda root: None)
    monkeypatch.setattr(service_apply, "_admit", lambda *args: (case.context, {}))
    monkeypatch.setattr(pulumi.runtime, "is_dry_run", lambda: dry_run)
    monkeypatch.setattr(pulumi, "get_organization", lambda: "organization")
    monkeypatch.setattr(pulumi, "get_project", lambda: "free-infrastructure")
    monkeypatch.setattr(pulumi, "get_stack", lambda: case.unit)
    called = []
    monkeypatch.setattr(driver.oci_apply, "register", lambda context: called.append(context))
    if dry_run:
        service_apply.program_from_request()
        assert called == [case.context]
    else:
        with pytest.raises(ValueError):
            service_apply.program_from_request()
        assert not called


def test_workflow_and_cli_are_explicit_and_default_denied(case, monkeypatch):
    import yaml
    from infra_core import cli as core
    from infra_program import cli

    workflow = yaml.load(
        (ROOT / ".github/workflows/resource-import.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert (
        workflow["concurrency"]["group"]
        == "pulumi-operation-${{ github.repository }}-oci-dependency"
    )
    job = workflow["jobs"]["import"]
    assert job["needs"] == "verify" and job["environment"] == "${{ inputs.unit }}-import"
    before = next(s for s in job["steps"] if "--check" in s.get("run", ""))
    assert set(before["env"]) == {"GH_TOKEN"}
    args = argparse.Namespace(
        unit=case.unit, commit="a" * 40, actor="owner", environment=case.unit + "-import"
    )
    for name, value in dict(
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/main",
        GITHUB_SHA="a" * 40,
        GITHUB_ACTOR="owner",
        GITHUB_REPOSITORY_OWNER="owner",
    ).items():
        monkeypatch.setenv(name, value)
    called = []
    monkeypatch.setattr(driver, "execute", lambda root, args, creds: called.append(args.unit))
    cli._import(ROOT, args)
    assert called == [case.unit]
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    with pytest.raises(ValueError):
        cli._import(ROOT, args)
    assert (
        core.main(
            [
                "resource-import",
                "--check",
                "--unit",
                case.unit,
                "--commit",
                "a" * 40,
                "--actor",
                "owner",
                "--environment",
                case.unit + "-import",
                "--bundle",
                ".infra/bundle.json",
                "--journal",
                ".infra/operations/" + case.unit + ".json",
            ]
        )
        == 1
    )


@pytest.mark.operation_integration
@pytest.mark.skipif(
    __import__("os").environ.get("RUN_OPERATION_INTEGRATION") != "1",
    reason="opt-in protected import transport",
)
@pytest.mark.parametrize("fault", [None, "exit", "timeout", "incomplete", "post-change"])
def test_real_import_process_transport_is_bounded(case, tmp_path, monkeypatch, capsys, fault):
    import subprocess
    import sys
    import time

    import test_preview_runtime as fixtures
    from infra_program.preview_runtime import cli_runtime

    (tmp_path / "transport").mkdir()
    root, archive, work = fixtures.prepared.__wrapped__(tmp_path / "transport", monkeypatch)
    cli = cli_runtime(root, archive, work / "bin")
    env = fixtures.environment(work)
    runtime = driver.ImportRuntime(
        cli,
        work,
        env,
        case.context.contract.stack_identity,
        ROOT / "policies",
        case.context,
        case.inputs,
    )
    (work / "import.json").write_bytes(driver.import_file(case.inputs))
    (work / "case.json").write_bytes(
        operations.encoded(dict(fault=fault, mapping=json.loads(driver.import_file(case.inputs))))
    )
    real = operation_runtime.subprocess.Popen
    processes = []

    def launch(argv, **options):
        process = real(
            [sys.executable, str(ROOT / "tests/fixtures/service_apply_cli.py"), *argv[1:]],
            **options,
        )
        processes.append(process)
        return process

    monkeypatch.setattr(operation_runtime.subprocess, "Popen", launch)
    monkeypatch.setattr(driver, "validate_imported", lambda checkpoint, context, raw: None)
    if fault == "timeout":
        runtime.deadline = time.monotonic() + 0.5
    if fault:
        with pytest.raises((ValueError, subprocess.TimeoutExpired)):
            runtime.operation(preview=False)
    else:
        assert runtime.operation(preview=False)["import"] == len(case.graph)
    assert all(p.poll() is not None for p in processes)
    assert "SYNTHETIC_PRIVATE_OUTPUT" not in str(capsys.readouterr())


@pytest.mark.parametrize("case", ["oci-oke"], indirect=True)
def test_oke_import_accepts_only_a_successful_equivalent_network_import(case):
    raw = dict(case.inputs)
    entries = json.loads(raw["network_journal"])
    previous = None
    for entry in entries:
        entry["request"]["operation"] = "import"
        entry["previous"] = operations.digest(previous) if previous else None
        previous = entry
    receipt = json.loads(raw["network_receipt"])
    receipt.update(journal_head=operations.digest(entries[-1]), post_import_equivalent=True)
    raw["network_journal"] = operations.encoded(entries)
    raw["network_receipt"] = operations.encoded(receipt)
    assert driver.oci_apply.dependency(case.context, raw, True)["post_import_equivalent"] is True
    with pytest.raises(ValueError):
        driver.oci_apply.dependency(case.context, raw)
    receipt["post_import_equivalent"] = False
    raw["network_receipt"] = operations.encoded(receipt)
    with pytest.raises(ValueError):
        driver.oci_apply.dependency(case.context, raw, True)


def test_continuation_rejects_a_different_prepared_request(case):
    original = json.loads(case.raw["journal"])
    original[-1]["request"]["operation_id"] = "22345678-1234-4234-8234-123456789abc"
    snapshot = operations.encoded(original)
    doc = json.loads(case.inputs["ownership"])
    doc["artifacts"]["journal"]["sha256"] = hashlib.sha256(snapshot).hexdigest()
    with pytest.raises(ValueError):
        ownership.prepare(case.root, doc, prepared_journal=snapshot)
