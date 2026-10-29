"""Single-service apply validation and durable outcomes without cloud execution."""

import argparse
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pulumi
import pytest
import test_backend
import test_preview_program
import test_services
from infra_core import operations
from infra_core.foundation import load_foundation
from infra_program import import_driver, oci_apply
from infra_program import service_apply as apply
from test_operation_runtime import plan

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
service = test_services.service


def test_service_preflight_audits_existing_inputs_before_secret_lookup(
    service, tmp_path, monkeypatch
):
    proposal, evidence, _ = service
    for name in (
        *apply.preview.SOURCES,
        "config/toolchain.json",
        "config/provider-toolchain.json",
        "config/quotas/profiles.toml",
        "config/pulumi.toml",
    ):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    config = tmp_path / "config/pulumi.toml"
    config.write_text(
        config.read_text().replace("preview_enabled = false", "preview_enabled = true")
    )
    (tmp_path / "config/service-apply.json").write_text('{"schema_version":1,"enabled":true}')
    context = test_preview_program.context.__wrapped__(service)
    config_keys = {context.contract.unit + ":token": {"secure": "v1:fixture"}}
    if proposal["provider"] == "supabase":
        config_keys[context.contract.unit + ":databasePassword-app"] = {"secure": "v1:fixture"}
    raw = dict(
        proposal=json.dumps(proposal).encode(),
        evidence=context.evidence,
        envelope=context.envelope,
        encrypted_configuration=json.dumps(
            dict(encryptionsalt="v1:fixture", config=config_keys)
        ).encode(),
        plan=json.dumps(plan(context.contract.unit, full=True)).encode(),
        qualification=json.dumps(test_backend.receipt(load_foundation(tmp_path))).encode(),
    )
    raw.update(posture=b"fixture", posture_envelope=b"fixture")
    monkeypatch.setattr(pulumi, "Config", lambda *a, **kw: pytest.fail("early secret lookup"))
    result, _ = apply._service(tmp_path, context.contract.unit, COMMIT, raw)
    assert result.proposal == proposal
    raw["evidence"] += b" "
    with pytest.raises(ValueError):
        apply._service(tmp_path, context.contract.unit, COMMIT, raw)


@pytest.mark.parametrize("unit", ["cloudflare-edge", "supabase-database", "oci-network", "oci-oke"])
@pytest.mark.parametrize(
    "fault", [None, "preview", "up", "mutate-preview", "mutate-up", "checkpoint", "credentials"]
)
def test_apply_journal_and_credential_ordering(tmp_path, monkeypatch, unit, fault, importing=False):
    oci = unit.startswith("oci-")
    private = tmp_path / ".infra"
    private.mkdir()
    (tmp_path / "config").mkdir()
    (tmp_path / "config/service-apply.json").write_text('{"schema_version":1,"enabled":true}')
    if oci:
        (tmp_path / "config/oci-apply.json").write_text('{"schema_version":1,"enabled":true}')
    if importing:
        (tmp_path / "config/resource-import.json").write_text('{"schema_version":1,"enabled":true}')
    uv = private / "tools/uv/uv"
    uv.parent.mkdir(parents=True)
    uv.write_bytes(b"fixture-uv")
    (tmp_path / "config/toolchain.json").write_text(
        json.dumps(
            {
                "tools": {
                    "uv": {
                        "assets": {
                            "linux-x64": {
                                "binary_sha256": hashlib.sha256(uv.read_bytes()).hexdigest()
                            }
                        }
                    }
                }
            }
        )
    )
    value = json.loads((ROOT / "config/operations.example.json").read_bytes())
    value.update(
        unit=unit,
        operation="import" if importing else "apply",
        expires_at="2099-01-01T00:00:00+00:00",
    )
    journal = private / "operations" / (unit + ".json")
    head = operations.journal(tmp_path, journal, value, "prepared", predecessor=None)
    paths = {n: str(private / (n + ".bin")) for n in apply._names(oci, unit, importing)}
    for name, path in paths.items():
        Path(path).write_bytes(json.dumps(value).encode() if name == "operation" else b"frozen")
    bundle = dict(
        schema_version=1,
        paths=paths,
        backend_account_id="fixture",
        cli_archive=str(private / "cli.tar.gz"),
        provider_home=str(private / "providers"),
        output=str(private / "result.json"),
    )
    bundle_file = private / "bundle.json"
    bundle_file.write_text(json.dumps(bundle))
    args = argparse.Namespace(
        unit=unit,
        commit=COMMIT,
        actor="owner",
        environment=unit + ("-import" if importing else "-apply"),
        journal=journal,
        bundle=bundle_file,
        check=False,
        allow_resource_writes=True,
    )
    context = SimpleNamespace(
        foundation=load_foundation(ROOT),
        contract=SimpleNamespace(stack_identity="organization/free-infrastructure/" + unit),
    )
    expected = {"checkpoint_sha256": "fixture-checkpoint", "journal_head": head}
    monkeypatch.setattr(apply.preview, "_checkout", lambda root: None)
    monkeypatch.setattr(apply, "_admit", lambda *a: (context, expected))
    monkeypatch.setattr(apply, "_current_environment", lambda *a: None)
    monkeypatch.setattr(
        apply, "cli_runtime", lambda root, archive, target: SimpleNamespace(verify=lambda: None)
    )
    monkeypatch.setattr(apply, "materialize_home", lambda *a, **kw: {})
    monkeypatch.setattr(apply, "verified_environment", lambda *a: {})
    monkeypatch.setattr(apply, "verified_supabase_environment", lambda *a: {})
    events = []

    def confirm_dependency(*args):
        if (fault == "dependency-before-up" and "preview" in events) or (
            fault == "dependency-after-up" and "up" in events
        ):
            raise ValueError("changed network")

    def network_result(*args):
        if fault == "network-output":
            raise ValueError("unavailable committed outputs")
        return {"dependency_outputs_sha256": "fixture", "checkpoint_sha256": "fixture"}

    monkeypatch.setattr(oci_apply, "confirm_dependency", confirm_dependency)
    monkeypatch.setattr(oci_apply, "network_result", network_result)

    class FakeRuntime:
        def __init__(self, *args):
            pass

        def select(self):
            events.append("select")

        def checkpoint(self):
            return "changed" if fault == "checkpoint" else "fixture-checkpoint"

        def operation(self, *, preview):
            stage = "preview" if preview else "up"
            events.append(stage)
            if fault == stage:
                raise RuntimeError("PRIVATE_ERROR")
            if fault == "mutate-" + stage:
                Path(paths["proposal"]).write_bytes(b"changed")
            return {"same": 1}

    monkeypatch.setattr(apply, "Runtime", FakeRuntime)
    monkeypatch.setattr(import_driver, "ImportRuntime", FakeRuntime)
    monkeypatch.setattr(import_driver, "import_file", lambda raw: b"frozen-import")

    def credentials():
        assert operations.inspect_journal(journal)["state"] == "admitted"
        events.append("credentials")
        if fault == "credentials":
            raise RuntimeError("PRIVATE_ERROR")
        result = dict(
            AWS_ACCESS_KEY_ID="fixture",
            AWS_SECRET_ACCESS_KEY="fixture",
            PULUMI_CONFIG_PASSPHRASE="synthetic-passphrase-long",
        )

        if oci:
            key = private / "key.pem"
            key.write_bytes(b"synthetic key")
            result.update(
                OCI_USER_OCID="fixture", OCI_FINGERPRINT="fixture", OCI_PRIVATE_KEY_PATH=str(key)
            )
        return result

    if fault:
        with pytest.raises(ValueError, match="APPLY001") as error:
            apply.execute(tmp_path, args, credentials, oci, importing)
        assert "PRIVATE_ERROR" not in str(error.value)
        assert operations.inspect_journal(journal)["state"] == (
            "indeterminate"
            if fault in {"up", "mutate-up", "dependency-after-up", "network-output"}
            else "failed"
        )
        assert not Path(bundle["output"]).exists()
    else:
        apply.execute(tmp_path, args, credentials, oci, importing)
        assert operations.inspect_journal(journal)["state"] == "succeeded"
        assert events == ["credentials", "select", "preview", "up"]
        # Real admission rejects the advanced journal before another credential load.
        monkeypatch.setattr(apply, "_admit", lambda *a: (_ for _ in ()).throw(ValueError("replay")))
        with pytest.raises(ValueError):
            apply.execute(tmp_path, args, lambda: pytest.fail("replay credentials"), oci, importing)


@pytest.mark.parametrize("dry_run", [True, False])
@pytest.mark.parametrize("fault", [None, "identity", "journal-mode"])
def test_owned_bootstrap_checks_identity_and_mode_before_factory(
    service, tmp_path, monkeypatch, dry_run, fault
):
    context = test_preview_program.context.__wrapped__(service)
    private = tmp_path / ".infra"
    private.mkdir()
    value = json.loads((ROOT / "config/operations.example.json").read_bytes())
    value.update(unit=context.contract.unit, expires_at="2099-01-01T00:00:00+00:00")
    journal = private / "operations" / (context.contract.unit + ".json")
    head = operations.journal(tmp_path, journal, value, "prepared", predecessor=None)
    head = operations.journal(tmp_path, journal, value, "admitted", predecessor=head)
    if not dry_run and fault != "journal-mode":
        head = operations.journal(tmp_path, journal, value, "running", predecessor=head)
    elif dry_run and fault == "journal-mode":
        head = operations.journal(tmp_path, journal, value, "running", predecessor=head)
    raw = {n: b"fixture" for n in apply.NAMES}
    (tmp_path / "plan.json").write_bytes(raw["plan"])
    (tmp_path / "stack.yaml").write_bytes(raw["encrypted_configuration"])
    data = dict(
        root=str(tmp_path),
        unit=context.contract.unit,
        commit=COMMIT,
        actor="owner",
        environment=context.contract.unit + "-apply",
        journal=str(journal),
        journal_head=head,
        journal_snapshot=b"[]".hex(),
        bundle={},
        raw={n: v.hex() for n, v in raw.items()},
    )
    (tmp_path / "apply.json").write_text(json.dumps(data))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(apply.preview, "_checkout", lambda root: None)
    monkeypatch.setattr(apply, "_admit", lambda *a: (context, {}))
    monkeypatch.setattr(pulumi.runtime, "is_dry_run", lambda: dry_run)
    monkeypatch.setattr(pulumi, "get_organization", lambda: "organization")
    monkeypatch.setattr(pulumi, "get_project", lambda: "free-infrastructure")
    monkeypatch.setattr(
        pulumi, "get_stack", lambda: "wrong" if fault == "identity" else context.contract.unit
    )
    called = []
    monkeypatch.setattr(apply, "register_services_from_config", lambda *a, **kw: called.append(a))
    if fault:
        with pytest.raises(ValueError):
            apply.program_from_request()
        assert not called
    else:
        apply.program_from_request()
        assert called[0][0] == context.proposal


def test_preflight_is_disabled_by_default():
    with pytest.raises(ValueError):
        apply.check(ROOT, argparse.Namespace())


@pytest.mark.parametrize(
    "unit,fault",
    [
        ("oci-network", "network-output"),
        ("oci-oke", "dependency-before-up"),
        ("oci-oke", "dependency-after-up"),
    ],
)
def test_oci_dependency_failure_records_own_outcome(tmp_path, monkeypatch, unit, fault):
    test_apply_journal_and_credential_ordering(tmp_path, monkeypatch, unit, fault)
