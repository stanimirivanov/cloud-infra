"""Four-unit executor/bootstrap admission using semantic preflight and SDK/runtime spies."""

import hashlib
import json
import time
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_oci
import test_oci_dependency
import test_services
from infra_core.foundation import load_foundation
from infra_core.inventory_evidence import capture_inventory
from infra_core.preview_contracts import describe_preview
from infra_core.service_evidence import capture_service_evidence
from infra_program import preview_driver as driver
from infra_program.preview_program import (
    NetworkPreviewContext,
    OkePreviewContext,
    ServicePreviewContext,
)

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
config = test_oci.config


@pytest.fixture(params=["cloudflare-edge", "supabase-database", "oci-network", "oci-oke"])
def case(request, config, tmp_path):
    foundation = load_foundation(ROOT)
    foundation = replace(
        foundation, units=tuple(replace(u, preview_enabled=True) for u in foundation.units)
    )
    unit = request.param
    contract = describe_preview(foundation, unit, COMMIT)
    dependency = None
    if unit.startswith("oci-"):
        account, profile, inventory = test_oci.evidence()
        raw, envelope = capture_inventory(account, profile, inventory, commit=COMMIT)
        cls = OkePreviewContext if unit == "oci-oke" else NetworkPreviewContext
        context = cls(foundation, contract, COMMIT, config, account, profile, raw, envelope)
        if unit == "oci-oke":
            dependency = json.dumps(test_oci_dependency.committed(config)).encode()
    else:
        proposal, evidence, profile = test_services.service.__wrapped__(
            SimpleNamespace(param="supabase" if unit == "supabase-database" else "cloudflare")
        )
        raw = json.dumps(evidence).encode()
        envelope = capture_service_evidence(proposal, profile, raw, commit=COMMIT)
        context = ServicePreviewContext(
            foundation, contract, COMMIT, proposal, profile, raw, envelope
        )
    keys = []
    if isinstance(context, ServicePreviewContext):
        keys = [unit + ":token"]
        if unit == "supabase-database":
            keys += [unit + ":databasePassword-app"]
    ciphertext = driver._encoded(
        {
            "encryptionsalt": "v1:synthetic-salt",
            "config": {k: {"secure": "v1:synthetic-ciphertext"} for k in keys},
        }
    )
    credentials = {
        k: "test-only-env"
        for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "PULUMI_CONFIG_PASSPHRASE")
    }
    credentials["PULUMI_CONFIG_PASSPHRASE"] = "test-only-env" * 3
    if unit.startswith("oci-"):
        private_key = tmp_path / "key.pem"
        private_key.write_text("synthetic key")
        credentials.update(
            OCI_USER_OCID="synthetic",
            OCI_FINGERPRINT="synthetic",
            OCI_PRIVATE_KEY_PATH=str(private_key),
        )
    return context, ciphertext, credentials, dependency


@pytest.fixture
def execution(case, monkeypatch):
    context, _, _, _ = case
    state = SimpleNamespace(
        fault=None,
        selected=False,
        work=None,
        after=False,
        prepared=False,
        dispatches=[],
        verify_calls=0,
        sources=0,
    )
    monkeypatch.setattr(driver, "load_foundation", lambda root: context.foundation)
    monkeypatch.setattr(
        driver,
        "repository_state",
        lambda root: (
            ("b" * 40 if state.fault == "head" else COMMIT),
            not (state.fault == "dirty" or (state.fault == "source" and state.after)),
        ),
    )
    monkeypatch.setattr(driver, "dispatch_preview", lambda value: state.dispatches.append(value))
    actual_version = driver.version
    monkeypatch.setattr(
        driver,
        "version",
        lambda package: "0.0.0"
        if package == "pulumi"
        and (
            state.fault == "version"
            or (state.fault == "child-version" and state.selected)
            or (state.fault == "post-version" and state.after)
        )
        else actual_version(package),
    )

    def verify():
        state.verify_calls += 1
        if state.fault == "runtime" and state.after:
            raise RuntimeError("private-runtime-diagnostic")

    def runtime(root, archive, target):
        state.work = target.parent
        target.mkdir()
        return SimpleNamespace(binary=target / "pulumi", verify=verify)

    def home(root, source, target, *, supabase):
        target.mkdir()
        state.prepared = True
        settings = {
            "PULUMI_HOME": str(target),
            "PULUMI_IGNORE_AMBIENT_PLUGINS": "true",
            "PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION": "true",
        }
        if supabase:
            settings.update(
                PULUMI_DYNAMIC_TF_PLUGIN_CACHE_DIR=str(target / "dynamic_tf_plugins"),
                PULUMI_BRIDGE_REATTACH_PROVIDERS="",
                TF_REATTACH_PROVIDERS="",
            )
        return settings

    def provider(root, home):
        if state.fault == "provider":
            raise RuntimeError("private-provider-diagnostic")
        return {}

    class Stack:
        @classmethod
        def select(cls, name, workspace):
            assert name == context.contract.stack_identity
            state.selected, state.workspace = True, workspace
            return cls()

        def preview(self, **options):
            assert options == dict(
                policy_packs=[str(ROOT / "policies")],
                parallel=1,
                color="never",
                suppress_outputs=True,
                suppress_progress=True,
                refresh=False,
                config_file=str(state.work / "stack.yaml"),
            )
            env = state.workspace.pulumi_command.env
            assert env["PULUMI_BACKEND_URL"] == context.foundation.backend.url()
            for key in (
                "PULUMI_ACCESS_TOKEN",
                "HTTPS_PROXY",
                "PYTHONPATH",
                "PULUMI_DEBUG_PROVIDERS",
            ):
                assert key not in env
            state.request = (state.work / "context.json").read_bytes()
            assert b"test-only-env" not in state.request
            if state.fault is None:
                # Caller mutations after capture must not reach the worker or receipt.
                context.profile["enabled"] = False
                case[2]["AWS_SECRET_ACCESS_KEY"] = "caller-mutation"
                assert env["AWS_SECRET_ACCESS_KEY"] == "test-only-env"
            if state.fault == "failure":
                raise RuntimeError("private-backend-diagnostic")
            if state.fault == "config":
                value = json.loads((state.work / "stack.yaml").read_bytes())
                keys = list(value["config"])
                value["config"][keys[0] if keys else "unreviewed:token"] = "plaintext"
                (state.work / "stack.yaml").write_bytes(driver._encoded(value))
            if state.fault == "input":
                value = json.loads(state.request)
                value["context"]["profile"]["enabled"] = False
                (state.work / "context.json").write_bytes(driver._encoded(value))
            # Exercise the actual bootstrap parser, frozen input binding and preflight.
            with monkeypatch.context() as child:
                child.chdir(state.work)
                driver.program_from_request()
            if state.fault == "request":
                (state.work / "context.json").write_bytes(state.request + b" ")
            state.after = True
            now = int(datetime.now(UTC).timestamp())
            summary = {
                "maybeCorrupt": False,
                "isPreview": state.fault != "events",
                "result": "succeeded",
                "resourceChanges": {"same": 1},
                "PolicyPacks": {"always-free-governance": "local"},
            }
            records = [
                (
                    "policyAnalyzeSummaryEvent",
                    {
                        "policyPackName": "always-free-governance",
                        "passed": ["reviewed-resource-costs"],
                    },
                ),
                ("summaryEvent", summary),
                ("cancelEvent", {}),
            ]
            self.wire = SimpleNamespace(
                records=[
                    driver._encoded({"sequence": n, "timestamp": now, kind: value})
                    for n, (kind, value) in enumerate(records)
                ]
            )

    monkeypatch.setattr(driver, "cli_runtime", runtime)
    monkeypatch.setattr(driver, "materialize_home", home)
    monkeypatch.setattr(driver, "verified_environment", provider)
    monkeypatch.setattr(driver, "verified_supabase_environment", provider)
    monkeypatch.setattr(driver, "Stack", Stack)
    for key in ("PULUMI_ACCESS_TOKEN", "HTTPS_PROXY", "PYTHONPATH", "PULUMI_DEBUG_PROVIDERS"):
        monkeypatch.setenv(key, "injected-parent-value")
    return state


def execute(case):
    context, ciphertext, credentials, dependency = case
    return driver.run_preview(
        ROOT,
        context,
        cli_archive=ROOT / ".infra/unused-archive",
        provider_home=ROOT / ".infra/unused-provider-home",
        encrypted_configuration=ciphertext,
        credentials=credentials,
        dependency_outputs=dependency,
    )


def test_all_units_bind_inputs_run_owned_bootstrap_and_cleanup(case, execution):
    context, _, _, dependency = case
    profile = deepcopy(context.profile)
    result = json.loads(execute(case))
    assert result["inputs"]["profile"] == hashlib.sha256(driver._encoded(profile)).hexdigest()
    assert result["deployment_authorized"] is False and result["cutover_authorized"] is False
    assert execution.selected and execution.dispatches and execution.verify_calls >= 2
    child = execution.dispatches[0]
    assert type(child) is type(context) and child.profile == profile
    assert context.profile["enabled"] is False
    if type(child) is OkePreviewContext:
        assert child.expected_network_sha256 == driver.network_digest(json.loads(dependency))
    assert not execution.work.exists()


@pytest.mark.parametrize(
    "fault",
    [
        "dirty",
        "head",
        "config",
        "input",
        "request",
        "failure",
        "source",
        "runtime",
        "provider",
        "events",
        "budget",
        "version",
        "child-version",
        "post-version",
    ],
)
def test_failed_admission_or_completion_never_returns_a_receipt(
    case, execution, monkeypatch, fault
):
    execution.fault = fault
    if fault == "budget":
        monkeypatch.setattr(time, "monotonic", lambda: 401 if execution.prepared else 100)
    with pytest.raises(RuntimeError, match="PREVIEW005") as error:
        execute(case)
    assert "private-" not in str(error.value)
    if execution.work is not None:
        assert not execution.work.exists()
    if fault in {"dirty", "head", "budget", "version"}:
        assert not execution.selected
    if fault in {"config", "input", "child-version"}:
        assert not execution.dispatches


def test_disabled_contract_and_extra_credentials_fail_before_selection(
    case, execution, monkeypatch
):
    context, ciphertext, credentials, dependency = case
    disabled = load_foundation(ROOT)
    contract = describe_preview(disabled, context.contract.unit, COMMIT)
    monkeypatch.setattr(driver, "load_foundation", lambda root: disabled)
    with pytest.raises(RuntimeError, match="PREVIEW005"):
        execute(
            (
                replace(context, foundation=disabled, contract=contract),
                ciphertext,
                credentials,
                dependency,
            )
        )
    monkeypatch.setattr(driver, "load_foundation", lambda root: context.foundation)
    with pytest.raises(RuntimeError, match="PREVIEW005"):
        execute(
            (context, ciphertext, dict(credentials, PULUMI_ACCESS_TOKEN="unexpected"), dependency)
        )
    assert not execution.selected


@pytest.mark.parametrize(
    "fault", ["plaintext", "short-passphrase", "duplicates", "salt", "wrong-unit"]
)
def test_invalid_configuration_inputs_are_rejected_before_tools(case, execution, fault):
    context, ciphertext, credentials, dependency = case
    settings = json.loads(ciphertext)
    if fault == "plaintext":
        keys = list(settings["config"])
        settings["config"][keys[0] if keys else "unreviewed:token"] = "plaintext"
    elif fault == "short-passphrase":
        credentials = dict(credentials, PULUMI_CONFIG_PASSPHRASE="short")
    elif fault == "salt":
        settings["encryptionsalt"] = "v1:"
    elif fault == "wrong-unit":
        if isinstance(context, ServicePreviewContext):
            other = (
                "supabase-database"
                if context.contract.unit == "cloudflare-edge"
                else "cloudflare-edge"
            )
        else:
            other = "oci-network" if context.contract.unit != "oci-network" else "oci-oke"
        context = replace(context, contract=describe_preview(context.foundation, other, COMMIT))
    ciphertext = (
        b'{"encryptionsalt":"v1:a","encryptionsalt":"v1:b","config":{}}'
        if fault == "duplicates"
        else driver._encoded(settings)
    )
    with pytest.raises(RuntimeError, match="PREVIEW005"):
        execute((context, ciphertext, credentials, dependency))
    assert not execution.selected and execution.work is None
