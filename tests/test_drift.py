"""Four-unit graph boundaries, monitor-only signatures and explicit credential custody."""

import argparse
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_operation_admission
import test_preview_driver
from infra_core import backup, operation_admission, operations
from infra_core import drift_results as results
from infra_program import cli, drift
from infra_program.preview_program import ServicePreviewContext
from test_drift_results import REQUEST

ROOT = Path(__file__).resolve().parents[1]
config = test_preview_driver.config
case = test_preview_driver.case
admission = test_operation_admission.admission


def checkpoint(context):
    specs = drift.specification(context)
    values = []
    for urn, spec in specs.items():
        record = dict(
            urn=urn,
            type=spec["type"],
            parent=spec["parent"],
            protect=spec["protect"],
            inputs={},
            outputs={},
        )
        if spec["provider"]:
            record["id"] = "synthetic-native-id"
            record["provider"] = spec["provider"] + "::synthetic-provider-id"
        if spec["type"].startswith("pulumi:providers:"):
            record["id"] = "synthetic-provider-id"
            provider = spec["type"].split(":")[-1]
            if provider == "oci":
                record["inputs"] = dict(
                    region=context.configuration.region, tenancyOcid=context.account["account_id"]
                )
            elif provider != "pulumi":
                token, endpoint, url = (
                    ("apiToken", "baseUrl", "https://api.cloudflare.com/client/v4")
                    if provider == "cloudflare"
                    else ("accessToken", "endpoint", "https://api.supabase.com")
                )
                record["inputs"] = {
                    token: {
                        backup.SIGNATURE: backup.ENCRYPTED_VALUE_SIGNATURE,
                        "ciphertext": "v1:synthetic",
                    },
                    endpoint: url,
                }
        values.append(record)
    return dict(
        version=3,
        deployment=dict(
            secrets_providers=dict(type="passphrase", state=dict(salt="v1:synthetic")),
            resources=values,
        ),
    )


def test_four_unit_checkpoints_preserve_closed_provider_scope(case):
    context, *_ = case
    state = checkpoint(context)
    records = drift._checkpoint(ROOT, context, operations.encoded(state))
    assert set(records) == set(drift.specification(context))
    assert all(
        r["urn"].startswith("urn:pulumi:" + context.contract.unit + "::") for r in records.values()
    )


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "extra",
        "duplicate",
        "pending",
        "unprotected",
        "foreign",
        "parent",
        "provider",
        "provider-version",
        "alternate-auth",
        "plaintext",
        "backend",
    ],
)
def test_checkpoint_failures_reject_before_credentials(case, fault):
    context, *_ = case
    state = checkpoint(context)
    resources = state["deployment"]["resources"]
    native = next(r for r in resources if r.get("provider"))
    provider = next(
        r
        for r in resources
        if r["type"].startswith("pulumi:providers:") and r["type"] != "pulumi:providers:pulumi"
    )
    if fault == "missing":
        resources.remove(native)
    elif fault == "extra":
        resources.append(dict(native, urn=native["urn"] + "-foreign"))
    elif fault == "duplicate":
        resources.append(deepcopy(native))
    elif fault == "pending":
        state["deployment"]["pending_operations"] = [{}]
    elif fault == "unprotected":
        native["protect"] = False
    elif fault == "foreign":
        native["urn"] = native["urn"].replace(context.contract.unit, "foreign", 1)
    elif fault == "parent":
        native["parent"] = "foreign"
    elif fault == "provider":
        native["provider"] = "foreign::id"
    elif fault == "provider-version":
        provider["inputs"]["version"] = "999.0.0"
    elif fault == "alternate-auth":
        provider["inputs"]["configFileProfile"] = "ambient"
    elif fault == "plaintext":
        if isinstance(context, ServicePreviewContext):
            token = "apiToken" if context.proposal["provider"] == "cloudflare" else "accessToken"
            provider["outputs"][token] = "PRIVATE"
        else:
            provider["inputs"]["privateKey"] = "PRIVATE"
    elif fault == "backend":
        state["deployment"]["secrets_providers"]["type"] = "service"
    with pytest.raises((ValueError, KeyError)):
        drift._checkpoint(ROOT, context, operations.encoded(state))


def test_monitor_schema_two_approval_cannot_be_reused_for_apply(admission):
    root, inputs, policy, environment, entry, context, manifest = admission
    entry["request"]["operation"] = "monitor"
    policy["environments"] = {"monitor/oci-network": "oci-network-monitor"}
    context["environment"] = "oci-network-monitor"
    response = environment["responses"]["environment"]
    response["name"] = "oci-network-monitor"
    response["url"] = response["url"].replace("oci-network-apply", "oci-network-monitor")
    manifest["request_sha256"] = operations.digest(entry["request"])
    context["journal_head"] = operations.digest(entry)
    args = inputs(b"isolated-observation-profile")
    assert (
        operation_admission.admit(root, execution_inputs=b"isolated-observation-profile", **args)[
            "admission_verified"
        ]
        is True
    )
    args["request"] = operations.encoded(dict(entry["request"], operation="apply"))
    with pytest.raises(ValueError):
        operation_admission.admit(root, execution_inputs=b"isolated-observation-profile", **args)


def test_disabled_gate_and_check_only_never_load_credentials(tmp_path, monkeypatch):
    args = argparse.Namespace(unit="oci-network", check=True, allow_local_writes=False)
    called = []
    with pytest.raises(ValueError, match="DRIFT001"):
        drift.execute(ROOT, args, lambda: pytest.fail("credentials before admission"))
    monkeypatch.setattr(drift, "check", lambda *a: ({}, {}, b"prepared"))
    drift.execute(tmp_path, args, lambda: called.append(True))
    assert called == [] and list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("fault", [None, "event", "branch", "commit", "actor", "environment"])
def test_cli_requires_explicit_protected_monitor_context(monkeypatch, fault):
    args = argparse.Namespace(
        unit="cloudflare-edge",
        commit="a" * 40,
        actor="owner",
        environment="cloudflare-edge-monitor",
    )
    env = dict(
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/main",
        GITHUB_SHA=args.commit,
        GITHUB_ACTOR="owner",
        GITHUB_REPOSITORY_OWNER="owner",
    )
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    if fault in {"event", "branch", "commit", "actor"}:
        monkeypatch.setenv(
            dict(
                event="GITHUB_EVENT_NAME",
                branch="GITHUB_REF",
                commit="GITHUB_SHA",
                actor="GITHUB_ACTOR",
            )[fault],
            "foreign",
        )
    elif fault == "environment":
        args.environment = "cloudflare-edge-apply"
    called = []
    monkeypatch.setattr(drift, "execute", lambda *a: called.append(a))
    if fault:
        with pytest.raises(ValueError):
            cli._drift(ROOT, args)
        assert called == []
    else:
        cli._drift(ROOT, args)
        assert len(called) == 1  # callback remains lazy with no credential env present


def test_preflight_binds_full_monitor_inputs(case, monkeypatch):
    context, ciphertext, _, _ = case
    unit = context.contract.unit
    monkeypatch.setattr(drift, "_context", lambda *a: context)
    monkeypatch.setattr(drift, "_checkpoint", lambda *a: {})
    monkeypatch.setattr(drift, "validate_posture_evidence", lambda *a, **kw: None)
    # Dependency root validation is exercised with the real four-unit graph separately.
    raw = {name: b"fixture" for name in drift.names(unit)}
    raw.update(
        plan=results.plan(unit), checkpoint=b"checkpoint", encrypted_configuration=ciphertext
    )
    value = dict(
        REQUEST,
        unit=unit,
        checkpoint_sha256=drift.shared._hash(raw["checkpoint"]),
        configuration_sha256=drift.shared._hash(ciphertext),
        expires_at=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
    )
    raw["operation"] = operations.encoded(value)
    raw["credential_review"] = operations.encoded(
        dict(
            schema_version=1,
            unit=unit,
            checkpoint_sha256=value["checkpoint_sha256"],
            configuration_sha256=value["configuration_sha256"],
            read_only_scopes_reviewed=True,
            historical_provider_credentials_reviewed=True,
            provider_identity_sha256="f" * 64 if unit.startswith("oci-") else None,
            reviewed_at=datetime.now(UTC).isoformat(),
            expires_at=value["expires_at"],
        )
    )
    if unit == "oci-oke":
        import test_oci_dependency

        dependency = test_oci_dependency.committed(context.configuration)
        raw["dependency_outputs"] = operations.encoded(dependency)
        raw["network_checkpoint"] = operations.encoded(
            dict(
                version=3,
                deployment=dict(
                    resources=[
                        dict(
                            type="pulumi:pulumi:Stack",
                            urn="urn:pulumi:oci-network::free-infrastructure::"
                            "pulumi:pulumi:Stack::free-infrastructure-oci-network",
                            outputs=dependency,
                        )
                    ]
                ),
            )
        )
    journal = operations.encoded(
        [dict(request=value, state="prepared", previous=None, at=datetime.now(UTC).isoformat())]
    )
    calls = []
    monkeypatch.setattr(drift.operation_admission, "admit", lambda *a, **kw: calls.append(kw))
    args = SimpleNamespace(
        unit=unit, commit=value["commit"], actor="requester", environment=unit + "-monitor"
    )
    drift._admit(ROOT, args, dict(backend_account_id="fixture"), raw, journal)
    binding = json.loads(calls[-1]["execution_inputs"])
    assert binding["adapter"] == "isolated-drift-v1"
    assert set(binding["inputs"]) == drift.names(unit) - drift.shared.APPROVAL
    assert calls[-1]["context"]["environment"] == unit + "-monitor"
    review = json.loads(raw["credential_review"])
    review["historical_provider_credentials_reviewed"] = False
    raw["credential_review"] = operations.encoded(review)
    with pytest.raises(ValueError):
        drift._admit(ROOT, args, dict(backend_account_id="fixture"), raw, journal)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "drift",
        "provider-error",
        "input-change",
        "source-change",
        "source-unavailable",
        "local-change",
        "credential-error",
    ],
)
def test_owned_lifecycle_rechecks_source_and_persists_unknown(case, tmp_path, monkeypatch, fault):
    import hashlib

    from test_drift_results import events

    context, _, credentials, _ = case
    unit = context.contract.unit
    private = tmp_path / ".infra"
    private.mkdir(exist_ok=True)
    (private / "operations").mkdir(exist_ok=True)
    (private / "tools/uv").mkdir(parents=True)
    (private / "tools/uv/uv").write_bytes(b"uv")
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config/toolchain.json").write_bytes(
        operations.encoded(
            dict(
                tools=dict(
                    uv=dict(
                        assets={"linux-x64": dict(binary_sha256=hashlib.sha256(b"uv").hexdigest())}
                    )
                )
            )
        )
    )
    raw = {name: b"fixture" for name in drift.names(unit)}
    value = dict(
        REQUEST, unit=unit, expires_at=(datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    )
    raw["operation"] = operations.encoded(value)
    identity = (
        operations.digest({k: credentials[k] for k in ("OCI_USER_OCID", "OCI_FINGERPRINT")})
        if unit.startswith("oci-")
        else None
    )
    raw["credential_review"] = operations.encoded(dict(provider_identity_sha256=identity))
    if unit.startswith("oci-"):
        key = private / "key.pem"
        key.write_bytes(b"synthetic-key")
        credentials["OCI_PRIVATE_KEY_PATH"] = str(key)
    if unit == "oci-oke":
        raw["network_checkpoint"] = operations.encoded(
            dict(
                version=3,
                deployment=dict(
                    resources=[
                        dict(
                            type="pulumi:pulumi:Stack", outputs={"network": "real-verified-output"}
                        ),
                        dict(type="oci:core:Vcn", id="not-projected"),
                    ]
                ),
            )
        )
    paths = {}
    for name, data in raw.items():
        paths[name] = ".infra/" + name
        (tmp_path / paths[name]).write_bytes(data)
    bundle = dict(
        paths=paths,
        cli_archive=".infra/cli",
        provider_home=".infra/plugins",
        output=".infra/result.json",
    )
    path = private / "operations" / (unit + ".json")
    operations.journal(tmp_path, path, value, "prepared", predecessor=None)
    journal = path.read_bytes()
    args = SimpleNamespace(
        unit=unit,
        commit=value["commit"],
        journal=path,
        actor="requester",
        environment=unit + "-monitor",
    )
    monkeypatch.setattr(drift, "_admit", lambda *a: context)
    monkeypatch.setattr(drift.shared, "_current_environment", lambda *a: None)
    monkeypatch.setattr(drift, "cli_runtime", lambda *a: SimpleNamespace(verify=lambda: None))
    monkeypatch.setattr(drift, "materialize_home", lambda *a, **kw: {})
    monkeypatch.setattr(drift, "verified_environment", lambda *a: None)
    monkeypatch.setattr(drift, "verified_supabase_environment", lambda *a: None)
    monkeypatch.setattr(drift.preview, "_prepare", lambda *a: (context, {}, None))
    monkeypatch.setattr(drift.preview, "_request", lambda *a: b"context")
    source_calls, commands, environments = [], [], []

    class Reader:
        def __init__(self, cli, work, env, stack, deadline):
            environments.append(("source", env))

        def export(self, stack):
            source_calls.append(stack)
            if fault == "source-unavailable" and len(source_calls) > (
                2 if unit == "oci-oke" else 1
            ):
                raise ValueError("PRIVATE")
            return (
                raw["network_checkpoint"]
                if stack.endswith("oci-network") and unit == "oci-oke"
                else b"changed"
                if fault == "source-change"
                else raw["checkpoint"]
            )

    class Observer:
        def __init__(self, cli, work, env, stack, deadline):
            environments.append(("local", env))
            self.count = 0

        def load(self, target, data):
            commands.append(("load", target))
            if target != unit:
                resources = json.loads(data)["deployment"]["resources"]
                assert (
                    len(resources) == 1
                    and resources[0]["outputs"]["network"] == "real-verified-output"
                )

        def checkpoint(self):
            self.count += 1
            return str(self.count) if fault == "local-change" else "baseline"

        def refresh(self):
            commands.append(("refresh", unit))
            if fault == "provider-error":
                raise ValueError("PRIVATE")
            if fault == "input-change":
                (tmp_path / paths["proposal"]).write_bytes(b"changed")
            return results.summarize(
                events(True, {"delete": 1} if fault == "drift" else None),
                refresh=True,
                policy="/policy",
            )

        def compare(self):
            commands.append(("compare", unit))
            return results.summarize(events(False), refresh=False, policy="/policy")

    monkeypatch.setattr(drift, "SourceReader", Reader)
    monkeypatch.setattr(drift, "LocalObserver", Observer)

    def acquire():
        assert operations.inspect_journal(path)["state"] == "admitted"
        if fault == "credential-error":
            raise ValueError("PRIVATE")
        return credentials

    report = drift._observe(tmp_path, args, bundle, raw, journal, acquire)
    assert report == json.loads((private / "result.json").read_bytes())
    assert (private / "result.json").stat().st_mode & 0o777 == 0o600
    assert "PRIVATE" not in json.dumps(report)
    assert not list(private.glob("drift-*"))
    assert report["journal_head"] == operations.inspect_journal(path)["head"]
    assert report["status"] == (
        "clean" if fault is None else "drifted" if fault == "drift" else "unknown"
    )
    assert operations.inspect_journal(path)["state"] == (
        "succeeded"
        if fault in {None, "drift"}
        else "indeterminate"
        if fault in {"source-unavailable", "local-change"}
        else "failed"
    )
    if fault != "credential-error":
        assert len(source_calls) >= (
            3
            if unit == "oci-oke" and fault == "source-unavailable"
            else 4
            if unit == "oci-oke"
            else 2
        )
        source_env, local_env = environments[0][1], environments[1][1]
        assert "AWS_ACCESS_KEY_ID" in source_env and not any(
            k.startswith("OCI_") for k in source_env
        )
        assert not any(k.startswith("AWS_") for k in local_env)
    if fault in {"provider-error", "input-change", "source-change", "credential-error"}:
        assert ("compare", unit) not in commands


def test_real_context_preflight_reuses_existing_four_unit_factories(case, tmp_path):
    import re
    import shutil
    import tomllib
    from dataclasses import asdict

    import test_backend
    from infra_core.foundation import load_foundation
    from infra_core.inventory_evidence import capture_inventory

    context, ciphertext, _, dependency = case
    for name in (
        *drift.preview.SOURCES,
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
    unit = context.contract.unit
    raw = dict(
        encrypted_configuration=ciphertext,
        evidence=context.evidence
        if isinstance(context, ServicePreviewContext)
        else context.inventory,
        envelope=context.envelope,
    )
    if isinstance(context, ServicePreviewContext):
        raw["proposal"] = operations.encoded(context.proposal)
    else:
        cfg = asdict(context.configuration)
        image = cfg.pop("image")
        raw["proposal"] = operations.encoded(dict(foundation=cfg, image=image))
        raw["account"] = operations.encoded(context.account)
        path = tmp_path / "config/quotas/profiles.toml"
        path.write_text(
            re.sub(
                r'reviewed_at = "[^"]+"',
                'reviewed_at = "' + datetime.now(UTC).isoformat() + '"',
                path.read_text(),
            )
        )
        profile = tomllib.loads(path.read_text())["profiles"]["oci-free"]
        raw["evidence"], raw["envelope"] = capture_inventory(
            context.account, profile, json.loads(context.inventory), commit=context.expected_commit
        )
    if dependency is not None:
        raw["dependency_outputs"] = dependency
    raw["qualification"] = operations.encoded(test_backend.receipt(load_foundation(tmp_path)))
    result = drift._context(tmp_path, unit, context.expected_commit, raw)
    assert type(result) is type(context)
    assert drift.specification(result) == drift.specification(context)


def test_core_cli_requires_composition_and_explicit_local_write_mode(capsys):
    from infra_core.cli import build_parser, main

    args = [
        "drift",
        "--unit",
        "cloudflare-edge",
        "--commit",
        "a" * 40,
        "--actor",
        "owner",
        "--environment",
        "cloudflare-edge-monitor",
        "--bundle",
        ".infra/drift/bundle.json",
        "--journal",
        ".infra/operations/cloudflare-edge.json",
    ]
    with pytest.raises(SystemExit):
        build_parser().parse_args(args)
    assert main([*args, "--check"]) == 1
    assert "DRIFT001" in str(capsys.readouterr())
    called = []
    assert main([*args, "--check"], drift=lambda root, parsed: called.append(parsed)) == 0
    assert len(called) == 1 and called[0].check and not called[0].allow_local_writes
