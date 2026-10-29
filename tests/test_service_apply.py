"""Single-service apply validation and durable outcomes without cloud execution."""

import argparse
import json
from pathlib import Path

import pulumi
import pytest
import test_backend
import test_preview_program
import test_services
from infra_core.foundation import load_foundation
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


def test_preflight_is_disabled_by_default():
    with pytest.raises(ValueError):
        apply.check(ROOT, argparse.Namespace())
