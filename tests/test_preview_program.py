"""Admission negatives and real SDK service dispatch without cloud/provider execution."""

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pulumi
import pytest
import test_services
from infra_core.foundation import load_foundation
from infra_core.preview_contracts import describe_preview
from infra_core.service_evidence import capture_service_evidence
from infra_program import preview_program as program
from infra_program.__main__ import main

service = test_services.service

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40


@pytest.fixture
def context(service):
    proposal, evidence, profile = service
    foundation = load_foundation(ROOT)
    foundation = replace(
        foundation, units=tuple(replace(u, preview_enabled=True) for u in foundation.units)
    )
    payload = json.dumps(evidence).encode()
    return program.ServicePreviewContext(
        foundation,
        describe_preview(foundation, proposal["unit"], COMMIT),
        COMMIT,
        proposal,
        profile,
        payload,
        capture_service_evidence(proposal, profile, payload, commit=COMMIT),
    )


@pytest.fixture
def runtime(monkeypatch, context):
    monkeypatch.setattr(pulumi.runtime, "is_dry_run", lambda: True)
    monkeypatch.setattr(pulumi, "get_project", lambda: "free-infrastructure")
    monkeypatch.setattr(pulumi, "get_stack", lambda: context.contract.unit)
    monkeypatch.setattr(pulumi, "get_organization", lambda: "organization")
    monkeypatch.setattr(pulumi, "Config", lambda *a, **kw: pytest.fail("early secret lookup"))
    monkeypatch.setattr(
        pulumi.Resource, "__init__", lambda *a, **kw: pytest.fail("early registration")
    )


@pytest.mark.parametrize(
    "case",
    [
        "absent",
        "wrong-type",
        "apply",
        "project",
        "stack",
        "organization",
        "disabled",
        "digest",
        "commit",
        "malformed-commit",
        "unit",
        "provider",
        "mutable-evidence",
        "mutable-envelope",
        "invalid-profile",
        "oci-network",
        "oci-oke",
    ],
)
def test_admission_denies_before_factory(context, runtime, monkeypatch, case):
    monkeypatch.setattr(
        program, "register_services_from_config", lambda *a, **kw: pytest.fail("early dispatch")
    )
    candidate = context
    if case == "absent":
        candidate = None
    elif case == "wrong-type":
        candidate = object()
    elif case == "apply":
        monkeypatch.setattr(pulumi.runtime, "is_dry_run", lambda: False)
    elif case in {"project", "stack", "organization"}:
        monkeypatch.setattr(pulumi, "get_" + case, lambda: "foreign")
    elif case == "disabled":
        foundation = load_foundation(ROOT)
        candidate = replace(
            context,
            foundation=foundation,
            contract=describe_preview(foundation, context.contract.unit, COMMIT),
        )
    elif case == "digest":
        candidate = replace(
            context, contract=replace(context.contract, configuration_sha256="b" * 64)
        )
    elif case in {"commit", "malformed-commit"}:
        candidate = replace(context, expected_commit="b" * 40 if case == "commit" else "HEAD")
    elif case in {"unit", "provider"}:
        candidate = replace(context, proposal=dict(context.proposal, **{case: "foreign"}))
    elif case == "mutable-evidence":
        candidate = replace(context, evidence=bytearray(context.evidence))
    elif case == "mutable-envelope":
        candidate = replace(context, envelope=bytearray(context.envelope))
    elif case == "invalid-profile":
        candidate = replace(context, profile=None)
    else:
        candidate = replace(context, contract=describe_preview(context.foundation, case, COMMIT))
        monkeypatch.setattr(pulumi, "get_stack", lambda: case)
    with pytest.raises(RuntimeError, match="PREVIEW002"):
        main(candidate)


def test_real_factory_rejects_altered_evidence_before_secrets(context, runtime):
    with pytest.raises(ValueError, match="EVID002"):
        main(replace(context, evidence=context.evidence + b" "))


def test_dispatch_snapshots_inputs_and_passes_independent_commit(context, runtime, monkeypatch):
    def factory(proposal, evidence, profile, *, envelope, commit):
        assert proposal == context.proposal and proposal is not context.proposal
        assert profile == context.profile and profile is not context.profile
        assert (evidence, envelope, commit) == (context.evidence, context.envelope, COMMIT)
        proposal["resources"].clear()
        profile.clear()
        return None

    monkeypatch.setattr(program, "register_services_from_config", factory)
    main(context)
    assert context.proposal["resources"] and context.profile


def test_sdk_dry_run_dispatch_uses_existing_secret_factories(context, tmp_path):
    inputs = tmp_path / "inputs.json"
    inputs.write_text(
        json.dumps(
            {
                "proposal": context.proposal,
                "profile": context.profile,
                "evidence": context.evidence.decode(),
                "envelope": context.envelope.decode(),
            }
        )
    )
    script = tmp_path / "preview.py"
    script.write_text(
        r"""
import json
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
import pulumi
from pulumi.runtime import rpc
from pulumi.runtime.config import set_all_config
from infra_core.foundation import load_foundation
from infra_core.preview_contracts import describe_preview
from infra_program.preview_program import ServicePreviewContext
from infra_program.__main__ import main

data = json.loads(Path(sys.argv[1]).read_text())
proposal = data['proposal']
unit = proposal['unit']
observed = []
class Offline(pulumi.runtime.Mocks):
    def new_resource(self, args):
        observed.append(args)
        return args.name + '-id', args.inputs
    def call(self, args):
        raise AssertionError('provider invoke attempted')
pulumi.runtime.set_mocks(Offline(), project='free-infrastructure', stack=unit,
                         organization='organization', preview=True)
foundation = load_foundation(Path(sys.argv[2]))
foundation = replace(foundation, units=tuple(replace(u, preview_enabled=True)
                                           for u in foundation.units))
context = ServicePreviewContext(foundation, describe_preview(foundation, unit, 'a'*40),
    'a'*40, proposal, data['profile'], data['evidence'].encode(), data['envelope'].encode())
values = {unit + ':token': 'synthetic-token'}
if proposal['provider'] == 'supabase':
    values[unit + ':databasePassword-app'] = 'synthetic-password'
set_all_config(values, secret_keys=list(values))
lookups = []
real_require = pulumi.Config.require_secret
def require(self, key):
    lookups.append((self.name, key))
    return real_require(self, key)

@pulumi.runtime.test
def check():
    with patch.object(pulumi.Config, 'require_secret', require):
        main(context)
    # Runtime waits for every queued registration before returning from check().
check()
assert len(observed) == 3, [(r.typ, r.name) for r in observed]
assert lookups == ([(unit, 'token'), (unit, 'databasePassword-app')]
                   if proposal['provider'] == 'supabase' else [(unit, 'token')])
provider = next(r for r in observed if r.typ.startswith('pulumi:providers:'))
token_key = 'apiToken' if proposal['provider'] == 'cloudflare' else 'accessToken'
assert provider.inputs[token_key]['value'] == 'synthetic-token'
assert rpc.is_rpc_secret(provider.inputs[token_key])
if proposal['provider'] == 'supabase':
    project = next(r for r in observed if r.typ == 'supabase:index/project:Project')
    assert project.inputs['databasePassword']['value'] == 'synthetic-password'
    assert rpc.is_rpc_secret(project.inputs['databasePassword'])
print('preview dispatch passed')
""",
        encoding="utf-8",
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(("PULUMI_", "OCI_", "AWS_", "TF_", "TG_"))
    }
    result = subprocess.run(
        [sys.executable, str(script), str(inputs), str(ROOT)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "preview dispatch passed"
