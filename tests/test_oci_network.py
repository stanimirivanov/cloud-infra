"""Independent network preflight, admission, SDK graph and stack export contracts."""

import json
import os
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path

import pulumi
import pytest
import test_oci
from infra_core.foundation import load_foundation
from infra_core.governance.audit import audit
from infra_core.oci.graph import NETWORK_UNIT, foundation_graph, network_graph, proposal
from infra_core.preview_contracts import describe_preview
from infra_program import preview_program as program

config = test_oci.config
ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40


def test_network_graph_is_existing_subset_and_proposal_cannot_hide_oke(config):
    graph = network_graph(config)
    assert graph == tuple(r for r in foundation_graph(config) if r.unit == NETWORK_UNIT)
    account, profile, inventory = test_oci.evidence()
    plan = proposal(graph, account["account_id"], config.region, units=(NETWORK_UNIT,))
    assert [unit["name"] for unit in plan["units"]] == [NETWORK_UNIT]
    result = audit(account, profile, inventory, plan)
    assert result["peak"] == {"ocpus": "0", "memory_gb": "0", "block_gb": "0"}
    assert result["deployment_authorized"] is False
    with pytest.raises(ValueError, match="OCI001"):
        proposal(
            foundation_graph(config), account["account_id"], config.region, units=(NETWORK_UNIT,)
        )


@pytest.mark.parametrize("case", ["apply", "stack", "disabled", "oke", "service", "bytes"])
def test_network_admission_denies_before_factory(config, monkeypatch, case):
    foundation = load_foundation(ROOT)
    if case != "disabled":
        foundation = replace(
            foundation, units=tuple(replace(u, preview_enabled=True) for u in foundation.units)
        )
    unit = {"oke": "oci-oke", "service": "cloudflare-edge"}.get(case, "oci-network")
    contract = describe_preview(foundation, unit, COMMIT)
    context = program.NetworkPreviewContext(
        foundation, contract, COMMIT, config, {}, {}, b"inventory", b"envelope"
    )
    if case == "bytes":
        context = replace(context, inventory=bytearray(b"inventory"))
    monkeypatch.setattr(pulumi.runtime, "is_dry_run", lambda: case != "apply")
    monkeypatch.setattr(pulumi, "get_project", lambda: foundation.project)
    monkeypatch.setattr(pulumi, "get_organization", lambda: "organization")
    monkeypatch.setattr(pulumi, "get_stack", lambda: "foreign" if case == "stack" else unit)
    monkeypatch.setattr(
        "infra_program.oci.components.register_network",
        lambda *a, **kw: pytest.fail("early factory"),
    )
    monkeypatch.setattr(pulumi, "export", lambda *a: pytest.fail("early export"))
    with pytest.raises(RuntimeError, match="PREVIEW002"):
        program.dispatch_preview(context)


def test_network_sdk_and_export_match_audited_graph_with_failed_preflight_isolated(
    config, tmp_path
):
    inputs = tmp_path / "inputs.json"
    inputs.write_text(json.dumps({"config": asdict(config), "evidence": test_oci.evidence()}))
    script = tmp_path / "network.py"
    script.write_text(
        r"""
import json
import sys
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pulumi
from infra_core.foundation import load_foundation
from infra_core.oci.config import FoundationConfig, ImageEvidence
from infra_core.oci.graph import Ref, network_graph, wire
from infra_core.inventory_evidence import capture_inventory
from infra_core.preview_contracts import describe_preview
from infra_program.oci import components
from infra_program import governance, preview_program
from infra_program.__main__ import main

data = json.loads(Path(sys.argv[1]).read_text())
values = data['config']
values['image'] = ImageEvidence(**values['image'])
for key in ('administrator_cidrs', 'availability_domains', 'supported_versions'):
    values[key] = tuple(values[key])
cfg = FoundationConfig(**values)
account, profile, inventory = data['evidence']
payload, envelope = capture_inventory(account, profile, inventory, commit='a'*40)
graph = network_graph(cfg)
expected = {cfg.name + '-' + r.key: r for r in graph}
observed = {}
options = []
exports = {}
audits = []
original_account = deepcopy(account)

def wire_ids(value):
    if isinstance(value, Ref):
        return cfg.name + '-' + value.key + '-id'
    if isinstance(value, dict):
        return wire({key: wire_ids(item) for key, item in value.items()})
    if isinstance(value, list):
        return [wire_ids(item) for item in value]
    return value

class Offline(pulumi.runtime.Mocks):
    def new_resource(self, args):
        assert 'ContainerEngine' not in args.typ and 'StackReference' not in args.typ
        if args.typ.startswith('oci:'):
            spec = expected[args.name]
            actual = {k: v for k, v in args.inputs.items() if v is not None}
            assert args.typ == spec.kind and actual == wire_ids(spec.props), (args.name, actual)
            assert args.provider
        if args.typ == 'pulumi:providers:oci':
            assert args.inputs['tenancyOcid'] == original_account['account_id']
            assert args.inputs['region'] == cfg.region
        violations = []
        governance.validate_resource(SimpleNamespace(resource_type=args.typ, props=args.inputs),
                                     lambda message, urn: violations.append(message))
        assert not violations, violations
        observed[args.name] = args
        return args.name + '-id', args.inputs
    def call(self, args):
        raise AssertionError('provider lookup attempted')

pulumi.runtime.set_mocks(Offline(), project='free-infrastructure', stack='oci-network',
                         organization='organization', preview=True)
def register(c, a, p, raw=payload, sidecar=envelope, commit='a'*40):
    return components.register_network(c, a, p, raw, envelope=sidecar, commit=commit)

with patch.object(pulumi.Resource, '__init__', side_effect=AssertionError('early registration')):
    negatives = [
        lambda: register(replace(cfg, administrator_cidrs=('0.0.0.0/0',)), account, profile),
        lambda: register(cfg, dict(account, home_region='us-ashburn-1'), profile),
        lambda: register(cfg, account, profile, payload + b' '),
        lambda: register(cfg, account, profile, commit='b'*40),
        lambda: register(cfg, account, profile, sidecar=b''),
        lambda: register(cfg, account, dict(profile, enabled=False)),
    ]
    # Rebind a valid envelope so the account-wide capacity audit itself must reject.
    over = dict(account, reservations={'ocpus': 5})
    over_raw, over_sidecar = capture_inventory(over, profile, inventory, commit='a'*40)
    negatives.append(lambda: register(cfg, over, profile, over_raw, over_sidecar))
    for negative in negatives:
        try:
            negative()
        except ValueError:
            pass
        else:
            raise AssertionError('invalid network preflight passed')
assert not observed

foundation = load_foundation(Path(sys.argv[2]))
foundation = replace(foundation, units=tuple(replace(u, preview_enabled=True)
                                           for u in foundation.units))
context = preview_program.NetworkPreviewContext(foundation,
    describe_preview(foundation, 'oci-network', 'a'*40), 'a'*40,
    cfg, account, profile, payload, envelope)
real_init = pulumi.Resource.__init__
def record(self, typ, name, custom, props=None, opts=None, *args, **kwargs):
    assert opts.protect is True and opts.import_ is None and opts.aliases is None
    if typ.startswith('oci:'):
        assert isinstance(opts.parent, components.Network) and opts.provider is not None
    options.append(name)
    return real_init(self, typ, name, custom, props, opts, *args, **kwargs)
real_audit = governance.audit
def audit(a, p, i, plan):
    assert [u['name'] for u in plan['units']] == ['oci-network']
    assert len(plan['units'][0]['changes']) == len(graph)
    result = real_audit(a, p, i, plan)
    audits.append(plan)
    account['account_id'] = 'mutated-after-audit'
    return result

@pulumi.runtime.test
def check():
    with patch.object(pulumi.Resource, '__init__', record), \
         patch.object(governance, 'audit', audit), \
         patch('infra_core.oci.graph._oke_graph', side_effect=AssertionError('OKE graph built')), \
         patch.object(pulumi, 'export', lambda key, value: exports.update({key: value})):
        main(context)
    def complete(values):
        assert set(values) == {'network', 'network_stack_identity'}
        assert values['network_stack_identity'] == 'organization/free-infrastructure/oci-network'
        assert values['network'] == {
            'schema_version': 1, 'account_id': original_account['account_id'],
            'region': cfg.region, 'compartment_id': cfg.compartment_id,
            'cidrs': {'vcn': cfg.vcn_cidr, 'api': cfg.api_cidr,
                      'worker': cfg.worker_cidr, 'pod': cfg.pod_cidr},
            'ids': {key: cfg.name + '-' + key + '-id' for key in
                    ('vcn', 'api-subnet', 'worker-subnet', 'pod-subnet',
                     'api-nsg', 'worker-nsg', 'pod-nsg')},
        }, values
    return pulumi.Output.all(**exports).apply(complete)
check()
assert len(audits) == 1
assert set(observed) == set(expected) | {cfg.name + '-provider', cfg.name + '-network'}
assert len(options) == len(observed)
print('independent network passed')
""",
        encoding="utf-8",
    )
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith(("PULUMI_", "OCI_", "AWS_", "TF_", "TG_"))
    }
    result = subprocess.run(
        [sys.executable, str(script), str(inputs), str(ROOT)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "independent network passed"
