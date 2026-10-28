"""Committed network admission and OKE-only SDK registration, without a backend."""

import asyncio
import json
import os
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pulumi
import pytest
import test_oci
from infra_program.governance import validate_resource
from infra_program.oci.dependencies import NETWORK_STACK, read_network, validate_network

config = test_oci.config
ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "ocid1.tenancy.oc1..synthetic"


def committed(cfg):
    kinds = {
        "vcn": "vcn",
        "api-subnet": "subnet",
        "worker-subnet": "subnet",
        "pod-subnet": "subnet",
        "api-nsg": "networksecuritygroup",
        "worker-nsg": "networksecuritygroup",
        "pod-nsg": "networksecuritygroup",
    }
    return {
        "network_stack_identity": NETWORK_STACK,
        "network": {
            "schema_version": 1,
            "account_id": ACCOUNT,
            "region": cfg.region,
            "compartment_id": cfg.compartment_id,
            "cidrs": {
                "vcn": cfg.vcn_cidr,
                "api": cfg.api_cidr,
                "worker": cfg.worker_cidr,
                "pod": cfg.pod_cidr,
            },
            "ids": {
                key: f"ocid1.{kind}.oc1.eu-frankfurt-1.synthetic{index}"
                for index, (key, kind) in enumerate(kinds.items())
            },
        },
    }


@pytest.mark.parametrize(
    "path,bad",
    [
        ("network_stack_identity", "other/stack"),
        ("network.schema_version", True),
        ("network.schema_version", 1.0),
        ("network.account_id", "other"),
        ("network.region", "other"),
        ("network.compartment_id", "other"),
        ("network.cidrs.api", "10.1.0.0/28"),
        ("network", None),
        ("network.credentials", "not-allowed"),
        ("network.ids.vcn", None),
        ("network.ids.vcn", "ocid1.subnet.oc1.region.synthetic"),
        ("network.ids.api-nsg", "ocid1.networksecuritygroup.oc1.eu-frankfurt-1.synthetic5"),
        ("network.ids.vcn", object()),
        ("network.ids.vcn", {"value": "wrapped"}),
        ("network.ids.vcn", ""),
    ],
)
def test_closed_network_contract_rejects_invalid_outputs(config, path, bad):
    value = committed(config)
    parent = value
    *parents, key = path.split(".")
    for part in parents:
        parent = parent[part]
    if bad is None:
        del parent[key]
    else:
        parent[key] = bad
    with pytest.raises(ValueError, match="OCI041"):
        validate_network(value, config, ACCOUNT)


def test_dependency_read_error_is_sanitized(config):
    async def run():
        async def unavailable():
            raise RuntimeError("private-backend-diagnostic")

        reference = SimpleNamespace(name=pulumi.Output.from_input(unavailable()))
        with pytest.raises(ValueError, match="OCI041") as error:
            await read_network(reference, config, ACCOUNT)
        assert "private-backend-diagnostic" not in str(error.value)

    asyncio.run(run())


@pytest.mark.parametrize(
    "name,extra",
    [
        (NETWORK_STACK, {}),
        ("oci-network", {}),
        ("organization/foreign/oci-network", {}),
        (NETWORK_STACK, {"unreviewed": True}),
    ],
)
def test_policy_allows_only_the_exact_network_reference(name, extra):
    violations = []
    validate_resource(
        SimpleNamespace(
            resource_type="pulumi:pulumi:StackReference", props={"name": name, **extra}
        ),
        lambda message, urn: violations.append(message),
    )
    assert bool(violations) == (name != NETWORK_STACK or bool(extra))


@pytest.mark.parametrize(
    "mode", ["valid", "secret", "unknown", "missing", "scope", "expired", "changed"]
)
def test_sdk_oke_reference_and_no_registration_on_invalid_dependency(config, tmp_path, mode):
    data = tmp_path / "inputs.json"
    data.write_text(
        json.dumps(
            {
                "config": asdict(config),
                "evidence": test_oci.evidence(),
                "outputs": committed(config),
            }
        )
    )
    script = tmp_path / "oke.py"
    script.write_text(
        r"""
import json
import sys
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch
import pulumi
from pulumi.runtime import rpc
from infra_core.foundation import load_foundation
from infra_core.inventory_evidence import capture_inventory
from infra_core.oci.config import FoundationConfig, ImageEvidence
from infra_core.oci.graph import Ref, oke_graph, wire
from infra_program import governance, preview_program
from infra_program.oci import components
from infra_program.oci.dependencies import network_digest

data = json.loads(Path(sys.argv[1]).read_text())
mode = sys.argv[3]
values = data['config']
values['image'] = ImageEvidence(**values['image'])
for key in ('administrator_cidrs', 'availability_domains', 'supported_versions'):
    values[key] = tuple(values[key])
cfg = FoundationConfig(**values)
account, profile, inventory = data['evidence']
payload, envelope = capture_inventory(account, profile, inventory, commit='a'*40)
source = data['outputs']
captured_digest = network_digest(source)
ids = deepcopy(source['network']['ids'])
if mode == 'changed':
    source['network']['ids']['vcn'] = 'ocid1.vcn.oc1.eu-frankfurt-1.changed'
if mode == 'missing':
    source = {}
if mode == 'scope':
    source['network']['region'] = 'foreign'
seen = []
refs = []
options = []
exports = {}
class Offline(pulumi.runtime.Mocks):
    def new_resource(self, args):
        if args.typ == 'pulumi:pulumi:StackReference':
            assert args.resource_id == 'organization/free-infrastructure/oci-network'
            assert args.inputs['name'] == args.resource_id
            refs.append(args)
            outputs = source
            if mode == 'secret':
                outputs = rpc.wrap_rpc_secret(source)
            if mode == 'unknown':
                outputs = rpc.UNKNOWN
            return args.resource_id, {'name': args.resource_id, 'outputs': outputs,
                                      'secretOutputNames': ['network'] if mode == 'secret' else []}
        assert mode == 'valid', 'managed registration before dependency/freshness validation'
        assert args.typ in ('pulumi:providers:oci', 'infrastructure:oci:Oke',
                            'oci:ContainerEngine/cluster:Cluster',
                            'oci:ContainerEngine/nodePool:NodePool')
        if args.typ.startswith('oci:'):
            spec = next(r for r in oke_graph(cfg, ids) if cfg.name + '-' + r.key == args.name)
            def bind(value):
                if isinstance(value, Ref):
                    return cfg.name + '-' + value.key + '-id'
                if isinstance(value, dict):
                    return wire({k: bind(v) for k, v in value.items()})
                if isinstance(value, list):
                    return [bind(v) for v in value]
                return value
            assert {k:v for k,v in args.inputs.items() if v is not None} == bind(spec.props)
            assert args.provider
        seen.append(args.typ)
        return args.name + '-id', args.inputs
    def call(self, args):
        raise AssertionError('provider invoke attempted')
pulumi.runtime.set_mocks(Offline(), project='free-infrastructure', stack='oci-oke',
                         organization='organization', preview=True)
foundation = load_foundation(Path(sys.argv[2]))
foundation = replace(foundation, units=tuple(replace(u, preview_enabled=True)
                                           for u in foundation.units))
from infra_core.preview_contracts import describe_preview
context = preview_program.OkePreviewContext(foundation,
    describe_preview(foundation, 'oci-oke', 'a'*40), 'a'*40,
    cfg, account, profile, payload, envelope,
    expected_network_sha256=captured_digest if mode == 'changed' else None)
real_init = pulumi.Resource.__init__
def record(self, typ, name, custom, props=None, opts=None, *args, **kwargs):
    assert opts.protect is True and opts.import_ is None and opts.aliases is None
    if typ == 'infrastructure:oci:Oke':
        assert len(opts.depends_on) == 1 and isinstance(opts.depends_on[0], pulumi.StackReference)
    if typ.startswith('oci:'):
        assert isinstance(opts.parent, components.Oke) and opts.provider is not None
    options.append(typ)
    return real_init(self, typ, name, custom, props, opts, *args, **kwargs)
audits = []
real_audit = governance.audit
def audit(a, p, i, plan):
    assert [u['name'] for u in plan['units']] == ['oci-oke']
    assert len(plan['units'][0]['changes']) == 2
    audits.append(plan)
    if mode == 'expired' and len(audits) == 2:
        return real_audit(a, p, i, plan,
            now=datetime.fromisoformat(i['observed_at']) + timedelta(minutes=16))
    return real_audit(a, p, i, plan)
@pulumi.runtime.test
def run():
    return preview_program.dispatch_preview(context)
with patch.object(pulumi.Resource, '__init__', record), \
     patch.object(governance, 'audit', audit), \
     patch.object(pulumi, 'export', lambda key, value: exports.update({key: value})):
    if mode == 'valid':
        run()
        assert len(seen) == 4 and len(refs) == 1 and len(audits) == 2
        assert set(exports) == {'oke'} and set(exports['oke']) == {
            'schema_version', 'region', 'cluster_id', 'node_pool_id'}
    else:
        try:
            run()
        except ValueError as error:
            assert ('GOV004' if mode == 'expired' else 'OCI041') in str(error), str(error)
        else:
            raise AssertionError('invalid dependency admitted')
        assert not seen and len(refs) == 1
print('OKE dependency passed')
""",
        encoding="utf-8",
    )
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith(("PULUMI_", "OCI_", "AWS_", "TF_", "TG_"))
    }
    result = subprocess.run(
        [sys.executable, str(script), str(data), str(ROOT), mode],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "OKE dependency passed"
