"""Pure OCI contracts and actual native SDK serialization, without cloud credentials."""

import hashlib
import json
import os
import subprocess
import sys
import tomllib
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from evidence_helpers import upgrade_inventory
from infra_core.governance.audit import audit
from infra_core.governance.contracts import GovernanceError
from infra_core.governance.resources import INVENTORY_TYPES
from infra_core.oci.config import FoundationConfig, ImageEvidence, load_config
from infra_core.oci.graph import NETWORK_UNIT, OKE_UNIT, Ref, foundation_graph, proposal, wire
from infra_core.oci.security import validate_resource

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def config():
    return FoundationConfig(
        name="fixture",
        region="eu-frankfurt-1",
        compartment_id="ocid1.compartment.oc1..synthetic",
        administrator_cidrs=("198.51.100.10/32",),
        service_id="ocid1.service.oc1.fra.synthetic",
        service_cidr="all-fra-services-in-oracle-services-network",
        availability_domains=("fixture:EU-FRANKFURT-1-AD-1",),
        kubernetes_version="v1.34.1",
        supported_versions=("v1.34.1",),
        image=ImageEvidence(
            "ocid1.image.oc1.eu-frankfurt-1.synthetic",
            "eu-frankfurt-1",
            "aarch64",
            "v1.34.1",
            datetime.now(UTC).isoformat(),
            "synthetic offline fixture",
        ),
    )


def evidence():
    now = datetime.now(UTC).isoformat()
    profile = tomllib.loads((ROOT / "config/quotas/profiles.toml").read_text())["profiles"][
        "oci-free"
    ]
    profile["reviewed_at"] = now  # Synthetic freshness; does not assert live published terms.
    account = {
        "provider": "oci",
        "account_id": "ocid1.tenancy.oc1..synthetic",
        "home_region": "eu-frankfurt-1",
        "profile": "oci-free",
        "profile_revision": 1,
        "verified": True,
        "verified_at": now,
        "other_services_reviewed": True,
        "reservations": {},
    }
    inventory = {
        "schema_version": 1,
        "provider": "oci",
        "account_id": account["account_id"],
        "observed_at": now,
        "complete": True,
        "covered_types": sorted(INVENTORY_TYPES),
        "all_regions": True,
        "all_compartments": True,
        "resources": [],
        "usage": {
            "account_id": account["account_id"],
            "provider": "oci",
            "month": now[:7],
            "observed_at": now,
            "source": "synthetic fixture, not billing evidence",
            "values": {"a1_ocpu_hours": 0, "a1_memory_gb_hours": 0, "block_gb_months": 0},
        },
    }
    # Near the start of a 31-day month, 2*744=1488 and 12*744=8928 fit the free profile.
    upgrade_inventory(inventory, account["home_region"])
    return account, profile, inventory


def test_graph_is_complete_ordered_and_passes_governance(config):
    graph = foundation_graph(config)
    keys = [item.key for item in graph]
    assert len(set(keys)) == len(keys)
    seen = set()

    def refs(value):
        if isinstance(value, Ref):
            assert value.key in seen, "forward/reverse references cross the layer boundary"
        elif isinstance(value, dict):
            for item in value.values():
                refs(item)
        elif isinstance(value, list):
            for item in value:
                refs(item)

    for item in graph:
        refs(item.props)
        if item.unit == NETWORK_UNIT:
            assert "cluster" not in seen and "workers" not in seen
        validate_resource(item.kind, wire(item.props))
        seen.add(item.key)
    account, profile, inventory = evidence()
    result = audit(
        account, profile, inventory, proposal(graph, account["account_id"], config.region)
    )
    assert result["peak"] == {"ocpus": "2", "memory_gb": "12", "block_gb": "100"}
    assert result["deployment_authorized"] is False
    assert {item.unit for item in graph} == {NETWORK_UNIT, OKE_UNIT}


def test_graph_matches_pre_extraction_baseline(config):
    # Captured from merged PR82 before extracting builders: includes all properties,
    # Ref targets, resource types, names, unit assignments and registration order.
    graph = foundation_graph(config)
    serialized = json.dumps(
        [asdict(resource) for resource in graph], sort_keys=True, separators=(",", ":")
    ).encode()
    assert len(graph) == 50
    assert hashlib.sha256(serialized).hexdigest() == (
        "1a657ca4fff980b001823eeb08cb9fccdd4c433d44ef422a9147986f2005ecb3"
    )


@pytest.mark.parametrize(
    "field,value,rule",
    [
        ("administrator_cidrs", (), "OCI010"),
        ("administrator_cidrs", ("0.0.0.0/0",), "OCI010"),
        ("administrator_cidrs", ("198.51.100.0/16",), "OCI010"),
        ("worker_cidr", "10.0.0.0/24", "OCI010"),
        ("pod_cidr", "10.1.0.0/24", "OCI010"),
        ("pod_cidr", "10.0.20.0/28", "OCI010"),
        ("services_cidr", "10.0.0.0/16", "OCI010"),
        ("vcn_cidr", "198.51.0.0/16", "OCI010"),
        ("availability_domains", (), "OCI001"),
        ("service_id", "", "OCI001"),
        ("nodes", True, "OCI001"),
        ("nodes", 5, "OCI001"),
        ("boot_gb_per_node", 49, "OCI001"),
        ("boot_gb_per_node", 150, "OCI001"),
        ("max_pods_per_node", 31, "OCI001"),
        ("kubernetes_version", "latest", "OCI020"),
        ("kubernetes_version", "v1.99.1", "OCI020"),
    ],
)
def test_invalid_configuration_fails_before_graph(config, field, value, rule):
    with pytest.raises(ValueError, match=rule):
        foundation_graph(replace(config, **{field: value}))


@pytest.mark.parametrize(
    "field,value",
    [
        ("architecture", "x86_64"),
        ("region", "us-ashburn-1"),
        ("kubernetes_version", "v1.99.1"),
        ("image_id", ""),
        ("source", ""),
        ("reviewed_at", (datetime.now(UTC) - timedelta(days=31)).isoformat()),
        ("reviewed_at", (datetime.now(UTC) + timedelta(days=1)).isoformat()),
    ],
)
def test_image_fallback_stale_and_cross_region_images_fail(config, field, value):
    cfg = replace(config, image=replace(config.image, **{field: value}))
    with pytest.raises(ValueError, match="OCI020"):
        foundation_graph(cfg)


def test_graph_enforces_security_and_cni(config):
    graph = {item.key: item for item in foundation_graph(config)}
    for role in ("api", "worker", "pod"):
        assert graph[role + "-subnet"].props["security_list_ids"] == [Ref("empty-security")]
    assert graph["empty-security"].props["ingress_security_rules"] == []
    assert graph["empty-security"].props["egress_security_rules"] == []
    assert graph["pod-subnet"].props["prohibit_public_ip_on_vnic"] is True
    assert graph["pod-routes"].props["route_rules"] == [
        {
            "destination": config.service_cidr,
            "destination_type": "SERVICE_CIDR_BLOCK",
            "network_entity_id": Ref("services"),
        }
    ]
    assert not any(
        "NatGateway" in item.kind or "LoadBalancer" in item.kind for item in graph.values()
    )
    pool = wire(graph["workers"].props)
    assert pool["nodeConfigDetails"]["nodePoolPodNetworkOptionDetails"]["podNsgIds"]
    assert pool["nodeSourceDetails"]["imageId"] == config.image.image_id
    assert "nodePoolCyclingDetails" not in pool
    for item in graph.values():
        if item.props.get("direction") == "INGRESS" and item.props.get("source") == "0.0.0.0/0":
            assert item.props["protocol"] == "1"
            assert item.props["icmp_options"] == {"type": 3, "code": 4}


@pytest.mark.parametrize("protocol,port", [("all", None), ("6", 22), ("6", 30000), ("6", 6443)])
def test_policy_rejects_broad_public_ingress(protocol, port):
    props = {
        "direction": "INGRESS",
        "source": "0.0.0.0/0",
        "sourceType": "CIDR_BLOCK",
        "protocol": protocol,
        "stateless": False,
    }
    if port:
        props["tcpOptions"] = {"destinationPortRange": {"min": port, "max": port}}
    with pytest.raises(GovernanceError, match="OCI030"):
        validate_resource(
            "oci:Core/networkSecurityGroupSecurityRule:NetworkSecurityGroupSecurityRule", props
        )


def test_policy_rejects_missing_cni_encryption_and_security_list(config):
    graph = {item.key: item for item in foundation_graph(config)}
    for key, field in (
        ("workers", "nodeConfigDetails"),
        ("cluster", "clusterPodNetworkOptions"),
        ("api-subnet", "securityListIds"),
        ("empty-security", "ingressSecurityRules"),
    ):
        props = wire(graph[key].props)
        del props[field]
        with pytest.raises(GovernanceError):
            validate_resource(graph[key].kind, props)


def test_example_requires_actual_reviewed_inputs():
    with pytest.raises(ValueError):
        load_config(ROOT / "config/oci.example.toml")


def test_native_sdk_matches_every_proposed_property_and_failed_preflight_registers_nothing(
    config, tmp_path
):
    payload = {"config": asdict(config), "evidence": evidence()}
    data = tmp_path / "fixture.json"
    data.write_text(json.dumps(payload), encoding="utf-8")
    script = tmp_path / "mock_components.py"
    script.write_text(
        r"""
import hashlib
import json
import sys
from dataclasses import replace
from datetime import datetime, timedelta
import pulumi
from infra_core.oci.config import FoundationConfig, ImageEvidence
from infra_core.oci.graph import Ref, foundation_graph, wire
from infra_program.oci.components import register_foundation as bound_foundation
from infra_core.inventory_evidence import capture_inventory
from infra_program import governance
from infra_program.governance import validate_resource
from types import SimpleNamespace
from unittest.mock import patch

payload = json.load(open(sys.argv[1], encoding="utf-8"))
values = payload["config"]
values["image"] = ImageEvidence(**values["image"])
for key in ("administrator_cidrs", "availability_domains", "supported_versions"):
    values[key] = tuple(values[key])
cfg = FoundationConfig(**values)
account, profile, inventory = payload["evidence"]
COMMIT = 'a' * 40
base_payload, base_envelope = capture_inventory(account, profile, inventory, commit=COMMIT)
expected_account_id = account['account_id']

def register_foundation(cfg, account, profile, inventory):
    # Rebind deliberate negative fixtures without pre-validating them in a producer helper.
    payload = json.dumps(inventory).encode()
    envelope = json.loads(base_envelope)
    envelope['subject'][0]['digest']['sha256'] = hashlib.sha256(payload).hexdigest()
    canonical = json.dumps({'account': account, 'profile': profile}, sort_keys=True,
                           separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
    envelope['predicate']['scope']['configuration_sha256'] = hashlib.sha256(canonical).hexdigest()
    return bound_foundation(cfg, account, profile, payload,
                            envelope=json.dumps(envelope).encode(), commit=COMMIT)
expected = {cfg.name + "-" + item.key: item for item in foundation_graph(cfg)}
observed = {}
violations = []

def expected_wire(value):
    if isinstance(value, Ref):
        return cfg.name + "-" + value.key + "-id"
    if isinstance(value, dict):
        return wire({key: expected_wire(item) for key, item in value.items()})
    if isinstance(value, list):
        return [expected_wire(item) for item in value]
    return value

class Offline(pulumi.runtime.Mocks):
    def new_resource(self, args):
        if args.typ == 'pulumi:providers:oci':
            assert args.inputs['region'] == cfg.region
            assert args.inputs['tenancyOcid'] == expected_account_id
        if args.typ.startswith("oci:"):
            spec = expected[args.name]
            assert args.typ == spec.kind
            # SDK outputs with None are not supplied inputs; compare every intended input exactly.
            actual = {key: value for key, value in args.inputs.items() if value is not None}
            wanted = expected_wire(spec.props)
            assert actual == wanted, (args.name, actual, wanted)
            assert args.provider, "native resources must use the explicit provider"
            observed[args.name] = actual
        validate_resource(SimpleNamespace(resource_type=args.typ, props=args.inputs),
                          lambda message, urn: violations.append(message))
        return args.name + "-id", args.inputs
    def call(self, args):
        raise AssertionError("No live provider lookups or image/version fallbacks are permitted")

pulumi.runtime.set_mocks(Offline(), project="oci-offline", stack="test", preview=True)
for bad_cfg, bad_account, bad_inventory in [
    (replace(cfg, administrator_cidrs=("0.0.0.0/0",)), account, inventory),
    (cfg, dict(account, verified=False), inventory),
    (cfg, {key: value for key, value in account.items() if key != "account_id"}, inventory),
    (cfg, account, dict(inventory, complete=False)),
    (cfg, account, dict(inventory, usage=None)),
    (replace(cfg, memory_gb_per_node=8), account, inventory),
    (replace(cfg, region="us-ashburn-1"), account, inventory),
]:
    try:
        with patch.object(pulumi.Resource, "__init__",
                          side_effect=AssertionError("registration before gate")):
            register_foundation(bad_cfg, bad_account, profile, bad_inventory)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid preflight passed")
assert not observed
with patch.object(pulumi.Resource, '__init__', side_effect=AssertionError('early registration')):
    for fault in ('dictionary', 'mutable', 'bytes', 'missing', 'scope', 'commit', 'stale', 'clock'):
        data, envelope, commit = base_payload, base_envelope, COMMIT
        if fault == 'dictionary':
            data = inventory
        elif fault == 'mutable':
            data = bytearray(data)
        elif fault == 'bytes':
            data += b' '
        elif fault == 'missing':
            envelope = b'{}'
        elif fault == 'commit':
            commit = 'b' * 40
        else:
            statement = json.loads(envelope)
            if fault == 'scope':
                statement['predicate']['scope']['unit'] = 'oci-oke'
            else:
                age = timedelta(hours=1) if fault == 'stale' else timedelta(seconds=1)
                statement['predicate']['collection_started_at'] = (
                    datetime.fromisoformat(inventory['observed_at']) - age).isoformat()
            envelope = json.dumps(statement).encode()
        try:
            bound_foundation(cfg, account, profile, data, envelope=envelope, commit=commit)
            raise AssertionError('invalid evidence passed: ' + fault)
        except ValueError as error:
            assert 'EVID' in str(error) or 'GOV043' in str(error), (fault, str(error))
    for kwargs in ({'commit': COMMIT}, {'envelope': base_envelope}):
        try:
            bound_foundation(cfg, account, profile, base_payload, **kwargs)
            raise AssertionError('missing binding argument passed')
        except TypeError:
            pass
assert not observed
from infra_program.oci import components
with patch.object(pulumi.Resource, '__init__', side_effect=AssertionError('permit bypass')):
    for constructor, arguments in (
        (components.Network, (cfg, (), None, {}, expected_account_id)),
        (components.Oke, (cfg, (), None, {}, None, expected_account_id)),
    ):
        try:
            constructor(*arguments)
            raise AssertionError('component accepted a missing permit')
        except ValueError as error:
            assert 'OCI040' in str(error)
registration_order = []
parents = {}
for kind, constructor in list(components.CONSTRUCTORS.items()):
    def guarded(resource_name, *, opts, _constructor=constructor, **props):
        assert opts.protect is True
        assert opts.parent is not None and opts.provider is not None
        assert opts.import_ is None and not opts.aliases
        unit = expected[resource_name].unit
        assert isinstance(opts.parent, components.Network if unit == 'oci-network'
                          else components.Oke)
        parents[unit] = opts.parent
        registration_order.append(resource_name)
        return _constructor(resource_name, opts=opts, **props)
    components.CONSTRUCTORS[kind] = guarded
real_audit = governance.audit
def mutating_audit(a, p, observed_inventory, plan):
    account['account_id'] = 'unexpected-account'
    account['home_region'] = 'unexpected-region'
    profile['enabled'] = False
    return real_audit(a, p, observed_inventory, plan)
with patch.object(governance, 'audit', mutating_audit):
    network, cluster = register_foundation(cfg, account, profile, inventory)
assert registration_order == list(expected)
assert parents == {'oci-network': network, 'oci-oke': cluster}
for field, value in (('schema_version', 2), ('region', 'other'),
                     ('compartment_id', 'other'), ('account_id', 'other'), ('cidrs', {})):
    try:
        components._validate_network_outputs(replace(network.outputs, **{field: value}),
                                             cfg, expected_account_id)
        raise AssertionError('network interface mismatch accepted: ' + field)
    except ValueError as error:
        assert 'OCI001' in str(error)

@pulumi.runtime.test
def check():
    def complete(outputs):
        assert len(observed) == len(expected), (len(observed), len(expected))
        assert not violations, violations
        assert network.outputs.schema_version == 1
        assert network.outputs.account_id == expected_account_id
        assert network.outputs.region == cfg.region
        assert network.outputs.compartment_id == cfg.compartment_id
        assert network.outputs.cidrs == {'vcn': cfg.vcn_cidr, 'api': cfg.api_cidr,
                                        'worker': cfg.worker_cidr, 'pod': cfg.pod_cidr}
        assert set(network.outputs.ids) == {"vcn", "api-subnet", "worker-subnet", "pod-subnet",
                                            "api-nsg", "worker-nsg", "pod-nsg"}
        assert outputs[:2] == [cfg.name + "-cluster-id", cfg.name + "-workers-id"]
        prefix = 'urn:pulumi:test::oci-offline::'
        assert outputs[2:] == [prefix + 'infrastructure:oci:Network::' + cfg.name + '-network',
                              prefix + 'infrastructure:oci:Oke::' + cfg.name + '-oke']
        print(json.dumps({"resources": len(observed), "violations": violations}))
    return pulumi.Output.all(cluster.cluster_id, cluster.node_pool_id,
                             network.urn, cluster.urn).apply(complete)
check()
""",
        encoding="utf-8",
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(("PULUMI_", "OCI_", "AWS_", "TF_", "TG_"))
    }
    result = subprocess.run(
        [sys.executable, str(script), str(data)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        encoding="utf-8",
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["resources"] == len(foundation_graph(config))


def test_cli_renders_same_graph_and_rejects_unknown_config_keys(config, tmp_path, capsys):
    from infra_core.cli import main

    values = asdict(config)
    image = values.pop("image")
    text = "[foundation]\n" + "\n".join(
        f"{key} = {json.dumps(value)}" for key, value in values.items()
    )
    text += "\n[image]\n" + "\n".join(
        f"{key} = {json.dumps(value)}" for key, value in image.items()
    )
    path = tmp_path / "valid.toml"
    path.write_text(text, encoding="utf-8")
    assert load_config(path) == config
    assert (
        main(
            [
                "--root",
                str(ROOT),
                "oci",
                "proposal",
                "--config",
                str(path),
                "--account-id",
                "synthetic-tenancy",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == proposal(
        foundation_graph(config), "synthetic-tenancy", config.region
    )
    path.write_text(text + '\nunknown_field = "reject"\n', encoding="utf-8")
    with pytest.raises(GovernanceError, match="GOV003"):
        load_config(path)
