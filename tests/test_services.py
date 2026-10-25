"""Closed service proposals, billing scopes and real SDK serialization without cloud access."""

import json
import os
import subprocess
import sys
import tomllib
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from infra_core.governance.contracts import GovernanceError
from infra_core.services.governance import DNS, PROJECT, audit, validate_resource
from infra_program.governance import validate_resource as policy

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(params=["cloudflare", "supabase"])
def service(request):
    provider = request.param
    now = datetime.now(UTC)
    scope = "a" * 32 if provider == "cloudflare" else "example-org"
    metrics = (
        {}
        if provider == "cloudflare"
        else {
            "egress_mb": 100,
            "cached_egress_mb": 100,
            "storage_mb": 100,
            "mau": 100,
        }
    )
    config = {
        "schema_version": 1,
        "provider": provider,
        "unit": ("cloudflare-edge" if provider == "cloudflare" else "supabase-database"),
        "account_id": "synthetic-account",
        "scope_id": scope,
        "growth": metrics.copy(),
        "resources": [
            {
                "key": "app",
                "type": DNS if provider == "cloudflare" else PROJECT,
                "props": (
                    {
                        "zoneId": scope,
                        "name": "app.example.com",
                        "type": "A",
                        "ttl": 300,
                        "content": "192.0.2.1",
                        "proxied": False,
                    }
                    if provider == "cloudflare"
                    else {
                        "organizationId": scope,
                        "name": "example-db",
                        "region": "eu-central-1",
                        "instanceSize": "nano",
                        "legacyApiKeysEnabled": False,
                    }
                ),
            }
        ],
    }
    evidence = {
        "schema_version": 1,
        "provider": provider,
        "account_id": "synthetic-account",
        "scope_id": scope,
        "scope_name": "example.com" if provider == "cloudflare" else scope,
        "profile_revision": 1,
        "verified": True,
        "verified_at": now.isoformat(),
        "observed_at": now.isoformat(),
        "complete": True,
        "source": "synthetic-test",
        "plan": "free",
        "other_services_reviewed": True,
        "usage_month": now.strftime("%Y-%m"),
        "resources": [],
        "usage": metrics.copy(),
        "coverage": (
            "all-zone-dns-records"
            if provider == "cloudflare"
            else "all-owned-admin-free-projects-and-target-org-usage"
        ),
    }
    profile = tomllib.loads((ROOT / "config/quotas/profiles.toml").read_text())["profiles"][
        provider + "-free"
    ]
    return config, evidence, profile


def test_audit_is_offline_bound_and_never_authorizes(service):
    config, evidence, profile = service
    original = deepcopy(service)
    result = audit(config, evidence, profile)
    assert result["deployment_authorized"] is False
    assert result["peak_resources"] == 1
    assert service == original
    config["resources"][0]["props"]["name"] = "changed"
    assert result["resources"][0]["props"]["name"] != "changed"


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("verified", False, "EXT003"),
        ("complete", False, "EXT003"),
        ("other_services_reviewed", False, "EXT003"),
        ("plan", "pro", "EXT003"),
        ("account_id", "other", "EXT004"),
        ("scope_id", "other", "EXT004"),
        ("provider", "oci", "EXT004"),
        ("coverage", "one-project", "EXT003"),
        ("profile_revision", 2, "EXT001"),
        ("usage_month", "2000-01", "EXT002"),
        ("observed_at", "2000-01-01T00:00:00+00:00", "EXT002"),
        ("verified_at", "2000-01-01T00:00:00+00:00", "EXT002"),
    ],
)
def test_untrusted_or_wrong_scope_evidence_is_rejected(service, field, value, code):
    config, evidence, profile = service
    evidence[field] = value
    with pytest.raises(GovernanceError, match=code):
        audit(config, evidence, profile)


def test_partial_unknown_future_and_duplicate_documents_fail(service):
    config, evidence, profile = service
    evidence["observed_at"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    with pytest.raises(GovernanceError, match="EXT002"):
        audit(config, evidence, profile)
    evidence["observed_at"] = datetime.now(UTC).isoformat()
    config["resources"] *= 2
    with pytest.raises(GovernanceError, match="EXT005"):
        audit(config, evidence, profile)
    config["resources"] = config["resources"][:1]
    config["action"] = "replace"
    with pytest.raises(GovernanceError, match="GOV003"):
        audit(config, evidence, profile)


def test_unmanaged_capacity_counts_at_peak(service):
    config, evidence, profile = service
    cf = config["provider"] == "cloudflare"
    evidence["resources"] = [
        (
            {"id": str(i), "name": f"record{i}.example.com", "type": "TXT"}
            if cf
            else {"id": str(i), "scope_id": "other-free-org", "database_mb": 100}
        )
        for i in range(200 if cf else 2)
    ]
    with pytest.raises(GovernanceError, match="EXT020"):
        audit(config, evidence, profile)
    evidence["resources"].pop()
    assert audit(config, evidence, profile)["peak_resources"] == (200 if cf else 2)
    evidence["resources"].append(deepcopy(evidence["resources"][0]))
    with pytest.raises(GovernanceError, match="EXT005"):
        audit(config, evidence, profile)


@pytest.mark.parametrize(
    "change",
    [
        {"type": "TXT"},
        {"proxied": True},
        {"ttl": True},
        {"ttl": 0},
        {"content": "invalid"},
        {"name": "outside.invalid"},
        {"zoneId": "b" * 32},
        {"settings": {}},
    ],
)
@pytest.mark.parametrize("service", ["cloudflare"], indirect=True)
def test_dns_subset_is_closed(service, change):
    config, evidence, profile = service
    config["resources"][0]["props"].update(change)
    with pytest.raises(GovernanceError):
        audit(config, evidence, profile)


@pytest.mark.parametrize(
    "change",
    [
        {"instanceSize": "micro"},
        {"legacyApiKeysEnabled": True},
        {"region": "auto"},
        {"organizationId": "other-org"},
        {"customDomain": "db.example.com"},
        {"databasePassword": "must-not-enter-proposal"},
    ],
)
@pytest.mark.parametrize("service", ["supabase"], indirect=True)
def test_database_subset_is_closed(service, change):
    config, evidence, profile = service
    config["resources"][0]["props"].update(change)
    with pytest.raises(GovernanceError):
        audit(config, evidence, profile)


@pytest.mark.parametrize("service", ["supabase"], indirect=True)
def test_org_usage_plus_growth_and_per_project_database_limits(service):
    config, evidence, profile = service
    config["growth"]["egress_mb"] = 4900
    assert audit(config, evidence, profile)["forecast"]["egress_mb"] == "5000"
    config["growth"]["egress_mb"] = 4901
    with pytest.raises(GovernanceError, match="EXT021"):
        audit(config, evidence, profile)
    config["growth"]["egress_mb"] = 0
    evidence["resources"] = [{"id": "external", "scope_id": "other-org", "database_mb": 501}]
    with pytest.raises(GovernanceError, match="EXT020"):
        audit(config, evidence, profile)


def test_mandatory_policy_agrees_and_denies_unknown_paid_fields(service):
    config, _, _ = service
    item = config["resources"][0]
    props = deepcopy(item["props"])
    if item["type"] == PROJECT:
        props["databasePassword"] = "synthetic-secret"
    violations = []
    policy(
        SimpleNamespace(resource_type=item["type"], props=props),
        lambda msg, urn: violations.append(msg),
    )
    assert violations == []
    props["paidAddon"] = True
    policy(
        SimpleNamespace(resource_type=item["type"], props=props),
        lambda msg, urn: violations.append(msg),
    )
    assert violations and "synthetic-secret" not in violations[0]
    with pytest.raises(GovernanceError, match="EXT012"):
        validate_resource("cloudflare:index/workersScript:WorkersScript", {})


@pytest.mark.parametrize(
    "kind,props",
    [
        ("pulumi:providers:cloudflare", {"apiToken": "synthetic", "baseUrl": "http://untrusted"}),
        ("pulumi:providers:supabase", {"accessToken": "synthetic", "endpoint": "http://untrusted"}),
        (
            "pulumi:providers:cloudflare",
            {
                "apiToken": "synthetic",
                "baseUrl": "https://api.cloudflare.com/client/v4",
                "pluginDownloadURL": "https://untrusted",
            },
        ),
        (
            "pulumi:providers:supabase",
            {
                "accessToken": "synthetic",
                "endpoint": "https://api.supabase.com",
                "version": "latest",
            },
        ),
    ],
)
def test_policy_rejects_provider_overrides(kind, props):
    violations = []
    policy(
        SimpleNamespace(resource_type=kind, props=props), lambda msg, urn: violations.append(msg)
    )
    assert len(violations) == 1 and "EXT012" in violations[0]


@pytest.mark.parametrize("service", ["cloudflare"], indirect=True)
def test_existing_service_records_count_and_new_records_remain_closed(service):
    config, evidence, profile = service
    evidence["resources"] = [
        {"id": "txt", "name": "_dkim.example.com", "type": "TXT"},
        {"id": "wildcard", "name": "*.example.com", "type": "A"},
    ]
    assert audit(config, evidence, profile)["peak_resources"] == 3
    props = config["resources"][0]["props"]
    props.update(type="CNAME", content="target.example.net")
    assert audit(config, evidence, profile)["peak_resources"] == 3
    props.update(type="AAAA", content="2001:db8::1")
    assert audit(config, evidence, profile)["peak_resources"] == 3
    props["name"] = "_dkim.example.com"
    with pytest.raises(GovernanceError):
        audit(config, evidence, profile)


def test_cli_audits_same_proposal_and_fails_closed(service, tmp_path, capsys):
    from infra_core.cli import main

    config, evidence, profile = service
    c, e = tmp_path / "proposal.json", tmp_path / "evidence.json"
    c.write_text(json.dumps(config))
    e.write_text(json.dumps(evidence))
    argv = ["--root", str(ROOT), "services", "audit", "--config", str(c), "--evidence", str(e)]
    assert main(argv) == 0
    assert json.loads(capsys.readouterr().out) == audit(config, evidence, profile)
    evidence["complete"] = False
    e.write_text(json.dumps(evidence))
    assert main(argv) == 1
    assert "EXT003" in capsys.readouterr().err
    c.write_text("[]")
    assert main(argv) == 1
    assert "GOV003" in capsys.readouterr().err


def test_actual_sdks_emit_only_audited_protected_secret_resources(service, tmp_path):
    data = tmp_path / "data.json"
    data.write_text(json.dumps(service))
    script = tmp_path / "mock_services.py"
    script.write_text(
        r"""
import json
import sys
from types import SimpleNamespace
from unittest.mock import patch
import pulumi
from pulumi.runtime import rpc
from pulumi.runtime.settings import get_monitor
from infra_program.services.components import register_services, Services
from infra_program.governance import validate_resource

config, evidence, profile = json.load(open(sys.argv[1]))
observed = {}
class Offline(pulumi.runtime.Mocks):
    def new_resource(self, args):
        violations = []
        validate_resource(SimpleNamespace(resource_type=args.typ, props=args.inputs),
                          lambda msg, urn: violations.append(msg))
        assert not violations, violations
        observed[args.name] = args
        return args.name + '-id', args.inputs
    def call(self, args):
        raise AssertionError('No provider invokes allowed')
pulumi.runtime.set_mocks(Offline(), project='external-test', stack='offline', preview=True)
monitor = get_monitor()
real_package = monitor.RegisterPackage
packages = []
def register_package(request):
    packages.append(request)
    return real_package(request)
monitor.RegisterPackage = register_package
token = pulumi.Output.secret('synthetic-token')
passwords = ({'app': pulumi.Output.secret('synthetic-password')}
             if config['provider'] == 'supabase' else {})
with patch.object(pulumi.ComponentResource, '__init__', side_effect=AssertionError('early')):
    bad = dict(evidence, complete=False)
    try:
        register_services(config, bad, profile, token, passwords)
        raise AssertionError('invalid evidence passed')
    except ValueError as error:
        assert 'EXT003' in str(error)
    try:
        Services({}, token, {})
        raise AssertionError('direct construction passed')
    except ValueError as error:
        assert 'EXT030' in str(error)
    for bad_token, bad_passwords in [('plaintext', passwords), (token, {'extra': token})]:
        try:
            register_services(config, evidence, profile, bad_token, bad_passwords)
            raise AssertionError('invalid secret inputs passed')
        except ValueError as error:
            assert 'EXT031' in str(error)
real_init = pulumi.Resource.__init__
options = []
def record(self, typ, name, custom, props=None, opts=None, *args, **kwargs):
    assert opts.protect is True
    options.append((typ, opts))
    return real_init(self, typ, name, custom, props, opts, *args, **kwargs)
with patch.object(pulumi.Resource, '__init__', record):
    component = register_services(config, evidence, profile, token, passwords)

@pulumi.runtime.test
def verify():
    resource = component.resources['app']
    def check(_):
        assert len(observed) == 3, observed.keys()
        item = config['resources'][0]
        args = observed[config['unit'] + '-app']
        actual = dict(args.inputs)
        if config['provider'] == 'supabase':
            password = actual.pop('databasePassword')
            assert rpc.is_rpc_secret(password)
            assert rpc.unwrap_rpc_secret(password) == 'synthetic-password'
            assert len(packages) == 1
            package = packages[0]
            assert (package.name, package.version) == ('terraform-provider', '1.5.0')
            assert (package.parameterization.name, package.parameterization.version) == (
                'supabase', '1.11.0')
            assert json.loads(package.parameterization.value) == {
                'remote': {'url': 'registry.opentofu.org/supabase/supabase', 'version': '1.11.0'}}
        else:
            assert not packages
        assert actual == item['props'], (actual, item['props'])
        assert args.provider and args.provider.endswith('-provider-id')
        for typ, opts in options:
            if typ != 'infrastructure:services:Independent':
                assert opts.parent is component
            if typ == item['type']:
                assert opts.provider is component.provider
        print(json.dumps({'provider': config['provider'], 'resources': len(observed)}))
    secrets = [pulumi.Output.is_secret(token)]
    if config['provider'] == 'supabase':
        secrets += [pulumi.Output.is_secret(resource.database_password),
                    pulumi.Output.is_secret(component.provider.access_token)]
    else:
        secrets += [pulumi.Output.is_secret(component.provider.api_token)]
    def checked(values):
        assert all(values[1:]), values
        check(values[0])
    return pulumi.Output.all(resource.id, *secrets).apply(checked)
verify()
""",
        encoding="utf-8",
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(("PULUMI_", "OCI_", "AWS_", "SUPABASE_", "CLOUDFLARE_"))
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
    assert json.loads(result.stdout)["resources"] == 3
