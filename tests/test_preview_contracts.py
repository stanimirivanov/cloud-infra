"""Closed identity/DAG contracts must not confer execution authority."""

import json
import subprocess
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path

import pytest
from infra_core import cli
from infra_core.foundation import deny_deployment, load_foundation
from infra_core.preview_contracts import describe_preview

ROOT = Path(__file__).resolve().parents[1]


def test_four_explicit_identities_match_the_program_project():
    config = load_foundation(ROOT)
    assert f"name: {config.project}\n" in (ROOT / "packages/infra-program/Pulumi.yaml").read_text()
    assert len(config.units) == 4
    for unit in config.units:
        assert unit.stack_identity == f"organization/free-infrastructure/{unit.name}"
        assert unit.preview_enabled is False
        assert unit.depends_on == (("oci-network",) if unit.name == "oci-oke" else ())


@pytest.mark.parametrize(
    "old,new",
    [
        ("schema_version = 3", "schema_version = 2"),
        ('project = "free-infrastructure"', 'project = "other"'),
        ('project = "free-infrastructure"', 'project = "../escape"'),
        ('project = "free-infrastructure"\n', ""),
        ('stack = "oci-network"', 'stack = "oci-oke"'),
        ('provider = "oci"', 'provider = "aws"'),
        ("enabled = false", "enabled = true"),
        ("preview_enabled = false", 'preview_enabled = "false"'),
        ("preview_enabled = false\n", ""),
        ("depends_on = []", 'depends_on = "oci-network"'),
        ("depends_on = []", "depends_on = [1]"),
        ("depends_on = []", 'depends_on = ["missing"]'),
        ('depends_on = ["oci-network"]', 'depends_on = ["oci-network", "oci-network"]'),
        ('depends_on = ["oci-network"]', "depends_on = []"),
        ("depends_on = []", 'depends_on = ["oci-oke"]'),
        ("depends_on = []", "depends_on = []\nunknown = false"),
        ("[units.cloudflare-edge]", "[units.unreviewed]"),
    ],
)
def test_invalid_foundation_fails_closed(tmp_path, old, new):
    source = (ROOT / "config/pulumi.toml").read_text()
    assert old in source
    (tmp_path / "config").mkdir()
    (tmp_path / "config/pulumi.toml").write_text(source.replace(old, new, 1))
    with pytest.raises(ValueError):
        load_foundation(tmp_path)


def test_direct_construction_cannot_bypass_identity_or_cycle_checks():
    config = load_foundation(ROOT)
    network, oke, *services = config.units
    for units in (
        (network, network, *services),
        (network, replace(oke, stack=network.stack), *services),
        (replace(network, depends_on=("oci-oke",)), oke, *services),
        (replace(network, project="other"), oke, *services),
        (network, oke),
    ):
        with pytest.raises(ValueError, match="STACK00"):
            replace(config, units=units)


def test_description_is_immutable_serializable_and_bound_to_configuration():
    config = load_foundation(ROOT)
    contract = describe_preview(config, "oci-oke", "a" * 40)
    assert contract.dependency_stacks == ("organization/free-infrastructure/oci-network",)
    assert contract.configuration_sha256 == config.digest
    assert json.loads(json.dumps(asdict(contract)))["schema_version"] == 1
    with pytest.raises(FrozenInstanceError):
        contract.preview_enabled = True
    changed = replace(config, units=tuple(replace(u, preview_enabled=True) for u in config.units))
    assert changed.digest != config.digest
    assert describe_preview(changed, "oci-oke", "a" * 40).digest != contract.digest
    assert describe_preview(config, "oci-oke", "b" * 40).digest != contract.digest
    assert (
        replace(config, backend=replace(config.backend, prefix="pulumi/other")).digest
        != config.digest
    )


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"commit_sha": "main"},
        {"configuration_sha256": ""},
        {"stack_identity": "oci-oke"},
        {"dependency_stacks": ()},
        {"preview_enabled": "true"},
        {"unit": "unknown"},
    ],
)
def test_malformed_preview_contract_is_rejected(change):
    contract = describe_preview(load_foundation(ROOT), "oci-oke", "a" * 40)
    with pytest.raises(ValueError, match="PREVIEW001"):
        replace(contract, **change)


def test_unknown_unit_and_ambient_commit_are_rejected():
    config = load_foundation(ROOT)
    with pytest.raises(ValueError, match="unknown preview unit"):
        describe_preview(config, "other", "a" * 40)
    with pytest.raises(ValueError, match="commit"):
        describe_preview(config, "oci-network", "HEAD")


def test_flag_and_description_never_enable_execution(monkeypatch):
    config = load_foundation(ROOT)
    config = replace(config, units=tuple(replace(u, preview_enabled=True) for u in config.units))
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("execution attempted"))
    monkeypatch.setattr(cli, "load_foundation", lambda root: config)
    for unit in config.units:
        assert describe_preview(config, unit.name, "a" * 40).preview_enabled is True
        with pytest.raises(RuntimeError, match="disabled"):
            deny_deployment(config, unit.name)
        for operation in ("preview", "deploy"):
            assert cli.main(["--root", str(ROOT), operation, "--unit", unit.name]) == 1
