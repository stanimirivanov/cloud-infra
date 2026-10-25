"""Shared configuration and workspace installation contracts."""

import dataclasses
import tomllib
from importlib.metadata import distribution
from pathlib import Path

import pytest
from infra_core.config import AccountConfig, Provider, UnitConfig

ROOT = Path(__file__).resolve().parents[1]


def test_workspace_members_install_from_one_root_lock():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8-sig"))
    assert config["tool"]["uv"]["workspace"]["members"] == [
        "packages/infra-core",
        "packages/infra-program",
    ]
    for name in ("infra-core", "infra-program"):
        assert distribution(name).version == "0.1.0"
        assert not (ROOT / "packages" / name / "uv.lock").exists()
    core = tomllib.loads(
        (ROOT / "packages/infra-core/pyproject.toml").read_text(encoding="utf-8-sig")
    )
    assert not any("pulumi" in dependency for dependency in core["project"]["dependencies"])


def test_valid_account_and_unit_are_immutable():
    account = AccountConfig("personal", Provider.OCI, "ocid1.tenancy.example", "eu-frankfurt-1")
    unit = UnitConfig("oci-network", account)
    assert unit.account.provider == Provider.OCI
    with pytest.raises(dataclasses.FrozenInstanceError):
        unit.name = "changed"


@pytest.mark.parametrize("name", ["", "../escape", "UPPER", "two words", "double--hyphen"])
def test_unit_names_are_identifiers(name):
    with pytest.raises(ValueError, match="unit name"):
        UnitConfig(name, AccountConfig("personal", Provider.CLOUDFLARE, "account-id"))


def test_oci_account_requires_home_region():
    with pytest.raises(ValueError, match="home_region"):
        AccountConfig("personal", Provider.OCI, "ocid1.tenancy.example")


@pytest.mark.parametrize("account_id", ["", "  ", " leading", "trailing "])
def test_account_identifier_cannot_be_blank_or_padded(account_id):
    with pytest.raises(ValueError, match="account_id"):
        AccountConfig("personal", Provider.CLOUDFLARE, account_id)
