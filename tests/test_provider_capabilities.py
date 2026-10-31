"""Capability reports describe bounded source support without operational authority."""

import json
import subprocess
import sys
import tomllib
from dataclasses import replace
from pathlib import Path

import pytest
from infra_core.cli import main
from infra_core.provider_capabilities import CATALOG, PROVIDERS, inspect, validate_catalog

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def checkout(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config/pulumi.toml").write_bytes((ROOT / "config/pulumi.toml").read_bytes())
    return tmp_path


def test_report_distinguishes_source_support_from_authority():
    report = inspect(ROOT)
    assert report["schema_version"] == 1
    assert report["kind"] == "provider-capabilities"
    for field in (
        "sdk_installation_checked",
        "live_controls_verified",
        "execution_authorized",
        "activation_authorized",
    ):
        assert report[field] is False
    entries = {item["provider"]: item for item in report["providers"]}
    assert set(entries) == set(PROVIDERS)
    assert entries["oci"]["support"] == "partial"
    assert "watermark" in entries["oci"]["limitations"][0]
    assert "supplemental" in entries["supabase"]["limitations"][0]
    for name in ("aws", "gcp", "neon", "flyio", "render", "vercel", "netlify"):
        assert entries[name]["support"] == "unsupported"
        assert entries[name]["sdk_binding"] is None
        assert entries[name]["units"] == []
        assert entries[name]["components"] == ()
    assert {unit["name"] for item in entries.values() for unit in item["units"]} == {
        "oci-network",
        "oci-oke",
        "cloudflare-edge",
        "supabase-database",
    }


def test_sdk_claims_match_declared_dependencies():
    manifest = tomllib.loads((ROOT / "packages/infra-program/pyproject.toml").read_text())
    bindings = {
        dependency.split("==")[0]
        for dependency in manifest["project"]["dependencies"]
        if dependency.startswith("pulumi-") and "==" in dependency
    }
    assert {item.sdk_binding for item in CATALOG if item.sdk_binding} == bindings


def test_preview_flag_is_read_from_configuration_without_granting_authority(checkout):
    path = checkout / "config/pulumi.toml"
    path.write_text(
        path.read_text().replace("preview_enabled = false", "preview_enabled = true", 1)
    )
    report = inspect(checkout, "oci")
    assert report["providers"][0]["units"][0]["preview_enabled"] is True
    assert report["providers"][0]["units"][0]["foundation_enabled"] is False
    assert report["execution_authorized"] is False


def test_invalid_enabled_configuration_is_rejected(checkout):
    path = checkout / "config/pulumi.toml"
    path.write_text(path.read_text().replace("enabled = false", "enabled = true", 1))
    with pytest.raises(ValueError, match="STACK001"):
        inspect(checkout)


@pytest.mark.parametrize("provider", ["unknown", "OCI", "", "../oci"])
def test_unknown_provider_selection_is_rejected(provider):
    with pytest.raises(ValueError, match="CAP002"):
        inspect(ROOT, provider)


@pytest.mark.parametrize(
    "catalog",
    [
        CATALOG[:-1],
        CATALOG + (CATALOG[0],),
        (replace(CATALOG[0], sdk_binding=None), *CATALOG[1:]),
        (replace(CATALOG[0], classification=()), *CATALOG[1:]),
        (replace(CATALOG[0], units=()), *CATALOG[1:]),
        (replace(CATALOG[0], limitations=()), *CATALOG[1:]),
        (replace(CATALOG[0], units=("oci-network", "oci-network")), *CATALOG[1:]),
    ],
)
def test_inconsistent_catalog_is_rejected(catalog):
    with pytest.raises(ValueError, match="CAP001"):
        validate_catalog(catalog)


def test_unit_scope_disagreement_is_rejected(monkeypatch):
    monkeypatch.setattr(
        "infra_core.provider_capabilities.CATALOG",
        (
            replace(CATALOG[0], units=("unexpected-unit",)),
            *CATALOG[1:],
        ),
    )
    with pytest.raises(ValueError, match="CAP001"):
        inspect(ROOT)


def test_cli_filter_and_unknown_selection(capsys):
    assert main(["--root", str(ROOT), "providers", "inspect", "--provider", "gcp"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert [item["provider"] for item in report["providers"]] == ["gcp"]
    assert main(["--root", str(ROOT), "providers", "inspect", "--provider", "unknown"]) == 1
    captured = capsys.readouterr()
    assert not captured.out
    assert "CAP002" in captured.err


def test_inspection_does_not_import_sdks_or_use_network_or_write_files():
    script = """
import sys
from pathlib import Path
from infra_core.provider_capabilities import inspect

def audit(event, args):
    if event.startswith("socket."):
        raise AssertionError("network access")
    if event == "open" and isinstance(args[1], str) and any(c in args[1] for c in "wax+"):
        raise AssertionError("file write")
    if event == "import" and args[0].split(".")[0] in {
        "pulumi", "pulumi_oci", "pulumi_cloudflare", "pulumi_supabase", "oci"
    }:
        raise AssertionError("SDK import")
sys.addaudithook(audit)
assert len(inspect(Path(sys.argv[1]))["providers"]) == 10
"""
    subprocess.run([sys.executable, "-B", "-c", script, str(ROOT)], check=True, timeout=30)
