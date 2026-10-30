"""Independent service gates isolate Cloudflare staging from Supabase and other writers."""

import argparse
import json
from pathlib import Path

import pytest
from infra_program import service_apply as a

ROOT = Path(__file__).resolve().parents[1]
UNITS = ("cloudflare-edge", "supabase-database")


def write(root, value):
    (root / "config").mkdir(exist_ok=True)
    (root / "config/service-apply.json").write_text(json.dumps(value))


@pytest.mark.parametrize("enabled", UNITS)
@pytest.mark.parametrize("selected", UNITS)
def test_only_selected_service_can_be_enabled(tmp_path, enabled, selected):
    write(tmp_path, dict(schema_version=2, units={u: u == enabled for u in UNITS}))
    if selected == enabled:
        a._enabled(tmp_path, unit=selected)
    else:
        with pytest.raises(ValueError):
            a._enabled(tmp_path, unit=selected)


@pytest.mark.parametrize(
    "value",
    [
        {"schema_version": 1, "enabled": True},
        {"schema_version": 1, "enabled": False},
        {"schema_version": True, "units": dict.fromkeys(UNITS, True)},
        {"schema_version": 2, "units": {"cloudflare-edge": True}},
        {"schema_version": 2, "units": dict.fromkeys((*UNITS, "oci-network"), True)},
        {"schema_version": 2, "units": {"cloudflare-edge": True, "supabase-database": 0}},
        {"schema_version": 2, "units": {"cloudflare-edge": "true", "supabase-database": False}},
        {"schema_version": 2, "units": dict.fromkeys(UNITS, False)},
        {"schema_version": 2, "units": dict.fromkeys(UNITS, True), "enabled": True},
        {"schema_version": 2, "units": []},
        None,
    ],
)
def test_malformed_legacy_or_disabled_gate_fails_closed(tmp_path, value):
    write(tmp_path, value)
    with pytest.raises(ValueError):
        a._enabled(tmp_path, unit="cloudflare-edge")


def test_unknown_unit_rejected(tmp_path):
    write(tmp_path, dict(schema_version=2, units=dict.fromkeys(UNITS, True)))
    with pytest.raises(ValueError):
        a._enabled(tmp_path, unit="oci-network")


@pytest.mark.parametrize("entry", ["load", "service"])
def test_disabled_cloudflare_rejected_before_bundle_or_secret_reads(tmp_path, monkeypatch, entry):
    write(
        tmp_path,
        dict(schema_version=2, units={"cloudflare-edge": False, "supabase-database": True}),
    )
    monkeypatch.setattr(a, "_private", lambda *args: pytest.fail("bundle read"))
    monkeypatch.setattr(a.preview, "_read", lambda *args: pytest.fail("input read"))
    with pytest.raises(ValueError):
        if entry == "load":
            a._load(tmp_path, argparse.Namespace(unit="cloudflare-edge"))
        else:
            # _service is also called by the owned child through _admit.
            a._service(tmp_path, "cloudflare-edge", "a" * 40, {})


@pytest.mark.parametrize("importing", [False, True])
def test_oci_and_import_gate_contracts_unchanged(tmp_path, importing):
    write(tmp_path, dict(schema_version=2, units=dict.fromkeys(UNITS, False)))
    path = tmp_path / ("config/resource-import.json" if importing else "config/oci-apply.json")
    path.write_text('{"schema_version":1,"enabled":true}')
    a._enabled(tmp_path, oci=True, importing=importing)
    path.write_text('{"schema_version":1,"enabled":false}')
    with pytest.raises(ValueError):
        a._enabled(tmp_path, oci=True, importing=importing)


def test_committed_policy_keeps_both_services_disabled():
    assert json.loads((ROOT / "config/service-apply.json").read_bytes()) == dict(
        schema_version=2, units=dict.fromkeys(UNITS, False)
    )
