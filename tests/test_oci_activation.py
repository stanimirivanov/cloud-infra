"""Network staging never enables OKE or another action; defaults remain disabled."""

import argparse
import json
from pathlib import Path

import pytest
from infra_program import import_driver, oci_apply
from infra_program import service_apply as driver

ROOT = Path(__file__).resolve().parents[1]
UNITS = ("oci-network", "oci-oke")


def policy(root, action, units):
    (root / "config").mkdir(exist_ok=True)
    path = root / "config" / ("resource-import.json" if action == "import" else "oci-apply.json")
    path.write_text(json.dumps(dict(schema_version=2, units=units)))
    return path


@pytest.mark.parametrize("enabled_action", ["apply", "import"])
@pytest.mark.parametrize("selected_action", ["apply", "import"])
@pytest.mark.parametrize("enabled_unit", UNITS)
@pytest.mark.parametrize("selected_unit", UNITS)
def test_unit_and_action_are_independently_gated(
    tmp_path, enabled_action, selected_action, enabled_unit, selected_unit
):
    for action in ("apply", "import"):
        policy(tmp_path, action, {u: action == enabled_action and u == enabled_unit for u in UNITS})
    if selected_action == enabled_action and selected_unit == enabled_unit:
        driver._enabled(tmp_path, True, selected_action == "import", unit=selected_unit)
    else:
        with pytest.raises(ValueError):
            driver._enabled(tmp_path, True, selected_action == "import", unit=selected_unit)


@pytest.mark.parametrize("action", ["apply", "import"])
@pytest.mark.parametrize(
    "value",
    [
        {"schema_version": 1, "enabled": True},
        {"schema_version": 1, "enabled": False},
        {"schema_version": True, "units": dict.fromkeys(UNITS, True)},
        {"schema_version": 2, "units": {"oci-network": True}},
        {"schema_version": 2, "units": dict.fromkeys((*UNITS, "cloudflare-edge"), True)},
        {"schema_version": 2, "units": {"oci-network": True, "oci-oke": 0}},
        {"schema_version": 2, "units": {"oci-network": "true", "oci-oke": False}},
        {"schema_version": 2, "units": dict.fromkeys(UNITS, True), "enabled": True},
        {"schema_version": 2, "units": []},
        None,
    ],
)
def test_closed_schema_and_legacy_rejection(tmp_path, action, value):
    path = policy(tmp_path, action, dict.fromkeys(UNITS, False))
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        driver._enabled(tmp_path, True, action == "import", unit="oci-network")


@pytest.mark.parametrize("action", ["apply", "import"])
@pytest.mark.parametrize("entry", ["load", "prepare", "execute"])
def test_oke_denied_before_lock_inputs_or_credentials(tmp_path, monkeypatch, action, entry):
    policy(tmp_path, action, {"oci-network": True, "oci-oke": False})
    module = import_driver if action == "import" else oci_apply

    def forbidden(*args, **kwargs):
        pytest.fail("disabled unit reached inputs, locks or credentials")

    monkeypatch.setattr(module, "_private", forbidden)
    monkeypatch.setattr(driver, "_private", forbidden)
    args = argparse.Namespace(unit="oci-oke", check=False)
    with pytest.raises(ValueError):
        if entry == "load":
            driver._load(tmp_path, args, True, action == "import")
        elif entry == "prepare":
            if action == "import":
                module.prepare(tmp_path, "oci-oke", "a" * 40, {}, b"[]")
            else:
                module.prepare(tmp_path, "oci-oke", "a" * 40, {})
        else:
            module.execute(tmp_path, args, forbidden)


@pytest.mark.parametrize("action", ["apply", "import"])
@pytest.mark.parametrize("unit", [None, "cloudflare-edge", "unknown"])
def test_missing_or_wrong_unit_cannot_use_oci_gate(tmp_path, action, unit):
    policy(tmp_path, action, dict.fromkeys(UNITS, True))
    with pytest.raises(ValueError):
        driver._enabled(tmp_path, True, action == "import", unit=unit)


def test_import_mode_cannot_be_selected_without_oci(tmp_path):
    policy(tmp_path, "import", dict.fromkeys(UNITS, True))
    with pytest.raises(ValueError):
        driver._enabled(tmp_path, False, True, unit="oci-network")


def test_committed_gates_remain_disabled():
    for name in ("oci-apply.json", "resource-import.json"):
        assert json.loads((ROOT / "config" / name).read_bytes()) == dict(
            schema_version=2, units=dict.fromkeys(UNITS, False)
        )
