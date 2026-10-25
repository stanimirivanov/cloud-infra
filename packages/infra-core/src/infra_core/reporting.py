"""Render Terragrunt execution reports, not Terraform resource plans or state."""

import json
from pathlib import Path


def _units(path: Path) -> dict[str, dict[str, object]]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    units = (
        data if isinstance(data, list) else data.get("units") if isinstance(data, dict) else None
    )
    if not isinstance(units, list):
        raise ValueError(f"{path.name}: expected a unit list or an object with a units list")
    result: dict[str, dict[str, object]] = {}
    for unit in units:
        if not isinstance(unit, dict) or not isinstance(unit.get("name"), str) or not unit["name"]:
            raise ValueError(f"{path.name}: every unit must have a nonempty string name")
        result[unit["name"]] = unit
    return result


def _cell(value: object) -> str:
    return str(value).replace("|", "&#124;").replace("\r", " ").replace("\n", " ")


def render_report(directory: Path) -> str:
    planned = _units(directory / "plan_report.json")
    applied = _units(directory / "apply_report.json")
    lines = [
        "### Infrastructure Deployment Reconciliation Report\n",
        "| Module / Unit | Plan Execution Reported? | Apply Status | Cause / Details |",
        "| :--- | :---: | :---: | :--- |",
    ]
    statuses = {
        "succeeded": "Present / Applied",
        "failed": "Failed",
        "early exit": "Skipped (Upstream Failed)",
    }
    for name in sorted(planned.keys() | applied.keys()):
        unit = applied.get(name, {})
        result = str(unit.get("result", "skipped / not reached"))
        status = statuses.get(result, result)
        reason = unit.get("reason", unit.get("cause", "Dependency or upstream failure"))
        # A unit report records execution, not whether Terraform found resource changes.
        lines.append(
            f"| {_cell(name)} | {'Yes' if name in planned else 'No'} | "
            f"{_cell(status)} | {_cell(reason)} |"
        )
    return "\n".join(lines) + "\n"
