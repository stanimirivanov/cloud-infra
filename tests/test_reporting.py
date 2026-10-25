"""Execution-report parsing and CLI integration without cloud operations."""

import json

import pytest
from infra_core.cli import main
from infra_core.reporting import render_report


def test_missing_reports_produce_empty_table(tmp_path):
    markdown = render_report(tmp_path)
    assert "Plan Execution Reported?" in markdown
    assert len(markdown.splitlines()) == 4


@pytest.mark.parametrize("wrapper", [False, True])
def test_report_handles_list_and_object_units_and_statuses(tmp_path, wrapper):
    units = [
        {"name": "network", "result": "succeeded"},
        {"name": "compute", "result": "failed", "cause": "quota"},
    ]
    (tmp_path / "apply_report.json").write_text(json.dumps({"units": units} if wrapper else units))
    (tmp_path / "plan_report.json").write_text(json.dumps([{"name": "compute"}]))
    markdown = render_report(tmp_path)
    assert "| compute | Yes | Failed | quota |" in markdown
    assert "| network | No | Present / Applied |" in markdown
    assert markdown.index("| compute") < markdown.index("| network")


@pytest.mark.parametrize("data", [None, {}, {"units": None}, [None], [{"name": ""}]])
def test_malformed_reports_fail_clearly(tmp_path, data):
    (tmp_path / "plan_report.json").write_text(json.dumps(data))
    with pytest.raises(ValueError, match="plan_report.json"):
        render_report(tmp_path)


def test_report_keeps_multiline_and_pipe_details_in_one_table_cell(tmp_path):
    (tmp_path / "apply_report.json").write_text(
        json.dumps([{"name": "compute", "result": "early exit", "reason": "one|two\nthree"}])
    )
    assert "Skipped (Upstream Failed) | one&#124;two three |" in render_report(tmp_path)


def test_cli_appends_github_summary_and_reports_execution_only(tmp_path, monkeypatch, capsys):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "oci-oke-infrastructure"\n')
    (tmp_path / "terraform").mkdir()
    summary = tmp_path / "summary.md"
    summary.write_text("existing\n")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert main(["--root", str(tmp_path), "report"]) == 0
    output = capsys.readouterr().out
    assert summary.read_text() == "existing\n" + output
    assert "Planned Changes?" not in output
