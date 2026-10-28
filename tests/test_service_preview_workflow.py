"""Synthetic protected handoff and workflow capability sensors; no live dispatch."""

import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from infra_core import cutover, foundation
from infra_program import cli

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40


@pytest.fixture(params=["cloudflare-edge", "supabase-database"])
def case(request, tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "service_preview_adapter", ROOT / ".github/scripts/service-preview.py"
    )
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    monkeypatch.setattr(sys, "argv", ["service-preview.py"])
    disabled = foundation.load_foundation(ROOT)
    config = disabled
    config = replace(config, units=tuple(replace(u, preview_enabled=True) for u in config.units))
    monkeypatch.setattr(foundation, "load_foundation", lambda root: config)
    monkeypatch.setattr(cutover, "repository_state", lambda root: (COMMIT, True))
    (tmp_path / "config").mkdir()
    pins = (ROOT / "config/toolchain.json").read_bytes()
    (tmp_path / "config/toolchain.json").write_bytes(pins)
    tools = tmp_path / ".infra/tools/stage"
    tools.mkdir(parents=True)
    (tools / "pulumi-v3.272.0-linux-x64.tar.gz").write_bytes(
        b"synthetic archive; executor verifies"
    )
    unit = request.param
    bundle = dict(
        schema_version=1,
        unit=unit,
        configuration='{"private":"proposal"}',
        encrypted_configuration='{"private":"ciphertext"}',
        qualification='{"private":"qualification"}',
    )
    bundle.update(review='{"private":"review"}') if unit == "cloudflare-edge" else bundle.update(
        supplement='{"private":"supplement"}', organizations=["example-org"]
    )
    source = dict(
        PREVIEW_UNIT=unit,
        PREVIEW_COMMIT=COMMIT,
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_REF="refs/heads/main",
        GITHUB_SHA=COMMIT,
        GITHUB_ACTOR="owner",
        GITHUB_REPOSITORY_OWNER="owner",
        SERVICE_PREVIEW_INPUTS=json.dumps(bundle),
        BACKEND_POSTURE_ACCOUNT_ID="backend-tenancy",
        OCI_BACKEND_AUDIT_CREDENTIALS=json.dumps(
            dict(
                tenancy="backend-tenancy",
                user="synthetic-user",
                fingerprint="synthetic-fingerprint",
                key_content="PRIVATE_SIGNING_MATERIAL\nsecond-line",
            )
        ),
    )
    state = SimpleNamespace(
        adapter=adapter,
        root=tmp_path,
        source=source,
        calls=[],
        files=[],
        fault=None,
        disabled=disabled,
    )

    def preview(args):
        state.calls.append(args)
        request = json.loads(Path(args[-1]).read_text())
        work = Path(args[-1]).parent
        state.files = list(work.iterdir())
        assert all(path.stat().st_size > 0 for path in state.files)
        assert "PRIVATE_SIGNING_MATERIAL" in (work / "signing-key.pem").read_text()
        assert json.loads(Path(request["configuration"]).read_bytes()) == {"private": "proposal"}
        assert request["schema_version"] == 1 and request["backend_account_id"] == "backend-tenancy"
        assert args[args.index("--unit") + 1] == unit and args[args.index("--commit") + 1] == COMMIT
        print("PRIVATE_DIAGNOSTICS")
        if state.fault == "raise":
            raise RuntimeError("PRIVATE_EXCEPTION")
        if state.fault == "nonzero":
            return 1
        if state.fault == "dirty-after":
            monkeypatch.setattr(cutover, "repository_state", lambda root: (COMMIT, False))
        report = dict(
            kind="preview-orchestration", deployment_authorized=False, cutover_authorized=False
        )
        Path(request["output"]).write_text(
            json.dumps(report) if state.fault != "oversize" else "x" * 65537
        )
        return 0

    monkeypatch.setattr(cli, "main", preview)
    return state


@pytest.mark.parametrize("fault", [None, "raise", "nonzero", "dirty-after", "oversize"])
def test_handoff_cleans_private_material_and_only_exports_success(case, fault, capsys):
    case.fault = fault
    assert case.adapter.main(case.root, case.source) == (0 if fault is None else 1)
    assert case.calls and case.files and all(not p.exists() for p in case.files)
    report = case.root / ".infra/service-preview.json"
    assert report.exists() == (fault is None)
    captured = capsys.readouterr()
    assert "PRIVATE" not in captured.out + captured.err
    if fault is None:
        assert json.loads(report.read_bytes())["deployment_authorized"] is False


@pytest.mark.parametrize(
    "fault",
    [
        "ref",
        "actor",
        "sha",
        "event",
        "unit",
        "disabled",
        "extra",
        "signer",
        "duplicate",
        "file-type",
    ],
)
def test_admission_rejects_before_cli_and_cleans_inputs(case, fault, monkeypatch, capsys):
    keys = dict(
        ref="GITHUB_REF",
        actor="GITHUB_ACTOR",
        sha="GITHUB_SHA",
        event="GITHUB_EVENT_NAME",
        unit="PREVIEW_UNIT",
    )
    if fault in keys:
        case.source[keys[fault]] = "unapproved"
    elif fault == "disabled":
        monkeypatch.setattr(foundation, "load_foundation", lambda root: case.disabled)
    elif fault == "extra":
        case.source["SERVICE_PREVIEW_INPUTS"] = (
            case.source["SERVICE_PREVIEW_INPUTS"][:-1] + ',"extra":true}'
        )
    elif fault == "signer":
        case.source["OCI_BACKEND_AUDIT_CREDENTIALS"] = '{"key_file":"unreviewed"}'
    elif fault == "file-type":
        bundle = json.loads(case.source["SERVICE_PREVIEW_INPUTS"])
        bundle["configuration"] = {}
        case.source["SERVICE_PREVIEW_INPUTS"] = json.dumps(bundle)
    else:
        case.source["SERVICE_PREVIEW_INPUTS"] = '{"unit":"x","unit":"y"}'
    assert case.adapter.main(case.root, case.source) == 1
    assert case.calls == [] and not list((case.root / ".infra").glob("service-preview*"))
    assert capsys.readouterr().err.strip() == "FAIL: " + case.adapter.MESSAGE


def test_existing_receipt_is_not_replaced(case):
    output = case.root / ".infra/service-preview.json"
    output.write_bytes(b"existing receipt")
    assert case.adapter.main(case.root, case.source) == 1
    assert case.calls == [] and output.read_bytes() == b"existing receipt"


def test_cleanup_requires_no_packages_or_credentials(case, monkeypatch):
    private = case.root / ".infra/service-preview-abcdefgh"
    private.mkdir()
    (private / "key").write_text("synthetic")
    monkeypatch.setattr(sys, "argv", ["service-preview.py", "--cleanup"])
    assert case.adapter.main(case.root, {}) == 0 and not private.exists()


def test_check_mode_needs_no_credentials_and_writes_nothing(case, monkeypatch):
    source = {k: v for k, v in case.source.items() if k.startswith(("GITHUB_", "PREVIEW_"))}
    monkeypatch.setattr(sys, "argv", ["service-preview.py", "--check"])
    assert case.adapter.main(case.root, source) == 0 and case.calls == []
    assert not list((case.root / ".infra").glob("service-preview*"))


def assert_workflow(workflow):
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == dict(
        group="pulumi-preview-${{ github.repository }}-${{ inputs.unit }}",
        **{"cancel-in-progress": "false"},
    )
    verify, job = workflow["jobs"]["verify"], workflow["jobs"]["preview"]
    expected = (
        "github.ref == 'refs/heads/main' && github.actor == github.repository_owner "
        "&& github.sha == inputs.commit"
    )
    assert (
        verify["if"] == job["if"] == expected and verify["uses"] == "./.github/workflows/verify.yml"
    )
    assert job["needs"] == "verify" and job["timeout-minutes"] == "25"
    assert job["environment"] == "pulumi-preview-${{ inputs.unit }}"
    assert workflow["on"]["workflow_dispatch"]["inputs"]["unit"]["options"] == [
        "cloudflare-edge",
        "supabase-database",
    ]
    assert "secrets." not in str(job["env"])
    steps = job["steps"]
    checkout = steps[0]
    assert checkout["with"] == {
        "ref": "${{ github.sha }}",
        "persist-credentials": "false",
        "fetch-depth": "0",
    }
    run = next(s for s in steps if s.get("id") == "preview")
    assert [s for s in steps if "secrets." in str(s)] == [run]
    assert run["run"] == "./.venv/bin/python .github/scripts/service-preview.py"
    for provider, unit in (("CLOUDFLARE", "cloudflare-edge"), ("SUPABASE", "supabase-database")):
        assert (
            run["env"][provider + "_API_TOKEN"]
            == "${{ inputs.unit == '" + unit + "' && secrets.SERVICE_API_TOKEN || '' }}"
        )
    check = next(s for s in steps[: steps.index(run)] if "--check" in s.get("run", ""))
    assert "if" not in check and not any("continue-on-error" in s for s in steps)
    uploads = [s for s in steps if s.get("uses", "").startswith("actions/upload-artifact@")]
    assert (
        len(uploads) == 1 and uploads[0]["if"] == "success() && steps.preview.outcome == 'success'"
    )
    assert (
        uploads[0]["with"]["path"] == ".infra/service-preview.json"
        and uploads[0]["with"]["retention-days"] == "1"
    )
    assert (
        steps[-1]["if"] == "always()"
        and steps[-1]["run"] == "python3 .github/scripts/service-preview.py --cleanup"
    )


@pytest.mark.parametrize(
    "mutation", [None, "trigger", "needs", "credentials", "upload", "cleanup", "ref"]
)
def test_workflow_capability_regressions_fail(mutation):
    workflow = yaml.load(
        (ROOT / ".github/workflows/service-preview.yml").read_text(), Loader=yaml.BaseLoader
    )
    job = workflow["jobs"]["preview"]
    if mutation == "trigger":
        workflow["on"]["pull_request"] = {}
    elif mutation == "needs":
        job["needs"] = "other"
    elif mutation == "credentials":
        job["env"]["TOKEN"] = "${{ secrets.SERVICE_API_TOKEN }}"
    elif mutation == "upload":
        job["steps"][-2]["with"]["path"] = ".infra/*"
    elif mutation == "cleanup":
        job["steps"][-1]["if"] = "success()"
    elif mutation == "ref":
        job["steps"][0]["with"]["ref"] = "main"
    if mutation:
        with pytest.raises(AssertionError):
            assert_workflow(workflow)
    else:
        assert_workflow(workflow)
