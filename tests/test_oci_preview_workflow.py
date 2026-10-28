"""OCI-specific handoff, namespace isolation and protected workflow regressions."""

import configparser
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_service_preview_workflow as shared
import yaml
from infra_core import cutover, foundation
from infra_program import cli

ROOT = shared.ROOT


@pytest.fixture(params=["oci-network", "oci-oke"])
def case(request, tmp_path, monkeypatch):
    state = shared.case.__wrapped__(SimpleNamespace(param="cloudflare-edge"), tmp_path, monkeypatch)
    unit = request.param
    state.source["PREVIEW_UNIT"] = unit
    state.source.pop("SERVICE_PREVIEW_INPUTS")
    state.bundle = dict(
        schema_version=1,
        unit=unit,
        configuration="# original OCI configuration\n",
        account=(
            'provider = "oci"\naccount_id = "resource-tenancy"\nhome_region = "eu-frankfurt-1"\n'
        ),
        usage='{"covered_through":"original-clock","values":{}}',
        usage_cutoff="original-cutoff",
        qualification='{"original":"qualification"}',
        encrypted_configuration='{"config":{}}',
    )
    if unit == "oci-oke":
        state.bundle["dependency_outputs"] = '{"original":"committed-network"}'
    state.source["OCI_RESOURCE_PREVIEW_CREDENTIALS"] = json.dumps(
        dict(
            tenancy="resource-tenancy",
            user="resource-user",
            fingerprint="resource-fingerprint",
            key_content="PRIVATE_RESOURCE_KEY\nsecond-line",
        )
    )
    monkeypatch.setattr(sys, "argv", ["service-preview.py", "--oci"])

    def preview(args):
        state.calls.append(args)
        data = json.loads(Path(args[-1]).read_bytes())
        work = Path(args[-1]).parent
        state.files = list(work.iterdir())
        for key in (
            "configuration",
            "account",
            "usage",
            "qualification",
            "encrypted_configuration",
        ):
            assert Path(data[key]).read_bytes() == state.bundle[key].encode()
        assert data["usage_cutoff"] == state.bundle["usage_cutoff"]
        if unit == "oci-oke":
            assert (
                Path(data["dependency_outputs"]).read_bytes()
                == state.bundle["dependency_outputs"].encode()
            )
        else:
            assert "dependency_outputs" not in data
        for field, tenancy, user in (
            ("oci_config", "resource-tenancy", "resource-user"),
            ("backend_oci_config", "backend-tenancy", "synthetic-user"),
        ):
            ini = configparser.ConfigParser(interpolation=None)
            ini.read(data[field])
            assert ini["DEFAULT"]["tenancy"] == tenancy and ini["DEFAULT"]["user"] == user
            assert Path(ini["DEFAULT"]["key_file"]).is_file()
            assert "key_content" not in ini["DEFAULT"]
        print("PRIVATE_DIAGNOSTICS")
        if state.fault == "runtime":
            raise RuntimeError("PRIVATE_EXCEPTION")
        if state.fault == "dirty-after":
            monkeypatch.setattr(cutover, "repository_state", lambda root: (shared.COMMIT, False))
        Path(data["output"]).write_text(
            json.dumps(
                dict(
                    kind="preview-orchestration",
                    deployment_authorized=False,
                    cutover_authorized=False,
                )
            )
        )
        return 0

    monkeypatch.setattr(cli, "main", preview)
    return state


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "runtime",
        "dirty-after",
        "disabled",
        "signer-scope",
        "passphrase",
        "injection",
        "dependency",
        "extra",
        "mode",
    ],
)
def test_oci_handoff_and_fail_closed_cleanup(case, fault, monkeypatch, capsys):
    case.fault = fault
    if fault == "disabled":
        monkeypatch.setattr(foundation, "load_foundation", lambda root: case.disabled)
    elif fault in ("signer-scope", "passphrase", "injection"):
        signer = json.loads(case.source["OCI_RESOURCE_PREVIEW_CREDENTIALS"])
        signer.update(
            {"tenancy": "wrong"}
            if fault == "signer-scope"
            else {"pass_phrase": "unsupported"}
            if fault == "passphrase"
            else {"user": "bad\nkey_file=other"}
        )
        case.source["OCI_RESOURCE_PREVIEW_CREDENTIALS"] = json.dumps(signer)
    elif fault == "dependency":
        if case.bundle["unit"] == "oci-oke":
            case.bundle.pop("dependency_outputs")
        else:
            case.bundle["dependency_outputs"] = "unrequested"
    elif fault == "extra":
        case.bundle["oci_config"] = "/unreviewed/key"
    elif fault == "mode":
        monkeypatch.setattr(sys, "argv", ["service-preview.py"])
    case.source["OCI_PREVIEW_INPUTS"] = json.dumps(case.bundle)
    assert case.adapter.main(case.root, case.source) == (0 if fault is None else 1)
    assert not list((case.root / ".infra").glob("oci-preview-*"))
    output = case.root / ".infra/oci-preview.json"
    assert output.exists() == (fault is None)
    if fault not in (None, "runtime", "dirty-after"):
        assert case.calls == []
    assert all(not path.exists() for path in case.files)
    captured = capsys.readouterr()
    assert "PRIVATE" not in captured.out + captured.err
    if fault:
        message = case.adapter.MESSAGE if fault == "mode" else case.adapter.OCI_MESSAGE
        assert captured.err.strip() == "FAIL: " + message


def test_oci_check_requires_no_signing_or_input_secrets(case, monkeypatch):
    source = {k: v for k, v in case.source.items() if k.startswith(("GITHUB_", "PREVIEW_"))}
    monkeypatch.setattr(sys, "argv", ["service-preview.py", "--oci", "--check"])
    assert case.adapter.main(case.root, source) == 0 and case.calls == []
    assert not list((case.root / ".infra").glob("oci-preview*"))


def test_oci_cleanup_preserves_service_namespace(case, monkeypatch):
    private = case.root / ".infra"
    for name in ("oci-preview", "service-preview"):
        (private / (name + "-abcdefgh")).mkdir()
        (private / (name + ".json")).write_text("receipt")
    monkeypatch.setattr(sys, "argv", ["service-preview.py", "--oci", "--cleanup"])
    assert case.adapter.main(case.root, {}) == 0
    assert not list(private.glob("oci-preview*"))
    assert len(list(private.glob("service-preview*"))) == 2


def assert_workflow(workflow):
    assert set(workflow["on"]) == {"workflow_dispatch"} and workflow["permissions"] == {
        "contents": "read"
    }
    assert workflow["on"]["workflow_dispatch"]["inputs"]["unit"]["options"] == [
        "oci-network",
        "oci-oke",
    ]
    verify, job = workflow["jobs"]["verify"], workflow["jobs"]["preview"]
    assert verify["uses"] == "./.github/workflows/verify.yml" and job["needs"] == "verify"
    expected = (
        "github.ref == 'refs/heads/main' && github.actor == github.repository_owner "
        "&& github.sha == inputs.commit"
    )
    assert verify["if"] == job["if"] == expected
    assert (
        job["environment"] == "pulumi-preview-${{ inputs.unit }}" and job["timeout-minutes"] == "25"
    )
    assert workflow["concurrency"] == dict(
        group="pulumi-preview-${{ github.repository }}-${{ inputs.unit }}",
        **{"cancel-in-progress": "false"},
    )
    steps = job["steps"]
    assert steps[0]["with"] == {
        "ref": "${{ github.sha }}",
        "fetch-depth": "0",
        "persist-credentials": "false",
    }
    run = next(s for s in steps if s.get("id") == "preview")
    assert [s for s in steps if "secrets." in str(s)] == [run] and "secrets." not in str(job["env"])
    assert run["run"] == "./.venv/bin/python .github/scripts/service-preview.py --oci"
    assert "OCI_RESOURCE_PREVIEW_CREDENTIALS" in run["env"] and "API_TOKEN" not in str(run)
    check = next(s for s in steps[: steps.index(run)] if "--oci --check" in s.get("run", ""))
    assert "if" not in check and not any("continue-on-error" in s for s in steps)
    uploads = [s for s in steps if s.get("uses", "").startswith("actions/upload-artifact@")]
    assert (
        len(uploads) == 1 and uploads[0]["if"] == "success() && steps.preview.outcome == 'success'"
    )
    assert (
        uploads[0]["with"]["path"] == ".infra/oci-preview.json"
        and uploads[0]["with"]["retention-days"] == "1"
    )
    assert (
        steps[-1]["if"] == "always()"
        and steps[-1]["run"] == "python3 .github/scripts/service-preview.py --oci --cleanup"
    )


@pytest.mark.parametrize(
    "mutation", [None, "ref", "environment", "scope", "upload", "cleanup", "gate"]
)
def test_protected_oci_workflow_sensor(mutation):
    workflow = yaml.load(
        (ROOT / ".github/workflows/oci-preview.yml").read_text(), Loader=yaml.BaseLoader
    )
    job = workflow["jobs"]["preview"]
    if mutation == "ref":
        job["steps"][0]["with"]["ref"] = "main"
    elif mutation == "environment":
        job.pop("environment")
    elif mutation == "scope":
        job["env"]["KEY"] = "${{ secrets.OCI_RESOURCE_PREVIEW_CREDENTIALS }}"
    elif mutation == "upload":
        job["steps"][-2]["with"]["path"] = ".infra/*"
    elif mutation == "cleanup":
        job["steps"][-1]["if"] = "success()"
    elif mutation == "gate":
        next(s for s in job["steps"] if "--oci --check" in s.get("run", ""))["if"] = "false"
    if mutation:
        with pytest.raises((AssertionError, KeyError)):
            assert_workflow(workflow)
    else:
        assert_workflow(workflow)
