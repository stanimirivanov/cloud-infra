"""Default-denied CLI composition and protected workflow boundaries."""

import argparse
import json
from pathlib import Path

import pytest
import yaml
from infra_program import oci_apply
from infra_program import service_apply as apply

ROOT = Path(__file__).resolve().parents[1]


def test_default_gate_and_workflow_are_explicit(tmp_path):
    args = argparse.Namespace()
    with pytest.raises(ValueError):
        apply.execute(ROOT, args, lambda: pytest.fail("disabled credentials"))
    workflow = yaml.load(
        (ROOT / ".github/workflows/service-apply.yml").read_text(), Loader=yaml.BaseLoader
    )
    job = workflow["jobs"]["apply"]
    assert set(workflow["on"]) == {"workflow_dispatch"} and job["needs"] == "verify"
    assert job["steps"][0]["with"]["clean"] == "false"
    preflight = next(s for s in job["steps"] if "--check" in s.get("run", ""))
    assert set(preflight["env"]) == {"GH_TOKEN"} and "secrets.OCI_S3" not in json.dumps(preflight)


@pytest.mark.parametrize("allowed", [False, True])
@pytest.mark.parametrize("unit", ["cloudflare-edge", "oci-network", "oci-oke"])
def test_cli_checks_dispatch_identity_before_adapter(monkeypatch, allowed, unit):
    from infra_program import cli

    args = argparse.Namespace(
        actor="owner", commit="a" * 40, unit=unit, environment=unit + "-apply"
    )
    for name, value in dict(
        GITHUB_EVENT_NAME="workflow_dispatch" if allowed else "pull_request",
        GITHUB_REF="refs/heads/main",
        GITHUB_SHA="a" * 40,
        GITHUB_ACTOR="owner",
        GITHUB_REPOSITORY_OWNER="owner",
    ).items():
        monkeypatch.setenv(name, value)
    called = []

    def execute(root, args, credentials):
        called.append("checked")

    monkeypatch.setattr(apply, "execute", execute)
    monkeypatch.setattr(oci_apply, "execute", execute)
    if allowed:
        cli._apply(ROOT, args)
        assert called == ["checked"]
    else:
        with pytest.raises(ValueError):
            cli._apply(ROOT, args)
        assert not called


def test_core_only_cli_has_no_apply_executor(capsys):
    from infra_core import cli

    result = cli.main(
        [
            "--root",
            str(ROOT),
            "apply",
            "--check",
            "--unit",
            "cloudflare-edge",
            "--commit",
            "a" * 40,
            "--actor",
            "owner",
            "--environment",
            "cloudflare-edge-apply",
            "--bundle",
            ".infra/bundle.json",
            "--journal",
            ".infra/operations/cloudflare-edge.json",
        ]
    )
    assert result == 1 and "composition" in capsys.readouterr().err
