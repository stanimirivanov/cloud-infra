"""Credential-free tests of the protected audit adapter and workflow capability boundaries."""

import configparser
import importlib.util
import json
import os
from pathlib import Path

import pytest
import test_operations_evidence as fixtures
import yaml
from infra_core import backend_posture as bp
from infra_core import cli

config = fixtures.config
posture = fixtures.posture
ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
ACCOUNT = "synthetic-tenancy"


@pytest.fixture
def adapter():
    spec = importlib.util.spec_from_file_location(
        "backend_audit_adapter", ROOT / ".github/scripts/collect-backend-posture.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def setup(tmp_path, monkeypatch, adapter, posture):
    (tmp_path / "config").mkdir()
    (tmp_path / "config/pulumi.toml").write_bytes((ROOT / "config/pulumi.toml").read_bytes())
    (tmp_path / "pyproject.toml").write_text('[project]\nname="oci-oke-infrastructure"\n')
    monkeypatch.setattr(cli, "_posture_commit", lambda root: COMMIT)
    monkeypatch.setattr(adapter, "repository_state", lambda root: (COMMIT, True))
    credentials = dict(
        tenancy=ACCOUNT,
        user="synthetic-user",
        fingerprint="synthetic-fingerprint",
        key_content="PRIVATE_KEY_SENTINEL\nsecond-line",
        pass_phrase="PRIVATE_PHRASE%literal",
    )
    source = dict(
        OCI_BACKEND_AUDIT_CREDENTIALS=json.dumps(credentials), BACKEND_POSTURE_ACCOUNT_ID=ACCOUNT
    )
    files = []

    class Reader:
        def __init__(self, config_file, profile, tenancy):
            parser = configparser.ConfigParser(interpolation=None)
            parser.read(config_file)
            data = parser["DEFAULT"]
            key = Path(data["key_file"])
            assert data["tenancy"] == tenancy == ACCOUNT
            assert data.get("pass_phrase") == credentials.get("pass_phrase")
            assert key.read_text() == credentials["key_content"]
            assert not key.is_relative_to(tmp_path)
            files.extend([Path(config_file), key])
            if os.name != "nt":
                assert all(path.stat().st_mode & 0o077 == 0 for path in files)
            print("PRIVATE_SDK_WARNING")

        def backend_posture(self, config):
            return posture

    import infra_core.inventory.oci as oci

    monkeypatch.setattr(oci, "OCIReader", Reader)
    return adapter, tmp_path, source, credentials, files


@pytest.mark.parametrize("encrypted_key", [True, False])
def test_protected_collection_cleans_credentials_and_publishes_only_safe_summary(
    setup, config, capsys, encrypted_key
):
    adapter, root, source, credentials, files = setup
    if not encrypted_key:
        credentials.pop("pass_phrase")
        source["OCI_BACKEND_AUDIT_CREDENTIALS"] = json.dumps(credentials)
    assert adapter.main(root, source) == 0
    assert files and all(not path.exists() for path in files)
    assert not files[0].parent.exists()
    payload, envelope = bp.read_posture_pair(root / ".infra/backend-posture.json")
    assert (
        bp.validate_posture_evidence(config, payload, envelope, account_id=ACCOUNT, commit=COMMIT)[
            "deployment_authorized"
        ]
        is False
    )
    report = (root / ".infra/backend-audit.json").read_text()
    summary = json.loads(report)
    assert set(summary) == {
        "schema_version",
        "status",
        "deployment_authorized",
        "commit",
        "configuration_sha256",
        "payload_sha256",
        "envelope_sha256",
        "collection_started_at",
        "collection_completed_at",
    }
    import hashlib

    assert summary["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert summary["envelope_sha256"] == hashlib.sha256(envelope).hexdigest()
    assert summary["commit"] == COMMIT and summary["deployment_authorized"] is False
    assert ACCOUNT not in report and "PRIVATE" not in report
    captured = capsys.readouterr()
    assert "PRIVATE" not in captured.out + captured.err


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "invalid",
        "duplicate",
        "extra",
        "mismatch",
        "blank",
        "newline",
        "passphrase",
        "oversized",
        "account",
        "list",
    ],
)
def test_bad_credentials_fail_before_collection_and_invalidate_stale_evidence(
    setup, monkeypatch, capsys, change
):
    adapter, root, source, credentials, files = setup
    path = root / ".infra/backend-posture.json"
    path.parent.mkdir()
    for target in (path, bp.envelope_path(path), root / ".infra/backend-audit.json"):
        target.write_text("old success")
    if change in ("missing", "invalid", "oversized", "list"):
        source["OCI_BACKEND_AUDIT_CREDENTIALS"] = {
            "missing": "",
            "invalid": "PRIVATE{",
            "oversized": "x" * 65537,
            "list": "[]",
        }[change]
    elif change == "account":
        source.pop("BACKEND_POSTURE_ACCOUNT_ID")
    elif change == "duplicate":
        source["OCI_BACKEND_AUDIT_CREDENTIALS"] = source["OCI_BACKEND_AUDIT_CREDENTIALS"].replace(
            '"tenancy":', '"tenancy":"duplicate", "tenancy":'
        )
    else:
        if change == "extra":
            credentials["key_file"] = "/unreviewed/key"
        elif change == "mismatch":
            credentials["tenancy"] = "other"
        elif change == "blank":
            credentials["key_content"] = " "
        elif change == "newline":
            credentials["user"] = "injected\nkey_file=/other"
        else:
            credentials["pass_phrase"] = "injected\r\n[OTHER]"
        source["OCI_BACKEND_AUDIT_CREDENTIALS"] = json.dumps(credentials)
    monkeypatch.setattr(cli, "main", lambda *args: pytest.fail("credentials reached collector"))
    assert adapter.main(root, source) == 1
    assert not files and not path.exists() and not bp.envelope_path(path).exists()
    assert not (root / ".infra/backend-audit.json").exists()
    captured = capsys.readouterr()
    assert "AUDIT001" in captured.err and "PRIVATE" not in captured.out + captured.err


@pytest.mark.parametrize("failure", ["exception", "nonzero", "tamper", "dirty"])
def test_collection_failures_remove_pairs_reports_and_temporary_credentials(
    setup, monkeypatch, failure, capsys
):
    adapter, root, source, _, files = setup
    original = cli.main

    def collect(args):
        assert original(args) == 0
        if failure == "exception":
            raise RuntimeError("PRIVATE_EXCEPTION")
        if failure == "nonzero":
            return 1
        if failure == "tamper":
            path = root / ".infra/backend-posture.json"
            path.write_bytes(path.read_bytes() + b" ")
        return 0

    if failure == "dirty":
        monkeypatch.setattr(adapter, "repository_state", lambda root: (COMMIT, False))
    monkeypatch.setattr(cli, "main", collect)
    assert adapter.main(root, source) == 1
    assert files and all(not path.exists() for path in files)
    assert not list((root / ".infra").glob("*.json"))
    captured = capsys.readouterr()
    assert "AUDIT001" in captured.err and "PRIVATE" not in captured.out + captured.err


def assert_protected_audit(workflow):
    job = workflow["jobs"]["foundation"]
    assert "audit" in workflow["on"]["workflow_dispatch"]["inputs"]["operation"]["options"]
    assert "env" not in job
    steps = job["steps"]
    audit = next(step for step in steps if step.get("id") == "audit")
    qualify = next(step for step in steps if "--allow-backend-writes" in step.get("run", ""))
    assert audit["if"] == "inputs.operation == 'audit' || inputs.operation == 'qualify'"
    assert qualify["if"] == "inputs.operation == 'qualify'"
    assert (
        audit["run"]
        == "uv run --locked --extra inventory-oci python .github/scripts/collect-backend-posture.py"
    )
    assert audit["env"] == {
        "OCI_BACKEND_AUDIT_CREDENTIALS": "${{ secrets.OCI_BACKEND_AUDIT_CREDENTIALS }}",
        "BACKEND_POSTURE_ACCOUNT_ID": "${{ vars.BACKEND_POSTURE_ACCOUNT_ID }}",
    }
    assert "OCI_BACKEND_AUDIT_CREDENTIALS" not in str(qualify)
    assert [step for step in steps if "secrets." in str(step)] == [audit, qualify]
    assert steps.index(audit) < steps.index(qualify)
    cleanup = next(step for step in steps if step.get("name") == "Remove private backend posture")
    assert cleanup["if"] == "always()" and "backend-posture.json.envelope.json" in cleanup["run"]
    uploads = {
        step["with"]["path"]: step
        for step in steps
        if step.get("uses", "").startswith("actions/upload-artifact@")
    }
    assert set(uploads) == {".infra/backend-audit.json", ".infra/qualification.json"}
    report = uploads[".infra/backend-audit.json"]
    assert report["if"] == "always() && steps.audit.outcome == 'success'"
    assert report["with"]["retention-days"] == "1"


@pytest.mark.parametrize("mutation", [None, "credentials", "upload", "cleanup"])
def test_workflow_rejects_broad_credentials_and_private_evidence_exports(mutation):
    workflow = yaml.load(
        (ROOT / ".github/workflows/pulumi.yml").read_text(), Loader=yaml.BaseLoader
    )
    job = workflow["jobs"]["foundation"]
    if mutation == "credentials":
        job["env"] = {"OCI_BACKEND_AUDIT_CREDENTIALS": "secret"}
    elif mutation == "upload":
        job["steps"][-1]["with"]["path"] = ".infra/*"
    elif mutation == "cleanup":
        next(step for step in job["steps"] if step.get("name") == "Remove private backend posture")[
            "if"
        ] = "success()"
    if mutation:
        with pytest.raises(AssertionError):
            assert_protected_audit(workflow)
    else:
        assert_protected_audit(workflow)
