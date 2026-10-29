"""Encrypted pair capture failures and opt-in local restic round trip."""

import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from infra_core import backup as b

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    root = tmp_path / "checkout"
    private = root / ".infra"
    private.mkdir(parents=True)
    (root / "config").mkdir()
    (root / "config/pulumi.toml").write_bytes((ROOT / "config/pulumi.toml").read_bytes())
    state = {
        "version": 3,
        "deployment": {
            "secrets_providers": {"type": "passphrase", "state": {"salt": "fixture-salt"}},
            "resources": [
                {
                    "type": "pulumi:pulumi:Stack",
                    "urn": (
                        "urn:pulumi:oci-network::free-infrastructure::pulumi:pulumi:Stack::fixture"
                    ),
                    "outputs": {
                        "secret": {
                            b.SIGNATURE: b.ENCRYPTED_VALUE_SIGNATURE,
                            "ciphertext": "fixture",
                        }
                    },
                }
            ],
        },
    }
    config = {"encryptionsalt": "fixture-salt", "config": {"key": {"secure": "v1:fixture"}}}
    checkpoint, settings, request = (
        private / n for n in ("checkpoint.json", "config.json", "request.json")
    )
    checkpoint.write_text(json.dumps(state))
    settings.write_text(json.dumps(config))
    value = json.loads((ROOT / "config/operations.example.json").read_bytes())
    value.update(
        expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        checkpoint_sha256=hashlib.sha256(checkpoint.read_bytes()).hexdigest(),
        configuration_sha256=hashlib.sha256(settings.read_bytes()).hexdigest(),
    )
    request.write_text(json.dumps(value))
    password = private / "password"
    password.write_text("synthetic-restic-password")
    password.chmod(0o600)
    repository = tmp_path / "repository"
    repository.mkdir()
    args = [
        root,
        request,
        checkpoint,
        settings,
        repository,
        "a" * 64,
        password,
        datetime.now(UTC).isoformat(),
    ]
    return args, value


def runner(monkeypatch, code=0, snapshot="b" * 64, repo="a" * 64):
    calls = []
    monkeypatch.setattr(b, "executable", lambda root: Path("/verified/restic"))

    def run(argv, **kw):
        calls.append((argv, kw))
        output = (
            {"id": repo}
            if argv[1:3] == ["cat", "config"]
            else {"message_type": "summary", "snapshot_id": snapshot, "total_files_processed": 3}
        )
        return SimpleNamespace(
            returncode=0 if len(calls) == 1 else code,
            stdout=json.dumps(output),
            stderr="PRIVATE_DIAGNOSTIC",
        )

    monkeypatch.setattr(b.subprocess, "run", run)
    return calls


def test_capture_exact_manifest_binding_and_no_ambient_credentials(bundle, monkeypatch):
    args, value = bundle
    calls = runner(monkeypatch)
    receipt = b.capture(*args)
    manifest = json.loads((receipt.parent / "manifest.json").read_bytes())
    assert manifest["checkpoint_sha256"] == value["checkpoint_sha256"]
    assert manifest["configuration_sha256"] == value["configuration_sha256"]
    assert manifest["stack"] == "organization/free-infrastructure/oci-network"
    assert json.loads(receipt.read_bytes())["snapshot_id"] == "b" * 64
    assert all("AWS_ACCESS_KEY_ID" not in kw["env"] for _, kw in calls)
    assert "--" in calls[1][0] and "init" not in calls[1][0]
    with pytest.raises(RuntimeError):
        b.capture(*args)


@pytest.mark.parametrize("fault", ["missing", "digest", "plaintext", "salt", "stack", "expired"])
def test_invalid_pair_never_calls_restic(bundle, monkeypatch, fault):
    args, value = bundle
    if fault == "missing":
        args[3].unlink()
    elif fault == "expired":
        value["expires_at"] = "2000-01-01T00:00:00+00:00"
    else:
        state = json.loads(args[2].read_bytes())
        if fault == "plaintext":
            state["deployment"]["resources"][0]["outputs"]["secret"] = {
                b.SIGNATURE: b.ENCRYPTED_VALUE_SIGNATURE,
                "plaintext": "PRIVATE_SECRET",
            }
        elif fault == "salt":
            state["deployment"]["secrets_providers"]["state"]["salt"] = "different"
        elif fault == "stack":
            state["deployment"]["resources"][0]["urn"] = "urn:wrong"
        args[2].write_text(json.dumps(state))
        if fault != "digest":
            value["checkpoint_sha256"] = hashlib.sha256(args[2].read_bytes()).hexdigest()
        else:
            value["checkpoint_sha256"] = "0" * 64
    args[1].write_text(json.dumps(value))
    monkeypatch.setattr(b.subprocess, "run", lambda *a, **kw: pytest.fail("unexpected process"))
    with pytest.raises(RuntimeError) as error:
        b.capture(*args)
    assert "PRIVATE_SECRET" not in str(error.value)


@pytest.mark.parametrize(
    "code,snapshot,repo",
    [
        (3, "b" * 64, "a" * 64),
        (1, "b" * 64, "a" * 64),
        (0, "bad", "a" * 64),
        (0, "b" * 64, "c" * 64),
    ],
)
def test_partial_upload_or_wrong_repository_has_no_receipt(
    bundle, monkeypatch, code, snapshot, repo
):
    args, _ = bundle
    runner(monkeypatch, code, snapshot, repo)
    with pytest.raises(RuntimeError) as error:
        b.capture(*args)
    assert "PRIVATE_DIAGNOSTIC" not in str(error.value)
    assert not list((args[0] / ".infra").glob("backups/*/receipt.json"))


@pytest.mark.operation_integration
@pytest.mark.skipif(os.environ.get("RUN_OPERATION_INTEGRATION") != "1", reason="opt-in real restic")
def test_local_restic_round_trip(bundle, monkeypatch):
    args, value = bundle
    binary = (
        b.executable
    )  # The fixture substitutes verification; restore the actual function below.
    del binary
    binary = b.executable(ROOT)
    monkeypatch.setattr(b, "executable", lambda root: binary)
    env = {
        "RESTIC_REPOSITORY": str(args[4]),
        "RESTIC_PASSWORD_FILE": str(args[6]),
        "GOMAXPROCS": "2",
        "RESTIC_CACHE_DIR": str(args[4].parent / "cache"),
    }
    subprocess.run(
        [str(binary), "init", "--json"], env=env, check=True, capture_output=True, timeout=60
    )
    result = subprocess.run(
        [str(binary), "cat", "config"], env=env, check=True, capture_output=True, timeout=60
    )
    args[5] = json.loads(result.stdout)["id"]
    receipt = b.capture(*args)
    snapshot = json.loads(receipt.read_bytes())["snapshot_id"]
    restored = args[4].parent / "restored"
    subprocess.run(
        [str(binary), "restore", snapshot, "--target", str(restored)],
        env=env,
        check=True,
        capture_output=True,
        timeout=60,
    )
    files = {p.name: p for p in restored.rglob("*") if p.is_file()}
    assert set(files) == {"checkpoint.json", "stack-config.json", "manifest.json"}
    assert (
        hashlib.sha256(files["checkpoint.json"].read_bytes()).hexdigest()
        == value["checkpoint_sha256"]
    )
    assert files["stack-config.json"].read_bytes() == args[3].read_bytes()


@pytest.mark.parametrize(
    "fault", ["inside-checkout", "password-mode", "old-export", "config-plaintext"]
)
def test_destination_credentials_and_plaintext_config_fail_before_process(
    bundle, monkeypatch, fault
):
    args, value = bundle
    if fault == "inside-checkout":
        args[4] = args[0]
    elif fault == "password-mode":
        args[6].chmod(0o644)
    elif fault == "old-export":
        args[7] = "2000-01-01T00:00:00+00:00"
    else:
        args[3].write_text('{"encryptionsalt":"fixture-salt","config":{"key":"private"}}')
        value["configuration_sha256"] = hashlib.sha256(args[3].read_bytes()).hexdigest()
        args[1].write_text(json.dumps(value))
    monkeypatch.setattr(b.subprocess, "run", lambda *a, **kw: pytest.fail("unexpected process"))
    with pytest.raises(RuntimeError):
        b.capture(*args)


def test_tampered_restic_binary_fails_before_execution(bundle):
    args, _ = bundle
    root = args[0]
    (root / "config/toolchain.json").write_bytes((ROOT / "config/toolchain.json").read_bytes())
    binary = root / ".infra/tools/restic/restic"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="BACKUP001"):
        b.executable(root)


def test_timeout_preserves_reserved_capture_without_success(bundle, monkeypatch):
    args, _ = bundle
    runner(monkeypatch)
    run = b.subprocess.run

    def timeout(argv, **kwargs):
        if argv[1] == "backup":
            raise subprocess.TimeoutExpired("PRIVATE_DIAGNOSTIC", 180)
        return run(argv, **kwargs)

    monkeypatch.setattr(b.subprocess, "run", timeout)
    with pytest.raises(RuntimeError) as error:
        b.capture(*args)
    assert "PRIVATE_DIAGNOSTIC" not in str(error.value)
    assert list((args[0] / ".infra").glob("backups/*/manifest.json"))
    assert not list((args[0] / ".infra").glob("backups/*/receipt.json"))
