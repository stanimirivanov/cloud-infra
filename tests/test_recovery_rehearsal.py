"""Isolated recovery admission, failure receipts and real encrypted readback."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_backup
import yaml
from infra_core import backup as b
from infra_core import recovery_rehearsal as r
from test_backup import runner

bundle = test_backup.bundle
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def recovery(bundle, monkeypatch):
    args, _ = bundle
    runner(monkeypatch)
    receipt = b.capture(*args)
    password = args[0] / ".infra/passphrase"
    password.write_text("synthetic-passphrase")
    password.chmod(0o600)
    policy = args[0] / ".infra/policy.json"
    policy.write_text(
        json.dumps(
            dict(
                schema_version=1,
                max_backup_age_seconds=3600,
                restore_objective_seconds=60,
                require_independent_host=False,
            )
        )
    )
    output = args[0] / ".infra/rehearsal.json"
    files = {p.name: p.read_bytes() for p in receipt.parent.iterdir() if p.name != "receipt.json"}
    calls = []
    monkeypatch.setattr(r, "_tool", lambda root, name: Path("/verified") / name)

    def run(argv, **kw):
        calls.append((argv, kw))
        if argv[0].endswith("restic"):
            if argv[2] == "cat":
                raw = json.dumps({"id": "a" * 64}).encode()
            elif argv[2] == "ls":
                raw = b"\n".join(
                    json.dumps(dict(type="file", path="/" + name, size=len(data))).encode()
                    for name, data in files.items()
                )
            else:
                raw = files[Path(argv[-1]).name]
            return SimpleNamespace(returncode=0, stdout=raw, stderr=b"")
        wrong = "wrong-" in kw["env"]["PULUMI_HOME"]
        return SimpleNamespace(
            returncode=1 if wrong else 0,
            stdout=b'{"key":{"secret":true,"value":"fixture"}}',
            stderr=b"incorrect passphrase" if wrong else b"",
        )

    monkeypatch.setattr(r.subprocess, "run", run)
    return [args[0], policy, receipt, args[4], args[6], password, output], files, calls


@pytest.mark.parametrize("independent", [False, True])
def test_isolation_and_same_host_evidence(recovery, monkeypatch, independent):
    args, _, calls = recovery
    if independent:
        monkeypatch.setattr(b, "host_id", lambda: "b" * 64)
        policy = json.loads(args[1].read_bytes())
        policy["require_independent_host"] = True
        args[1].write_text(json.dumps(policy))
    report = r.rehearse(*args)
    assert report["kind"] == ("off-host" if independent else "same-host")
    assert report["objectives_met"]
    assert report["execution_authorized"] is False
    assert report["restore_seconds"] > 0 and report["backup_age_seconds"] >= 0
    commands = [(a, k) for a, k in calls if a[0].endswith("pulumi")]
    assert all(k["env"]["PULUMI_BACKEND_URL"].startswith("file://") for _, k in commands)
    assert all("AWS_ACCESS_KEY_ID" not in k["env"] for _, k in commands)
    assert len({k["env"]["PULUMI_HOME"] for _, k in commands}) == 5
    assert not list((args[0] / ".infra/rehearsals").iterdir())


@pytest.mark.parametrize(
    "fault", ["manifest", "checkpoint", "missing-config", "independent", "policy", "missing-key"]
)
def test_invalid_evidence_has_no_receipt(recovery, fault):
    args, files, _ = recovery
    if fault == "manifest":
        files["manifest.json"] += b" "
    elif fault == "checkpoint":
        files["checkpoint.json"] += b" "
    elif fault == "missing-config":
        del files["stack-config.json"]
    elif fault == "missing-key":
        args[5].unlink()
    else:
        policy = json.loads(args[1].read_bytes())
        policy["require_independent_host"] = True
        if fault == "policy":
            policy["restore_objective_seconds"] = None
        args[1].write_text(json.dumps(policy))
    with pytest.raises(RuntimeError, match="RECOVERY002"):
        r.rehearse(*args)
    assert not args[-1].exists()


@pytest.mark.parametrize("metric", ["max_backup_age_seconds", "restore_objective_seconds"])
def test_exceeded_objective_is_recorded_as_failure(recovery, metric):
    args, _, _ = recovery
    policy = json.loads(args[1].read_bytes())
    policy[metric] = 0.000000001
    args[1].write_text(json.dumps(policy))
    assert r.rehearse(*args)["objectives_met"] is False


def test_wrong_key_unrecognized_failure_is_not_crypto_evidence(recovery, monkeypatch):
    args, _, _ = recovery
    real = r.subprocess.run

    def run(argv, **kw):
        result = real(argv, **kw)
        if "wrong-" in kw.get("env", {}).get("PULUMI_HOME", ""):
            result.stderr = b"PRIVATE_NETWORK_DIAGNOSTIC"
        return result

    monkeypatch.setattr(r.subprocess, "run", run)
    with pytest.raises(RuntimeError) as error:
        r.rehearse(*args)
    assert "PRIVATE_NETWORK_DIAGNOSTIC" not in str(error.value)
    assert not args[-1].exists()


@pytest.mark.operation_integration
@pytest.mark.skipif(
    os.environ.get("RUN_OPERATION_INTEGRATION") != "1", reason="opt-in local recovery"
)
def test_real_encrypted_pair_rehearsal(bundle, monkeypatch):
    args, value = bundle
    root, request, checkpoint, settings, repository, _, password, _ = args
    cli, restic = r._tool(ROOT, "pulumi"), r._tool(ROOT, "restic")
    source = root / ".infra/source"
    source.mkdir()
    backend = source / "backend"
    backend.mkdir()
    key = "synthetic-recovery-passphrase"
    env = {
        # Checkout-local CI scratch inherits the parent uv workspace discovery.
        # Pulumi needs uv for package inspection even with an explicit virtualenv.
        "PATH": os.pathsep.join(
            (str(ROOT / ".infra/tools/uv"), str(Path(sys.executable).parent), str(cli.parent))
        ),
        "HOME": str(source),
        "UV_CACHE_DIR": str(source / "uv-cache"),
        "UV_OFFLINE": "1",
        "PIP_NO_INDEX": "1",
        "PULUMI_IGNORE_AMBIENT_PLUGINS": "true",
        "PULUMI_PYTHON_CMD": sys.executable,
        "PULUMI_HOME": str(source / "home"),
        "PULUMI_CONFIG_PASSPHRASE": key,
        "PULUMI_BACKEND_URL": backend.as_uri(),
        "PULUMI_SKIP_UPDATE_CHECK": "true",
        "PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION": "true",
    }
    (source / "Pulumi.yaml").write_text(
        json.dumps(
            {
                "name": "free-infrastructure",
                "runtime": {"name": "python", "options": {"virtualenv": sys.prefix}},
            }
        )
    )
    (source / "__main__.py").write_text(
        'import pulumi\npulumi.export("fixture", pulumi.Config().require_secret("sentinel"))\n'
    )

    def run(arguments):
        return subprocess.run(
            [str(cli), *arguments, "--non-interactive"],
            cwd=source,
            env=env,
            check=True,
            capture_output=True,
            timeout=60,
        ).stdout

    run(["stack", "init", "oci-network", "--secrets-provider", "passphrase"])
    run(["config", "set", "sentinel", "fixture-value", "--secret", "--stack", "oci-network"])
    run(["up", "--yes", "--skip-preview", "--stack", "oci-network"])
    config = yaml.safe_load((source / "Pulumi.oci-network.yaml").read_text())
    state = json.loads(run(["stack", "export", "--stack", "oci-network"]))
    checkpoint.write_text(json.dumps(state))
    settings.write_text(json.dumps(config))
    value.update(
        checkpoint_sha256=hashlib.sha256(checkpoint.read_bytes()).hexdigest(),
        configuration_sha256=hashlib.sha256(settings.read_bytes()).hexdigest(),
    )
    request.write_text(json.dumps(value))
    monkeypatch.setattr(b, "executable", lambda root: restic)
    restic_env = {
        "RESTIC_REPOSITORY": str(repository),
        "RESTIC_PASSWORD_FILE": str(password),
        "RESTIC_CACHE_DIR": str(source / "cache"),
        "GOMAXPROCS": "2",
    }
    subprocess.run(
        [str(restic), "init"], env=restic_env, check=True, capture_output=True, timeout=60
    )
    meta = subprocess.run(
        [str(restic), "cat", "config"], env=restic_env, check=True, capture_output=True, timeout=60
    )
    args[5] = json.loads(meta.stdout)["id"]
    receipt = b.capture(*args)
    policy = root / ".infra/policy.json"
    policy.write_text(
        json.dumps(
            dict(
                schema_version=1,
                max_backup_age_seconds=3600,
                restore_objective_seconds=120,
                require_independent_host=False,
            )
        )
    )
    passphrase = root / ".infra/passphrase"
    passphrase.write_text(key)
    passphrase.chmod(0o600)
    monkeypatch.setattr(r, "_tool", lambda root, name: cli if name == "pulumi" else restic)
    report = r.rehearse(
        root, policy, receipt, repository, password, passphrase, root / ".infra/result.json"
    )
    assert report["objectives_met"] and report["kind"] == "same-host"


def test_workflow_keeps_recovery_separate_from_pr_credentials():
    workflow = yaml.load(
        (ROOT / ".github/workflows/recovery-rehearsal.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert set(workflow["on"]) == {"workflow_dispatch"}
    job = workflow["jobs"]["rehearse"]
    assert job["needs"] == "verify" and job["environment"] == "recovery-rehearsal"
    assert job["runs-on"]["group"] == "recovery" and "refs/heads/main" in job["if"]
    assert job["steps"][0]["with"]["persist-credentials"] == "false"
