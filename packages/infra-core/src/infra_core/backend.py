"""Opt-in, isolated Pulumi backend qualification. Never manages cloud resources."""

import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from importlib.metadata import version
from pathlib import Path
from typing import Any
from uuid import uuid4

from infra_core.foundation import FoundationConfig


class QualificationError(RuntimeError):
    """Safe diagnostic: raw Pulumi output can contain decrypted secrets."""


class PulumiSession:
    def __init__(self, cwd: Path, env: dict[str, str]) -> None:
        self.cwd, self.env = cwd, env

    def command(self, args: list[str]) -> list[str]:
        return ["pulumi", *args, "--non-interactive", "--color=never"]

    def run(self, phase: str, args: list[str]) -> str:
        try:
            result = subprocess.run(
                self.command(args),
                cwd=self.cwd,
                env=self.env,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise QualificationError(
                f"{phase}: CLI unavailable or timed out; raw output withheld"
            ) from None
        if result.returncode:
            raise QualificationError(
                f"{phase}: Pulumi exited {result.returncode}; raw output withheld"
            )
        return result.stdout

    def check_lock(self, stack: str, marker: Path) -> None:
        env = self.env | {"INFRA_QUALIFICATION_HOLD": str(marker)}
        holder = subprocess.Popen(
            self.command(["up", "--yes", "--skip-preview", "--stack", stack]),
            cwd=self.cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 30
            while not marker.with_suffix(".ready").exists():
                if holder.poll() is not None or time.monotonic() >= deadline:
                    raise QualificationError("locking: holder did not reach ready state")
                time.sleep(0.1)
            contender = subprocess.run(
                self.command(["up", "--yes", "--skip-preview", "--stack", stack]),
                cwd=self.cwd,
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if (
                contender.returncode == 0
                or "the stack is currently locked"
                not in (contender.stderr + contender.stdout).lower()
            ):
                raise QualificationError(
                    "locking: competing writer was not rejected by a backend lock"
                )
        finally:
            marker.with_suffix(".release").touch()
            try:
                holder.communicate(timeout=90)
            except subprocess.TimeoutExpired:
                holder.kill()
                holder.communicate()
                raise QualificationError(
                    "locking: holder timed out; inspect the isolated namespace"
                ) from None
        if holder.returncode:
            raise QualificationError("locking: holder failed; raw output withheld")


def qualification_environment(source: dict[str, str], home: Path, *, local: bool) -> dict[str, str]:
    env = {
        key: value
        for key, value in source.items()
        if not key.upper().startswith(
            ("AWS_", "OCI_", "PULUMI_", "TF_", "TG_", "TERRAGRUNT_", "INFRA_QUALIFICATION_")
        )
    }
    if local:
        passphrase = secrets.token_urlsafe(32)
    else:
        for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "PULUMI_CONFIG_PASSPHRASE"):
            if not source.get(key, "").strip():
                raise QualificationError(f"missing required environment variable: {key}")
        passphrase = source["PULUMI_CONFIG_PASSPHRASE"]
        if len(passphrase) < 20:
            raise QualificationError("PULUMI_CONFIG_PASSPHRASE must contain at least 20 characters")
        env.update({key: source[key] for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")})
    env.update(
        PULUMI_HOME=str(home),
        PULUMI_CONFIG_PASSPHRASE=passphrase,
        PULUMI_PYTHON_CMD=sys.executable,
        PULUMI_SKIP_UPDATE_CHECK="true",
        PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION="true",
        AWS_EC2_METADATA_DISABLED="true",
        AWS_REQUEST_CHECKSUM_CALCULATION="when_required",
        AWS_RESPONSE_CHECKSUM_VALIDATION="when_required",
        PIP_DISABLE_PIP_VERSION_CHECK="true",
        PIP_NO_INDEX="true",
    )
    return env


def qualify(config: FoundationConfig, *, local: bool, allow_writes: bool) -> dict[str, Any]:
    if not allow_writes:
        raise QualificationError(
            "qualification writes isolated test state; pass --allow-backend-writes"
        )
    if version("pulumi") != config.pulumi_version:
        raise QualificationError("Pulumi CLI pin must match the locked Python SDK")
    run_id = uuid4().hex
    stack = f"qualification-{run_id}"
    print(f"Qualification run: {run_id} ({'local' if local else 'oci-s3'}); no resource adoption")
    with tempfile.TemporaryDirectory(prefix="pulumi-qualification-") as directory:
        work = Path(directory)
        env = qualification_environment(dict(os.environ), work / "home", local=local)
        if local:
            (work / "backend").mkdir()
        backend = (work / "backend").as_uri() if local else config.backend.url(run_id)
        project = {
            "name": "backend-qualification",
            "runtime": {"name": "python", "options": {"virtualenv": sys.prefix}},
            "main": ".",
        }
        (work / "Pulumi.yaml").write_text(json.dumps(project), encoding="utf-8")
        (work / "__main__.py").write_text(
            "from infra_program.qualification import main\nmain()\n", encoding="utf-8"
        )
        session = PulumiSession(work, env)
        actual_version = session.run("version", ["version"]).strip().removeprefix("v")
        if actual_version != config.pulumi_version:
            raise QualificationError("install the exact configured Pulumi CLI version")
        session.run("login", ["login", backend])
        session.run("initialize", ["stack", "init", stack, "--secrets-provider", "passphrase"])
        complete = False
        try:
            sentinel = "qualification-only-" + secrets.token_hex(24)
            session.run(
                "configure", ["config", "set", "sentinel", sentinel, "--secret", "--stack", stack]
            )
            session.run("preview", ["preview", "--stack", stack])
            session.run("checkpoint", ["up", "--yes", "--skip-preview", "--stack", stack])
            checkpoint = session.run("export", ["stack", "export", "--stack", stack])
            if sentinel in checkpoint or len(checkpoint.encode()) > 1024 * 1024:
                raise QualificationError("encryption: plaintext sentinel or oversized checkpoint")
            document = json.loads(checkpoint)
            resources = document["deployment"]["resources"]
            if any(resource["type"] != "pulumi:pulumi:Stack" for resource in resources):
                raise QualificationError(
                    "qualification unexpectedly registered provider/cloud resources"
                )
            if not resources or "ciphertext" not in checkpoint:
                raise QualificationError("encryption: missing encrypted secret checkpoint")
            config_file = work / f"Pulumi.{stack}.yaml"
            if sentinel in config_file.read_text():
                raise QualificationError("encryption: plaintext sentinel in stack config")
            session.check_lock(stack, work / "holder")
            backup = work / "encrypted-checkpoint.json"
            backup.write_text(checkpoint, encoding="utf-8")
            session.run("restore", ["stack", "import", "--file", str(backup), "--stack", stack])
            restored = session.run(
                "readback",
                ["stack", "output", "sentinel", "--show-secrets", "--json", "--stack", stack],
            )
            if json.loads(restored) != sentinel:
                raise QualificationError("recovery: restored secret did not decrypt correctly")
            complete = True
        finally:
            # Only this invocation's generated stack in its unique namespace may be removed.
            # No --force/cancel fallback: an unexpected nonempty stack or active lock must fail.
            session.run("cleanup", ["stack", "rm", stack, "--yes"])
        if not complete:
            raise QualificationError("qualification did not complete")
    return {
        "schema_version": 1,
        "kind": "local" if local else "oci-s3",
        "configuration_sha256": config.digest,
        "pulumi_version": config.pulumi_version,
        "run_id": run_id,
        "completed_at": datetime.now(UTC).isoformat(),
        "checks": [
            "encrypted-config",
            "encrypted-checkpoint",
            "lock-contention",
            "restore-readback",
        ],
        "deployment_authorized": False,
    }


def validate_receipt(config: FoundationConfig, receipt: dict[str, Any]) -> None:
    expected_checks = {
        "encrypted-config",
        "encrypted-checkpoint",
        "lock-contention",
        "restore-readback",
    }
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema_version") != 1
        or receipt.get("kind") != "oci-s3"
        or receipt.get("configuration_sha256") != config.digest
        or receipt.get("pulumi_version") != config.pulumi_version
        or not isinstance(receipt.get("checks"), list)
        or any(not isinstance(check, str) for check in receipt["checks"])
        or set(receipt["checks"]) != expected_checks
        or receipt.get("deployment_authorized") is not False
    ):
        raise QualificationError(
            "receipt does not match the configured OCI backend and required checks"
        )
    if not isinstance(receipt.get("completed_at"), str):
        raise QualificationError("qualification receipt has no valid timestamp")
    completed = datetime.fromisoformat(receipt["completed_at"])
    now = datetime.now(UTC)
    if (
        completed.tzinfo is None
        or completed > now
        or now - completed > timedelta(hours=config.qualification_ttl_hours)
    ):
        raise QualificationError("qualification receipt is stale or has an invalid timestamp")
