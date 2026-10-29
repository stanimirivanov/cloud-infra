"""Explicit encrypted-pair capture to an existing local restic repository; no restore."""

import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from infra_core.foundation import load_foundation
from infra_core.operations import MAX_BYTES, encoded, read_json, request

SIGNATURE = "4dabf18193072939515e22adb298388d"
ENCRYPTED_VALUE_SIGNATURE = "1b47061264138c4ac30d75fd1eb44270"


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("BACKUP001: invalid encrypted pair, repository binding or backup result")


def _path(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)))
    return path


def executable(root: Path) -> Path:
    asset = read_json(root / "config/toolchain.json")["tools"]["restic"]["assets"]["linux-x64"]
    binary = _path(root / ".infra/tools/restic" / asset["binary"])
    require(hashlib.sha256(binary.read_bytes()).hexdigest() == asset["binary_sha256"])
    return binary


def host_id() -> str:
    """Stable host fingerprint, not an attestation or a raw machine identifier."""
    identity = Path("/etc/machine-id").read_bytes().strip()
    require(bool(identity))
    return hashlib.sha256(identity).hexdigest()


def _encrypted(value: object) -> None:
    if isinstance(value, dict):
        require("plaintext" not in value)
        if value.get(SIGNATURE) == ENCRYPTED_VALUE_SIGNATURE:
            require(set(value) == {SIGNATURE, "ciphertext"})
            require(type(value["ciphertext"]) is str and bool(value["ciphertext"]))
        for child in value.values():
            _encrypted(child)
    elif isinstance(value, list):
        for child in value:
            _encrypted(child)


def capture(
    root: Path,
    request_path: Path,
    checkpoint: Path,
    config: Path,
    repository: Path,
    repository_id: str,
    password_file: Path,
    exported_at: str,
) -> Path:
    """Pack supplied exports, not live state. The caller must freeze source writers.

    Repository independence, provenance and ciphertext decryptability require separate
    acceptance. No environment credentials, init, prune or automatic retry are used.
    """
    try:
        return _capture(
            root,
            request_path,
            checkpoint,
            config,
            repository,
            repository_id,
            password_file,
            exported_at,
        )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        raise RuntimeError(
            "BACKUP002: capture failed or outcome uncertain; reconcile before retry"
        ) from None


def _capture(
    root: Path,
    request_path: Path,
    checkpoint: Path,
    config: Path,
    repository: Path,
    repository_id: str,
    password_file: Path,
    exported_at: str,
) -> Path:
    root = root.resolve()
    checkpoint, config, password_file = (_path(p) for p in (checkpoint, config, password_file))
    require(
        all(
            p.is_file() and p.is_relative_to(root / ".infra")
            for p in (checkpoint, config, password_file)
        )
    )
    require(password_file.stat().st_mode & 0o077 == 0 and password_file.stat().st_size > 0)
    require(repository.is_absolute())
    repository = _path(repository)
    require(
        repository.is_dir()
        and not repository.is_relative_to(root)
        and not root.is_relative_to(repository)
    )
    require(re.fullmatch("[a-f0-9]{64}", repository_id) is not None)
    value = request(read_json(request_path))
    require(datetime.fromisoformat(value["expires_at"]) > datetime.now(UTC))
    stack = next(
        unit.stack_identity for unit in load_foundation(root).units if unit.name == value["unit"]
    )
    now = datetime.now(UTC)
    exported = datetime.fromisoformat(exported_at)
    require(exported.utcoffset() is not None)
    require(0 <= (now - exported).total_seconds() <= 3600)
    started = now.isoformat()
    # Parse then capture the exact original bytes; hashes detect concurrent source edits.
    state, settings = read_json(checkpoint), read_json(config)
    with checkpoint.open("rb") as stream:
        state_raw = stream.read(MAX_BYTES + 1)
    with config.open("rb") as stream:
        config_raw = stream.read(MAX_BYTES + 1)
    require(len(state_raw) <= MAX_BYTES and len(config_raw) <= MAX_BYTES)
    require(hashlib.sha256(state_raw).hexdigest() == value["checkpoint_sha256"])
    require(hashlib.sha256(config_raw).hexdigest() == value["configuration_sha256"])
    require(json.loads(state_raw) == state and json.loads(config_raw) == settings)
    require(type(state) is dict and state.get("version") == 3)
    deployment = state["deployment"]
    provider = deployment["secrets_providers"]
    require(
        provider["type"] == "passphrase"
        and type(provider["state"]["salt"]) is str
        and bool(provider["state"]["salt"])
    )
    resources = deployment["resources"]
    require(type(resources) is list and len(resources) > 0)
    identity = stack.split("/")
    for resource in resources:
        require(resource["urn"].startswith(f"urn:pulumi:{identity[2]}::{identity[1]}::"))
    require(sum(r["type"] == "pulumi:pulumi:Stack" for r in resources) == 1)
    _encrypted(state)
    require(
        type(settings) is dict and set(settings) <= {"secretsprovider", "encryptionsalt", "config"}
    )
    require(settings.get("secretsprovider", "passphrase") == "passphrase")
    require(settings.get("encryptionsalt") == provider["state"]["salt"])
    require(type(settings.get("config")) is dict)
    for item in settings["config"].values():
        # Closed JSON-formatted YAML subset: every config value must be encrypted.
        require(type(item) is dict and set(item) == {"secure"})
        require(type(item["secure"]) is str and item["secure"].startswith("v1:"))
    binary = executable(root)
    env = {
        "RESTIC_REPOSITORY": str(repository),
        "RESTIC_PASSWORD_FILE": str(password_file),
        "RESTIC_CACHE_DIR": str(_path(root / ".infra/restic-cache")),
        "GOMAXPROCS": "2",
    }

    def run(args: list[str]) -> str:
        result = subprocess.run(
            [str(binary), *args], env=env, capture_output=True, text=True, timeout=180, check=False
        )
        require(result.returncode == 0)  # Includes rejection of partial-success exit 3.
        return result.stdout

    require(json.loads(run(["cat", "config"]))["id"] == repository_id)
    parent = _path(root / ".infra/backups")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = parent / str(value["operation_id"])
    destination.mkdir(mode=0o700)  # Reserve identity even if upload outcome is uncertain.
    manifest = dict(
        schema_version=2,
        source_host_id=host_id(),
        operation_id=value["operation_id"],
        unit=value["unit"],
        stack=stack,
        commit=value["commit"],
        repository_id=repository_id,
        request_sha256=hashlib.sha256(encoded(value)).hexdigest(),
        checkpoint_sha256=value["checkpoint_sha256"],
        configuration_sha256=value["configuration_sha256"],
        source_exported_at=exported_at,
        capture_started_at=started,
        captured_at=datetime.now(UTC).isoformat(),
    )
    for name, payload in (
        ("checkpoint.json", state_raw),
        ("stack-config.json", config_raw),
        ("manifest.json", encoded(manifest)),
    ):
        path = destination / name
        with path.open("xb") as output:
            os.chmod(path, 0o600)
            output.write(payload)
    summaries = [
        json.loads(line)
        for line in run(
            [
                "backup",
                "--json",
                "--host",
                "cloud-infra",
                "--tag",
                value["operation_id"],
                "--",
                str(destination / "checkpoint.json"),
                str(destination / "stack-config.json"),
                str(destination / "manifest.json"),
            ]
        ).splitlines()
    ]
    summaries = [s for s in summaries if s.get("message_type") == "summary"]
    require(len(summaries) == 1)
    summary = summaries[0]
    snapshot = summary.get("snapshot_id", "")
    require(type(snapshot) is str and re.fullmatch("[a-f0-9]{64}", snapshot) is not None)
    require(summary.get("total_files_processed") == 3)
    receipt = destination / "receipt.json"
    with receipt.with_suffix(".pending").open("xb") as receipt_stream:
        os.chmod(receipt.with_suffix(".pending"), 0o600)
        receipt_stream.write(
            encoded(
                dict(
                    schema_version=1,
                    snapshot_id=snapshot,
                    manifest_sha256=hashlib.sha256(encoded(manifest)).hexdigest(),
                    repository_id=repository_id,
                    completed_at=datetime.now(UTC).isoformat(),
                    execution_authorized=False,
                )
            )
        )
        receipt_stream.flush()
        os.fsync(receipt_stream.fileno())
    os.replace(receipt.with_suffix(".pending"), receipt)
    directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return receipt
