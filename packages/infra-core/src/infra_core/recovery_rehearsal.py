"""Restore encrypted evidence to disposable local state; never select a live backend."""

import hashlib
import json
import math
import os
import re
import secrets
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infra_core import backup
from infra_core.foundation import load_foundation
from infra_core.operations import MAX_BYTES, encoded, read_json


def require(value: bool) -> None:
    if not value:
        raise ValueError("RECOVERY001: rehearsal prerequisite or readback failed")


def _tool(root: Path, name: str) -> Path:
    pin = read_json(root / "config/toolchain.json")["tools"][name]
    path = backup._path(root / f".infra/tools/{name}/{name}")
    require(
        hashlib.sha256(path.read_bytes()).hexdigest() == pin["assets"]["linux-x64"]["binary_sha256"]
    )
    return path


def rehearse(
    root: Path,
    policy: Path,
    receipt: Path,
    repository: Path,
    password_file: Path,
    passphrase_file: Path,
    output: Path,
) -> dict[str, Any]:
    try:
        return _rehearse(
            root.resolve(), policy, receipt, repository, password_file, passphrase_file, output
        )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        OverflowError,
        subprocess.SubprocessError,
    ):
        raise RuntimeError("RECOVERY002: isolated rehearsal failed; diagnostics withheld") from None


def _rehearse(
    root: Path,
    policy: Path,
    receipt: Path,
    repository: Path,
    password_file: Path,
    passphrase_file: Path,
    output: Path,
) -> dict[str, Any]:
    settings, evidence = read_json(policy), read_json(receipt)
    require(
        type(settings) is dict
        and set(settings)
        == {
            "schema_version",
            "max_backup_age_seconds",
            "restore_objective_seconds",
            "require_independent_host",
        }
    )
    require(type(settings["schema_version"]) is int and settings["schema_version"] == 1)
    for key in ("max_backup_age_seconds", "restore_objective_seconds"):
        value = settings[key]
        require(type(value) in (int, float) and math.isfinite(value) and value > 0)
    require(type(settings["require_independent_host"]) is bool)
    require(type(evidence) is dict and evidence.get("schema_version") == 1)
    for field in ("snapshot_id", "manifest_sha256", "repository_id"):
        require(
            type(evidence[field]) is str
            and re.fullmatch("[a-f0-9]{64}", evidence[field]) is not None
        )
    repository = backup._path(repository)
    require(
        repository.is_absolute()
        and repository.is_dir()
        and not repository.is_relative_to(root)
        and not root.is_relative_to(repository)
    )
    for path in (password_file, passphrase_file, output):
        require(backup._path(path).is_relative_to(root / ".infra"))
    require(not output.exists())
    for path in (password_file, passphrase_file):
        require(
            path.is_file() and path.stat().st_mode & 0o077 == 0 and 0 < path.stat().st_size <= 4096
        )
    require(password_file != passphrase_file)
    key = passphrase_file.read_text().rstrip("\r\n")
    require(bool(key))
    restic, pulumi = _tool(root, "restic"), _tool(root, "pulumi")
    parent = backup._path(root / ".infra/rehearsals")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        work = Path(directory)
        env = {
            "RESTIC_REPOSITORY": str(repository),
            "RESTIC_PASSWORD_FILE": str(password_file),
            "RESTIC_CACHE_DIR": str(work / "cache"),
            "GOMAXPROCS": "2",
        }

        def restic_run(args: list[str]) -> bytes:
            result = subprocess.run(
                [str(restic), "--no-lock", *args],
                env=env,
                capture_output=True,
                timeout=180,
                check=False,
            )
            require(result.returncode == 0)
            return result.stdout

        require(json.loads(restic_run(["cat", "config"]))["id"] == evidence["repository_id"])
        nodes = [
            json.loads(line)
            for line in restic_run(["ls", "--json", evidence["snapshot_id"]]).splitlines()
        ]
        files = [node for node in nodes if node.get("type") == "file"]
        require(
            len(files) == 3
            and {Path(n["path"]).name for n in files}
            == {"manifest.json", "checkpoint.json", "stack-config.json"}
        )
        require(all(type(n["size"]) is int and 0 < n["size"] <= MAX_BYTES for n in files))
        for node in files:
            raw = restic_run(["dump", evidence["snapshot_id"], node["path"]])
            require(len(raw) == node["size"])
            (work / Path(node["path"]).name).write_bytes(raw)
        manifest_raw = (work / "manifest.json").read_bytes()
        require(hashlib.sha256(manifest_raw).hexdigest() == evidence["manifest_sha256"])
        manifest = read_json(work / "manifest.json")
        require(
            manifest["schema_version"] == 2
            and manifest["repository_id"] == evidence["repository_id"]
        )
        unit = next((u for u in load_foundation(root).units if u.name == manifest["unit"]), None)
        require(unit is not None and manifest["stack"] == unit.stack_identity)
        assert unit is not None
        for name, field in (
            ("checkpoint.json", "checkpoint_sha256"),
            ("stack-config.json", "configuration_sha256"),
        ):
            require(hashlib.sha256((work / name).read_bytes()).hexdigest() == manifest[field])
        source_time = datetime.fromisoformat(manifest["source_exported_at"])
        require(source_time.utcoffset() is not None)
        age = (datetime.now(UTC) - source_time).total_seconds()
        require(age >= 0)
        independent = manifest["source_host_id"] != backup.host_id()
        require(
            type(manifest["source_host_id"]) is str
            and re.fullmatch("[a-f0-9]{64}", manifest["source_host_id"]) is not None
        )
        require(independent or not settings["require_independent_host"])
        backend = work / "backend"
        backend.mkdir()
        (work / "Pulumi.yaml").write_bytes(encoded({"name": unit.project, "runtime": "python"}))
        base = {
            "PULUMI_BACKEND_URL": backend.as_uri(),
            "PULUMI_SKIP_UPDATE_CHECK": "true",
            "PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION": "true",
            "PULUMI_IGNORE_AMBIENT_PLUGINS": "true",
        }

        def pulumi_run(
            args: list[str], passphrase: str, home: str, *, rejected: bool = False
        ) -> bytes:
            env = base | {
                "PULUMI_HOME": str(work / home),
                "HOME": str(work / home),
                "PULUMI_CONFIG_PASSPHRASE": passphrase,
            }
            result = subprocess.run(
                [str(pulumi), *args, "--non-interactive", "--color=never"],
                cwd=work,
                env=env,
                capture_output=True,
                timeout=120,
                check=False,
            )
            if rejected:
                require(
                    result.returncode in (1, 255)
                    and b"incorrect passphrase" in result.stderr.lower()
                )
            else:
                require(result.returncode == 0)
            return result.stdout

        pulumi_run(
            ["stack", "init", unit.stack, "--secrets-provider", "passphrase"], key, "setup-home"
        )
        (work / f"Pulumi.{unit.stack}.yaml").write_bytes((work / "stack-config.json").read_bytes())
        pulumi_run(
            ["stack", "import", "--file", str(work / "checkpoint.json"), "--stack", unit.stack],
            key,
            "setup-home",
        )
        wrong = secrets.token_urlsafe(32)
        require(wrong != key)
        commands = [
            ["config", "--json", "--show-secrets", "--stack", unit.stack],
            ["stack", "output", "--json", "--show-secrets", "--stack", unit.stack],
        ]
        for index, args in enumerate(commands):
            pulumi_run(args, wrong, f"wrong-{index}", rejected=True)
        for index, args in enumerate(commands):
            result = json.loads(pulumi_run(args, key, f"correct-{index}"))
            require(type(result) is dict and bool(result))
            if index == 0:
                require(
                    any(
                        type(v) is dict and v.get("secret") is True and "value" in v
                        for v in result.values()
                    )
                )
        duration = time.perf_counter() - started
        report = dict(
            schema_version=1,
            policy_sha256=hashlib.sha256(encoded(settings)).hexdigest(),
            kind="off-host" if independent else "same-host",
            snapshot_id=evidence["snapshot_id"],
            manifest_sha256=evidence["manifest_sha256"],
            backup_age_seconds=age,
            restore_seconds=duration,
            objectives_met=(
                age <= settings["max_backup_age_seconds"]
                and duration <= settings["restore_objective_seconds"]
            ),
            wrong_key_rejected=True,
            correct_key_readback=True,
            execution_authorized=False,
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as stream:
        stream.write(encoded(report))
        stream.flush()
        os.fsync(stream.fileno())
    return report
