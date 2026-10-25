"""Offline workflow syntax sensor using only the reviewed actionlint executable."""

import hashlib
import json
import platform
import re
import subprocess
import tempfile
from pathlib import Path


def workflow_linter(root: Path) -> Path:
    target = {"Windows": "windows-x64", "Linux": "linux-x64"}.get(platform.system())
    if target is None or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise RuntimeError("WORKFLOW001: actionlint requires reviewed Linux/Windows x64")
    try:
        asset = json.loads((root / "config/toolchain.json").read_text())["tools"]["actionlint"][
            "assets"
        ][target]
        binary = root / ".infra/tools/actionlint" / str(asset["binary"])
        with binary.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != asset["binary_sha256"]:
            raise RuntimeError(
                "WORKFLOW001: actionlint checksum mismatch; reinstall reviewed tools"
            )
    except (OSError, KeyError, ValueError, TypeError):
        raise RuntimeError(
            "WORKFLOW001: install verified tools with .github/scripts/install-tools.ps1"
        ) from None
    return binary


def check_workflows(root: Path, *, tool_root: Path | None = None) -> None:
    """Lint every workflow; explicit config disallows repository-local ignore rules."""
    root = root.resolve()
    directory = root / ".github/workflows"
    workflows = sorted(set(directory.glob("*.yml")) | set(directory.glob("*.yaml")))
    if not workflows:
        raise RuntimeError("WORKFLOW001: no workflow files found")
    if any(path.is_symlink() or not path.resolve().is_relative_to(root) for path in workflows):
        raise RuntimeError("WORKFLOW001: workflow inputs must be regular repository files")
    binary = workflow_linter((tool_root or root).resolve())
    # Never execute shell/python integrations from PATH or read a local ignore config.
    with tempfile.TemporaryDirectory(prefix="infra-workflows-") as temporary:
        config = Path(temporary) / "actionlint.yaml"
        config.write_text("{}\n", encoding="utf-8")
        for path in workflows:
            try:
                result = subprocess.run(
                    [
                        str(binary),
                        "-config-file",
                        str(config),
                        "-shellcheck=",
                        "-pyflakes=",
                        "-no-color",
                        "-format",
                        "{{range .}}{{.Line}}:{{.Column}} [{{.Kind}}]\n{{end}}",
                        str(path),
                    ],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                raise RuntimeError(
                    "WORKFLOW001: actionlint could not complete; raw diagnostics suppressed"
                ) from None
            if result.returncode:
                # Exclude source snippets, messages and stderr even for parser/tool crashes.
                locations = result.stdout.splitlines()
                safe = [
                    line for line in locations if re.fullmatch(r"[0-9]+:[0-9]+ \[[a-z-]+\]", line)
                ]
                detail = "; ".join(safe[:10]) or "raw diagnostics suppressed"
                raise RuntimeError(
                    f"WORKFLOW001: actionlint rejected {path.relative_to(root).as_posix()}: "
                    f"{detail}"
                )
