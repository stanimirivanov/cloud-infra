"""Fail-closed, redacted Gitleaks checks; no network or secret-bearing diagnostics."""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, timeout=60, check=False)
    if result.returncode:
        raise RuntimeError("SECRET003: cannot read Git evidence; raw diagnostics suppressed")
    return result.stdout


def scanner(root: Path) -> Path:
    target = {"Linux": "linux-x64"}.get(platform.system())
    if target is None or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise RuntimeError("SECRET003: scanner requires a reviewed Linux x64 platform")
    asset = json.loads((root / "config/toolchain.json").read_text())["tools"]["gitleaks"]["assets"][
        target
    ]
    binary = root / ".infra/tools/gitleaks" / str(asset["binary"])
    if not binary.is_file():
        raise RuntimeError(
            "SECRET003: install verified tools with .github/scripts/install-tools.py"
        )
    with binary.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != asset["binary_sha256"]:
        raise RuntimeError("SECRET003: scanner checksum mismatch; reinstall reviewed tools")
    return binary


def check_secrets(root: Path, *, tool_root: Path | None = None) -> None:
    """Scan worktree, staged additions and all locally reachable history, not ignored data."""
    tools = tool_root or root
    binary = scanner(tools)
    if _git(root, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise RuntimeError(
            "SECRET003: full history required; fetch complete history before verification"
        )
    with tempfile.TemporaryDirectory(prefix="infra-secrets-") as directory:
        scratch = Path(directory)
        content = scratch / "content"
        content.mkdir()
        names = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
        for name in set(names.split(b"\0")) - {b""}:
            relative = Path(os.fsdecode(name))
            source = root / relative
            if source.is_symlink() or not source.resolve().is_relative_to(root.resolve()):
                raise RuntimeError("SECRET003: scan inputs must be regular repository files")
            if source.is_file():
                destination = content / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
        empty_ignore = scratch / "empty-ignore"
        empty_ignore.write_text("")
        staged = _git(root, "diff", "--cached", "--no-ext-diff", "--no-textconv", "--binary")
        env = {key: value for key, value in os.environ.items() if not key.startswith("GITLEAKS_")}
        for mode, args, data in (
            ("working tree", ["dir", str(content)], None),
            ("staged additions", ["stdin"], staged),
            ("history", ["git", "--log-opts=--all --full-history -m", str(root)], None),
        ):
            report = scratch / "report.json"
            result = subprocess.run(
                [
                    str(binary),
                    *args,
                    "--config",
                    str(tools / ".gitleaks.toml"),
                    "--gitleaks-ignore-path",
                    str(empty_ignore),
                    "--ignore-gitleaks-allow",
                    "--redact=100",
                    "--no-banner",
                    "--no-color",
                    "--exit-code=1",
                    "--report-format=json",
                    "--report-path",
                    str(report),
                    "--timeout=240",
                ],
                cwd=root,
                input=data,
                capture_output=True,
                timeout=260,
                check=False,
                env=env,
            )
            if result.returncode:
                # Do not forward stdout/stderr or report snippets, even on scanner errors.
                raise RuntimeError(
                    f"SECRET003: {mode} secret scan failed (exit {result.returncode}); "
                    "review privately with Gitleaks --redact=100; no report is uploaded"
                )
    print("PASS: verified Gitleaks scanned working tree, staged additions and reachable history")
