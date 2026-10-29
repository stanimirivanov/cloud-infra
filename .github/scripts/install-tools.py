#!/usr/bin/env python3
"""Install reviewed Linux x64 tools, verifying archives before extraction."""

import argparse
import hashlib
import json
import os
import platform
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path


def install(root: Path, tools: list[str], archive: Path | None) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise RuntimeError("TOOL001: only reviewed Linux x64 is supported")
    if archive is not None and len(tools) != 1:
        raise RuntimeError("TOOL001: a local archive requires exactly one tool")
    pins = json.loads((root / "config/toolchain.json").read_text())["tools"]
    parent = root / ".infra/tools"
    parent.mkdir(parents=True, exist_ok=True)
    for name in tools:
        asset = pins[name]["assets"]["linux-x64"]
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            package = archive
            if package is None:
                package = Path(directory) / "release.tar.gz"
                with (
                    urllib.request.urlopen(asset["url"], timeout=180) as source,
                    package.open("wb") as target,
                ):
                    shutil.copyfileobj(source, target)
            with package.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if digest != asset["sha256"]:
                raise RuntimeError(
                    f"TOOL001: {name} archive checksum mismatch; nothing extracted or executed"
                )
            unpacked = Path(directory) / "unpacked"
            with tarfile.open(package, "r:gz") as release:
                release.extractall(unpacked, filter="data")
            binary = unpacked / asset["binary"]
            with binary.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if "binary_sha256" in asset and digest != asset["binary_sha256"]:
                raise RuntimeError(f"TOOL001: {name} binary checksum mismatch")
            destination = parent / name
            destination.mkdir(exist_ok=True)
            # Keep release companions, including the Pulumi Python language host.
            shutil.copytree(binary.parent, destination, dirs_exist_ok=True)
            (destination / binary.name).chmod(0o755)
        if os.environ.get("GITHUB_PATH"):
            with Path(os.environ["GITHUB_PATH"]).open("a") as stream:
                stream.write(str(destination) + "\n")
        print(f"Verified {name} {pins[name]['version']} for linux-x64")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tool",
        nargs="+",
        choices=["uv", "pulumi", "gitleaks", "actionlint"],
        default=["uv", "pulumi", "gitleaks", "actionlint"],
    )
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    try:
        install(Path(__file__).resolve().parents[2], args.tool, args.archive)
    except (OSError, ValueError, RuntimeError, tarfile.TarError) as error:
        parser.exit(1, str(error) + "\n")
