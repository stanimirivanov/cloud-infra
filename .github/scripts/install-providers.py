#!/usr/bin/env python3
"""Acquire pinned Linux provider archives; never execute provider code."""

import argparse
import hashlib
import json
import platform
import re
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path


def install(root: Path, providers: list[str], home: Path, archive: Path | None) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise RuntimeError("PROVIDER001: only reviewed Linux x64 is supported")
    if archive is not None and len(providers) != 1:
        raise RuntimeError("PROVIDER001: a local archive requires one provider")
    pins = json.loads((root / "config/provider-toolchain.json").read_text())
    parent = root / ".infra/provider-downloads"
    if any(p.is_symlink() for p in (parent, *parent.parents)):
        raise RuntimeError("PROVIDER001: linked download path")
    parent.mkdir(parents=True, exist_ok=True)
    for name in providers:
        pin = pins["downstream"] if name == "supabase" else pins["providers"][name]
        asset = pin["assets"]["linux-x64"]
        version = pin["version"]
        expected = (
            f"https://github.com/supabase/terraform-provider-supabase/releases/download/v{version}/"
            f"terraform-provider-supabase_{version}_linux_amd64.zip"
            if name == "supabase"
            else f"https://github.com/pulumi/pulumi-{name}/releases/download/v{version}/"
            f"pulumi-resource-{name}-v{version}-linux-amd64.tar.gz"
        )
        if (
            re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None
            or re.fullmatch(r"[a-f0-9]{64}", asset["sha256"]) is None
            or asset["url"] != expected
        ):
            raise RuntimeError("PROVIDER001: invalid release pin")
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            package = archive
            if package is None:
                package = Path(directory) / "release"
                with (
                    urllib.request.urlopen(asset["url"], timeout=180) as source,
                    package.open("wb") as target,
                ):
                    shutil.copyfileobj(source, target)
            with package.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if digest != asset["sha256"]:
                raise RuntimeError(
                    "PROVIDER001: archive checksum mismatch; nothing extracted or executed"
                )
            subprocess.run(
                [
                    "uv",
                    "run",
                    "--locked",
                    "python",
                    "-m",
                    "infra_core.provider_tools",
                    "--root",
                    str(root),
                    "--home",
                    str(root / home),
                    "--provider",
                    name,
                    "--archive",
                    str(package),
                ],
                cwd=root,
                check=True,
                timeout=180,
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--provider",
        nargs="+",
        choices=["oci", "cloudflare", "terraform-provider", "supabase"],
        default=["oci", "cloudflare", "terraform-provider"],
    )
    parser.add_argument("--home", type=Path, default=Path(".infra/provider-home"))
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    try:
        install(Path(__file__).resolve().parents[2], args.provider, args.home, args.archive)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + "\n")
