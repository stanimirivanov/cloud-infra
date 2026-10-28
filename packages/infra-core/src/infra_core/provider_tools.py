"""Native executable verification rooted in pinned archives; never acquire or execute."""

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

NAMES = {"oci", "cloudflare", "terraform-provider"}


def _require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError("PROVIDER001: " + message)


def _regular_path(path: Path) -> None:
    _require(
        not any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)),
        "links and reparse paths are forbidden",
    )


def load_assets(root: Path) -> dict[str, Any]:
    """Validate all platforms and URLs, even when installing only one provider."""
    try:
        data = json.loads((root / "config/provider-toolchain.json").read_text())
        _require(
            set(data) == {"schema_version", "providers", "downstream"}
            and type(data["schema_version"]) is int
            and data["schema_version"] == 2
            and set(data["providers"]) == NAMES,
            "unsupported provider manifest",
        )
        downstream = data["downstream"]
        _require(
            set(downstream) == {"source", "version", "assets"}
            and downstream["source"] == "registry.opentofu.org/supabase/supabase"
            and downstream["version"] == "1.11.0"
            and set(downstream["assets"]) == {"linux-x64", "windows-x64"},
            "invalid downstream identity",
        )
        for target, asset in downstream["assets"].items():
            system = target.split("-")[0]
            binary = "terraform-provider-supabase_v1.11.0" + (".exe" if system == "windows" else "")
            url = (
                "https://github.com/supabase/terraform-provider-supabase/releases/download/v1.11.0/"
                f"terraform-provider-supabase_1.11.0_{system}_amd64.zip"
            )
            _require(
                set(asset) == {"url", "sha256", "binary"}
                and asset["url"] == url
                and asset["binary"] == binary
                and re.fullmatch(r"[a-f0-9]{64}", asset["sha256"]) is not None,
                "invalid downstream asset",
            )
        for name, provider in data["providers"].items():
            version = provider["version"]
            _require(
                set(provider) == {"version", "assets"}
                and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is not None
                and set(provider["assets"]) == {"linux-x64", "windows-x64"},
                "invalid provider version/platforms",
            )
            for target, asset in provider["assets"].items():
                system = target.split("-")[0]
                binary = f"pulumi-resource-{name}" + (".exe" if system == "windows" else "")
                url = (
                    f"https://github.com/pulumi/pulumi-{name}/releases/download/v{version}/"
                    f"pulumi-resource-{name}-v{version}-{system}-amd64.tar.gz"
                )
                _require(
                    set(asset) == {"url", "sha256", "binary"}
                    and asset["url"] == url
                    and asset["binary"] == binary
                    and re.fullmatch(r"[a-f0-9]{64}", asset["sha256"]) is not None,
                    "invalid provider asset",
                )
        return dict(data["providers"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise RuntimeError("PROVIDER001: invalid or missing provider manifest") from None


def _paths(root: Path, name: str, home: Path) -> tuple[dict[str, str], Path, Path]:
    target = {"Linux": "linux-x64", "Windows": "windows-x64"}.get(platform.system())
    _require(
        target is not None and platform.machine().lower() in {"x86_64", "amd64"},
        "only reviewed Linux/Windows x64 is supported",
    )
    providers = load_assets(root)
    _require(name in providers, "unknown provider")
    home = Path(os.path.abspath(home))
    private = root.resolve() / ".infra"
    _require(
        home != private and home.is_relative_to(private), "use an explicit isolated .infra home"
    )
    _regular_path(home)
    provider = providers[name]
    directory = home / "plugins" / f"resource-{name}-v{provider['version']}"
    archive = home / ".provider-archives" / f"{name}-{provider['version']}-{target}.tar.gz"
    _regular_path(directory)
    _regular_path(archive)
    return provider["assets"][target], directory, archive


def _digest(path: Path) -> str:
    _regular_path(path)
    _require(path.is_file(), "required archive or executable is missing")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _archive_digest(archive: Path, asset: dict[str, str]) -> str:
    """Validate the archive before processing any member; never use extractall."""
    _require(archive.stat().st_size <= 128 * 1024 * 1024, "archive size exceeds reviewed bound")
    _require(
        _digest(archive) == asset["sha256"],
        "archive checksum mismatch; nothing extracted or executed",
    )
    digest = None
    size = 0
    with tarfile.open(archive, "r|gz") as package:
        for index, member in enumerate(package):
            path = PurePosixPath(member.name)
            size += member.size
            _require(
                index < 32
                and size <= 1024 * 1024 * 1024
                and not path.is_absolute()
                and ".." not in path.parts
                and not any(c in member.name for c in ("\\", ":"))
                and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE),
                "unsafe or excessive archive member",
            )
            if path.as_posix() == asset["binary"]:
                _require(
                    digest is None and member.isfile(), "duplicate or invalid executable member"
                )
                stream = package.extractfile(member)
                _require(stream is not None, "missing executable content")
                assert stream is not None
                with stream:
                    hashed = hashlib.sha256()
                    while chunk := stream.read(1024 * 1024):
                        hashed.update(chunk)
                    digest = hashed.hexdigest()
    _require(digest is not None, "expected executable missing from archive")
    assert digest is not None
    return digest


def verify_provider(root: Path, name: str, home: Path) -> Path:
    try:
        asset, directory, archive = _paths(root, name, home)
        expected = _archive_digest(archive, asset)
        _require(
            set(p.name for p in directory.iterdir()) == {asset["binary"]},
            "unexpected installed provider files",
        )
        binary = directory / asset["binary"]
        _require(_digest(binary) == expected, "installed executable checksum mismatch")
        _require(
            os.name == "nt" or bool(binary.stat().st_mode & 0o111),
            "provider is not executable",
        )
        return binary
    except (OSError, tarfile.TarError, EOFError):
        raise RuntimeError("PROVIDER001: provider files cannot be verified") from None


def install_provider(root: Path, name: str, archive: Path, home: Path) -> Path:
    asset, directory, cached = _paths(root, name, home)
    expected = _archive_digest(archive, asset)
    _require(not directory.exists() and not cached.exists(), "use a fresh provider destination")
    cached.parent.mkdir(parents=True, exist_ok=True)
    with archive.open("rb") as source, cached.open("xb") as destination:
        shutil.copyfileobj(source, destination)
    _require(_digest(cached) == asset["sha256"], "archive changed during capture")
    directory.mkdir(parents=True)
    binary = directory / asset["binary"]
    with tarfile.open(cached, "r|gz") as package:
        for member in package:
            if PurePosixPath(member.name).as_posix() == asset["binary"]:
                stream = package.extractfile(member)
                assert stream is not None
                with stream, binary.open("xb") as destination:
                    shutil.copyfileobj(stream, destination)
                break
    _require(_digest(binary) == expected, "executable changed during installation")
    binary.chmod(0o755)
    return binary


def verified_environment(root: Path, home: Path) -> dict[str, str]:
    home = Path(os.path.abspath(home))
    binaries = [verify_provider(root, name, home) for name in sorted(NAMES)]
    _require(
        set((home / "plugins").iterdir()) == {binary.parent for binary in binaries},
        "unexpected provider directories",
    )
    return {
        "PULUMI_HOME": str(home.resolve()),
        "PULUMI_IGNORE_AMBIENT_PLUGINS": "true",
        "PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION": "true",
    }


def materialize_home(root: Path, source: Path, target: Path, *, supabase: bool) -> dict[str, str]:
    """Reverify local assets and populate a new invocation home without downloading."""
    verifier = verified_supabase_environment if supabase else verified_environment
    verifier(root, source)
    _require(not target.exists(), "invocation home must be new")
    for name in sorted(NAMES):
        _, _, archive = _paths(root, name, source)
        install_provider(root, name, archive, target)
    if supabase:
        _, _, _, archive = _supabase_paths(root, source)
        install_supabase(root, archive, target)
    return verifier(root, target)


def _supabase_paths(root: Path, home: Path) -> tuple[dict[str, str], Path, Path, Path]:
    # Reuse native platform/home/reparse validation without executing the bridge.
    _paths(root, "terraform-provider", home)
    home = Path(os.path.abspath(home))
    target = "windows-x64" if platform.system() == "Windows" else "linux-x64"
    asset = json.loads((root / "config/provider-toolchain.json").read_text())["downstream"][
        "assets"
    ][target]
    cache = home / "dynamic_tf_plugins"
    directory = (
        cache / "registry.opentofu.org/supabase/supabase/1.11.0" / target.replace("-x64", "_amd64")
    )
    archive = home / ".provider-archives" / f"supabase-1.11.0-{target}.zip"
    _regular_path(directory)
    _regular_path(archive)
    return asset, cache, directory, archive


def _zip_digest(archive: Path, asset: dict[str, str]) -> str:
    _require(
        archive.stat().st_size <= 32 * 1024 * 1024 and _digest(archive) == asset["sha256"],
        "downstream archive checksum/size mismatch; nothing extracted or executed",
    )
    digest = None
    with zipfile.ZipFile(archive) as package:
        members = package.infolist()
        _require(
            len(members) <= 32 and sum(m.file_size for m in members) <= 128 * 1024 * 1024,
            "downstream archive exceeds bounds",
        )
        names: set[str] = set()
        for member in members:
            path = PurePosixPath(member.filename)
            _require(
                not path.is_absolute()
                and ".." not in path.parts
                and member.filename not in names
                and not any(c in member.filename for c in ("\\", ":"))
                and stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG, stat.S_IFDIR),
                "unsafe or duplicate downstream archive member",
            )
            names.add(member.filename)
            if member.filename == asset["binary"]:
                _require(
                    not member.is_dir()
                    and stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG),
                    "downstream executable must be a regular file",
                )
                with package.open(member) as stream:
                    hashed = hashlib.sha256()
                    while chunk := stream.read(1024 * 1024):
                        hashed.update(chunk)
                    digest = hashed.hexdigest()
    _require(digest is not None, "downstream executable missing from archive")
    assert digest is not None
    return digest


def install_supabase(root: Path, archive: Path, home: Path) -> Path:
    asset, _, directory, cached = _supabase_paths(root, home)
    expected = _zip_digest(archive, asset)
    _require(not directory.exists() and not cached.exists(), "use a fresh downstream destination")
    cached.parent.mkdir(parents=True, exist_ok=True)
    with archive.open("rb") as source, cached.open("xb") as destination:
        shutil.copyfileobj(source, destination)
    _require(_digest(cached) == asset["sha256"], "downstream archive changed during capture")
    directory.mkdir(parents=True)
    binary = directory / asset["binary"]
    with (
        zipfile.ZipFile(cached) as package,
        package.open(asset["binary"]) as member_stream,
        binary.open("xb") as destination,
    ):
        shutil.copyfileobj(member_stream, destination)
    _require(_digest(binary) == expected, "downstream executable checksum mismatch")
    binary.chmod(0o755)
    return binary


def verify_supabase(root: Path, home: Path) -> Path:
    try:
        asset, cache, directory, archive = _supabase_paths(root, home)
        expected = _zip_digest(archive, asset)
        current = cache
        for part in (*directory.relative_to(cache).parts, asset["binary"]):
            _regular_path(current)
            _require(
                {p.name for p in current.iterdir()} == {part}, "unexpected downstream cache content"
            )
            current = current / part
        _require(_digest(current) == expected, "downstream executable checksum mismatch")
        _require(
            os.name == "nt" or bool(current.stat().st_mode & 0o111), "downstream is not executable"
        )
        return current
    except (OSError, zipfile.BadZipFile, EOFError):
        raise RuntimeError("PROVIDER001: downstream cache cannot be verified") from None


def verified_supabase_environment(root: Path, home: Path) -> dict[str, str]:
    environment = verified_environment(root, home)
    verify_supabase(root, home)
    try:
        metadata = json.loads(
            (root / "sdks/supabase/pulumi_supabase/pulumi-plugin.json").read_text()
        )
        parameter = metadata["parameterization"]
        _require(
            metadata["name"] == "terraform-provider"
            and metadata["resource"] is True
            and metadata["version"] == "1.5.0"
            and metadata["version"] == load_assets(root)["terraform-provider"]["version"]
            and parameter["name"] == "supabase"
            and parameter["version"] == "1.11.0"
            and json.loads(base64.b64decode(parameter["value"], validate=True))
            == {"remote": {"url": "registry.opentofu.org/supabase/supabase", "version": "1.11.0"}},
            "SDK parameterization differs from verified cache",
        )
    except (OSError, ValueError, KeyError, TypeError):
        raise RuntimeError("PROVIDER001: cannot verify SDK parameterization") from None
    _, cache, _, _ = _supabase_paths(root, home)
    return {
        **environment,
        "PULUMI_DYNAMIC_TF_PLUGIN_CACHE_DIR": str(cache),
        "PULUMI_BRIDGE_REATTACH_PROVIDERS": "",
        "TF_REATTACH_PROVIDERS": "",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--provider", choices=sorted(NAMES | {"supabase"}), required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    if args.provider == "supabase":
        install_supabase(args.root, args.archive, args.home)
    else:
        install_provider(args.root, args.provider, args.archive, args.home)
    print("Verified provider installation")
