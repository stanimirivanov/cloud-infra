"""Provider verification never trusts PATH, receipts or unverified extraction."""

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tomllib
from pathlib import Path

import pytest
from infra_core import provider_tools as pt

ROOT = Path(__file__).resolve().parents[1]


def archive(path, names):
    with tarfile.open(path, "w:gz") as package:
        for name, kind in names:
            content = b"synthetic nonexecutable fixture"
            entry = tarfile.TarInfo(name)
            entry.type, entry.size = kind, len(content) if kind == tarfile.REGTYPE else 0
            package.addfile(entry, io.BytesIO(content) if entry.size else None)


@pytest.fixture(params=["Linux", "Windows"])
def fixture(tmp_path, monkeypatch, request):
    monkeypatch.setattr(pt.platform, "system", lambda: request.param)
    monkeypatch.setattr(pt.platform, "machine", lambda: "x86_64")
    (tmp_path / "config").mkdir()
    pins = json.loads((ROOT / "config/provider-toolchain.json").read_text())
    target = "linux-x64" if request.param == "Linux" else "windows-x64"
    archives = {}
    for name, provider in pins["providers"].items():
        asset = provider["assets"][target]
        path = tmp_path / (name + ".tar.gz")
        archive(path, [(asset["binary"], tarfile.REGTYPE), ("LICENSE", tarfile.REGTYPE)])
        asset["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        archives[name] = path
    (tmp_path / "config/provider-toolchain.json").write_text(json.dumps(pins))
    return tmp_path, tmp_path / ".infra/home", archives, target


def test_install_and_verify_without_executing_any_provider(fixture, monkeypatch):
    root, home, archives, _ = fixture
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("unexpected execution"))
    for name, source in archives.items():
        installed = pt.install_provider(root, name, source, home)
        assert pt.verify_provider(root, name, home) == installed
        assert list(installed.parent.iterdir()) == [installed]
    assert pt.verified_environment(root, home) == {
        "PULUMI_HOME": str(home.resolve()),
        "PULUMI_IGNORE_AMBIENT_PLUGINS": "true",
        "PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION": "true",
    }
    with pytest.raises(RuntimeError, match="fresh"):
        pt.install_provider(root, "oci", archives["oci"], home)


@pytest.mark.parametrize("fault", ["binary", "archive", "extra", "directory"])
def test_tampering_and_extra_files_fail_closed(fixture, fault):
    root, home, archives, _ = fixture
    for name, source in archives.items():
        binary = pt.install_provider(root, name, source, home)
    if fault == "binary":
        binary.write_bytes(b"tampered")
    elif fault == "archive":
        next((home / ".provider-archives").iterdir()).write_bytes(b"tampered")
    elif fault == "extra":
        (binary.parent / "extra").write_bytes(b"extra")
    else:
        (home / "plugins/resource-oci-v99.0.0").mkdir()
    with pytest.raises(RuntimeError, match="PROVIDER001"):
        pt.verified_environment(root, home)


@pytest.mark.parametrize("member", ["../escape", "/absolute", "link", "duplicate"])
def test_unsafe_verified_archive_is_rejected_before_any_extraction(fixture, member):
    root, home, archives, target = fixture
    pins = json.loads((root / "config/provider-toolchain.json").read_text())
    asset = pins["providers"]["oci"]["assets"][target]
    name = asset["binary"] if member == "duplicate" else member
    kind = tarfile.SYMTYPE if member == "link" else tarfile.REGTYPE
    archive(archives["oci"], [(asset["binary"], tarfile.REGTYPE), (name, kind)])
    asset["sha256"] = hashlib.sha256(archives["oci"].read_bytes()).hexdigest()
    (root / "config/provider-toolchain.json").write_text(json.dumps(pins))
    with pytest.raises(RuntimeError, match="PROVIDER001"):
        pt.install_provider(root, "oci", archives["oci"], home)
    assert not home.exists()


def test_altered_archive_and_outside_home_are_rejected(fixture):
    root, home, archives, _ = fixture
    archives["oci"].write_bytes(b"not the pinned archive")
    with pytest.raises(RuntimeError, match="nothing extracted or executed"):
        pt.install_provider(root, "oci", archives["oci"], home)
    with pytest.raises(RuntimeError, match="isolated"):
        pt.install_provider(root, "oci", archives["oci"], root / ".infra/../outside")
    assert not home.exists()


def test_linked_home_is_rejected(fixture):
    root, home, archives, _ = fixture
    (root / ".infra").mkdir()
    try:
        home.symlink_to(root / "config", target_is_directory=True)
    except OSError:
        pytest.skip("OS account cannot create test symlinks")
    with pytest.raises(RuntimeError, match="links"):
        pt.install_provider(root, "oci", archives["oci"], home)


def test_manifest_versions_match_locked_sdks_and_bridge():
    providers = pt.load_assets(ROOT)
    versions = {
        p["name"]: p["version"] for p in tomllib.loads((ROOT / "uv.lock").read_text())["package"]
    }
    for name in ("oci", "cloudflare"):
        assert providers[name]["version"] == versions["pulumi-" + name]
    bridge = json.loads((ROOT / "sdks/supabase/pulumi_supabase/pulumi-plugin.json").read_text())
    assert providers["terraform-provider"]["version"] == bridge["version"]


@pytest.mark.parametrize(
    "field,value",
    [("url", "https://example.invalid/latest"), ("binary", "../escape"), ("sha256", "unknown")],
)
def test_unreviewed_manifest_fields_fail_closed(fixture, field, value):
    root, _, _, target = fixture
    path = root / "config/provider-toolchain.json"
    pins = json.loads(path.read_text())
    pins["providers"]["oci"]["assets"][target][field] = value
    path.write_text(json.dumps(pins))
    with pytest.raises(RuntimeError, match="PROVIDER001"):
        pt.load_assets(root)


def test_junction_and_missing_files_fail_closed(fixture, monkeypatch):
    root, home, archives, _ = fixture
    with pytest.raises(RuntimeError, match="PROVIDER001"):
        pt.verify_provider(root, "oci", home)
    monkeypatch.setattr(Path, "is_junction", lambda path: path == home)
    with pytest.raises(RuntimeError, match="reparse"):
        pt.install_provider(root, "oci", archives["oci"], home)


def test_powershell_rejects_altered_archive_before_python_or_extraction(tmp_path):
    root = tmp_path / "repository"
    installer = root / ".github/scripts/install-providers.ps1"
    installer.parent.mkdir(parents=True)
    (root / "config").mkdir()
    (root / ".infra").mkdir()
    shutil.copyfile(ROOT / ".github/scripts/install-providers.ps1", installer)
    shutil.copyfile(
        ROOT / "config/provider-toolchain.json", root / "config/provider-toolchain.json"
    )
    launcher = tmp_path / "hidden-directory.ps1"
    launcher.write_text(
        "param([string]$Repository, [string]$Installer, [string]$Archive)\n"
        "$ErrorActionPreference = 'Stop'\n"
        "$directory = Join-Path $Repository '.infra'\n"
        "if ($IsWindows) {\n"
        "  [IO.File]::SetAttributes($directory, "
        "([IO.File]::GetAttributes($directory) -bor [IO.FileAttributes]::Hidden))\n"
        "}\n"
        "& $Installer -Provider oci -Archive $Archive\n"
        "exit $LASTEXITCODE\n",
        encoding="utf-8",
    )
    source = tmp_path / "bad.tar.gz"
    source.write_bytes(b"not a release")
    result = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-File",
            str(launcher),
            "-Repository",
            str(root),
            "-Installer",
            str(installer),
            "-Archive",
            str(source),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1
    assert result.stderr.splitlines() == [
        "PROVIDER001: archive checksum mismatch; nothing extracted or executed"
    ]
    assert not (root / ".infra/provider-home").exists()


@pytest.mark.provider_integration
@pytest.mark.skipif(
    os.environ.get("RUN_PROVIDER_INTEGRATION") != "1", reason="opt-in real release assets"
)
def test_real_release_executables_match_pinned_archives():
    assert pt.verified_environment(ROOT, ROOT / ".infra/provider-home")["PULUMI_HOME"]
