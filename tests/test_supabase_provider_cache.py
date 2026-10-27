"""Verify downstream cache bytes and SDK identity before the bridge can start."""

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest
import test_provider_tools as native
from infra_core import provider_tools as pt

ROOT = Path(__file__).resolve().parents[1]
fixture = native.fixture


@pytest.fixture
def cache(fixture):
    root, home, archives, target = fixture
    for name, source in archives.items():
        pt.install_provider(root, name, source, home)
    metadata = root / "sdks/supabase/pulumi_supabase/pulumi-plugin.json"
    metadata.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "sdks/supabase/pulumi_supabase/pulumi-plugin.json", metadata)
    path = root / "config/provider-toolchain.json"
    pins = json.loads(path.read_text())
    asset = pins["downstream"]["assets"][target]
    archive = root / "downstream.zip"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr(asset["binary"], b"synthetic downstream executable")
        package.writestr("LICENSE", b"synthetic license marker")
    asset["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    path.write_text(json.dumps(pins))
    return root, home, archive, target


def test_cache_layout_and_environment_match_pinned_bridge(cache, monkeypatch):
    root, home, archive, target = cache
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("unexpected execution"))
    binary = pt.install_supabase(root, archive, home)
    assert (
        binary.parent
        == home
        / "dynamic_tf_plugins/registry.opentofu.org/supabase/supabase/1.11.0"
        / target.replace("-x64", "_amd64")
    )
    assert pt.verify_supabase(root, home) == binary
    env = pt.verified_supabase_environment(root, home)
    assert env["PULUMI_DYNAMIC_TF_PLUGIN_CACHE_DIR"] == str(home / "dynamic_tf_plugins")
    assert env["TF_REATTACH_PROVIDERS"] == "" and env["PULUMI_IGNORE_AMBIENT_PLUGINS"] == "true"
    assert ({"PULUMI_BRIDGE_REATTACH_PROVIDERS": "untrusted-debug-server"} | env)[
        "PULUMI_BRIDGE_REATTACH_PROVIDERS"
    ] == ""
    with pytest.raises(RuntimeError, match="fresh"):
        pt.install_supabase(root, archive, home)


@pytest.mark.parametrize(
    "fault", ["missing", "binary", "archive", "extra", "version", "host", "sdk"]
)
def test_missing_tampered_or_ambiguous_cache_blocks_environment(cache, fault):
    root, home, source, _ = cache
    if fault == "missing":
        with pytest.raises(RuntimeError):
            pt.verified_supabase_environment(root, home)
        return
    binary = pt.install_supabase(root, source, home)
    if fault == "binary":
        binary.write_bytes(b"changed")
    elif fault == "archive":
        next((home / ".provider-archives").glob("*.zip")).write_bytes(b"changed")
    elif fault == "extra":
        (binary.parent / "terraform-provider-supabase_other").write_bytes(b"extra")
    elif fault == "version":
        (binary.parent.parent.parent / "99.0.0").mkdir()
    elif fault == "host":
        (home / "dynamic_tf_plugins/registry.terraform.io").mkdir()
    else:
        path = root / "sdks/supabase/pulumi_supabase/pulumi-plugin.json"
        data = json.loads(path.read_text())
        data["parameterization"]["value"] = base64.b64encode(
            b'{"remote":{"url":"other","version":"1.11.0"}}'
        ).decode()
        path.write_text(json.dumps(data))
    with pytest.raises(RuntimeError, match="PROVIDER001"):
        pt.verified_supabase_environment(root, home)


@pytest.mark.parametrize("fault", ["checksum", "traversal", "symlink", "duplicate"])
def test_invalid_zip_never_populates_cache(cache, fault):
    root, home, archive, target = cache
    path = root / "config/provider-toolchain.json"
    pins = json.loads(path.read_text())
    asset = pins["downstream"]["assets"][target]
    if fault == "checksum":
        archive.write_bytes(b"altered")
    else:
        with zipfile.ZipFile(archive, "a") as package:
            entry = zipfile.ZipInfo(
                asset["binary"]
                if fault == "duplicate"
                else "../escape"
                if fault == "traversal"
                else "link"
            )
            if fault == "symlink":
                entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            if fault == "duplicate":
                with pytest.warns(UserWarning, match="Duplicate name"):
                    package.writestr(entry, b"invalid")
            else:
                package.writestr(entry, b"invalid")
        asset["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
        path.write_text(json.dumps(pins))
    with pytest.raises(RuntimeError, match="PROVIDER001"):
        pt.install_supabase(root, archive, home)
    assert not (home / "dynamic_tf_plugins").exists()


def test_downstream_version_matches_generated_sdk():
    pins = json.loads((ROOT / "config/provider-toolchain.json").read_text())["downstream"]
    sdk = json.loads((ROOT / "sdks/supabase/pulumi_supabase/pulumi-plugin.json").read_text())
    assert pins["version"] == sdk["parameterization"]["version"]
    assert json.loads(base64.b64decode(sdk["parameterization"]["value"])) == {
        "remote": {"url": pins["source"], "version": pins["version"]}
    }


@pytest.mark.provider_integration
@pytest.mark.skipif(
    os.environ.get("RUN_PROVIDER_INTEGRATION") != "1", reason="opt-in real release schema RPC"
)
def test_real_bridge_uses_verified_cache_with_proxy_denied(tmp_path):
    home = ROOT / ".infra/provider-home"
    verified = pt.verified_supabase_environment(ROOT, home)
    bridge = pt.verify_provider(ROOT, "terraform-provider", home)
    pulumi = shutil.which("pulumi")
    assert pulumi is not None, "CI requires the pinned Pulumi CLI"
    allowed = {
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
    }
    env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    env.update(
        verified
        | {
            "PULUMI_SKIP_UPDATE_CHECK": "true",
            "GOMAXPROCS": "2",
            "PULUMI_BACKEND_URL": tmp_path.as_uri(),
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "127.0.0.1,localhost,::1",
        }
    )
    result = subprocess.run(
        [
            pulumi,
            "package",
            "get-schema",
            str(bridge),
            "--",
            "registry.opentofu.org/supabase/supabase",
            "1.11.0",
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, "offline schema RPC failed; raw diagnostics withheld"
    schema = json.loads(result.stdout)
    assert schema["name"] == "supabase" and schema["version"] == "1.11.0"
    assert "supabase:index/project:Project" in schema["resources"]
    pt.verify_supabase(ROOT, home)
