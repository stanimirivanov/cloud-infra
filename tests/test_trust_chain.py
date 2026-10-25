"""Exercise real scanner/checksum failures using isolated synthetic repositories."""

import json
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
from infra_core import secret_scanning, verification

ROOT = Path(__file__).resolve().parents[1]


def git(root, *args):
    return subprocess.run(
        [
            "git",
            "-c",
            "user.name=Harness Test",
            "-c",
            "user.email=harness@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=" + str(root / "no-hooks"),
            *args,
        ],
        cwd=root,
        check=True,
        capture_output=True,
        timeout=30,
    )


@pytest.fixture
def repository(tmp_path):
    git(tmp_path, "init")
    (tmp_path / "README.md").write_text("Synthetic repository\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-m", "initial")
    return tmp_path


@pytest.mark.parametrize("location", ["working tree", "staged additions", "history"])
def test_real_scanner_finds_planted_current_staged_and_deleted_secrets(
    repository, location, capsys
):
    # Assemble a synthetic, nonfunctional token; never place a matching literal in source/history.
    token = "gh" + "p_" + "3xK7b9Zq2M5v8Rs1N4d6Yw0CaLfJtUoEiHBg"
    path = repository / "credentials.env"
    path.write_text("ACCESS_TOKEN=" + token + "\n")
    if location != "working tree":
        git(repository, "add", ".")
        if location == "history":
            git(repository, "commit", "-m", "synthetic credential")
            path.unlink()
            git(repository, "add", "-u")
            git(repository, "commit", "-m", "delete credential")
        else:
            path.write_text("ACCESS_TOKEN=unset\n")
    with pytest.raises(RuntimeError, match=location) as error:
        secret_scanning.check_secrets(repository, tool_root=ROOT)
    output = str(error.value) + str(capsys.readouterr())
    assert token not in output


def test_clean_repository_passes(repository):
    secret_scanning.check_secrets(repository, tool_root=ROOT)


def test_shallow_history_fails_closed(repository, tmp_path):
    clone = tmp_path / "shallow"
    git(repository, "clone", "--depth=1", repository.as_uri(), str(clone))
    with pytest.raises(RuntimeError, match="full history required"):
        secret_scanning.check_secrets(clone, tool_root=ROOT)


def test_scanner_binary_tampering_fails_before_execution(tmp_path):
    target = tmp_path / ".infra/tools/gitleaks" / secret_scanning.scanner(ROOT).name
    target.parent.mkdir(parents=True)
    target.write_bytes(b"not an executable")
    (tmp_path / "config").mkdir()
    shutil.copyfile(ROOT / "config/toolchain.json", tmp_path / "config/toolchain.json")
    with pytest.raises(RuntimeError, match="scanner checksum mismatch"):
        secret_scanning.scanner(tmp_path)


def test_missing_scanner_fails_closed(tmp_path):
    (tmp_path / "config").mkdir()
    shutil.copyfile(ROOT / "config/toolchain.json", tmp_path / "config/toolchain.json")
    with pytest.raises(RuntimeError, match="install verified tools"):
        secret_scanning.scanner(tmp_path)


def test_altered_archive_fails_before_extraction(tmp_path):
    archive = tmp_path / "altered.zip"
    archive.write_bytes(b"not the pinned release archive")
    result = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-File",
            str(ROOT / ".github/scripts/install-tools.ps1"),
            "-Tool",
            "gitleaks",
            "-Archive",
            str(archive),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode != 0
    assert "TOOL001" in result.stderr and "nothing extracted or executed" in result.stderr


def test_tool_manifest_matches_locked_versions_and_reviewed_platforms():
    pins = json.loads((ROOT / "config/toolchain.json").read_text())["tools"]
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    foundation = tomllib.loads((ROOT / "config/pulumi.toml").read_text())
    assert pins["uv"]["version"] == project["tool"]["uv"]["required-version"].removeprefix("==")
    assert pins["pulumi"]["version"] == foundation["pulumi_version"]
    for tool in pins.values():
        assert set(tool["assets"]) == {"linux-x64", "windows-x64"}
        for asset in tool["assets"].values():
            assert len(bytes.fromhex(asset["sha256"])) == 32
            assert asset["url"].startswith("https://github.com/") and "latest" not in asset["url"]
            assert (
                not Path(asset["binary"]).is_absolute() and ".." not in Path(asset["binary"]).parts
            )
    assert tomllib.loads((ROOT / ".gitleaks.toml").read_text())["extend"] == {"useDefault": True}


def test_failed_secret_gate_stops_before_fitness_and_tools(monkeypatch):
    monkeypatch.setattr(verification, "check_tracked_artifacts", lambda root: None)

    def fail(root):
        raise RuntimeError("SECRET003: deliberate failure")

    monkeypatch.setattr(verification, "check_secrets", fail)
    monkeypatch.setattr(verification, "check_fitness", lambda root: pytest.fail("ran fitness"))
    with pytest.raises(RuntimeError, match="SECRET003"):
        verification.verify(ROOT)
