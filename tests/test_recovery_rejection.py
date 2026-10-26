"""Wrong-key rejection must be cryptographic evidence, not any failed command."""

import subprocess

import pytest
from infra_core import backend
from test_backend import receipt

STACK = "qualification-" + "a" * 32
SENTINEL = "private-synthetic-readback"


@pytest.fixture
def config():
    from pathlib import Path

    from infra_core.foundation import load_foundation

    return load_foundation(Path(__file__).resolve().parents[1])


@pytest.mark.parametrize("exit_code", [1, 255])
def test_both_reads_require_the_pinned_decryption_error(tmp_path, monkeypatch, capsys, exit_code):
    calls = []
    env = {"PULUMI_CONFIG_PASSPHRASE": "wrong-synthetic-passphrase"}

    def rejected(args, **kwargs):
        calls.append(args)
        assert kwargs["cwd"] == tmp_path and kwargs["env"] == env
        assert kwargs["capture_output"] and kwargs["timeout"] == 120
        assert "--non-interactive" in args and "--stack" in args
        assert args[args.index("--stack") + 1] == STACK
        return subprocess.CompletedProcess(args, exit_code, "", "error: incorrect passphrase")

    monkeypatch.setattr(backend.subprocess, "run", rejected)
    backend.PulumiSession(tmp_path, env).check_decryption_rejected(STACK, SENTINEL)
    assert [args[1:4] for args in calls] == [
        ["config", "get", "sentinel"],
        ["stack", "output", "sentinel"],
    ]
    assert "--show-secrets" in calls[1] and "--json" in calls[1]
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("failed_read", [0, 1])
@pytest.mark.parametrize(
    "code,stdout,stderr",
    [
        (0, SENTINEL, ""),
        (0, "", "incorrect passphrase"),
        (1, "", "network failure: private endpoint"),
        (1, "incorrect passphrase", "missing stack"),
        (255, SENTINEL, "incorrect passphrase"),
        (255, "", "incorrect passphrase: " + SENTINEL),
        (-9, "", "incorrect passphrase"),
        (3221225477, "", "incorrect passphrase"),
    ],
)
def test_success_partial_plaintext_or_unrelated_failure_cannot_pass(
    tmp_path, monkeypatch, capsys, failed_read, code, stdout, stderr
):
    calls = []

    def result(args, **kwargs):
        current = len(calls)
        calls.append(args)
        return (
            subprocess.CompletedProcess(args, code, stdout, stderr)
            if current == failed_read
            else (subprocess.CompletedProcess(args, 255, "", "incorrect passphrase"))
        )

    monkeypatch.setattr(backend.subprocess, "run", result)
    with pytest.raises(backend.QualificationError, match="not established") as error:
        backend.PulumiSession(tmp_path, {}).check_decryption_rejected(STACK, SENTINEL)
    assert len(calls) == failed_read + 1
    output = str(error.value) + str(capsys.readouterr())
    assert SENTINEL not in output and "private endpoint" not in output


@pytest.mark.parametrize(
    "error", [OSError("private path"), subprocess.TimeoutExpired("private", 120)]
)
def test_wrong_key_probe_launch_errors_are_sanitized(tmp_path, monkeypatch, error):
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(backend.subprocess, "run", fail)
    with pytest.raises(backend.QualificationError, match="raw output withheld") as failure:
        backend.PulumiSession(tmp_path, {}).check_decryption_rejected(STACK, SENTINEL)
    assert "private" not in str(failure.value)


def test_probe_rejects_nonsynthetic_identity_before_any_command(tmp_path, monkeypatch):
    monkeypatch.setattr(
        backend.subprocess, "run", lambda *a, **kw: pytest.fail("unexpected process")
    )
    with pytest.raises(backend.QualificationError, match="generated"):
        backend.PulumiSession(tmp_path, {}).check_decryption_rejected("production", SENTINEL)


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": 1},
        {"schema_version": 2},
        {"schema_version": True},
    ],
)
def test_old_receipt_versions_cannot_claim_wrong_passphrase_acceptance(config, change):
    with pytest.raises(backend.QualificationError):
        backend.validate_receipt(config, receipt(config) | change)


def test_receipt_requires_exact_new_check_without_duplicates(config):
    valid = receipt(config)
    backend.validate_receipt(config, valid)
    checks = valid["checks"]
    assert "wrong-passphrase-rejected" in checks
    for changed in (
        [check for check in checks if check != "wrong-passphrase-rejected"],
        checks + ["wrong-passphrase-rejected"],
    ):
        with pytest.raises(backend.QualificationError):
            backend.validate_receipt(config, valid | {"checks": changed})
