"""Offline journal integrity, replay, concurrency and interrupted persistence."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from infra_core import cli
from infra_core import operations as op

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 29, tzinfo=UTC)


@pytest.fixture
def value():
    data = json.loads((ROOT / "config/operations.example.json").read_text())
    data["expires_at"] = (NOW + timedelta(hours=1)).isoformat()
    return data


def append(root, value, state, previous=None, now=NOW):
    return op.journal(
        root, Path(".infra/journal.json"), value, state, predecessor=previous, now=now
    )


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"extra": "private"},
        {"operation_id": []},
        {"operation": "destroy"},
        {"unit": "unknown"},
        {"commit": "bad"},
        {"configuration_sha256": "bad"},
        {"checkpoint_sha256": "bad"},
        {"expected_predecessor": "bad"},
        {"expires_at": "2026-01-01"},
    ],
)
def test_closed_request(value, change):
    with pytest.raises(ValueError, match="OPS001"):
        op.request(value | change)


def test_detached_request_and_read_only_cli(tmp_path, value, capsys):
    copy = op.request(value)
    copy["operation"] = "import"
    assert value["operation"] == "apply"
    path = tmp_path / "request.json"
    path.write_text(json.dumps(value))
    before = path.read_bytes()
    assert cli.main(["operations", "inspect", "--request", str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["execution_authorized"] is False
    assert output["request_sha256"] == op.digest(value)
    assert path.read_bytes() == before
    assert not (tmp_path / ".infra").exists()
    assert op.inspect(path, now=NOW + timedelta(days=1))["expired"] is True


@pytest.mark.parametrize("terminal", ["succeeded", "failed", "indeterminate"])
def test_lifecycle_expired_completion_and_terminal_rejection(tmp_path, value, terminal):
    head = None
    for state in ("prepared", "admitted", "running"):
        head = append(tmp_path, value, state, head)
    head = append(tmp_path, value, terminal, head, NOW + timedelta(days=1))
    with pytest.raises(ValueError):
        append(tmp_path, value, "running", head)
    assert len(op.read_json(tmp_path / ".infra/journal.json")) == 4
    result = op.inspect_journal(tmp_path / ".infra/journal.json")
    assert result["head"] == head and result["state"] == terminal
    assert result["execution_authorized"] is False


def test_replay_predecessor_and_immutable_binding(tmp_path, value):
    head = append(tmp_path, value, "prepared")
    for state, request, predecessor in [
        ("prepared", value, head),
        ("admitted", value, None),
        ("running", value, head),
        ("admitted", value | {"unit": "oci-oke"}, head),
    ]:
        with pytest.raises(ValueError):
            append(tmp_path, request, state, predecessor)
    head = append(tmp_path, value, "failed", head)
    with pytest.raises(ValueError):
        append(tmp_path, value, "prepared", head)
    next_request = value | {
        "operation_id": "22345678-1234-4234-8234-123456789abc",
        "expected_predecessor": head,
    }
    append(tmp_path, next_request, "prepared", head)


def test_expiry_clock_regression_and_tampering(tmp_path, value):
    with pytest.raises(ValueError):
        append(tmp_path, value, "prepared", now=NOW + timedelta(days=1))
    head = append(tmp_path, value, "prepared")
    with pytest.raises(ValueError):
        append(tmp_path, value, "admitted", head, NOW - timedelta(seconds=1))
    path = tmp_path / ".infra/journal.json"
    entries = op.read_json(path)
    entries[0]["previous"] = "0" * 64
    path.write_text(json.dumps(entries))
    with pytest.raises(ValueError):
        append(tmp_path, value, "admitted", head)


def test_interrupted_replace_preserves_previous_snapshot(tmp_path, value, monkeypatch):
    head = append(tmp_path, value, "prepared")
    path = tmp_path / ".infra/journal.json"
    before = path.read_bytes()

    def fail(*args):
        raise OSError("private diagnostic")

    monkeypatch.setattr(op.os, "replace", fail)
    with pytest.raises(RuntimeError, match="OPS002") as error:
        append(tmp_path, value, "admitted", head)
    assert "private diagnostic" not in str(error.value)
    assert path.read_bytes() == before
    assert sorted(p.name for p in path.parent.iterdir()) == ["journal.json", "journal.json.lock"]


def test_concurrent_compare_and_swap_has_one_winner(tmp_path, value):
    head = append(tmp_path, value, "prepared")

    def attempt(_):
        try:
            append(tmp_path, value, "admitted", head)
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, range(2))) == [False, True]


def test_private_paths_and_duplicate_json(tmp_path, value):
    with pytest.raises(ValueError):
        op.journal(tmp_path, Path("outside.json"), value, "prepared", predecessor=None, now=NOW)
    (tmp_path / ".infra").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        append(tmp_path, value, "prepared")
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError):
        op.inspect(path)


@pytest.mark.parametrize("failure_call", [1, 2])
def test_fsync_failure_reports_uncertainty(tmp_path, value, monkeypatch, failure_call):
    head = append(tmp_path, value, "prepared")
    calls = 0
    real = op.os.fsync

    def sync(fd):
        nonlocal calls
        calls += 1
        if calls == failure_call:
            raise OSError("private storage failure")
        real(fd)

    monkeypatch.setattr(op.os, "fsync", sync)
    with pytest.raises(RuntimeError, match="OPS002"):
        append(tmp_path, value, "admitted", head)
    result = op.inspect_journal(tmp_path / ".infra/journal.json")
    assert result["state"] == ("prepared" if failure_call == 1 else "admitted")


def test_bounded_input_and_journal_cli(tmp_path, value, capsys):
    head = append(tmp_path, value, "prepared")
    path = tmp_path / ".infra/journal.json"
    assert cli.main(["operations", "inspect", "--journal", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["head"] == head
    path.write_bytes(b"x" * (op.MAX_BYTES + 1))
    assert cli.main(["operations", "inspect", "--journal", str(path)]) == 1
    assert "OPS001" in capsys.readouterr().err
