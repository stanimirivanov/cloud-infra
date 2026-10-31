"""Read-only CLI collection publishes a fresh private pair or fails closed."""

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_cloudflare_collection as fixtures
from infra_core import cli
from infra_core import service_collection as collection
from infra_core.service_evidence import read_service_pair, validate_service_evidence

network = fixtures.network
reviewed = fixtures.reviewed
ROOT = Path(__file__).resolve().parents[1]
COMMIT = "c" * 40


@pytest.fixture
def case(tmp_path, monkeypatch, reviewed, network):
    private = tmp_path / ".infra"
    private.mkdir(mode=0o700)
    (tmp_path / "config/quotas").mkdir(parents=True)
    (tmp_path / "config/quotas/profiles.toml").write_bytes(
        (ROOT / "config/quotas/profiles.toml").read_bytes()
    )
    config, profile, review = reviewed
    proposal, review_path, token, output = [
        private / name for name in ("proposal.json", "review.json", "token", "usage.json")
    ]
    proposal.write_text(json.dumps(config))
    review_path.write_text(json.dumps(review))
    token.write_text("synthetic-token\n")
    token.chmod(0o600)
    monkeypatch.setattr(collection, "reviewed_commit", lambda root: COMMIT)
    monkeypatch.setattr(cli, "find_repository", lambda root: tmp_path)
    return SimpleNamespace(
        root=tmp_path,
        proposal=proposal,
        review=review_path,
        token=token,
        output=output,
        sidecar=output.with_name(output.name + ".envelope.json"),
        config=config,
        profile=profile,
        network=network,
    )


def run(case):
    return cli.main(
        [
            "--root",
            str(case.root),
            "services",
            "collect-cloudflare",
            "--config",
            str(case.proposal),
            "--review",
            str(case.review),
            "--token-file",
            str(case.token),
            "--output",
            str(case.output),
        ]
    )


def absent(case):
    assert not case.output.exists() and not case.sidecar.exists()
    assert not list(case.output.parent.glob(".collection-*"))


def test_cli_collects_auditable_pair_with_original_clocks_and_private_modes(case, capsys):
    assert run(case) == 0
    payload, envelope = read_service_pair(case.output)
    result = validate_service_evidence(case.config, case.profile, payload, envelope, commit=COMMIT)
    assert result["deployment_authorized"] is False
    assert json.loads(payload)["verified_at"] == json.loads(case.review.read_bytes())["verified_at"]
    assert json.loads(envelope)["predicate"]["scope"]["commit"] == COMMIT
    for path in (case.output, case.sidecar):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert len(case.network.calls) == 2
    output = str(capsys.readouterr())
    assert "deployment disabled" in output
    assert "synthetic-token" not in output and "private-record-content" not in output
    assert b"private-record-content" not in payload + envelope


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "scope",
        "account",
        "domain",
        "entitlement",
        "stale",
        "revision",
        "extra",
        "duplicate",
        "bad-json",
        "provider",
        "resource",
    ],
)
def test_invalid_independent_inputs_fail_before_network(case, fault, capsys):
    data = json.loads(case.review.read_bytes())
    if fault == "missing":
        case.review.unlink()
    elif fault in {"provider", "resource"}:
        data = json.loads(case.proposal.read_bytes())
        if fault == "provider":
            data["provider"] = "supabase"
        else:
            data["resources"][0]["props"]["zoneId"] = "d" * 32
        case.proposal.write_text(json.dumps(data))
    elif fault == "duplicate":
        case.review.write_text('{"schema_version": 1, "schema_version": 1}')
    elif fault == "bad-json":
        case.review.write_text('{"private": NaN}')
    else:
        if fault in {"scope", "account"}:
            data[fault + "_id"] = "d" * 32
        elif fault == "domain":
            data["scope_name"] = "other.example.org"
        elif fault == "entitlement":
            data["verified"] = False
        elif fault == "stale":
            data["verified_at"] = (datetime.now(UTC) - timedelta(days=31)).isoformat()
        elif fault == "revision":
            data["profile_revision"] = 999
        else:
            data["private-extra"] = "private-substitution"
        case.review.write_text(json.dumps(data))
    assert run(case) == 1
    assert not case.network.calls
    absent(case)
    assert "COLLECT001" in capsys.readouterr().err


@pytest.mark.parametrize(
    "fault", ["world-readable", "empty", "newline", "oversize", "symlink", "hardlink", "fifo"]
)
def test_credential_must_be_an_explicit_private_regular_file(case, fault):
    if fault == "world-readable":
        case.token.chmod(0o644)
    elif fault == "empty":
        case.token.write_bytes(b"")
    elif fault == "newline":
        case.token.write_bytes(b"synthetic\ntoken")
    elif fault == "oversize":
        case.token.write_bytes(b"x" * 5000)
    elif fault in {"symlink", "hardlink"}:
        saved = case.token.with_name("saved")
        case.token.rename(saved)
        if fault == "symlink":
            case.token.symlink_to(saved)
        else:
            os.link(saved, case.token)
    else:
        case.token.unlink()
        os.mkfifo(case.token, 0o600)
    assert run(case) == 1
    assert not case.network.calls
    absent(case)


@pytest.mark.parametrize(
    "fault", ["payload", "sidecar", "outside", "symlink-parent", "symlink-sidecar", "collision"]
)
def test_stale_or_unsafe_destinations_are_preserved_without_network(case, fault):
    preserved = None
    if fault in {"payload", "sidecar"}:
        preserved = case.output if fault == "payload" else case.sidecar
        preserved.write_bytes(b"old-evidence")
    elif fault == "outside":
        case.output = case.root / "tracked.json"
    elif fault == "symlink-parent":
        alias = case.root / ".infra/alias"
        alias.symlink_to(case.root, target_is_directory=True)
        case.output = alias / "usage.json"
    elif fault == "symlink-sidecar":
        case.sidecar.symlink_to(case.root / "nonexistent")
    else:
        case.output = case.proposal
    assert run(case) == 1
    assert not case.network.calls
    if preserved is not None:
        assert preserved.read_bytes() == b"old-evidence"
    assert case.proposal.exists() and case.review.exists() and case.token.exists()


@pytest.mark.parametrize(
    "fault",
    [
        "pagination",
        "observed-scope",
        "private-error",
        "checkout",
        "proposal",
        "review",
        "profile",
        "token",
    ],
)
def test_collection_and_concurrent_input_failures_never_publish(case, monkeypatch, fault, capsys):
    original = collection.collect_zone

    def observe(*args, **kwargs):
        if fault == "private-error":
            raise RuntimeError("synthetic-token private-record-content private-path")
        result = original(*args, **kwargs)
        if fault == "checkout":
            monkeypatch.setattr(collection, "reviewed_commit", lambda root: "d" * 40)
        elif fault in {"proposal", "review", "profile", "token"}:
            target = (
                case.root / "config/quotas/profiles.toml"
                if fault == "profile"
                else getattr(case, fault)
            )
            target.write_bytes(target.read_bytes() + b" ")
        return result

    if fault == "pagination":
        case.network.replies[1]["result_info"]["total_count"] = 4
    elif fault == "observed-scope":
        case.network.replies[0]["result"]["account"]["id"] = "d" * 32
    monkeypatch.setattr(collection, "collect_zone", observe)
    assert run(case) == 1
    absent(case)
    output = str(capsys.readouterr())
    assert "COLLECT001" in output
    assert "synthetic-token" not in output and "private-record-content" not in output


@pytest.mark.parametrize("fault", ["first-link", "second-link", "write", "race"])
def test_partial_pair_publication_cleans_only_owned_outputs(case, monkeypatch, fault):
    link = collection.os.link
    calls = []

    def publish(source, target):
        calls.append(target)
        if fault == "race" and len(calls) == 2:
            target.write_bytes(b"other-writer")
        if fault == "first-link" or fault == "second-link" and len(calls) == 2:
            raise OSError("private-diagnostic")
        link(source, target)

    monkeypatch.setattr(collection.os, "link", publish)
    if fault == "write":
        monkeypatch.setattr(
            collection.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("private"))
        )
    assert run(case) == 1
    assert not case.sidecar.exists()
    if fault == "race":
        assert case.output.read_bytes() == b"other-writer"
    else:
        absent(case)


def test_dirty_checkout_blocks_collection_before_credentials(case, monkeypatch):
    monkeypatch.setattr(
        collection, "reviewed_commit", lambda root: (_ for _ in ()).throw(ValueError("EXT023"))
    )
    assert run(case) == 1
    assert not case.network.calls
    absent(case)
