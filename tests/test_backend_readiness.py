"""Offline backend evidence checks cannot create stacks or confer acceptance."""

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from infra_core import backend_posture, cli
from infra_core import backend_readiness as b
from infra_core.foundation import load_foundation
from test_backend import receipt
from test_operations_evidence import config as config_fixture
from test_operations_evidence import posture as posture_fixture

config = config_fixture
posture = posture_fixture
ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
ACCOUNT = "synthetic-tenancy"


@pytest.fixture
def bundle(tmp_path, monkeypatch, config, posture):
    (tmp_path / "config").mkdir()
    (tmp_path / "config/pulumi.toml").write_bytes((ROOT / "config/pulumi.toml").read_bytes())
    (tmp_path / ".infra").mkdir()
    monkeypatch.setattr(b, "repository_state", lambda root: (COMMIT, True))
    payload, envelope = backend_posture.capture_posture(
        config, posture, account_id=ACCOUNT, commit=COMMIT
    )
    (tmp_path / ".infra/posture.json").write_bytes(payload)
    (tmp_path / ".infra/posture.json.envelope.json").write_bytes(envelope)
    (tmp_path / ".infra/qualification.json").write_text(json.dumps(receipt(config)))
    now = datetime.now(UTC)
    stacks = dict(
        schema_version=1,
        account_id=ACCOUNT,
        commit=COMMIT,
        configuration_sha256=config.digest,
        backend=config.backend.url(),
        collection_started_at=now.isoformat(),
        collection_completed_at=now.isoformat(),
        stacks=[
            dict(
                unit=u.name,
                stack_identity=u.stack_identity,
                exists=True,
                secrets_provider="passphrase",
                pending_operations=0,
            )
            for u in config.units
        ],
    )
    (tmp_path / ".infra/stacks.json").write_text(json.dumps(stacks))
    index = dict(
        schema_version=1,
        qualification=".infra/qualification.json",
        posture=".infra/posture.json",
        stacks=".infra/stacks.json",
    )
    (tmp_path / ".infra/index.json").write_text(json.dumps(index))
    return tmp_path, index, now


def check(bundle):
    root, _, now = bundle
    return b.check(root, Path(".infra/index.json"), account_id=ACCOUNT, now=now)


def test_consistent_observations_remain_pending_and_read_only(bundle, monkeypatch):
    root, _, _ = bundle
    monkeypatch.setattr(b.backend, "qualify", lambda *a, **kw: pytest.fail("backend operation"))
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = check(bundle)
    assert result["status"] == "pending"
    assert result["evidence"] == dict(
        qualification="observed-controls-consistent",
        posture="observed-controls-consistent",
        stacks="operator-observations-consistent",
    )
    assert not any(
        result[key]
        for key in (
            "backend_ready",
            "activation_authorized",
            "execution_authorized",
            "live_controls_verified",
        )
    )
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == before
    assert ACCOUNT not in json.dumps(result)


@pytest.mark.parametrize("missing", ["all", "qualification", "posture", "stacks"])
def test_missing_evidence_is_pending(bundle, missing):
    root, index, now = bundle
    if missing == "all":
        result = b.check(root, account_id=ACCOUNT, now=now)
        assert set(result["evidence"].values()) == {"pending"}
    else:
        index[missing] = None
        (root / ".infra/index.json").write_text(json.dumps(index))
        assert check(bundle)["evidence"][missing] == "pending"


@pytest.mark.parametrize(
    "mutation",
    [
        "account",
        "commit",
        "digest",
        "backend",
        "stale",
        "future",
        "order",
        "missing",
        "duplicate",
        "wrong-stack",
        "absent",
        "plaintext",
        "pending",
        "bool",
        "extra",
        "schema",
    ],
)
def test_stack_observation_rejections(bundle, mutation):
    root, _, now = bundle
    path = root / ".infra/stacks.json"
    data = json.loads(path.read_bytes())
    if mutation in ("account", "commit", "digest", "backend"):
        field = {"account": "account_id", "digest": "configuration_sha256"}.get(mutation, mutation)
        data[field] = "PRIVATE-wrong"
    elif mutation == "stale":
        data["collection_started_at"] = (now - timedelta(hours=2)).isoformat()
    elif mutation == "future":
        data["collection_completed_at"] = (now + timedelta(seconds=1)).isoformat()
    elif mutation == "order":
        data["collection_completed_at"] = (now - timedelta(seconds=1)).isoformat()
    elif mutation == "missing":
        data["stacks"].pop()
    elif mutation == "duplicate":
        data["stacks"][1] = deepcopy(data["stacks"][0])
    elif mutation == "extra":
        data["stacks"][0]["private"] = "PRIVATE"
    elif mutation == "schema":
        data["schema_version"] = True
    else:
        field, value = {
            "wrong-stack": ("stack_identity", "organization/other/oci-network"),
            "absent": ("exists", False),
            "plaintext": ("secrets_provider", "none"),
            "pending": ("pending_operations", 1),
            "bool": ("pending_operations", False),
        }[mutation]
        data["stacks"][0][field] = value
    path.write_text(json.dumps(data))
    with pytest.raises(
        ValueError,
        match="^BREADY001: backend readiness input rejected; private diagnostics withheld$",
    ):
        check(bundle)


@pytest.mark.parametrize("mutation", ["local", "stale", "future", "digest", "measurements"])
def test_qualification_validator_is_not_bypassed(bundle, mutation):
    root, _, now = bundle
    path = root / ".infra/qualification.json"
    data = json.loads(path.read_bytes())
    if mutation == "local":
        data["kind"] = "local"
    elif mutation in ("stale", "future"):
        data["completed_at"] = (
            now + timedelta(hours=-25 if mutation == "stale" else 1)
        ).isoformat()
    elif mutation == "digest":
        data["configuration_sha256"] = "f" * 64
    else:
        data["recovery"]["restore_seconds"] = 0
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="BREADY001"):
        check(bundle)


@pytest.mark.parametrize(
    "mutation", ["tamper", "unsafe", "wrong-account", "wrong-commit", "stale", "missing-sidecar"]
)
def test_posture_validator_is_not_bypassed(bundle, mutation):
    root, _, now = bundle
    config = load_foundation(root)
    path = root / ".infra/posture.json"
    if mutation == "tamper":
        path.write_bytes(path.read_bytes() + b" ")
    elif mutation == "missing-sidecar":
        (root / ".infra/posture.json.envelope.json").unlink()
    else:
        data = json.loads(path.read_bytes())
        account, commit = ACCOUNT, COMMIT
        if mutation == "unsafe":
            data["versioning"] = "Disabled"
        elif mutation == "wrong-account":
            account = data["account_id"] = "other"
        elif mutation == "wrong-commit":
            commit = "b" * 40
        else:
            # Change both payload and envelope clocks without pretending fresh observation.
            data["collection_started_at"] = (now - timedelta(hours=2)).isoformat()
            data["collection_completed_at"] = data["collection_started_at"]
        # Envelope creation is structural; actual posture semantics remain consumer-owned.
        from infra_core.evidence import create_envelope

        payload = json.dumps(data).encode()
        envelope = create_envelope(
            kind="backend-posture",
            artifacts={"posture": payload},
            scope=backend_posture._scope(config, account, commit),
            producer={"name": "infra-core", "version": "1"},
            now=datetime.fromisoformat(data["collection_completed_at"]),
            max_age=timedelta(hours=1),
            collection_started_at=data["collection_started_at"],
            collection_completed_at=data["collection_completed_at"],
        )
        path.write_bytes(payload)
        (root / ".infra/posture.json.envelope.json").write_bytes(envelope)
    with pytest.raises(ValueError, match="BREADY001"):
        check(bundle)


@pytest.mark.parametrize(
    "mutation",
    [
        "escape",
        "symlink",
        "duplicate-path",
        "sidecar-alias",
        "duplicate-json",
        "oversize",
        "unknown-field",
        "dirty",
    ],
)
def test_private_input_boundaries(bundle, monkeypatch, mutation):
    root, index, _ = bundle
    if mutation == "dirty":
        monkeypatch.setattr(b, "repository_state", lambda root: (COMMIT, False))
    elif mutation == "symlink":
        (root / ".infra/link.json").symlink_to(root / ".infra/stacks.json")
        index["stacks"] = ".infra/link.json"
    elif mutation == "escape":
        index["stacks"] = "../PRIVATE.json"
    elif mutation == "duplicate-path":
        index["stacks"] = index["qualification"]
    elif mutation == "sidecar-alias":
        index["stacks"] = index["posture"] + ".envelope.json"
    elif mutation == "unknown-field":
        index["extra"] = False
    elif mutation == "duplicate-json":
        (root / ".infra/stacks.json").write_text('{"schema_version":1,"schema_version":1}')
    else:
        (root / ".infra/stacks.json").write_bytes(b" " * (1024 * 1024 + 1))
    (root / ".infra/index.json").write_text(json.dumps(index))
    with pytest.raises(ValueError, match="BREADY001"):
        check(bundle)


@pytest.mark.parametrize("mutation", ["commit", "config", "evidence"])
def test_changes_during_validation_fail(bundle, monkeypatch, mutation):
    root, _, _ = bundle
    count = 0

    def state(root):
        nonlocal count
        count += 1
        if count == 2:
            if mutation == "commit":
                return "b" * 40, True
            path = root / ("config/pulumi.toml" if mutation == "config" else ".infra/stacks.json")
            path.write_bytes(path.read_bytes() + b" ")
        return COMMIT, True

    monkeypatch.setattr(b, "repository_state", state)
    with pytest.raises(ValueError, match="BREADY001"):
        check(bundle)


def test_cli_pending_has_nonzero_exit(bundle, monkeypatch, capsys):
    root, _, _ = bundle
    monkeypatch.setattr(cli, "find_repository", lambda arg: root)
    assert cli.main(["backend", "check-readiness", "--account-id", ACCOUNT]) == 1
    assert json.loads(capsys.readouterr().out)["backend_ready"] is False
