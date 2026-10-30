"""Independent backup evidence consistency never grants restore/activation authority."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from infra_core import backup, cli, operations
from infra_core import backup_readiness as b
from infra_core.foundation import load_foundation

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
REPOSITORY = "d" * 64
HOST = "f" * 64
NOW = datetime(2026, 10, 30, tzinfo=UTC)


@pytest.fixture(params=["oci-network", "oci-oke", "cloudflare-edge", "supabase-database"])
def bundle(tmp_path, monkeypatch, request):
    unit = request.param
    (tmp_path / "config").mkdir()
    (tmp_path / ".infra").mkdir()
    (tmp_path / "config/pulumi.toml").write_bytes((ROOT / "config/pulumi.toml").read_bytes())
    monkeypatch.setattr(b, "repository_state", lambda root: (COMMIT, True))
    exported = (NOW - timedelta(seconds=30)).isoformat()
    start, end = ((NOW - timedelta(seconds=s)).isoformat() for s in (10, 5))
    docs = {
        "restore_checkpoint": dict(
            version=3,
            deployment=dict(
                secrets_providers=dict(type="passphrase", state=dict(salt="synthetic-salt")),
                resources=[
                    dict(
                        urn=f"urn:pulumi:{unit}::free-infrastructure::pulumi:pulumi:Stack::free-infrastructure-{unit}",
                        type="pulumi:pulumi:Stack",
                        outputs={},
                    )
                ],
            ),
        ),
        "restore_configuration": dict(
            encryptionsalt="synthetic-salt", config={"test:secret": {"secure": "v1:synthetic"}}
        ),
        "restore_policy": dict(
            schema_version=1,
            max_backup_age_seconds=3600,
            restore_objective_seconds=120,
            require_independent_host=True,
        ),
    }
    manifest = dict(
        schema_version=2,
        unit=unit,
        stack="organization/free-infrastructure/" + unit,
        operation_id="12345678-1234-4234-8234-123456789abc",
        commit="b" * 40,
        request_sha256="c" * 64,
        repository_id=REPOSITORY,
        source_host_id="e" * 64,
        source_exported_at=exported,
        capture_started_at=exported,
        captured_at=exported,
        checkpoint_sha256=operations.digest(docs["restore_checkpoint"]),
        configuration_sha256=operations.digest(docs["restore_configuration"]),
    )
    docs["restore_manifest"] = manifest
    docs["restore_receipt"] = dict(
        schema_version=1,
        repository_id=REPOSITORY,
        snapshot_id="1" * 64,
        manifest_sha256=operations.digest(manifest),
        completed_at=exported,
    )
    docs["rehearsal"] = dict(
        schema_version=2,
        kind="off-host",
        recovery_host_id=HOST,
        **{
            k: manifest[k]
            for k in (
                "unit",
                "stack",
                "operation_id",
                "checkpoint_sha256",
                "configuration_sha256",
                "source_host_id",
            )
        },
        policy_sha256=operations.digest(docs["restore_policy"]),
        snapshot_id="1" * 64,
        manifest_sha256=operations.digest(manifest),
        started_at=start,
        completed_at=end,
        backup_age_seconds=22,
        restore_seconds=5,
        objectives_met=True,
        wrong_key_rejected=True,
        correct_key_readback=True,
        execution_authorized=False,
    )
    index = dict(
        schema_version=1,
        unit=unit,
        commit=COMMIT,
        foundation_sha256=load_foundation(tmp_path).digest,
        artifacts={name: ".infra/" + name + ".json" for name in b.ARTIFACTS},
    )
    result = tmp_path, unit, docs, index
    save(result)
    return result


def save(bundle):
    root, _, docs, index = bundle
    for name, document in docs.items():
        (root / (".infra/" + name + ".json")).write_bytes(operations.encoded(document))
    (root / ".infra/index.json").write_bytes(operations.encoded(index))


def check(bundle, **kwargs):
    root, unit, _, _ = bundle
    args = dict(unit=unit, repository_id=REPOSITORY, recovery_host_id=HOST, now=NOW)
    return b.check(root, Path(".infra/index.json"), **(args | kwargs))


def test_valid_history_is_consistent_but_pending_and_read_only(bundle, monkeypatch):
    root, _, _, _ = bundle
    monkeypatch.setattr(backup, "capture", lambda *a, **k: pytest.fail("backup write"))
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = check(bundle)
    assert result["backup_evidence"] == "off-host-evidence-consistent"
    assert result["status"] == "pending"
    assert all(
        result[key] is False
        for key in (
            "backup_ready",
            "execution_authorized",
            "activation_authorized",
            "live_controls_verified",
        )
    )
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == before
    assert REPOSITORY not in json.dumps(result) and HOST not in json.dumps(result)


def test_no_evidence_remains_pending(bundle):
    root, unit, _, _ = bundle
    result = b.check(root, unit=unit, repository_id=REPOSITORY, recovery_host_id=HOST, now=NOW)
    assert result["backup_evidence"] == "pending"


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository_id", "2" * 64),
        ("recovery_host_id", "3" * 64),
        ("repository_id", "PRIVATE"),
        ("unit", "unknown"),
    ],
)
def test_independent_expectations_cannot_be_adopted_from_evidence(bundle, field, value):
    with pytest.raises(ValueError, match="BSAFE001"):
        check(bundle, **{field: value})


@pytest.mark.parametrize(
    "document,field,value",
    [
        ("restore_manifest", "unit", "other"),
        ("restore_manifest", "checkpoint_sha256", "0" * 64),
        ("restore_manifest", "configuration_sha256", "0" * 64),
        ("restore_manifest", "source_host_id", HOST),
        ("restore_manifest", "commit", "invalid"),
        ("restore_receipt", "repository_id", "0" * 64),
        ("restore_receipt", "snapshot_id", "0" * 64),
        ("restore_receipt", "manifest_sha256", "0" * 64),
        ("restore_policy", "require_independent_host", False),
        ("restore_policy", "restore_objective_seconds", 301),
        ("restore_policy", "max_backup_age_seconds", None),
        ("rehearsal", "kind", "same-host"),
        ("rehearsal", "objectives_met", False),
        ("rehearsal", "wrong_key_rejected", False),
        ("rehearsal", "correct_key_readback", False),
        ("rehearsal", "execution_authorized", True),
        ("rehearsal", "policy_sha256", "0" * 64),
        ("rehearsal", "backup_age_seconds", 0),
        ("rehearsal", "restore_seconds", 0),
        ("rehearsal", "restore_seconds", 121),
        ("rehearsal", "completed_at", (NOW + timedelta(seconds=1)).isoformat()),
    ],
)
def test_corrupt_or_unsafe_evidence_rejected(bundle, document, field, value):
    _, _, docs, _ = bundle
    docs[document][field] = value
    # Preserve hashes for manifest/policy mutations so semantic gates are exercised.
    docs["restore_receipt"]["manifest_sha256"] = (
        operations.digest(docs["restore_manifest"])
        if document == "restore_manifest"
        else docs["restore_receipt"]["manifest_sha256"]
    )
    if document == "restore_manifest":
        docs["rehearsal"]["manifest_sha256"] = operations.digest(docs[document])
    if document == "restore_policy":
        docs["rehearsal"]["policy_sha256"] = operations.digest(docs[document])
    save(bundle)
    with pytest.raises(ValueError, match="BSAFE001"):
        check(bundle)


@pytest.mark.parametrize(
    "mutation", ["stale", "salt", "plaintext", "pending", "capture-clock", "wrong-unit"]
)
def test_pair_and_original_clock_semantics(bundle, mutation):
    _, _, docs, _ = bundle
    if mutation == "stale":
        with pytest.raises(ValueError, match="BSAFE001"):
            check(bundle, now=NOW + timedelta(hours=2))
        return
    if mutation == "salt":
        docs["restore_configuration"]["encryptionsalt"] = "other"
    elif mutation == "plaintext":
        docs["restore_configuration"]["config"]["test:secret"] = "PRIVATE"
    elif mutation == "pending":
        docs["restore_checkpoint"]["deployment"]["pending_operations"] = [dict(type="creating")]
    elif mutation == "wrong-unit":
        docs["restore_checkpoint"]["deployment"]["resources"][0]["urn"] = (
            "urn:pulumi:other::free-infrastructure::x"
        )
    else:
        docs["restore_manifest"]["capture_started_at"] = NOW.isoformat()
    save(bundle)
    with pytest.raises(ValueError, match="BSAFE001"):
        check(bundle)


@pytest.mark.parametrize(
    "mutation",
    [
        "escape",
        "symlink",
        "duplicate",
        "index-alias",
        "unknown",
        "commit",
        "foundation",
        "dirty",
        "oversize",
        "json-duplicate",
        "missing",
    ],
)
def test_private_bundle_boundaries(bundle, monkeypatch, mutation):
    root, _, _, index = bundle
    if mutation == "escape":
        index["artifacts"]["rehearsal"] = "../PRIVATE.json"
    elif mutation == "symlink":
        (root / ".infra/link.json").symlink_to(root / ".infra/rehearsal.json")
        index["artifacts"]["rehearsal"] = ".infra/link.json"
    elif mutation == "duplicate":
        index["artifacts"]["rehearsal"] = index["artifacts"]["restore_policy"]
    elif mutation == "index-alias":
        index["artifacts"]["rehearsal"] = ".infra/index.json"
    elif mutation == "unknown":
        index["extra"] = True
    elif mutation == "commit":
        index["commit"] = "b" * 40
    elif mutation == "foundation":
        index["foundation_sha256"] = "0" * 64
    elif mutation == "dirty":
        monkeypatch.setattr(b, "repository_state", lambda root: (COMMIT, False))
    save(bundle)
    if mutation == "oversize":
        (root / ".infra/rehearsal.json").write_bytes(b" " * (1024 * 1024 + 1))
    elif mutation == "json-duplicate":
        (root / ".infra/rehearsal.json").write_text('{"schema_version":2,"schema_version":2}')
    elif mutation == "missing":
        (root / ".infra/rehearsal.json").unlink()
    with pytest.raises(
        ValueError,
        match="^BSAFE001: backup readiness input rejected; private diagnostics withheld$",
    ):
        check(bundle)


def test_change_during_validation_rejected(bundle, monkeypatch):
    root, _, _, _ = bundle
    calls = 0

    def state(root):
        nonlocal calls
        calls += 1
        if calls == 2:
            path = root / ".infra/rehearsal.json"
            path.write_bytes(path.read_bytes() + b" ")
        return COMMIT, True

    monkeypatch.setattr(b, "repository_state", state)
    with pytest.raises(ValueError, match="BSAFE001"):
        check(bundle)


def test_cli_returns_pending_nonzero(bundle, monkeypatch, capsys):
    root, unit, _, _ = bundle
    monkeypatch.setattr(cli, "find_repository", lambda arg: root)
    assert (
        cli.main(
            [
                "backup",
                "check-readiness",
                "--unit",
                unit,
                "--repository-id",
                REPOSITORY,
                "--recovery-host-id",
                HOST,
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["backup_ready"] is False
