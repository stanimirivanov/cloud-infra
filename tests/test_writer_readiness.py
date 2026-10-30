"""Writer evidence is an assertion, never a lock or external writer fence."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from infra_core import cli, operations
from infra_core import writer_readiness as w
from infra_core.foundation import load_foundation
from infra_core.readiness import digest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
NOW = datetime(2026, 10, 30, tzinfo=UTC)


def journal(unit, phases):
    request = dict(
        schema_version=1,
        operation_id="12345678-1234-4234-8234-123456789abc",
        operation="apply",
        unit=unit,
        commit=COMMIT,
        checkpoint_sha256="b" * 64,
        configuration_sha256="c" * 64,
        expires_at=(NOW + timedelta(minutes=10)).isoformat(),
        expected_predecessor=None,
    )
    entries = []
    for phase in phases:
        entries.append(
            dict(
                request=request.copy(),
                state=phase,
                previous=operations.digest(entries[-1]) if entries else None,
                at=(NOW - timedelta(minutes=1)).isoformat(),
            )
        )
    return entries


@pytest.fixture(params=["oci-network", "oci-oke", "cloudflare-edge", "supabase-database"])
def bundle(tmp_path, monkeypatch, request):
    unit = request.param
    units = {"oci-network", "oci-oke"} if unit.startswith("oci-") else {unit}
    (tmp_path / "config").mkdir()
    (tmp_path / "config/pulumi.toml").write_bytes((ROOT / "config/pulumi.toml").read_bytes())
    (tmp_path / ".infra/operations").mkdir(parents=True)
    monkeypatch.setattr(w, "repository_state", lambda root: (COMMIT, True))
    registry = dict(schema_version=1, units={u: ["d" * 64, "e" * 64] for u in units})
    (tmp_path / ".infra/writers.json").write_bytes(operations.encoded(registry))
    observation = dict(
        schema_version=1,
        commit=COMMIT,
        foundation_sha256=load_foundation(tmp_path).digest,
        writers_sha256=operations.digest(registry),
        frozen_at=(NOW - timedelta(seconds=30)).isoformat(),
        observed_at=NOW.isoformat(),
        expires_at=(NOW + timedelta(minutes=5)).isoformat(),
        complete=True,
        other_writers_reviewed=True,
        units={},
    )
    for name in units:
        entries = journal(name, ["prepared", "admitted", "running", "succeeded"])
        raw = operations.encoded(entries)
        (tmp_path / f".infra/operations/{name}.json").write_bytes(raw)
        observation["units"][name] = dict(
            journal_sha256=digest(raw),
            journal_head=operations.digest(entries[-1]),
            writers=[
                dict(identity_sha256=identity, frozen=True, active_operations=0)
                for identity in registry["units"][name]
            ],
        )
    (tmp_path / ".infra/freeze.json").write_bytes(operations.encoded(observation))
    return tmp_path, unit, observation


def check(bundle):
    root, unit, _ = bundle
    return w.check(
        root, Path(".infra/writers.json"), Path(".infra/freeze.json"), unit=unit, now=NOW
    )


def save(bundle):
    root, _, observation = bundle
    (root / ".infra/freeze.json").write_bytes(operations.encoded(observation))


def replace_journal(bundle, entries, unit=None):
    root, selected, observation = bundle
    unit = unit or selected
    raw = operations.encoded(entries)
    (root / f".infra/operations/{unit}.json").write_bytes(raw)
    observation["units"][unit]["journal_sha256"] = digest(raw)
    observation["units"][unit]["journal_head"] = operations.digest(entries[-1]) if entries else None
    save(bundle)


def test_consistency_never_grants_exclusion_or_changes_files(bundle, monkeypatch):
    root, _, _ = bundle
    monkeypatch.setattr(operations, "journal", lambda *a, **kw: pytest.fail("journal write"))
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = check(bundle)
    assert result["writer_evidence"] == "freeze-assertions-consistent"
    assert result["status"] == "pending"
    for key in (
        "writers_excluded",
        "locks_verified",
        "writer_release_authorized",
        "execution_authorized",
        "activation_authorized",
        "live_controls_verified",
    ):
        assert result[key] is False
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize(
    "phases",
    [
        ["prepared"],
        ["prepared", "admitted"],
        ["prepared", "admitted", "running"],
        ["prepared", "admitted", "running", "indeterminate"],
        ["prepared", "admitted", "running", "failed"],
    ],
)
def test_active_or_uncertain_journal_rejected(bundle, phases):
    replace_journal(bundle, journal(bundle[1], phases))
    with pytest.raises(ValueError, match="WREADY001"):
        check(bundle)


@pytest.mark.parametrize("phases", [[], ["prepared", "failed"], ["prepared", "admitted", "failed"]])
def test_empty_or_prelaunch_failed_is_only_an_assertion(bundle, phases):
    replace_journal(bundle, journal(bundle[1], phases))
    assert check(bundle)["writers_excluded"] is False


def test_later_success_does_not_hide_uncertain_history(bundle):
    entries = journal(bundle[1], ["prepared", "admitted", "running", "failed"])
    later = journal(bundle[1], ["prepared", "admitted", "running", "succeeded"])
    head = operations.digest(entries[-1])
    for entry in later:
        entry["request"]["operation_id"] = "22345678-1234-4234-8234-123456789abc"
        entry["request"]["expected_predecessor"] = head
        entry["previous"] = operations.digest(entries[-1])
        entries.append(entry)
    replace_journal(bundle, entries)
    with pytest.raises(ValueError, match="WREADY001"):
        check(bundle)


@pytest.mark.parametrize(
    "mutation",
    [
        "stale",
        "future",
        "expiry",
        "order",
        "commit",
        "foundation",
        "registry",
        "complete",
        "other",
        "hash",
        "head",
        "writer",
        "duplicate",
        "missing",
        "active",
        "boolean",
        "unfrozen",
        "extra",
    ],
)
def test_freeze_observation_rejections(bundle, mutation):
    _, unit, data = bundle
    row = data["units"][unit]
    if mutation == "stale":
        data["frozen_at"] = (NOW - timedelta(minutes=16)).isoformat()
    elif mutation == "future":
        data["observed_at"] = (NOW + timedelta(seconds=1)).isoformat()
    elif mutation == "expiry":
        data["expires_at"] = NOW.isoformat()
    elif mutation == "order":
        data["frozen_at"] = (NOW + timedelta(seconds=1)).isoformat()
    elif mutation in ("commit", "foundation", "registry"):
        data[
            {"commit": "commit", "foundation": "foundation_sha256", "registry": "writers_sha256"}[
                mutation
            ]
        ] = "0" * 64
    elif mutation in ("complete", "other"):
        data["complete" if mutation == "complete" else "other_writers_reviewed"] = False
    elif mutation in ("hash", "head"):
        row["journal_sha256" if mutation == "hash" else "journal_head"] = "0" * 64
    elif mutation == "writer":
        row["writers"][0]["identity_sha256"] = "f" * 64
    elif mutation == "duplicate":
        row["writers"][1] = row["writers"][0].copy()
    elif mutation == "missing":
        row["writers"].pop()
    elif mutation in ("active", "boolean"):
        row["writers"][0]["active_operations"] = 1 if mutation == "active" else False
    elif mutation == "unfrozen":
        row["writers"][0]["frozen"] = False
    else:
        data["extra"] = True
    save(bundle)
    with pytest.raises(ValueError, match="WREADY001"):
        check(bundle)


@pytest.mark.parametrize(
    "mutation",
    [
        "cross-unit",
        "chain",
        "after-freeze",
        "missing-file",
        "symlink",
        "duplicate-json",
        "oversize",
        "dirty",
    ],
)
def test_journal_and_private_boundaries(bundle, monkeypatch, mutation):
    root, unit, _ = bundle
    path = root / f".infra/operations/{unit}.json"
    entries = json.loads(path.read_bytes())
    if mutation == "cross-unit":
        entries = journal("oci-oke" if unit != "oci-oke" else "oci-network", ["prepared", "failed"])
    elif mutation == "chain":
        entries[-1]["previous"] = "0" * 64
    elif mutation == "after-freeze":
        entries[-1]["at"] = NOW.isoformat()
    replace_journal(bundle, entries)
    if mutation == "missing-file":
        path.unlink()
    elif mutation == "symlink":
        other = root / ".infra/copy.json"
        other.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(other)
    elif mutation == "duplicate-json":
        path.write_text('[{"state":"prepared","state":"succeeded"}]')
    elif mutation == "oversize":
        path.write_bytes(b" " * (1024 * 1024 + 1))
    elif mutation == "dirty":
        monkeypatch.setattr(w, "repository_state", lambda root: (COMMIT, False))
    with pytest.raises(
        ValueError,
        match="^WREADY001: writer readiness input rejected; private diagnostics withheld$",
    ):
        check(bundle)


def test_oci_dependency_scope_must_be_complete(bundle):
    _, unit, data = bundle
    if unit.startswith("oci-"):
        del data["units"]["oci-oke" if unit == "oci-network" else "oci-network"]
    else:
        data["units"]["oci-network"] = data["units"][unit]
    save(bundle)
    with pytest.raises(ValueError, match="WREADY001"):
        check(bundle)


def test_changed_journal_during_validation_rejected(bundle, monkeypatch):
    root, unit, _ = bundle
    calls = 0

    def state(root):
        nonlocal calls
        calls += 1
        if calls == 2:
            path = root / f".infra/operations/{unit}.json"
            path.write_bytes(path.read_bytes() + b" ")
        return COMMIT, True

    monkeypatch.setattr(w, "repository_state", state)
    with pytest.raises(ValueError, match="WREADY001"):
        check(bundle)


def test_cli_without_observation_reports_pending(bundle, monkeypatch, capsys):
    root, unit, _ = bundle
    monkeypatch.setattr(cli, "find_repository", lambda arg: root)
    assert (
        cli.main(
            ["operations", "check-readiness", "--unit", unit, "--writers", ".infra/writers.json"]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["writer_evidence"] == "pending"


@pytest.mark.parametrize("mutation", ["empty", "duplicate", "identity", "scope", "schema"])
def test_writer_registry_must_be_explicit_and_unambiguous(bundle, mutation):
    root, unit, _ = bundle
    path = root / ".infra/writers.json"
    registry = json.loads(path.read_bytes())
    if mutation == "empty":
        registry["units"][unit] = []
    elif mutation == "duplicate":
        registry["units"][unit] *= 2
    elif mutation == "identity":
        registry["units"][unit][0] = "PRIVATE"
    elif mutation == "scope":
        registry["units"]["unknown"] = ["f" * 64]
    else:
        registry["schema_version"] = True
    path.write_bytes(operations.encoded(registry))
    with pytest.raises(ValueError, match="WREADY001"):
        w.check(root, Path(".infra/writers.json"), unit=unit, now=NOW)
