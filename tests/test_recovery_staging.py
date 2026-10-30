"""Recovery compatibility checks reuse runtime contracts and never write state."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from infra_core import cli
from infra_core import recovery_staging as s

COMMIT = "a" * 40


@pytest.fixture(params=sorted(s.UNITS))
def bundle(request, tmp_path, monkeypatch):
    unit = request.param
    (tmp_path / ".infra").mkdir()
    prefix = f"urn:pulumi:{unit}::free-infrastructure::"
    provider = "oci" if unit.startswith("oci-") else unit.split("-")[0]
    state = dict(
        version=3,
        deployment=dict(
            secrets_providers=dict(type="passphrase", state=dict(salt="synthetic")),
            resources=[
                dict(
                    urn=prefix + "pulumi:pulumi:Stack::root", type="pulumi:pulumi:Stack", outputs={}
                ),
                dict(
                    urn=prefix + provider + ":fixture:Resource::child",
                    type=provider + ":fixture:Resource",
                    id="PRIVATE",
                    parent=prefix + "pulumi:pulumi:Stack::root",
                    provider="synthetic",
                    protect=True,
                    custom=True,
                    inputs={"value": "before"},
                    outputs={"value": "before"},
                ),
            ],
        ),
    )
    config = dict(encryptionsalt="synthetic", config={"fixture:secret": {"secure": "v1:PRIVATE"}})
    values = [state, config, deepcopy(state), deepcopy(config)]
    paths = [
        Path(f".infra/{name}.json")
        for name in (
            "current_checkpoint",
            "current_configuration",
            "restore_checkpoint",
            "restore_configuration",
        )
    ]
    for path, value in zip(paths, values, strict=True):
        (tmp_path / path).write_text(json.dumps(value))
    monkeypatch.setattr(s, "repository_state", lambda root: (COMMIT, True))
    return tmp_path, unit, paths, values


def check(bundle):
    root, unit, paths, _ = bundle
    return s.check(
        root,
        unit=unit,
        **dict(
            zip(
                (
                    "current_checkpoint",
                    "current_configuration",
                    "restore_checkpoint",
                    "restore_configuration",
                ),
                paths,
                strict=True,
            )
        ),
    )


def test_compatible_pairs_remain_pending_and_private(bundle):
    root, _, _, _ = bundle
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = check(bundle)
    assert result["status"] == "pending" and result["pair_evidence"] == "inputs-compatible"
    assert len(result["input_sha256"]) == 4
    assert not any(
        result[k]
        for k in (
            "activation_authorized",
            "execution_authorized",
            "writer_release_authorized",
            "live_controls_verified",
        )
    )
    assert "PRIVATE" not in json.dumps(result)
    assert before == {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize(
    "fault",
    [
        "salt",
        "plaintext",
        "pending",
        "identity",
        "parent",
        "provider",
        "protect",
        "inputs",
        "outputs",
        "missing",
        "foreign-unit",
        "duplicate",
        "oversize",
        "symlink",
        "alias",
        "dirty",
        "changed",
        "commit-change",
    ],
)
def test_incompatible_or_unsafe_pair_rejected(bundle, monkeypatch, fault):
    root, _, paths, values = bundle
    restored = values[2]["deployment"]
    child = restored["resources"][1]
    if fault == "salt":
        values[3]["encryptionsalt"] = "PRIVATE"
    elif fault == "plaintext":
        values[3]["config"]["fixture:secret"] = "PRIVATE"
    elif fault == "pending":
        restored["pending_operations"] = [{"type": "creating"}]
    elif fault in {"identity", "parent", "provider", "protect"}:
        child["id" if fault == "identity" else fault] = "PRIVATE-changed"
    elif fault in {"inputs", "outputs"}:
        child[fault]["value"] = "PRIVATE"
    elif fault == "missing":
        restored["resources"].pop()
    elif fault == "foreign-unit":
        child["urn"] = "urn:pulumi:other::PRIVATE"
    for path, value in zip(paths, values, strict=True):
        (root / path).write_text(json.dumps(value))
    path = root / paths[2]
    if fault == "duplicate":
        path.write_text('{"version":3,"version":3}')
    elif fault == "oversize":
        path.write_bytes(b" " * (1024 * 1024 + 1))
    elif fault == "symlink":
        path.unlink()
        path.symlink_to(root / paths[0])
    elif fault == "alias":
        paths[2] = paths[0]
    elif fault == "dirty":
        monkeypatch.setattr(s, "repository_state", lambda root: (COMMIT, False))
    elif fault in {"changed", "commit-change"}:
        calls = []

        def state(root):
            calls.append(1)
            if len(calls) == 2:
                if fault == "commit-change":
                    return "b" * 40, True
                path.write_bytes(path.read_bytes() + b" ")
            return COMMIT, True

        monkeypatch.setattr(s, "repository_state", state)
    with pytest.raises(ValueError, match="^" + s.MESSAGE + "$"):
        check(bundle)


def test_network_outputs_cannot_change_and_engine_manifest_can(bundle):
    root, unit, paths, values = bundle
    values[2]["deployment"]["manifest"] = {"time": "historical"}
    (root / paths[2]).write_text(json.dumps(values[2]))
    assert check(bundle)["pair_evidence"] == "inputs-compatible"
    if unit == "oci-network":
        values[2]["deployment"]["resources"][0]["outputs"] = {"PRIVATE": "changed"}
        (root / paths[2]).write_text(json.dumps(values[2]))
        with pytest.raises(ValueError, match="RESTAGE001"):
            check(bundle)


def test_cli_uses_checker_and_redacts_failure(bundle, monkeypatch, capsys):
    root, unit, paths, _ = bundle
    monkeypatch.setattr(cli, "find_repository", lambda _: root)
    args = ["backup", "check-recovery", "--unit", unit]
    for name, path in zip(
        (
            "current-checkpoint",
            "current-configuration",
            "restore-checkpoint",
            "restore-configuration",
        ),
        paths,
        strict=True,
    ):
        args.extend(["--" + name, str(path)])
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["execution_authorized"] is False
    (root / paths[0]).write_text('{"PRIVATE": "PRIVATE"}')
    assert cli.main(args) == 1
    output = capsys.readouterr()
    assert "RESTAGE001" in output.err and "PRIVATE" not in output.err + output.out
