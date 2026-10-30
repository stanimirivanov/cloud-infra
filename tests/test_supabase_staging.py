"""Supabase staging is offline, disabled-compatible and aligned with executor ciphertext checks."""

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_services
from infra_core import cli, operations, service_evidence
from infra_core import encrypted_configuration as encrypted
from infra_core import supabase_staging as s

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    config, evidence, profile = test_services.service.__wrapped__(SimpleNamespace(param="supabase"))
    for name in ("config/quotas/profiles.toml", "config/pulumi.toml", "config/service-apply.json"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / name).read_bytes())
    (tmp_path / ".infra").mkdir()
    (tmp_path / ".infra/proposal.json").write_bytes(operations.encoded(config))
    payload = operations.encoded(evidence)
    (tmp_path / ".infra/evidence.json").write_bytes(payload)
    envelope = service_evidence.capture_service_evidence(config, profile, payload, commit=COMMIT)
    (tmp_path / ".infra/evidence.json.envelope.json").write_bytes(envelope)
    secret = dict(
        encryptionsalt="v1:synthetic",
        config={
            "supabase-database:token": {"secure": "v1:PRIVATE-token"},
            "supabase-database:databasePassword-app": {"secure": "v1:PRIVATE-password"},
        },
    )
    (tmp_path / ".infra/stack.json").write_bytes(operations.encoded(secret))
    monkeypatch.setattr(s, "repository_state", lambda root: (COMMIT, True))
    return tmp_path, config, secret, datetime.now(UTC)


def check(bundle, **kwargs):
    root, config, _, now = bundle
    return s.check(
        root,
        Path(".infra/proposal.json"),
        Path(".infra/evidence.json"),
        Path(".infra/stack.json"),
        **(dict(account_id=config["account_id"], scope_id=config["scope_id"], now=now) | kwargs),
    )


def test_disabled_baseline_checks_without_activating_or_leaking(bundle):
    root, _, _, _ = bundle
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = check(bundle)
    assert result["status"] == "pending" and result["staging_evidence"] == "inputs-consistent"
    for key in (
        "preview_enabled",
        "apply_enabled",
        "execution_authorized",
        "activation_authorized",
        "live_controls_verified",
    ):
        assert result[key] is False
    assert "PRIVATE" not in json.dumps(result)
    assert before == {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize(
    "mutation",
    [
        "token-missing",
        "password-missing",
        "extra",
        "wrong-namespace",
        "plaintext",
        "short",
        "salt",
        "duplicate",
        "oversize",
    ],
)
def test_ciphertext_contract_rejections(bundle, mutation):
    root, _, value, _ = bundle
    if mutation == "token-missing":
        del value["config"]["supabase-database:token"]
    elif mutation == "password-missing":
        del value["config"]["supabase-database:databasePassword-app"]
    elif mutation == "extra":
        value["config"]["supabase-database:databasePassword-other"] = {"secure": "v1:PRIVATE"}
    elif mutation == "wrong-namespace":
        value["config"]["cloudflare-edge:token"] = value["config"].pop("supabase-database:token")
    elif mutation == "plaintext":
        value["config"]["supabase-database:token"] = "PRIVATE"
    elif mutation == "short":
        value["config"]["supabase-database:token"] = {"secure": "v1:"}
    elif mutation == "salt":
        value["encryptionsalt"] = "v1:"
    raw = operations.encoded(value)
    if mutation == "duplicate":
        raw = b'{"config":{},"config":{},"encryptionsalt":"v1:x"}'
    elif mutation == "oversize":
        raw = b" " * (1024 * 1024 + 1)
    (root / ".infra/stack.json").write_bytes(raw)
    with pytest.raises(
        ValueError,
        match="^STAGE001: Supabase staging input rejected; private diagnostics withheld$",
    ):
        check(bundle)


@pytest.mark.parametrize(
    "field,value", [("account_id", "other"), ("scope_id", "other"), ("account_id", "")]
)
def test_account_and_organization_must_be_independently_expected(bundle, field, value):
    with pytest.raises(ValueError, match="STAGE001"):
        check(bundle, **{field: value})


@pytest.mark.parametrize(
    "mutation",
    [
        "stale",
        "wrong-provider",
        "tamper",
        "missing-envelope",
        "symlink",
        "dirty",
        "gate-schema",
        "gate-type",
    ],
)
def test_input_and_policy_boundaries(bundle, monkeypatch, mutation):
    root, config, _, now = bundle
    if mutation == "stale":
        with pytest.raises(ValueError, match="STAGE001"):
            check(bundle, now=now + timedelta(minutes=16))
        return
    if mutation == "wrong-provider":
        config["provider"] = "cloudflare"
        (root / ".infra/proposal.json").write_bytes(operations.encoded(config))
    elif mutation == "tamper":
        path = root / ".infra/evidence.json"
        path.write_bytes(path.read_bytes() + b" ")
    elif mutation == "missing-envelope":
        (root / ".infra/evidence.json.envelope.json").unlink()
    elif mutation == "symlink":
        path = root / ".infra/stack.json"
        target = root / ".infra/other.json"
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
    elif mutation == "dirty":
        monkeypatch.setattr(s, "repository_state", lambda root: (COMMIT, False))
    else:
        path = root / "config/service-apply.json"
        policy = json.loads(path.read_bytes())
        if mutation == "gate-schema":
            policy = dict(schema_version=1, enabled=True)
        else:
            policy["units"]["supabase-database"] = 1
        path.write_bytes(operations.encoded(policy))
    with pytest.raises(ValueError, match="STAGE001"):
        check(bundle)


@pytest.mark.parametrize("which", ["foundation", "gate", "ciphertext", "commit"])
def test_changed_inputs_are_not_reported_consistent(bundle, monkeypatch, which):
    root, _, _, _ = bundle
    calls = 0

    def state(root):
        nonlocal calls
        calls += 1
        if calls == 2:
            if which == "commit":
                return "b" * 40, True
            path = (
                root
                / {
                    "foundation": "config/pulumi.toml",
                    "gate": "config/service-apply.json",
                    "ciphertext": ".infra/stack.json",
                }[which]
            )
            path.write_bytes(path.read_bytes() + b" ")
        return COMMIT, True

    monkeypatch.setattr(s, "repository_state", state)
    with pytest.raises(ValueError, match="STAGE001"):
        check(bundle)


def test_cli_reports_pending_nonzero(bundle, monkeypatch, capsys):
    root, config, _, _ = bundle
    monkeypatch.setattr(cli, "find_repository", lambda arg: root)
    assert (
        cli.main(
            [
                "services",
                "check-staging",
                "--account-id",
                config["account_id"],
                "--scope-id",
                config["scope_id"],
                "--config",
                ".infra/proposal.json",
                "--evidence",
                ".infra/evidence.json",
                "--encrypted-configuration",
                ".infra/stack.json",
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["activation_authorized"] is False


def test_core_staging_imports_no_provider_runtime():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import infra_core.supabase_staging; "
            "assert not any(n == 'pulumi' or "
            "n.startswith(('pulumi_', 'infra_program')) for n in sys.modules)",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0


@pytest.mark.parametrize(
    "keys",
    [
        set(),
        {"cloudflare-edge:token"},
        {
            "supabase-database:token",
            "supabase-database:databasePassword-one",
            "supabase-database:databasePassword-two",
        },
    ],
)
def test_shared_validator_covers_empty_oci_and_all_service_secret_sets(keys):
    value = dict(
        encryptionsalt="v1:synthetic", config={k: {"secure": "v1:synthetic"} for k in keys}
    )
    assert encrypted.validate(operations.encoded(value), keys) == value
    if keys:
        value["config"].pop(next(iter(keys)))
        with pytest.raises(ValueError, match="CONFIG001"):
            encrypted.validate(operations.encoded(value), keys)


def test_cloudflare_enablement_does_not_authorize_supabase(bundle):
    root, _, _, _ = bundle
    path = root / "config/service-apply.json"
    gate = json.loads(path.read_bytes())
    gate["units"]["cloudflare-edge"] = True
    path.write_bytes(operations.encoded(gate))
    result = check(bundle)
    assert result["apply_enabled"] is False and result["activation_authorized"] is False


def test_every_proposed_project_requires_its_password(bundle):
    import tomllib
    from copy import deepcopy

    root, proposal, secret, _ = bundle
    second = deepcopy(proposal["resources"][0])
    second["key"] = "second"
    second["props"]["name"] = "second-project"
    proposal["resources"].append(second)
    (root / ".infra/proposal.json").write_bytes(operations.encoded(proposal))
    payload = (root / ".infra/evidence.json").read_bytes()
    profile = tomllib.loads((root / "config/quotas/profiles.toml").read_text())["profiles"][
        "supabase-free"
    ]
    envelope = service_evidence.capture_service_evidence(proposal, profile, payload, commit=COMMIT)
    (root / ".infra/evidence.json.envelope.json").write_bytes(envelope)
    with pytest.raises(ValueError, match="STAGE001"):
        check(bundle)
    secret["config"]["supabase-database:databasePassword-second"] = {"secure": "v1:synthetic"}
    (root / ".infra/stack.json").write_bytes(operations.encoded(secret))
    assert check(bundle)["staging_evidence"] == "inputs-consistent"
