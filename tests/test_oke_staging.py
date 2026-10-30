"""OKE staging composes real validators without activation, writes or cluster access."""

import json
import subprocess
import sys
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import test_oci
import test_oci_dependency
from infra_core import cli
from infra_core import oke_staging as s
from infra_core.kubernetes.resources import render

config = test_oci.config
COMMIT = "a" * 40


@pytest.fixture
def bundle(tmp_path, monkeypatch, config, kube_config, kube_inventory):
    (tmp_path / ".infra").mkdir()
    cfg = asdict(config)
    image = cfg.pop("image")
    kube = asdict(kube_config)
    kube = dict(
        cluster={k: kube[k] for k in ("account_id", "cluster_id", "region", "policy_version")},
        reserved=kube["reserved"],
        namespaces=list(kube["namespaces"]),
    )
    kube["cluster"]["policy_version"] = config.kubernetes_version.rsplit(".", 1)[0]
    kube_inventory["policy_version"] = kube["cluster"]["policy_version"]
    outputs = test_oci_dependency.committed(config)
    outputs["network"]["account_id"] = kube_config.account_id
    controls = render(s.parse_kubernetes(kube))
    values = [kube, dict(foundation=cfg, image=image), outputs, kube_inventory, controls]
    paths = [
        Path(f".infra/{name}.json")
        for name in ("config", "oci", "network", "inventory", "resources")
    ]
    for path, value in zip(paths, values, strict=True):
        (tmp_path / path).write_text(json.dumps(value))
    monkeypatch.setattr(s, "repository_state", lambda root: (COMMIT, True))
    return tmp_path, paths, values


def check(bundle, **kwargs):
    root, paths, values = bundle
    return s.check(
        root,
        *paths,
        **(
            dict(
                account_id=values[0]["cluster"]["account_id"],
                cluster_id=values[0]["cluster"]["cluster_id"],
            )
            | kwargs
        ),
    )


def test_report_is_read_only_pending_and_redacted(bundle):
    root, _, _ = bundle
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = check(bundle)
    assert result["status"] == "pending"
    assert result["staging_evidence"] == "inputs-consistent"
    assert len(result["input_sha256"]) == 5
    assert not any(
        result[k]
        for k in ("activation_authorized", "execution_authorized", "live_controls_verified")
    )
    assert "ocid1" not in json.dumps(result)
    assert before == {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize(
    "fault",
    [
        "account",
        "cluster",
        "region",
        "minor",
        "network-account",
        "network-id",
        "network-cidr",
        "network-secret",
        "incomplete",
        "isolation",
        "stale",
        "future",
        "capacity",
        "usage",
        "controls",
        "unsupported",
        "duplicate",
        "oversize",
        "missing",
        "symlink",
        "alias",
        "dirty",
        "commit-change",
        "input-change",
    ],
)
def test_rejects_unsafe_or_changed_inputs(bundle, monkeypatch, fault):
    root, paths, values = bundle
    if fault in {"account", "cluster"}:
        with pytest.raises(ValueError, match="STAGE002"):
            check(bundle, **{fault + "_id": "PRIVATE"})
        return
    if fault == "region":
        values[0]["cluster"]["region"] = "us-ashburn-1"
    elif fault == "minor":
        values[0]["cluster"]["policy_version"] = "v1.99"
    elif fault == "network-account":
        values[2]["network"]["account_id"] = "PRIVATE"
    elif fault == "network-id":
        values[2]["network"]["ids"]["vcn"] = "PRIVATE"
    elif fault == "network-cidr":
        values[2]["network"]["cidrs"]["vcn"] = "10.9.0.0/16"
    elif fault == "network-secret":
        values[2]["network"]["extra"] = "PRIVATE"
    elif fault in {"incomplete", "isolation"}:
        values[3]["complete" if fault == "incomplete" else "network_policy_enforced"] = False
    elif fault in {"stale", "future"}:
        values[3]["observed_at"] = (
            datetime.now(UTC) + timedelta(minutes=-16 if fault == "stale" else 5)
        ).isoformat()
    elif fault == "capacity":
        values[3]["allocatable"]["cpu_m"] = 1
    elif fault == "usage":
        values[3]["namespaces"]["applications"]["pods"] = 99
    elif fault == "controls":
        values[4]["items"].pop()
    elif fault == "unsupported":
        values[4]["items"].append(dict(apiVersion="v1", kind="PersistentVolumeClaim"))
    for path, value in zip(paths, values, strict=True):
        (root / path).write_text(json.dumps(value))
    target = root / paths[0]
    if fault == "duplicate":
        target.write_text('{"cluster":{},"cluster":{}}')
    elif fault == "oversize":
        target.write_bytes(b" " * (1024 * 1024 + 1))
    elif fault == "missing":
        target.unlink()
    elif fault == "symlink":
        target.unlink()
        target.symlink_to(root / paths[1])
    elif fault == "alias":
        paths[1] = paths[0]
    elif fault == "dirty":
        monkeypatch.setattr(s, "repository_state", lambda root: (COMMIT, False))
    elif fault in {"commit-change", "input-change"}:
        calls = []

        def state(root):
            calls.append(1)
            if len(calls) == 2:
                if fault == "commit-change":
                    return "b" * 40, True
                target.write_bytes(target.read_bytes() + b" ")
            return COMMIT, True

        monkeypatch.setattr(s, "repository_state", state)
    with pytest.raises(ValueError, match="^" + s.MESSAGE + "$"):
        check(bundle)


def test_cli_uses_offline_checker(bundle, monkeypatch, capsys):
    root, paths, values = bundle
    monkeypatch.setattr(cli, "find_repository", lambda _: root)
    args = [
        "kubernetes",
        "check-staging",
        "--account-id",
        values[0]["cluster"]["account_id"],
        "--cluster-id",
        values[0]["cluster"]["cluster_id"],
    ]
    for key, path in zip(
        ("config", "oci-config", "network-outputs", "inventory", "resources"), paths, strict=True
    ):
        args.extend(["--" + key, str(path)])
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["activation_authorized"] is False
    args[3] = "PRIVATE"
    assert cli.main(args) != 0
    assert "PRIVATE" not in capsys.readouterr().err


def test_import_does_not_load_provider_or_cluster_clients():
    code = (
        "import sys; import infra_core.oke_staging; "
        "assert not any(n in sys.modules for n in "
        '("pulumi", "oci", "kubernetes", "infra_program"))'
    )
    subprocess.run([sys.executable, "-c", code], check=True, timeout=30)
