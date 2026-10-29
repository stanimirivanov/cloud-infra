"""Checkpoint-bound ownership preparation is read-only and never authorizes a writer."""

import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_oci
from infra_core import cli, operations, ownership
from infra_core.foundation import load_foundation
from infra_core.oci.graph import network_graph, oke_graph

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
config = test_oci.config
TYPES = {
    "Vcn": "oci_core_vcn",
    "InternetGateway": "oci_core_internet_gateway",
    "ServiceGateway": "oci_core_service_gateway",
    "RouteTable": "oci_core_route_table",
    "SecurityList": "oci_core_security_list",
    "Subnet": "oci_core_subnet",
    "NetworkSecurityGroup": "oci_core_network_security_group",
    "NetworkSecurityGroupSecurityRule": "oci_core_network_security_group_security_rule",
    "Cluster": "oci_containerengine_cluster",
    "NodePool": "oci_containerengine_node_pool",
}


@pytest.fixture(params=["oci-network", "oci-oke"])
def case(request, config, tmp_path, monkeypatch):
    now = datetime.now(UTC)
    (tmp_path / "pyproject.toml").write_bytes((ROOT / "pyproject.toml").read_bytes())
    (tmp_path / "config").mkdir()
    (tmp_path / "config/pulumi.toml").write_bytes((ROOT / "config/pulumi.toml").read_bytes())
    private = tmp_path / ".infra"
    private.mkdir()
    unit = request.param
    graph = network_graph(config) if unit == "oci-network" else oke_graph(config)
    root_urn = (
        f"urn:pulumi:{unit}::free-infrastructure::pulumi:pulumi:Stack::free-infrastructure-{unit}"
    )
    target = dict(
        version=3, deployment=dict(resources=[dict(urn=root_urn, type="pulumi:pulumi:Stack")])
    )
    source = dict(version=4, lineage="12345678-1234-4234-8234-123456789abc", serial=7, resources=[])
    entries = []
    for index, spec in enumerate(graph):
        resource_type = TYPES[spec.kind.split(":")[-1]]
        resource_id = "synthetic-id-" + spec.key
        source["resources"].append(
            dict(
                mode="managed",
                type=resource_type,
                name="r" + str(index),
                instances=[
                    dict(
                        attributes=dict(id=resource_id, private_value="PRIVATE_CHECKPOINT_SENTINEL")
                    )
                ],
            )
        )
        entries.append(
            dict(
                logical_key=spec.key,
                id=resource_id,
                unit=unit,
                pulumi_name=config.name + "-" + spec.key,
                pulumi_parent=config.name + ("-network" if unit == "oci-network" else "-oke"),
                provider_region=config.region,
                owner="terraform",
                terraform_address=resource_type + ".r" + str(index),
                operation="import",
            )
        )
    cfg = asdict(config)
    image = cfg.pop("image")
    raw = {
        "source_checkpoint": operations.encoded(source),
        "target_checkpoint": operations.encoded(target),
        "configuration": operations.encoded(dict(foundation=cfg, image=image)),
        "encrypted_configuration": b'{"encryptionsalt":"v1:fixture","config":{}}',
    }
    value = json.loads((ROOT / "config/operations.example.json").read_bytes())
    value.update(
        operation="import",
        unit=unit,
        commit=COMMIT,
        configuration_sha256=hashlib.sha256(raw["encrypted_configuration"]).hexdigest(),
        checkpoint_sha256=hashlib.sha256(raw["target_checkpoint"]).hexdigest(),
        expires_at=(now + timedelta(minutes=10)).isoformat(),
    )
    raw["request"] = operations.encoded(value)
    journal = private / "operations" / (unit + ".json")
    head = operations.journal(
        tmp_path, journal, value, "prepared", predecessor=None, now=now - timedelta(seconds=5)
    )
    raw["journal"] = journal.read_bytes()
    doc = dict(
        schema_version=1,
        source=dict(
            engine="terraform",
            backend_sha256="b" * 64,
            workspace="default",
            lineage=source["lineage"],
            serial=7,
        ),
        target_stack="organization/free-infrastructure/" + unit,
        entries=entries,
        artifacts={},
    )
    freeze = dict(
        schema_version=1,
        phase="writers-frozen",
        binding_sha256="",
        complete=True,
        other_writers_reviewed=True,
        active_operations=0,
        frozen_at=(now - timedelta(seconds=4)).isoformat(),
        checkpointed_at=(now - timedelta(seconds=3)).isoformat(),
        observed_at=(now - timedelta(seconds=2)).isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
        reviewed_by="offline-reviewer",
        writers=[
            dict(
                engine="terraform",
                identity_sha256=operations.digest(doc["source"]),
                frozen=True,
                active_operations=0,
            ),
            dict(
                engine="pulumi",
                identity_sha256=operations.digest(doc["target_stack"]),
                frozen=True,
                active_operations=0,
            ),
        ],
    )
    paths = {n: private / (n + ".json") for n in ownership.ARTIFACTS}
    paths["journal"] = journal

    def write(name, value):
        content = value if isinstance(value, bytes) else operations.encoded(value)
        raw[name] = content
        paths[name].write_bytes(content)
        doc["artifacts"][name] = dict(
            path=str(paths[name].relative_to(tmp_path)), sha256=hashlib.sha256(content).hexdigest()
        )

    def bind():
        freeze["binding_sha256"] = ownership.preparation_binding(
            doc,
            json.loads(raw["request"]),
            raw,
            foundation_sha256=load_foundation(tmp_path).digest,
            journal_head=operations.digest(json.loads(raw["journal"])[-1]),
        )
        write("freeze", freeze)

    for name, content in list(raw.items()):
        write(name, content)
    bind()
    monkeypatch.setattr(ownership, "repository_state", lambda root: (COMMIT, True))
    return SimpleNamespace(
        root=tmp_path,
        doc=doc,
        raw=raw,
        paths=paths,
        write=write,
        bind=bind,
        freeze=freeze,
        now=now,
        unit=unit,
        graph=graph,
        config=config,
        head=head,
    )


def test_complete_mapping_is_checkpointed_without_authority_or_writes(case):
    before = {p: p.read_bytes() for p in case.paths.values()}
    result = ownership.prepare(case.root, case.doc, now=case.now)
    assert result["phase"] == "checkpointed" and result["next_transition"] == "import-review"
    assert result["imports"] == len(case.graph) and result["unchanged"] == 0
    assert result["journal_head"] == case.head
    assert all(
        result[n] is False
        for n in (
            "execution_authorized",
            "ownership_transfer_authorized",
            "writer_release_authorized",
        )
    )
    assert before == {p: p.read_bytes() for p in before}
    assert "PRIVATE_CHECKPOINT_SENTINEL" not in json.dumps(result)
    assert case.doc["entries"][0]["id"] not in json.dumps(result)
    assert case.doc["entries"][0]["owner"] == "terraform"


@pytest.mark.parametrize(
    "fault",
    [
        "duplicate-id",
        "duplicate-key",
        "duplicate-address",
        "mixed-stack",
        "unknown-resource",
        "wrong-parent",
        "wrong-region",
        "wrong-name",
        "unknown-owner",
        "missing-resource",
        "wrong-source-id",
        "wrong-source-type",
        "deposed",
        "source-lineage",
        "source-serial",
        "source-version",
        "target-unit",
        "pending",
        "active-journal",
        "stale-freeze",
        "active-writer",
        "unknown-writer",
        "missing-writer",
        "unfrozen",
        "incomplete",
        "unreviewed-writers",
        "phase",
        "clock-order",
        "future",
        "expired",
        "checkpoint-hash",
        "config-hash",
        "dirty-checkout",
        "wrong-commit",
    ],
)
def test_inconsistent_or_out_of_order_preparation_is_rejected(case, monkeypatch, fault):
    entry = case.doc["entries"][0]
    if fault == "duplicate-id":
        case.doc["entries"][1]["id"] = entry["id"]
    elif fault == "duplicate-key":
        case.doc["entries"][1]["logical_key"] = entry["logical_key"]
    elif fault == "duplicate-address":
        case.doc["entries"][1]["terraform_address"] = entry["terraform_address"]
    elif fault in {
        "mixed-stack",
        "wrong-parent",
        "wrong-region",
        "wrong-name",
        "unknown-owner",
        "unknown-resource",
    }:
        field = {
            "mixed-stack": "unit",
            "wrong-parent": "pulumi_parent",
            "wrong-region": "provider_region",
            "wrong-name": "pulumi_name",
            "unknown-owner": "owner",
            "unknown-resource": "logical_key",
        }[fault]
        entry[field] = "unknown"
    elif fault == "missing-resource":
        case.doc["entries"].pop()
    elif fault.startswith("source-") or fault in {
        "wrong-source-id",
        "wrong-source-type",
        "deposed",
    }:
        value = json.loads(case.raw["source_checkpoint"])
        if fault == "wrong-source-id":
            value["resources"][0]["instances"][0]["attributes"]["id"] = "other"
        elif fault == "wrong-source-type":
            value["resources"][0]["type"] = "wrong"
        elif fault == "deposed":
            value["resources"][0]["instances"][0]["deposed"] = "old"
        else:
            field = fault.split("-")[1]
            value[field] = 9 if field in {"serial", "version"} else "other"
        case.write("source_checkpoint", value)
    elif fault in {"target-unit", "pending"}:
        value = json.loads(case.raw["target_checkpoint"])
        if fault == "target-unit":
            value["deployment"]["resources"][0]["urn"] = "urn:other"
        else:
            value["deployment"]["pending_operations"] = [{"type": "creating"}]
        case.write("target_checkpoint", value)
    elif fault == "active-journal":
        value = json.loads(case.raw["request"])
        operations.journal(
            case.root, case.paths["journal"], value, "admitted", predecessor=case.head, now=case.now
        )
        case.write("journal", case.paths["journal"].read_bytes())
    elif fault in {"active-writer", "unknown-writer", "missing-writer", "unfrozen"}:
        if fault == "missing-writer":
            case.freeze["writers"].pop()
        else:
            writer = case.freeze["writers"][0]
            writer[
                {
                    "active-writer": "active_operations",
                    "unknown-writer": "engine",
                    "unfrozen": "frozen",
                }[fault]
            ] = {"active-writer": 1, "unknown-writer": "unknown", "unfrozen": False}[fault]
    elif fault in {"incomplete", "unreviewed-writers"}:
        case.freeze["complete" if fault == "incomplete" else "other_writers_reviewed"] = False
    elif fault == "phase":
        case.freeze["phase"] = "source-released"
    elif fault in {"stale-freeze", "clock-order", "future", "expired"}:
        field = {
            "stale-freeze": "frozen_at",
            "clock-order": "checkpointed_at",
            "future": "observed_at",
            "expired": "expires_at",
        }[fault]
        case.freeze[field] = (
            case.now + timedelta(minutes=1) if fault == "future" else case.now - timedelta(hours=1)
        ).isoformat()
    elif fault in {"checkpoint-hash", "config-hash"}:
        key = "target_checkpoint" if fault == "checkpoint-hash" else "encrypted_configuration"
        case.write(key, case.raw[key] + b" ")
    else:
        monkeypatch.setattr(
            ownership,
            "repository_state",
            lambda root: (
                COMMIT if fault == "dirty-checkout" else "c" * 40,
                fault != "dirty-checkout",
            ),
        )
    case.bind()
    with pytest.raises(ValueError, match="OWN001"):
        ownership.prepare(case.root, case.doc, now=case.now)


def test_matching_pulumi_owner_requires_no_source_owner(case):
    target = json.loads(case.raw["target_checkpoint"])
    source = json.loads(case.raw["source_checkpoint"])
    prefix = f"urn:pulumi:{case.unit}::free-infrastructure::"
    component = "infrastructure:oci:" + ("Network" if case.unit == "oci-network" else "Oke")
    for entry, spec in zip(case.doc["entries"], case.graph, strict=True):
        entry.update(owner="pulumi", terraform_address=None, operation="same")
        target["deployment"]["resources"].append(
            dict(
                urn=prefix + component + "$" + spec.kind + "::" + entry["pulumi_name"],
                type=spec.kind,
                id=entry["id"],
                parent=prefix + component + "::" + entry["pulumi_parent"],
                provider=prefix + "pulumi:providers:oci::fixture-provider::provider-id",
                protect=True,
            )
        )
    target["deployment"]["resources"].extend(
        [
            dict(
                urn=prefix + component + "::" + case.doc["entries"][0]["pulumi_parent"],
                type=component,
                protect=True,
            ),
            dict(
                urn=prefix + "pulumi:providers:oci::fixture-provider",
                type="pulumi:providers:oci",
                id="provider-id",
                protect=True,
                inputs={"region": case.config.region},
            ),
        ]
    )
    case.write("target_checkpoint", target)
    request = json.loads(case.raw["request"])
    request["checkpoint_sha256"] = hashlib.sha256(case.raw["target_checkpoint"]).hexdigest()
    case.write("request", request)
    entries = json.loads(case.raw["journal"])
    entries[0]["request"] = request
    case.write("journal", entries)
    case.bind()
    with pytest.raises(ValueError):
        ownership.prepare(case.root, case.doc, now=case.now)
    source["resources"] = []
    case.write("source_checkpoint", source)
    case.bind()
    result = ownership.prepare(case.root, case.doc, now=case.now)
    assert result["imports"] == 0 and result["next_transition"] == "post-import-equivalence-review"


def test_cli_is_read_only_and_redacts_sensitive_inputs(case, capsys):
    path = case.root / ".infra/ownership.json"
    path.write_bytes(operations.encoded(case.doc))
    before = {p: p.read_bytes() for p in case.root.rglob("*") if p.is_file()}
    assert (
        cli.main(["--root", str(case.root), "ownership", "prepare", "--evidence", str(path)]) == 0
    )
    output = capsys.readouterr().out
    assert json.loads(output)["execution_authorized"] is False
    assert "PRIVATE_CHECKPOINT_SENTINEL" not in output and "synthetic-id" not in output
    assert before == {p: p.read_bytes() for p in before}


@pytest.mark.parametrize(
    "fault",
    [
        "symlink",
        "outside",
        "aliased",
        "tamper",
        "duplicate-json",
        "oversized",
        "extra",
        "boolean-schema",
    ],
)
def test_private_bounded_immutable_inputs(case, fault, monkeypatch, tmp_path):
    if fault == "symlink":
        path = case.paths["source_checkpoint"]
        saved = path.with_suffix(".original")
        path.rename(saved)
        path.symlink_to(saved)
    elif fault == "outside":
        path = case.root / "outside.json"
        path.write_bytes(case.raw["source_checkpoint"])
        case.doc["artifacts"]["source_checkpoint"]["path"] = str(path)
    elif fault == "aliased":
        case.doc["artifacts"]["source_checkpoint"] = case.doc["artifacts"]["target_checkpoint"]
    elif fault == "tamper":
        original = ownership._mapping

        def mutate(*args):
            result = original(*args)
            case.paths["source_checkpoint"].write_bytes(b"changed")
            return result

        monkeypatch.setattr(ownership, "_mapping", mutate)
    elif fault == "duplicate-json":
        case.write("source_checkpoint", b'{"version":4,"version":4}')
    elif fault == "oversized":
        case.write("source_checkpoint", b" " * (operations.MAX_BYTES + 1))
    elif fault == "extra":
        case.doc["transfer_authorized"] = True
    else:
        case.doc["schema_version"] = True
    with pytest.raises(ValueError, match="OWN001") as error:
        ownership.prepare(case.root, case.doc, now=case.now)
    assert "PRIVATE_CHECKPOINT_SENTINEL" not in str(error.value)


def test_cli_error_is_redacted_and_does_not_write_receipt(case, capsys):
    path = case.root / ".infra/bad-index.json"
    path.write_text('{"PRIVATE_CHECKPOINT_SENTINEL":true}')
    assert (
        cli.main(["--root", str(case.root), "ownership", "prepare", "--evidence", str(path)]) == 1
    )
    output = capsys.readouterr()
    assert "OWN001" in output.err and "PRIVATE_CHECKPOINT_SENTINEL" not in output.err
    assert not output.out


def test_index_is_rechecked_after_preparation(case, monkeypatch):
    path = case.root / ".infra/ownership.json"
    path.write_bytes(operations.encoded(case.doc))
    original = ownership.prepare

    def mutate(*args):
        result = original(*args)
        path.write_bytes(b"changed")
        return result

    monkeypatch.setattr(ownership, "prepare", mutate)
    with pytest.raises(ValueError, match="OWN001"):
        ownership.inspect(case.root, path)


@pytest.mark.parametrize("index_key", [0, "blue.pool"])
def test_source_module_and_index_addresses_are_exact(case, index_key):
    source = json.loads(case.raw["source_checkpoint"])
    source["resources"][0]["module"] = "module.network[0]"
    source["resources"][0]["instances"][0]["index_key"] = index_key
    case.doc["entries"][0]["terraform_address"] = (
        "module.network[0]."
        + case.doc["entries"][0]["terraform_address"]
        + "["
        + json.dumps(index_key)
        + "]"
    )
    case.write("source_checkpoint", source)
    case.bind()
    assert ownership.prepare(case.root, case.doc, now=case.now)["imports"] == len(case.graph)


def test_source_ready_status_and_unselected_data_do_not_create_ownership(case):
    source = json.loads(case.raw["source_checkpoint"])
    source["resources"][0]["instances"][0]["status"] = ""
    source["resources"].append(
        dict(
            mode="data",
            type="oci_identity_regions",
            name="regions",
            instances=[dict(attributes={})],
        )
    )
    case.write("source_checkpoint", source)
    case.bind()
    assert ownership.prepare(case.root, case.doc, now=case.now)["imports"] == len(case.graph)


@pytest.mark.parametrize(
    "fault",
    [
        "unknown-type",
        "provider-region",
        "tainted",
        "duplicate-source-id",
        "boolean-active-count",
        "duplicate-writers",
        "wrong-binding",
    ],
)
def test_ambiguous_scope_and_attestation_metadata_are_rejected(case, fault):
    if fault in {"unknown-type", "provider-region"}:
        value = json.loads(case.raw["target_checkpoint"])
        prefix = f"urn:pulumi:{case.unit}::free-infrastructure::"
        if fault == "unknown-type":
            value["deployment"]["resources"].append(
                dict(urn=prefix + "synthetic:index:Other::other", type="synthetic:index:Other")
            )
        else:
            value["deployment"]["resources"].append(
                dict(
                    urn=prefix + "pulumi:providers:oci::fixture-provider",
                    type="pulumi:providers:oci",
                    id="provider-id",
                    protect=True,
                    inputs={"region": "other"},
                )
            )
        case.write("target_checkpoint", value)
        request = json.loads(case.raw["request"])
        request["checkpoint_sha256"] = hashlib.sha256(case.raw["target_checkpoint"]).hexdigest()
        case.write("request", request)
        entries = json.loads(case.raw["journal"])
        entries[0]["request"] = request
        case.write("journal", entries)
    elif fault in {"tainted", "duplicate-source-id"}:
        value = json.loads(case.raw["source_checkpoint"])
        if fault == "tainted":
            value["resources"][0]["instances"][0]["status"] = "tainted"
        else:
            value["resources"][0]["instances"].append(value["resources"][0]["instances"][0])
        case.write("source_checkpoint", value)
    elif fault == "boolean-active-count":
        case.freeze["active_operations"] = False
    elif fault == "duplicate-writers":
        case.freeze["writers"][1] = case.freeze["writers"][0]
    case.bind()
    if fault == "wrong-binding":
        case.freeze["binding_sha256"] = "0" * 64
        case.write("freeze", case.freeze)
    with pytest.raises(ValueError, match="OWN001"):
        ownership.prepare(case.root, case.doc, now=case.now)


def test_clean_commit_is_rechecked_at_the_end(case, monkeypatch):
    calls = []

    def current(root):
        calls.append(root)
        return (COMMIT, len(calls) == 1)

    monkeypatch.setattr(ownership, "repository_state", current)
    with pytest.raises(ValueError, match="OWN001"):
        ownership.prepare(case.root, case.doc, now=case.now)
    assert len(calls) == 2


def test_caller_mapping_is_snapshotted_before_validation(case, monkeypatch):
    original = ownership._mapping

    def mutate(*args):
        case.doc["entries"][0]["owner"] = "unknown"
        return original(*args)

    monkeypatch.setattr(ownership, "_mapping", mutate)
    assert ownership.prepare(case.root, case.doc, now=case.now)["phase"] == "checkpointed"
