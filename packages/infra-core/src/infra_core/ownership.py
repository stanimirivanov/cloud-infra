"""Read-only OCI ownership preparation; recorded ownership never grants a writer permit."""

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from infra_core import operations
from infra_core.cutover import repository_state
from infra_core.foundation import load_foundation
from infra_core.oci.config import FoundationConfig, parse_config
from infra_core.oci.graph import NETWORK_UNIT, OKE_UNIT, Resource, network_graph, oke_graph

MESSAGE = "OWN001: ownership preparation rejected; inspect private mapping and checkpoints"
ARTIFACTS = {
    "request",
    "configuration",
    "encrypted_configuration",
    "source_checkpoint",
    "target_checkpoint",
    "freeze",
    "journal",
}
ENTRY = {
    "logical_key",
    "id",
    "unit",
    "pulumi_name",
    "pulumi_parent",
    "provider_region",
    "owner",
    "terraform_address",
    "operation",
}


def _require(value: bool) -> None:
    if not value:
        raise ValueError(MESSAGE)


def _fields(value: Any, names: set[str]) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == names)
    assert isinstance(value, dict)
    return value


def _text(value: Any) -> str:
    _require(type(value) is str and 0 < len(value) <= 1024 and value.strip() == value)
    assert isinstance(value, str)
    _require(not any(ord(c) < 32 for c in value))
    return value


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(raw: bytes) -> Any:
    _require(0 < len(raw) <= operations.MAX_BYTES)
    value = json.loads(raw, object_pairs_hook=operations._pairs)
    json.dumps(value, allow_nan=False)
    return value


def _read(root: Path, reference: Any) -> tuple[Path, bytes]:
    ref = _fields(reference, {"path", "sha256"})
    _require(operations._hash(ref["sha256"]))
    path = root / _text(ref["path"])
    _require(path.is_relative_to(root / ".infra") and path != root / ".infra")
    _require(not any(p.is_symlink() for p in (path, *path.parents)))
    _require(path.resolve().is_relative_to(root / ".infra"))
    with path.open("rb") as stream:
        raw = stream.read(operations.MAX_BYTES + 1)
    _require(0 < len(raw) <= operations.MAX_BYTES and _hash(raw) == ref["sha256"])
    return path.resolve(), raw


def _source(raw: bytes, identity: dict[str, Any]) -> dict[str, tuple[str, str]]:
    """Inspect state v4 records, not a backend or source-engine executable."""
    value = _json(raw)
    _require(type(value) is dict and type(value["version"]) is int and value["version"] == 4)
    _require(
        value["lineage"] == identity["lineage"]
        and type(value["serial"]) is int
        and value["serial"] >= 0
        and value["serial"] == identity["serial"]
        and type(value["resources"]) is list
    )
    resources: dict[str, tuple[str, str]] = {}
    identities: set[tuple[str, str]] = set()
    for resource in value["resources"]:
        _require(resource["mode"] in {"managed", "data"})
        if resource["mode"] == "data":
            continue
        kind, name = _text(resource["type"]), _text(resource["name"])
        address = (
            _text(resource.get("module", "") + "." + kind + "." + name)
            if resource.get("module")
            else kind + "." + name
        )
        _require(type(resource["instances"]) is list)
        for instance in resource["instances"]:
            # Deposed/tainted instances make writer freeze/ownership ambiguous.
            _require(not instance.get("deposed") and instance.get("status", "") == "")
            key = instance.get("index_key")
            _require(key is None or type(key) in {str, int})
            _require(type(key) is not int or key >= 0)
            indexed = address + (
                "[" + json.dumps(key, ensure_ascii=False, separators=(",", ":")) + "]"
                if key is not None
                else ""
            )
            resource_id = _text(instance["attributes"]["id"])
            _require(indexed not in resources and (kind, resource_id) not in identities)
            resources[indexed] = (kind, resource_id)
            identities.add((kind, resource_id))
    return resources


def _target(raw: bytes, stack: str) -> dict[str, dict[str, Any]]:
    value = _json(raw)
    _require(type(value["version"]) is int and value["version"] == 3)
    deployment = value["deployment"]
    _require(not deployment.get("pending_operations") and type(deployment["resources"]) is list)
    unit = stack.split("/")[-1]
    prefix = f"urn:pulumi:{unit}::free-infrastructure::"
    resources: dict[str, dict[str, Any]] = {}
    roots = 0
    for record in deployment["resources"]:
        urn = _text(record["urn"])
        _require(urn.startswith(prefix) and urn not in resources and not record.get("delete"))
        _require(record["type"] == urn.split("::")[-2].split("$")[-1])
        if record["type"] == "pulumi:pulumi:Stack":
            roots += 1
            _require(urn == prefix + "pulumi:pulumi:Stack::free-infrastructure-" + unit)
        resources[urn] = record
    _require(roots == 1)
    return resources


def _mapping(
    entries: Any,
    graph: tuple[Resource, ...],
    cfg: FoundationConfig,
    source: dict[str, tuple[str, str]],
    target: dict[str, dict[str, Any]],
    unit: str,
) -> int:
    _require(type(entries) is list and len(entries) == len(graph))
    expected = {resource.key: resource for resource in graph}
    keys, ids, addresses = set(), set(), set()
    prefix = f"urn:pulumi:{unit}::free-infrastructure::"
    component_type = "infrastructure:oci:" + ("Network" if unit == NETWORK_UNIT else "Oke")
    parent_name = cfg.name + ("-network" if unit == NETWORK_UNIT else "-oke")
    parent = prefix + component_type + "::" + parent_name
    provider = prefix + "pulumi:providers:oci::" + cfg.name + "-provider"
    managed = {urn: record for urn, record in target.items() if record["type"].startswith("oci:")}
    allowed = {
        prefix + "pulumi:pulumi:Stack::free-infrastructure-" + unit,
        parent,
        provider,
    }
    allowed.update(
        prefix + component_type + "$" + spec.kind + "::" + cfg.name + "-" + spec.key
        for spec in graph
    )
    if unit == OKE_UNIT:
        reference = prefix + "pulumi:pulumi:StackReference::" + cfg.name + "-network-reference"
        allowed |= {reference, prefix + "pulumi:providers:pulumi::default"}
        if reference in target:
            _require(
                target[reference].get("protect") is True
                and target[reference].get("inputs", {}).get("name")
                == "organization/free-infrastructure/oci-network"
            )
    _require(set(target) <= allowed)
    if provider in target:
        _require(
            target[provider].get("protect") is True
            and target[provider].get("inputs", {}).get("region") == cfg.region
        )
        _text(target[provider].get("id"))
    if parent in target:
        _require(target[parent].get("protect") is True)
    seen_targets = set()
    imports = 0
    for entry in entries:
        entry = _fields(entry, ENTRY)
        key, resource_id = _text(entry["logical_key"]), _text(entry["id"])
        _require(key in expected and key not in keys and resource_id not in ids)
        spec = expected[key]
        _require(
            entry["unit"] == unit
            and entry["pulumi_name"] == cfg.name + "-" + key
            and entry["pulumi_parent"] == parent_name
            and entry["provider_region"] == cfg.region
        )
        urn = prefix + component_type + "$" + spec.kind + "::" + entry["pulumi_name"]
        if entry["operation"] == "import":
            address = _text(entry["terraform_address"])
            _require(
                entry["owner"] == "terraform" and address in source and address not in addresses
            )
            source_type, source_id = source[address]
            # OCI's source type names and native tokens must describe the same resource.
            token_name = spec.kind.split("/")[-1].split(":")[-1]
            terraform_type = (
                "oci_"
                + ("containerengine" if spec.kind.startswith("oci:ContainerEngine/") else "core")
                + "_"
                + re.sub(r"(?<!^)(?=[A-Z])", "_", token_name).lower()
            )
            _require(source_type == terraform_type and source_id == resource_id)
            _require(
                urn not in target and resource_id not in {r.get("id") for r in managed.values()}
            )
            addresses.add(address)
            imports += 1
        else:
            _require(
                entry["operation"] == "same"
                and entry["owner"] == "pulumi"
                and entry["terraform_address"] is None
                and urn in managed
            )
            record = managed[urn]
            _require(
                record.get("id") == resource_id
                and record.get("protect") is True
                and record.get("parent") == parent
                and provider in target
                and parent in target
                and record.get("provider") == provider + "::" + target[provider]["id"]
            )
            _require(resource_id not in {v[1] for v in source.values()})
            seen_targets.add(urn)
        keys.add(key)
        ids.add(resource_id)
    _require(set(managed) == seen_targets)
    return imports


def prepare(
    root: Path,
    document: object,
    *,
    now: datetime | None = None,
    prepared_journal: bytes | None = None,
) -> dict[str, object]:
    """Check recorded checkpoint consistency; external freezes remain attestations."""
    try:
        return _prepare(
            root.resolve(),
            _json(operations.encoded(document)),
            now or datetime.now(UTC),
            prepared_journal,
        )
    except Exception:
        raise ValueError(MESSAGE) from None


def _prepare(
    root: Path, document: object, now: datetime, prepared_journal: bytes | None = None
) -> dict[str, object]:
    _require(now.utcoffset() == timedelta(0))
    data = _fields(document, {"schema_version", "source", "target_stack", "entries", "artifacts"})
    _require(type(data["schema_version"]) is int and data["schema_version"] == 1)
    references = _fields(data["artifacts"], ARTIFACTS)
    captured = {
        name: _read(root, ref)
        for name, ref in references.items()
        if name != "journal" or prepared_journal is None
    }
    continuation: tuple[Path, bytes] | None = None
    if prepared_journal is not None:
        ref = _fields(references["journal"], {"path", "sha256"})
        path = root / _text(ref["path"])
        _require(path.is_relative_to(root / ".infra") and path != root / ".infra")
        _require(not any(p.is_symlink() for p in (path, *path.parents)))
        _require(path.resolve().is_relative_to(root / ".infra"))
        with path.open("rb") as stream:
            current = stream.read(operations.MAX_BYTES + 1)
        # Validate path ancestry as usual, while independently pinning its current bytes.
        continuation = _read(root, {"path": str(path), "sha256": _hash(current)})
        _require(_hash(prepared_journal) == ref["sha256"])
        original_entries = operations._validate(_json(prepared_journal))
        actual_entries = operations._validate(_json(current))
        _require(
            bool(original_entries) and actual_entries[: len(original_entries)] == original_entries
        )
        suffix = actual_entries[len(original_entries) :]
        _require([e["state"] for e in suffix] in ([], ["admitted"], ["admitted", "running"]))
        captured["journal"] = (continuation[0], prepared_journal)
    _require(len({path for path, _ in captured.values()}) == len(captured))
    raw = {name: content for name, (_, content) in captured.items()}
    _require(sum(map(len, raw.values())) <= 4 * operations.MAX_BYTES)
    request = operations.request(_json(raw["request"]))
    unit = request["unit"]
    _require(
        request["operation"] == "import"
        and unit in {NETWORK_UNIT, OKE_UNIT}
        and now < operations._time(request["expires_at"])
    )
    _require(repository_state(root) == (request["commit"], True))
    _require(data["target_stack"] == "organization/free-infrastructure/" + unit)
    _require(
        request["configuration_sha256"] == _hash(raw["encrypted_configuration"])
        and request["checkpoint_sha256"] == _hash(raw["target_checkpoint"])
    )
    # The same closed encrypted-config encoding used by OCI preview/apply.
    encrypted = _fields(_json(raw["encrypted_configuration"]), {"encryptionsalt", "config"})
    _require(
        type(encrypted["encryptionsalt"]) is str
        and encrypted["encryptionsalt"].startswith("v1:")
        and len(encrypted["encryptionsalt"]) > 3
        and encrypted["config"] == {}
    )
    source_identity = _fields(
        data["source"], {"engine", "backend_sha256", "workspace", "lineage", "serial"}
    )
    _require(
        source_identity["engine"] == "terraform"
        and operations._hash(source_identity["backend_sha256"])
        and type(source_identity["serial"]) is int
    )
    _text(source_identity["workspace"])
    _require(str(UUID(source_identity["lineage"])) == source_identity["lineage"])
    entries = operations._validate(_json(raw["journal"]))
    _require(
        bool(entries) and entries[-1]["state"] == "prepared" and entries[-1]["request"] == request
    )
    _require(captured["journal"][0] == root / ".infra/operations" / (unit + ".json"))
    cfg = parse_config(_json(raw["configuration"]))
    graph = network_graph(cfg) if unit == NETWORK_UNIT else oke_graph(cfg)
    target = _target(raw["target_checkpoint"], data["target_stack"])
    source = _source(raw["source_checkpoint"], source_identity)
    imports = _mapping(data["entries"], graph, cfg, source, target, unit)
    binding = preparation_binding(
        data,
        request,
        raw,
        foundation_sha256=load_foundation(root).digest,
        journal_head=operations.digest(entries[-1]),
    )
    freeze = _fields(
        _json(raw["freeze"]),
        {
            "schema_version",
            "phase",
            "binding_sha256",
            "complete",
            "other_writers_reviewed",
            "active_operations",
            "frozen_at",
            "checkpointed_at",
            "observed_at",
            "expires_at",
            "reviewed_by",
            "writers",
        },
    )
    _require(
        type(freeze["schema_version"]) is int
        and freeze["schema_version"] == 1
        and freeze["phase"] == "writers-frozen"
        and freeze["binding_sha256"] == binding
        and freeze["complete"] is True
        and freeze["other_writers_reviewed"] is True
        and type(freeze["active_operations"]) is int
        and freeze["active_operations"] == 0
    )
    _text(freeze["reviewed_by"])
    clocks = [
        operations._time(freeze[n])
        for n in ("frozen_at", "checkpointed_at", "observed_at", "expires_at")
    ]
    _require(
        operations._time(entries[-1]["at"])
        <= clocks[0]
        <= clocks[1]
        <= clocks[2]
        <= now
        < clocks[3]
        <= operations._time(request["expires_at"])
        and now - clocks[0] <= timedelta(minutes=15)
    )
    writers = freeze["writers"]
    expected_writers = {
        ("terraform", operations.digest(source_identity)),
        ("pulumi", operations.digest(data["target_stack"])),
    }
    _require(type(writers) is list and len(writers) == 2)
    observed_writers = set()
    for writer in writers:
        writer = _fields(writer, {"engine", "identity_sha256", "frozen", "active_operations"})
        _require(
            writer["frozen"] is True
            and type(writer["active_operations"]) is int
            and writer["active_operations"] == 0
        )
        observed_writers.add((writer["engine"], writer["identity_sha256"]))
    _require(observed_writers == expected_writers)
    for name, (path, content) in captured.items():
        if name == "journal" and continuation is not None:
            _require(
                _read(root, {"path": str(path), "sha256": _hash(continuation[1])}) == continuation
            )
        else:
            _require(_read(root, references[name]) == (path, content))
    _require(repository_state(root) == (request["commit"], True))
    return {
        "schema_version": 1,
        "operation_id": request["operation_id"],
        "unit": unit,
        "phase": "checkpointed",
        "binding_sha256": binding,
        "freeze_sha256": _hash(raw["freeze"]),
        "journal_head": operations.digest(entries[-1]),
        "imports": imports,
        "unchanged": len(graph) - imports,
        "next_transition": "import-review" if imports else "post-import-equivalence-review",
        "execution_authorized": False,
        "ownership_transfer_authorized": False,
        "writer_release_authorized": False,
    }


def preparation_binding(
    data: dict[str, Any],
    request: dict[str, Any],
    raw: dict[str, bytes],
    *,
    foundation_sha256: str,
    journal_head: str,
) -> str:
    """Canonical review subject for an external freeze attestation; no authority."""
    return operations.digest(
        {
            "request": operations.digest(request),
            "source": data["source"],
            "target_stack": data["target_stack"],
            "mapping": data["entries"],
            "configuration_sha256": _hash(raw["configuration"]),
            "foundation_sha256": foundation_sha256,
            "source_checkpoint_sha256": _hash(raw["source_checkpoint"]),
            "target_checkpoint_sha256": _hash(raw["target_checkpoint"]),
            "journal_head": journal_head,
        }
    )


def inspect(root: Path, path: Path) -> dict[str, object]:
    """CLI adapter reads an immutable private index and emits a redacted checklist."""
    try:
        root = root.resolve()
        path = root / path
        _require(
            path.is_relative_to(root / ".infra") and path.resolve().is_relative_to(root / ".infra")
        )
        _require(not any(p.is_symlink() for p in (path, *path.parents)))
        with path.open("rb") as stream:
            raw = stream.read(operations.MAX_BYTES + 1)
        document = _json(raw)
        result = prepare(root, document)
        _require(_read(root, {"path": str(path), "sha256": _hash(raw)})[1] == raw)
        return result
    except Exception:
        raise ValueError(MESSAGE) from None
