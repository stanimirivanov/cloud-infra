"""Offline evidence consistency checks. Never executes a cutover or grants authority."""

import hashlib
import json
import re
import subprocess
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from infra_core.backend import validate_receipt
from infra_core.cutover_evidence import SIDECARS, SUBJECTS, review_scope, validate_review
from infra_core.evidence import MAX_ARTIFACT_BYTES, MAX_ENVELOPE_BYTES, MAX_TOTAL_BYTES
from infra_core.foundation import load_foundation
from infra_core.governance.audit import audit as audit_account
from infra_core.governance.contracts import fields, number, records, require, text, timestamp
from infra_core.governance.resources import CLUSTER, INSTANCE
from infra_core.kubernetes.audit import audit as audit_kubernetes
from infra_core.kubernetes.config import parse_config as parse_kubernetes
from infra_core.oci.config import parse_config as parse_oci
from infra_core.oci.graph import foundation_graph, proposal

ARTIFACTS = set((SUBJECTS - {"quota_profiles"}) | SIDECARS)
HEADER = {"commit", "account_id", "cluster_id", "region", "observed_at", "source", "reviewed_by"}
HEALTH = {
    "nodes-ready",
    "api-authenticated",
    "dns",
    "pod-isolation",
    "quota-admission",
    "arm-image",
    "network-contract",
}
ROLLBACK = {
    "encrypted-backups",
    "passphrase-recovery",
    "single-owner-rollback",
    "maintenance-window",
    "operator-review",
}


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def repository_state(root: Path) -> tuple[str, bool]:
    def git(args: list[str]) -> str:
        return subprocess.run(
            ["git", *args], cwd=root, check=True, capture_output=True, encoding="utf-8", timeout=10
        ).stdout.strip()

    return git(["rev-parse", "HEAD"]), not bool(
        git(["status", "--porcelain", "--untracked-files=all"])
    )


def check(root: Path, document: object, *, now: datetime | None = None) -> dict[str, Any]:
    # The transport adapter imports repository_state; defer this import to avoid a cycle.
    from infra_core.inventory_evidence import validate_inventory_evidence

    now = now or datetime.now(UTC)
    require(now.tzinfo is not None, "CUT001", "review clock requires an explicit timezone")
    now = now.astimezone(UTC)
    data = fields(
        document,
        {
            "schema_version",
            "commit",
            "account_id",
            "cluster_id",
            "region",
            "configuration_sha256",
            "captured_at",
            "artifacts",
        },
        "cutover bundle",
    )
    commit, clean = repository_state(root)
    require(
        clean
        and data["commit"] == commit
        and bool(re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit)),
        "CUT001",
        "evidence must bind to the exact clean committed checkout",
    )
    require(
        type(data["schema_version"]) is int and data["schema_version"] == 3,
        "CUT001",
        "unsupported cutover evidence schema",
    )
    require(
        timedelta(0)
        <= now - timestamp(data["captured_at"], "cutover capture")
        <= timedelta(minutes=15),
        "CUT001",
        "cutover bundle is stale or in the future",
    )
    config = load_foundation(root)
    require(
        data["configuration_sha256"] == config.digest, "CUT001", "backend configuration changed"
    )
    paths: dict[str, Path] = {}
    captured: dict[str, bytes] = {}
    total = 0
    for role, item in fields(data["artifacts"], ARTIFACTS, "cutover artifact roles").items():
        item = fields(item, {"path", "sha256"}, "artifact reference")
        path = (root / text(item["path"], "artifact path")).resolve()
        require(
            path.is_relative_to((root / ".infra").resolve())
            and path.is_relative_to(root.resolve())
            and path.is_file()
            and path.suffix in (".json", ".toml"),
            "CUT002",
            "artifacts must be private JSON/TOML files inside this checkout's .infra",
        )
        limit = (
            MAX_ENVELOPE_BYTES if role in SIDECARS | {"inventory_envelope"} else MAX_ARTIFACT_BYTES
        )
        with path.open("rb") as stream:
            content = stream.read(limit + 1)
        require(
            len(content) <= limit and hashlib.sha256(content).hexdigest() == item["sha256"],
            "CUT002",
            "artifact size/digest mismatch; regenerate the reviewed bundle",
        )
        if role not in SIDECARS:
            total += len(content)
            require(total <= MAX_TOTAL_BYTES, "CUT002", "aggregate review subject size exceeded")
        paths[role] = path
        captured[role] = content
    require(
        len(set(paths.values())) == len(paths), "CUT002", "artifact roles must use distinct files"
    )

    with (root / "config/quotas/profiles.toml").open("rb") as stream:
        quota_bytes = stream.read(MAX_ARTIFACT_BYTES + 1)
    require(
        len(quota_bytes) <= MAX_ARTIFACT_BYTES and total + len(quota_bytes) <= MAX_TOTAL_BYTES,
        "CUT002",
        "quota profiles exceed the review capture budget",
    )
    profiles = tomllib.loads(quota_bytes.decode("utf-8"))["profiles"]
    subjects = {role: content for role, content in captured.items() if role not in SIDECARS}
    subjects["quota_profiles"] = quota_bytes

    def read(role: str) -> Any:
        return json.loads(captured[role].decode("utf-8"))

    validate_receipt(config, read("backend_receipt"))
    account = tomllib.loads(captured["account"].decode("utf-8"))
    require(
        account.get("account_id") == data["account_id"]
        and account.get("home_region") == data["region"],
        "CUT003",
        "account identity does not match the bundle",
    )
    profile = profiles.get(account.get("profile"), {})
    inventory = validate_inventory_evidence(
        account,
        profile,
        captured["inventory"],
        captured["inventory_envelope"],
        commit=commit,
        now=now,
    )
    plan = read("oci_proposal")
    # Preparation covers unchanged/adopted resources. Changes need a separate reviewed operation.
    require(
        isinstance(plan, dict) and isinstance(plan.get("units"), list),
        "CUT003",
        "account proposal required",
    )
    units = records(plan["units"], "proposal units")
    require(
        all(isinstance(unit.get("name"), str) for unit in units)
        and {unit.get("name") for unit in units} == {"oci-network", "oci-oke"}
        and len(units) == 2
        and all(unit.get("changes") == [] for unit in units),
        "CUT003",
        "cutover preparation cannot authorize creates, updates, replacements or deletions",
    )
    audit_account(account, profile, inventory, plan, now=now)
    require(
        any(
            item.get("id") == data["cluster_id"] and item.get("type") == CLUSTER
            for item in records(inventory["resources"], "observed OCI resources")
        ),
        "CUT003",
        "target cluster is not present in the account inventory",
    )
    oci = parse_oci(tomllib.loads(captured["oci_config"].decode("utf-8")))
    require(oci.region == data["region"], "CUT003", "OCI region differs")
    graph = foundation_graph(oci, now=now)
    graph_digest = digest(proposal(graph, data["account_id"], oci.region))
    kube = parse_kubernetes(tomllib.loads(captured["kubernetes_config"].decode("utf-8")))
    require(
        kube.account_id == data["account_id"]
        and kube.cluster_id == data["cluster_id"]
        and kube.region == data["region"]
        and oci.kubernetes_version.rsplit(".", 1)[0] == kube.policy_version,
        "CUT003",
        "OCI and Kubernetes identities/versions differ",
    )
    kube_inventory = read("kubernetes_inventory")
    audit_kubernetes(kube, kube_inventory, read("kubernetes_resources"), now=now)
    instances = {item["id"]: item for item in inventory["resources"] if item["type"] == INSTANCE}
    require(
        all(node in instances for node in kube_inventory["node_ids"]),
        "CUT003",
        "cluster node IDs are not covered by the OCI inventory",
    )
    shapes = [instances[node]["props"]["shapeConfig"] for node in kube_inventory["node_ids"]]
    require(
        kube_inventory["allocatable"]["cpu_m"]
        <= sum(number(item["ocpus"], "node CPU") * 1000 for item in shapes)
        and kube_inventory["allocatable"]["memory_mi"]
        <= sum(number(item["memoryInGbs"], "node memory") * 1000**3 / 1024**2 for item in shapes),
        "CUT003",
        "allocatable exceeds observed OCI node hardware (conservative decimal GB)",
    )

    def report(role: str, extra: set[str], *, hours: int = 0) -> dict[str, Any]:
        scope = review_scope(
            role,
            account_id=account["account_id"],
            region=account["home_region"],
            cluster_id=kube.cluster_id,
            commit=commit,
            configuration_sha256=config.digest,
        )
        value = fields(
            validate_review(role, subjects, captured[role + "_envelope"], scope=scope, now=now),
            HEADER | extra,
            role,
        )
        require(
            all(
                value[key] == data[key] for key in ("commit", "account_id", "cluster_id", "region")
            ),
            "CUT004",
            "review report belongs to another commit or infrastructure scope",
        )
        ttl = timedelta(hours=hours) if hours else timedelta(minutes=15)
        require(
            timedelta(0) <= now - timestamp(value["observed_at"], role) <= ttl,
            "CUT004",
            "review report is stale or in the future",
        )
        text(value["source"], "report source")
        text(value["reviewed_by"], "reviewer reference")
        return value

    ownership = report("ownership", {"complete", "writers_frozen", "active_operations", "entries"})
    require(
        ownership["complete"] is True
        and ownership["writers_frozen"] is True
        and type(ownership["active_operations"]) is int
        and ownership["active_operations"] == 0,
        "CUT005",
        "complete ownership evidence and frozen idle writers required",
    )
    entries = records(ownership["entries"], "ownership mapping")
    expected = {item.key: item for item in graph}
    seen_keys: set[str] = set()
    seen_ids: set[str] = set()
    seen_addresses: set[str] = set()
    operations = []
    for entry in entries:
        fields(
            entry,
            {
                "logical_key",
                "id",
                "unit",
                "pulumi_name",
                "pulumi_parent",
                "provider_region",
                "owner",
                "terraform_address",
                "operation",
            },
            "ownership entry",
        )
        key = text(entry["logical_key"], "logical resource key")
        resource_id = text(entry["id"], "resource ID")
        require(
            key in expected and key not in seen_keys and resource_id not in seen_ids,
            "CUT005",
            "duplicate, unknown or ambiguous resource ownership",
        )
        spec = expected[key]
        require(
            entry["unit"] == spec.unit
            and entry["pulumi_name"] == oci.name + "-" + key
            and entry["pulumi_parent"]
            == oci.name + ("-network" if spec.unit == "oci-network" else "-oke")
            and entry["provider_region"] == oci.region,
            "CUT005",
            "resource target differs from reviewed unit/parent/provider graph",
        )
        operation = entry["operation"]
        require(
            operation in ("import", "same"),
            "CUT006",
            "only explicit import/same evidence is supported",
        )
        if operation == "import":
            address = text(entry["terraform_address"], "Terraform address")
            require(
                entry["owner"] == "terraform" and address not in seen_addresses,
                "CUT005",
                "import must have one distinct Terraform owner",
            )
            seen_addresses.add(address)
        else:
            require(
                entry["owner"] == "pulumi" and entry["terraform_address"] is None,
                "CUT005",
                "unchanged Pulumi resources must not retain a Terraform owner",
            )
        if key == "cluster":
            require(resource_id == data["cluster_id"], "CUT005", "ownership names another cluster")
        seen_keys.add(key)
        seen_ids.add(resource_id)
        operations.append(
            {"logical_key": key, "id": resource_id, "unit": spec.unit, "operation": operation}
        )
    require(
        seen_keys == set(expected), "CUT005", "mapping must cover the entire reviewed OCI graph"
    )
    preview = report("preview", {"complete", "graph_sha256", "operations"})
    require(
        preview["complete"] is True
        and preview["graph_sha256"] == graph_digest
        and preview["operations"] == operations,
        "CUT006",
        "preview must exactly match the full unchanged/import graph and ownership order",
    )
    # Network ownership is reviewed before OKE. This is ordering evidence, not an executor.
    ordered_units = [item["unit"] for item in operations]
    require(
        ordered_units == sorted(ordered_units, key=lambda unit: unit != "oci-network"),
        "CUT006",
        "network ownership must precede OKE",
    )
    for role, checks, hours in (("health", HEALTH, 0), ("rollback", ROLLBACK, 24)):
        value = report(role, {"checks"}, hours=hours)
        require(
            isinstance(value["checks"], list)
            and len(value["checks"]) == len(checks)
            and all(isinstance(item, str) for item in value["checks"])
            and set(value["checks"]) == checks,
            "CUT007",
            "all required health/admission/recovery review checks must be evidenced",
        )
    require(
        repository_state(root) == (commit, True),
        "CUT001",
        "checkout changed during evidence validation",
    )
    return {
        "status": "evidence-consistent",
        "commit": commit,
        "resources": len(operations),
        "deployment_authorized": False,
        "cutover_authorized": False,
        "remaining_gates": [
            "reviewed separate-stack orchestration",
            "protected operational approval",
            "explicit human cutover instruction",
        ],
    }
