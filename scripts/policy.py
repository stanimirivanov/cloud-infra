"""Fail-closed architectural sensors over parsed HCL, without cloud access."""

import ipaddress
import json
import re

import hcl2

NETWORK_TYPES = {
    "oci_core_vcn",
    "oci_core_subnet",
    "oci_core_internet_gateway",
    "oci_core_route_table",
    "oci_core_network_security_group",
    "oci_core_network_security_group_security_rule",
}
OKE_TYPES = {"oci_containerengine_cluster", "oci_containerengine_node_pool"}
DATA_TYPES = {
    "oci_identity_availability_domains",
    "oci_containerengine_cluster_option",
    "oci_containerengine_node_pool_option",
}
GENERATED = {"backend.tf", "provider.tf", "common_variables.tf"}


def load(path):
    with path.open(encoding="utf-8") as stream:
        return hcl2.load(stream)


def blocks(document, kind):
    for group in document.get(kind, []):
        for resource_type, named in group.items():
            for name, body in named.items():
                yield resource_type, name, body


def walk(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)
    else:
        yield value


def check(documents, public_baseline):
    """Return stable, actionable diagnostics. Expressions fail literal-only rules."""
    errors = []
    resources = []

    def require(condition, rule, message):
        if not condition:
            errors.append(f"{rule}: {message}")

    for filename, doc in documents.items():
        require(
            filename in {"main.tf", "vcn.tf", "oke.tf", "outputs.tf"},
            "ARCH001",
            f"{filename}: assign new files an explicit architecture owner",
        )
        require(
            not any(key in doc for key in ("provider", "variable", "module")),
            "ARCH002",
            f"{filename}: providers/variables belong to root.hcl; modules need review",
        )
        forbidden = {"provisioner", "local-exec", "remote-exec", "backend"}
        require(
            not any(isinstance(v, str) and v in forbidden for v in walk(doc)),
            "ARCH003",
            f"{filename}: remove execution escape hatches/backend duplication",
        )
        for kind, name, _body in blocks(doc, "data"):
            require(
                filename == "oke.tf" and kind in DATA_TYPES,
                "ARCH004",
                f"{filename}: data {kind}.{name} is outside OKE lookup ownership",
            )
        if filename == "vcn.tf":
            require(
                "oci_containerengine_" not in json.dumps(doc),
                "ARCH005",
                "vcn.tf: network must not depend on OKE",
            )
        for kind, name, body in blocks(doc, "resource"):
            owner = "vcn.tf" if kind in NETWORK_TYPES else "oke.tf" if kind in OKE_TYPES else None
            require(owner == filename, "ARCH006", f"{filename}: {kind}.{name} owner is {owner}")
            require(
                not any(k in body for k in ("count", "for_each", "dynamic")),
                "ARCH007",
                f"{kind}.{name}: resource multiplication/dynamic policy needs review",
            )
            resources.append((kind, name, body))
        for _, output in ((n, b) for group in doc.get("output", []) for n, b in group.items()):
            require(
                not any(
                    secret in json.dumps(output.get("value", ""))
                    for secret in ("private_key", "fingerprint", "secret", "password")
                ),
                "SECRET001",
                f"{filename}: do not expose credential outputs",
            )

    clusters = [b for k, _, b in resources if k == "oci_containerengine_cluster"]
    require(
        len(clusters) == 1 and clusters[0].get("type") == "BASIC_CLUSTER",
        "COST001",
        "keep exactly one literal BASIC_CLUSTER",
    )
    pools = [b for k, _, b in resources if k == "oci_containerengine_node_pool"]
    cpu = memory = 0
    require(bool(pools), "COST002", "retain at least one A1 pool")
    for pool in pools:
        require(pool.get("node_shape") == "VM.Standard.A1.Flex", "COST002", "use A1 Flex nodes")
        try:
            size = pool["node_config_details"][0]["size"]
            shape = pool["node_shape_config"][0]
            ocpus, ram = shape["ocpus"], shape["memory_in_gbs"]
            if not (
                type(size) is int
                and size > 0
                and all(type(v) in (int, float) and v > 0 for v in (ocpus, ram))
            ):
                raise ValueError("sizing must be positive literals")
            cpu += size * ocpus
            memory += size * ram
        except (KeyError, IndexError, TypeError, ValueError):
            require(False, "COST003", "use explicit positive literal node count/OCPUs/GiB")
    require(cpu <= 4 and memory <= 24, "COST004", "aggregate pools exceed 4 OCPUs / 24 GiB")

    subnets = []
    for kind, name, body in resources:
        if kind == "oci_core_subnet":
            try:
                subnet = ipaddress.ip_network(body["cidr_block"])
                require(
                    subnet.subnet_of(ipaddress.ip_network("10.0.0.0/16")),
                    "NET001",
                    f"{name}: subnet must stay within 10.0.0.0/16",
                )
                require(
                    not any(subnet.overlaps(other) for other in subnets),
                    "NET002",
                    f"{name}: overlapping subnet CIDRs",
                )
                subnets.append(subnet)
            except (KeyError, ValueError, TypeError):
                require(False, "NET001", f"{name}: use a literal valid IPv4 subnet")
        if kind == "oci_core_network_security_group_security_rule":
            if body.get("direction") != "INGRESS":
                continue
            source = body.get("source", "")
            internal = source in {
                "${oci_core_subnet.node_subnet.cidr_block}",
                "${oci_core_subnet.k8s_endpoint_subnet.cidr_block}",
                "${oci_core_subnet.pod_subnet.cidr_block}",
            }
            require(
                internal or public_baseline.get(name) == body,
                "NET003",
                f"{name}: ingress differs from reviewed baseline; restrict or review",
            )
    return errors


def check_repository(root):
    unit = root / "terraform/01-infrastructure"
    documents = {p.name: load(p) for p in sorted(unit.glob("*.tf"))}
    errors = check(documents, json.loads((root / "tests/public_ingress_baseline.json").read_text()))
    actual = {
        p.relative_to(root).as_posix()
        for p in (root / "terraform").rglob("*.tf")
        if ".terraform" not in p.parts and ".terragrunt-cache" not in p.parts
    }
    expected = {
        f"terraform/01-infrastructure/{name}"
        for name in ("main.tf", "vcn.tf", "oke.tf", "outputs.tf")
    }
    if actual != expected:
        errors.append(
            "ARCH008: unexpected/missing Terraform files; review unit and state ownership"
        )
    shared = load(root / "terraform/root.hcl")
    generators = {
        name: body for group in shared.get("generate", []) for name, body in group.items()
    }
    if {body.get("path") for body in generators.values()} != GENERATED or any(
        body.get("if_exists") != "overwrite_terragrunt" for body in generators.values()
    ):
        errors.append("ARCH009: root.hcl must own exactly the three reviewed generated files")
    if set(shared) != {"locals", "generate", "inputs"}:
        errors.append("ARCH010: root.hcl cannot execute hooks or read other state")
    allowed_functions = {"get_env", "path_relative_to_include"}
    for value in walk(shared):
        if isinstance(value, str) and "${" in value:
            functions = set(re.findall(r"\b([a-z_]\w*)\s*\(", value))
            if functions - allowed_functions:
                errors.append("ARCH012: root.hcl functions need review; no shell/file/state reads")
    child = load(unit / "terragrunt.hcl")
    if child != {"include": [{"root": {"path": '${find_in_parent_folders("root.hcl")}'}}]}:
        errors.append("ARCH011: child unit must only include root.hcl; review hooks/state changes")
    return errors
