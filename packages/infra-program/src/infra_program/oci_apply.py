"""Default-disabled OCI apply; network success and exact committed outputs precede OKE."""

import argparse
import fcntl
import os
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pulumi
from infra_core import administration, operations
from infra_core.backend import validate_receipt
from infra_core.foundation import load_foundation
from infra_core.oci.config import parse_config
from infra_core.oci.graph import network_graph, oke_graph
from infra_core.preview_contracts import describe_preview

from infra_program import preview_driver as preview
from infra_program import service_apply as driver
from infra_program.oci import components
from infra_program.oci.dependencies import NETWORK_STACK, network_digest, validate_network
from infra_program.operation_runtime import ALLOWED, MESSAGE, Runtime, require
from infra_program.preview_orchestration import _private
from infra_program.preview_program import NetworkPreviewContext, OkePreviewContext

UNITS = {"oci-network", "oci-oke"}


def names(unit: str) -> set[str]:
    require(unit in UNITS)
    base = driver.NAMES | {"account"}
    return base | (
        {"dependency_outputs", "network_receipt", "network_journal"} if unit == "oci-oke" else set()
    )


def validate_plan(raw: bytes, context: NetworkPreviewContext) -> None:
    """Exact existing graph, explicit provider/parents and non-destructive steps only."""
    plan = preview._json(raw, operations.MAX_BYTES)
    require(plan["manifest"]["version"] == "v" + context.foundation.pulumi_version)
    cfg, unit = context.configuration, context.contract.unit
    graph = oke_graph(cfg) if unit == "oci-oke" else network_graph(cfg)
    prefix = f"urn:pulumi:{unit}::{context.foundation.project}::"
    root = prefix + "pulumi:pulumi:Stack::" + context.foundation.project + "-" + unit
    kind = "infrastructure:oci:" + ("Oke" if unit == "oci-oke" else "Network")
    component = prefix + kind + "::" + cfg.name + ("-oke" if unit == "oci-oke" else "-network")
    provider = prefix + "pulumi:providers:oci::" + cfg.name + "-provider"
    expected: dict[str, tuple[str, str, str | None]] = {
        root: ("pulumi:pulumi:Stack", "", None),
        component: (kind, root, None),
        provider: ("pulumi:providers:oci", root, None),
    }
    if unit == "oci-oke":
        # The pinned engine omits read-only StackReferences from plans, but records
        # their built-in provider. The owned factory validates the actual reference.
        builtin = prefix + "pulumi:providers:pulumi::default"
        expected[builtin] = ("pulumi:providers:pulumi", root, None)
    for item in graph:
        expected[prefix + kind + "$" + item.kind + "::" + cfg.name + "-" + item.key] = (
            item.kind,
            component,
            provider,
        )
    resources = plan["resourcePlans"]
    require(type(resources) is dict and set(resources) == set(expected))
    for urn, (resource_type, parent, bound_provider) in expected.items():
        resource = resources[urn]
        goal = resource["goal"]
        require(
            type(resource["steps"]) is list
            and bool(resource["steps"])
            and set(resource["steps"]) <= ALLOWED
        )
        require(goal["type"] == resource_type and goal["name"] == urn.split("::")[-1])
        # Pulumi may omit the implicit root parent from top-level goals.
        require(goal.get("parent", "") in ({parent, ""} if parent == root else {parent}))
        if urn != root and resource_type != "pulumi:providers:pulumi":
            require(goal.get("protect") is True)
        if bound_provider:
            reference = goal.get("provider", "")
            require(
                reference.startswith(bound_provider + "::")
                and bool(reference[len(bound_provider) + 2 :])
            )


def dependency(
    context: NetworkPreviewContext, raw: dict[str, bytes], allow_import: bool = False
) -> dict[str, Any]:
    observed = preview._json(raw["dependency_outputs"], 65536)
    validate_network(observed, context.configuration, context.account["account_id"])
    entries = operations._validate(
        administration._json(raw["network_journal"], array=True)["items"]
    )
    require(bool(entries))
    entry = entries[-1]
    receipt = preview._json(raw["network_receipt"], 65536)
    require(
        entry["state"] == "succeeded"
        and entry["request"]["unit"] == "oci-network"
        and (
            entry["request"]["operation"] == "apply"
            or (
                allow_import
                and entry["request"]["operation"] == "import"
                and receipt.get("post_import_equivalent") is True
            )
        )
        and receipt["status"] == "succeeded"
        and receipt["operation_id"] == entry["request"]["operation_id"]
        and receipt["journal_head"] == operations.digest(entry)
        and receipt["dependency_outputs_sha256"] == network_digest(observed)
    )
    return receipt


def prepare(
    root: Path, unit: str, commit: str, raw: dict[str, bytes], importing: bool = False
) -> tuple[NetworkPreviewContext, bytes]:
    driver._enabled(root, True, importing)
    require(set(raw) == names(unit))
    foundation = load_foundation(root)
    configuration = parse_config(preview._json(raw["proposal"], operations.MAX_BYTES))
    account = preview._json(raw["account"], operations.MAX_BYTES)
    profile = tomllib.loads((root / "config/quotas/profiles.toml").read_text())["profiles"][
        account["profile"]
    ]
    cls = OkePreviewContext if unit == "oci-oke" else NetworkPreviewContext
    context = cls(
        foundation,
        describe_preview(foundation, unit, commit),
        commit,
        configuration,
        account,
        profile,
        raw["evidence"],
        raw["envelope"],
    )
    preview._contract(root, context)
    prepared, artifacts, _ = preview._prepare(
        root, context, raw["encrypted_configuration"], raw.get("dependency_outputs")
    )
    assert isinstance(prepared, NetworkPreviewContext)
    context = prepared
    preview._versions(root, context, artifacts)
    validate_plan(raw["plan"], context)
    validate_receipt(foundation, preview._json(raw["qualification"], operations.MAX_BYTES))
    if unit == "oci-oke":
        path = _private(root, ".infra/operations/oci-network.json")
        require(preview._read(path, operations.MAX_BYTES) == raw["network_journal"])
        dependency(context, raw, importing)
    return context, preview._encoded(
        {
            "adapter": "oci-apply-v1",
            "inputs": {n: driver._hash(raw[n]) for n in sorted(names(unit) - driver.APPROVAL)},
            "profile": driver._hash(preview._encoded(context.profile)),
            "foundation": foundation.digest,
        }
    )


def confirm_dependency(
    runtime: Runtime, context: preview.Context, raw: dict[str, bytes], allow_import: bool = False
) -> None:
    require(isinstance(context, OkePreviewContext))
    assert isinstance(context, OkePreviewContext)
    receipt = dependency(context, raw, allow_import)
    checkpoint, observed = runtime.network_outputs()
    validate_network(observed, context.configuration, context.account["account_id"])
    require(
        checkpoint == receipt["checkpoint_sha256"]
        and network_digest(observed) == context.expected_network_sha256
    )


def network_result(runtime: Runtime, context: preview.Context) -> dict[str, Any]:
    require(type(context) is NetworkPreviewContext)
    assert isinstance(context, NetworkPreviewContext)
    checkpoint, observed = runtime.network_outputs()
    validate_network(observed, context.configuration, context.account["account_id"])
    return {"checkpoint_sha256": checkpoint, "dependency_outputs_sha256": network_digest(observed)}


def register(context: NetworkPreviewContext) -> None:
    """Owned apply bootstrap delegates the same audited factories and exports as preview."""
    args = (context.configuration, context.account, context.profile, context.inventory)
    if type(context) is OkePreviewContext:
        assert isinstance(context, OkePreviewContext)
        result = components.register_oke(
            *args,
            envelope=context.envelope,
            commit=context.expected_commit,
            dependency_stack=NETWORK_STACK,
            expected_network_sha256=context.expected_network_sha256,
        )

        def export(oke: components.Oke) -> None:
            pulumi.export(
                "oke",
                {
                    "schema_version": 1,
                    "region": context.configuration.region,
                    "cluster_id": oke.cluster_id,
                    "node_pool_id": oke.node_pool_id,
                },
            )

        result.apply(export)
    else:
        network = components.register_network(
            *args, envelope=context.envelope, commit=context.expected_commit
        )
        output = network.outputs
        pulumi.export("network_stack_identity", context.contract.stack_identity)
        pulumi.export(
            "network",
            dict(
                schema_version=output.schema_version,
                account_id=output.account_id,
                region=output.region,
                compartment_id=output.compartment_id,
                cidrs=output.cidrs,
                ids=output.ids,
            ),
        )


def execute(
    root: Path, args: argparse.Namespace, credentials: Callable[[], dict[str, str]]
) -> None:
    """One stack per approval; serialize both units without an implicit network update."""
    try:
        root = root.resolve()
        driver._enabled(root, True)
        require(args.unit in UNITS)
        if args.check:
            driver.check(root, args, True)
            return
        lock = _private(root, ".infra/operations/oci-dependency.apply.lock")
        require(lock.parent.is_dir())
        with os.fdopen(os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600), "a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            driver.execute(root, args, credentials, True)
    except Exception:
        raise ValueError(MESSAGE) from None
