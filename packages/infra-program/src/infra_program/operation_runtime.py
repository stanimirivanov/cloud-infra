"""Closed service/OCI update commands; private bounded transport, never operational admission."""

import hashlib
import json
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from infra_core.operations import _pairs
from infra_core.preview_results import _EVENTS, MAX_EVENT_BYTES, MAX_EVENTS, PACK, RULE
from infra_core.services.governance import DNS, PROJECT

from infra_program.preview_runtime import CliRuntime, Wire, _events, _futures, _grpc

MESSAGE = "APPLY001: constrained resource operation rejected; diagnostics withheld"
ALLOWED = {"same", "create", "update", "read"}


def require(value: bool) -> None:
    if not value:
        raise ValueError(MESSAGE)


def validate_plan(raw: bytes, stack: str, version: str) -> None:
    require(0 < len(raw) <= 1024 * 1024)
    plan = json.loads(raw, object_pairs_hook=_pairs)
    require(plan["manifest"]["version"] == "v" + version)
    resources = plan["resourcePlans"]
    require(type(resources) is dict and bool(resources))
    unit = stack.split("/")[-1]
    prefix = f"urn:pulumi:{unit}::free-infrastructure::"
    provider = "cloudflare" if unit == "cloudflare-edge" else "supabase"
    require(unit in {"cloudflare-edge", "supabase-database"})
    types = {
        "pulumi:pulumi:Stack",
        "infrastructure:services:Independent",
        "pulumi:providers:" + provider,
        DNS if provider == "cloudflare" else PROJECT,
    }
    providers = {
        urn
        for urn, r in resources.items()
        if r.get("goal", {}).get("type") == "pulumi:providers:" + provider
    }
    components = {
        urn
        for urn, r in resources.items()
        if r.get("goal", {}).get("type") == "infrastructure:services:Independent"
    }
    roots = {
        urn
        for urn, r in resources.items()
        if r.get("goal", {}).get("type") == "pulumi:pulumi:Stack"
    }
    require(len(roots) == 1)
    for urn, resource in resources.items():
        require(
            urn.startswith(prefix)
            and type(resource["steps"]) is list
            and bool(resource["steps"])
            and set(resource["steps"]) <= ALLOWED
        )
        goal = resource["goal"]
        require(goal["type"] in types and urn.split("::")[-2].split("$")[-1] == goal["type"])
        if goal["type"] != "pulumi:pulumi:Stack":
            require(goal.get("protect") is True)
        if goal["type"] == "pulumi:providers:" + provider:
            require(goal.get("parent") in components)
        if goal["type"] == "infrastructure:services:Independent":
            require(goal.get("parent", "") in roots | {""})
        if goal["type"] in {DNS, PROJECT}:
            require(
                goal.get("parent") in components
                and any(goal.get("provider", "").startswith(p + "::") for p in providers)
            )


def validate_events(records: list[bytes], *, preview: bool, policy: Path) -> dict[str, int]:
    require(0 < len(records) <= MAX_EVENTS)
    previous, checks, terminal = -1, 0, False
    summary: dict[str, int] | None = None
    for raw in records:
        event = json.loads(raw, object_pairs_hook=_pairs)
        require(not terminal and type(event["sequence"]) is int and event["sequence"] > previous)
        previous = event["sequence"]
        kinds = set(event) - {"sequence", "timestamp"}
        require(len(kinds) == 1 and kinds <= _EVENTS)
        kind = next(iter(kinds))
        body = event[kind]
        require(type(body) is dict)
        if kind == "diagnosticEvent":
            require(body.get("severity") in {"debug", "info", "info#err", "warning"})
        elif kind.startswith("policy") and kind != "policyLoadEvent":
            require(body.get("policyPackName") == PACK and body.get("failed", []) == [])
            if kind == "policyAnalyzeSummaryEvent":
                require(body.get("passed") == [RULE])
                checks += 1
        elif kind == "summaryEvent":
            require(
                summary is None
                and body.get("isPreview") is preview
                and body.get("result") == "succeeded"
                and body.get("maybeCorrupt") is False
            )
            require(set(body["PolicyPacks"]) == {PACK + "|local|" + str(policy)})
            require(all(type(v) is str and 0 < len(v) <= 128 for v in body["PolicyPacks"].values()))
            counts = body["resourceChanges"]
            require(
                type(counts) is dict
                and bool(counts)
                and set(counts) <= ALLOWED
                and all(type(v) is int and v >= 0 for v in counts.values())
                and sum(counts.values()) > 0
            )
            summary = counts
        elif kind == "cancelEvent":
            require(summary is not None and body == {})
            terminal = True
    require(terminal and summary is not None and checks > 0)
    assert summary is not None
    return summary


class Runtime:
    def __init__(self, cli: CliRuntime, work: Path, env: dict[str, str], stack: str, policy: Path):
        self.cli, self.work, self.env, self.stack, self.policy = cli, work, dict(env), stack, policy
        require(
            stack
            in {
                "organization/free-infrastructure/" + u
                for u in ("cloudflare-edge", "supabase-database", "oci-network", "oci-oke")
            }
        )
        require(policy == Path(__file__).resolve().parents[4] / "policies")
        self.deadline = time.monotonic() + 300

    def _run(self, args: list[str]) -> None:
        self.cli.verify()
        remaining = self.deadline - time.monotonic()
        require(remaining > 0)
        process = subprocess.Popen(
            [str(self.cli.binary), *args, "--non-interactive", "--color=never"],
            cwd=self.work,
            env=self.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            require(process.wait(timeout=remaining) == 0)
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
        self.cli.verify()

    def select(self) -> None:
        self._run(["stack", "select", "--stack", self.stack])

    def checkpoint(self) -> str:
        path = self.work / "current.json"
        path.unlink(missing_ok=True)
        self._run(["stack", "export", "--file", str(path), "--stack", self.stack])
        require(path.stat().st_size <= 1024 * 1024)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def network_outputs(self) -> tuple[str, dict[str, Any]]:
        """Export only the fixed network stack; never refresh or reveal secrets."""
        require(self.stack.endswith(("/oci-network", "/oci-oke")))
        path = self.work / "network-checkpoint.json"
        path.unlink(missing_ok=True)
        self._run(
            [
                "stack",
                "export",
                "--file",
                str(path),
                "--stack",
                "organization/free-infrastructure/oci-network",
            ]
        )
        require(path.stat().st_size <= 1024 * 1024)
        raw = path.read_bytes()
        checkpoint = json.loads(raw, object_pairs_hook=_pairs)
        roots = [
            r for r in checkpoint["deployment"]["resources"] if r["type"] == "pulumi:pulumi:Stack"
        ]
        require(len(roots) == 1)
        outputs = roots[0]["outputs"]
        require(type(outputs) is dict and set(outputs) == {"network", "network_stack_identity"})
        return hashlib.sha256(raw).hexdigest(), outputs

    def operation(self, *, preview: bool) -> dict[str, int]:
        server = _grpc.server(
            _futures.ThreadPoolExecutor(max_workers=1),
            options=[("grpc.max_receive_message_length", MAX_EVENT_BYTES + 256)],
        )
        wire = Wire(lambda event: None)
        _events.add_EventsServicer_to_server(wire, server)
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        args = (
            ["preview"]
            if preview
            else ["up", "--yes", "--skip-preview", "--plan", str(self.work / "plan.json")]
        )
        args += [
            "--stack",
            self.stack,
            "--policy-pack",
            str(self.policy),
            "--parallel",
            "1",
            "--suppress-outputs",
            "--suppress-progress",
            "--config-file",
            str(self.work / "stack.yaml"),
            "--event-log",
            f"tcp://127.0.0.1:{port}",
            "--refresh=false",
        ]
        try:
            self._run(args)
            return validate_events(wire.records, preview=preview, policy=self.policy)
        finally:
            server.stop(0).wait()
