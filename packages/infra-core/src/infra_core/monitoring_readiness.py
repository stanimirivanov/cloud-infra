"""Offline durable incident-state inspection; no collector, lock or delivery calls."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from infra_core import incidents, operations
from infra_core.cutover import repository_state
from infra_core.readiness import digest, parsed, private, read

MESSAGE = "MONREADY001: monitoring readiness input rejected; private diagnostics withheld"


def require(condition: bool) -> None:
    if not condition:
        raise ValueError(MESSAGE)


def check(
    root: Path,
    *,
    unit: str,
    binding_sha256: str,
    heartbeat_seconds: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    try:
        return _check(root, unit, binding_sha256, heartbeat_seconds, now or datetime.now(UTC))
    except (
        ValueError,
        RuntimeError,
        OSError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
    ) as error:
        raise ValueError(MESSAGE) from error


def _check(
    root: Path, unit: str, binding: str, heartbeat_seconds: int, now: datetime
) -> dict[str, Any]:
    require(unit in incidents.UNITS and operations._hash(binding))
    require(type(heartbeat_seconds) is int and 1 <= heartbeat_seconds <= 3600)
    require(now.tzinfo is not None)
    commit, clean = repository_state(root)
    require(clean)
    path = private(root, f".infra/monitoring/state/{unit}.json")
    raw = read(path) if path.exists() else None
    gaps = []
    summary: dict[str, Any] | None = None
    if raw is None:
        gaps.append("state-missing")
    else:
        state = incidents.validate(parsed(raw))
        require(state["unit"] == unit and state["binding"] == binding)
        clocks = [state[k] for k in ("started_at", "last_observed_at") if state[k] is not None]
        clocks += [event["at"] for event in state["pending"]]
        if state["last_transition"] is not None:
            clocks.append(state["last_transition"]["at"])
        require(all(operations._time(value) <= now for value in clocks))
        if state["phase"] == "idle":
            gaps.append("state-unobserved")
        elif state["phase"] == "running":
            gaps.append("unfinished-run-requires-reconciliation")
        observed = state["last_observed_at"]
        if observed is None:
            gaps.append("heartbeat-missing")
        elif now - operations._time(observed) > timedelta(
            seconds=heartbeat_seconds
        ) or now > operations._time(state["next_due_at"]):
            gaps.append("heartbeat-overdue")
        if any(not source["available"] for source in state["sources"].values()):
            gaps.append("source-unavailable")
        if any("unknown" in source["values"].values() for source in state["sources"].values()):
            gaps.append("unknown-findings")
        if state["severity"] != "normal" or any(
            level in {"warning", "critical"}
            for source in state["sources"].values()
            for level in source["values"].values()
        ):
            gaps.append("active-incident")
        if state["pending"]:
            gaps.append("outbox-pending")
        if state["delivery_error"]:
            gaps.append("delivery-error")
        summary = {
            "phase": state["phase"],
            "stage": state["stage"],
            "severity": state["severity"],
            "pending_events": len(state["pending"]),
            "delivery_enabled": state["delivery_enabled"],
        }
    require(repository_state(root) == (commit, True))
    # Revalidate the path too: absence and parent symlinks must not change silently.
    require(private(root, f".infra/monitoring/state/{unit}.json") == path)
    require(not path.exists() if raw is None else read(path) == raw)
    return {
        "schema_version": 1,
        "status": "pending",
        "unit": unit,
        "commit": commit,
        "state_sha256": None if raw is None else digest(raw),
        "binding_sha256": binding,
        "heartbeat_seconds": heartbeat_seconds,
        "state_evidence": "missing" if raw is None else "inputs-consistent",
        "state_summary": summary,
        "gaps": gaps,
        "remaining_reviews": [
            "durable runner custody, actor enrollment, scopes and observation thresholds",
            "fresh producer evidence and signed drift admission for every cycle",
            "independent watchdog and runner/storage outage rehearsal",
            "GitHub bot permissions, recipient subscriptions and real delivery/recovery",
        ],
        "activation_authorized": False,
        "execution_authorized": False,
        "live_controls_verified": False,
    }
