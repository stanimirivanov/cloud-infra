"""Grouped monitoring transitions and a durable local outbox; never resource authority."""

import fcntl
import json
import os
import re
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from infra_core import operations
from infra_core.governance.contracts import timestamp

MESSAGE = "MON001: monitoring rejected; diagnostics withheld"
PERSISTENCE = "MON002: monitor persistence uncertain; inspect durable state before retrying"
SOURCES = {"cost", "health", "drift"}
UNITS = {"oci-network", "oci-oke", "cloudflare-edge", "supabase-database"}
LEVELS = {"normal": 0, "warning": 1, "unknown": 2, "critical": 3}


def require(value: bool) -> None:
    if not value:
        raise ValueError(MESSAGE)


def parsed(raw: bytes) -> dict[str, Any]:
    require(type(raw) is bytes and 0 < len(raw) <= operations.MAX_BYTES)
    value = json.loads(raw, object_pairs_hook=operations._pairs)
    json.dumps(value, allow_nan=False)
    require(type(value) is dict)
    assert isinstance(value, dict)
    return value


def source(
    available: bool, values: dict[str, str], evidence: dict[str, str] | None = None
) -> dict[str, Any]:
    require(
        type(available) is bool
        and type(values) is dict
        and len(values) <= 128
        and all(operations._hash(k) and v in LEVELS for k, v in values.items())
        and (not available or bool(values))
    )
    if evidence is not None:
        require(
            type(evidence) is dict
            and 0 < len(evidence) <= 128
            and operations._hash(evidence.get("report_sha256"))
        )
        for key, value in evidence.items():
            require(type(key) is str and re.fullmatch(r"[a-z0-9/_-]{1,160}", key) is not None)
            if key == "report_sha256":
                continue
            if key.endswith("/month"):
                require(
                    type(value) is str
                    and re.fullmatch(r"[0-9]{4}-(0[1-9]|1[0-2])", value) is not None
                )
            else:
                timestamp(value, "source evidence clock")
    return dict(available=available, values=values, evidence=evidence)


def empty(unit: str, binding: str) -> dict[str, Any]:
    require(unit in UNITS and operations._hash(binding))
    return dict(
        schema_version=1,
        unit=unit,
        binding=binding,
        run_number=0,
        run_id=None,
        phase="idle",
        stage="pending",
        drift_report=None,
        last_observed_at=None,
        next_due_at=None,
        started_at=None,
        generation=0,
        summary_sha256=None,
        severity="normal",
        sources={s: source(False, {}) for s in sorted(SOURCES)},
        delivery_enabled=False,
        delivery_error=False,
        pending=[],
        last_transition=None,
    )


def _event(value: dict[str, Any]) -> None:
    require(
        type(value) is dict
        and set(value)
        == {"id", "generation", "run_id", "unit", "at", "severity", "transition", "counts"}
    )
    require(
        operations._hash(value["id"])
        and type(value["generation"]) is int
        and value["generation"] > 0
        and value["unit"] in UNITS
        and value["severity"] in LEVELS
        and value["transition"] in {"open", "change", "recovery", "baseline"}
        and type(value["run_id"]) is str
        and re.fullmatch(r"[0-9]{1,20}", value["run_id"]) is not None
    )
    operations._time(value["at"])
    require(type(value["counts"]) is dict and set(value["counts"]) == SOURCES)
    for counts in value["counts"].values():
        require(
            type(counts) is dict
            and set(counts) == set(LEVELS)
            and all(type(n) is int and 0 <= n <= 130 for n in counts.values())
        )


def validate(value: dict[str, Any]) -> dict[str, Any]:
    require(type(value) is dict and set(value) == set(empty(value["unit"], value["binding"])))
    require(
        type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and type(value["run_number"]) is int
        and value["run_number"] >= 0
        and value["phase"] in {"idle", "running", "complete"}
        and value["stage"] in {"pending", "drift-complete", "collecting", "complete"}
        and (value["drift_report"] is None or type(value["drift_report"]) is dict)
        and value["severity"] in LEVELS
        and type(value["generation"]) is int
        and value["generation"] >= 0
        and type(value["delivery_enabled"]) is bool
        and type(value["delivery_error"]) is bool
        and (value["summary_sha256"] is None or operations._hash(value["summary_sha256"]))
    )
    require(
        (value["run_number"] == 0 and value["run_id"] is None and value["phase"] == "idle")
        or (
            value["run_number"] > 0
            and type(value["run_id"]) is str
            and re.fullmatch(r"[0-9]{1,20}", value["run_id"]) is not None
            and value["phase"] != "idle"
        )
    )
    for key in ("last_observed_at", "next_due_at", "started_at"):
        if value[key] is not None:
            operations._time(value[key])
    require(type(value["sources"]) is dict and set(value["sources"]) == SOURCES)
    for record in value["sources"].values():
        require(type(record) is dict and set(record) == {"available", "values", "evidence"})
        source(record["available"], record["values"], record["evidence"])
    require(type(value["pending"]) is list and len(value["pending"]) <= 128)
    for event in value["pending"]:
        _event(event)
        require(event["unit"] == value["unit"] and event["generation"] <= value["generation"])
    require(
        len({e["id"] for e in value["pending"]}) == len(value["pending"])
        and [e["generation"] for e in value["pending"]]
        == sorted(e["generation"] for e in value["pending"])
    )
    if value["phase"] == "idle":
        require(value == empty(value["unit"], value["binding"]))
    else:
        require(value["started_at"] is not None)
        if value["last_observed_at"] is not None:
            require(
                value["next_due_at"] is not None
                and operations._time(value["next_due_at"])
                > operations._time(value["last_observed_at"])
            )
        if value["phase"] == "complete":
            require(
                value["stage"] == "complete"
                and value["last_observed_at"] is not None
                and operations._time(value["started_at"])
                <= operations._time(value["last_observed_at"])
            )
        else:
            require(value["stage"] != "complete")
    if value["last_transition"] is not None:
        _event(value["last_transition"])
    return value


def begin(
    state: dict[str, Any], run_number: int, run_id: str, now: datetime
) -> dict[str, Any] | None:
    validate(state)
    require(
        type(run_number) is int
        and run_number > 0
        and type(run_id) is str
        and re.fullmatch(r"[0-9]{1,20}", run_id) is not None
    )
    if run_number == state["run_number"]:
        require(run_id == state["run_id"] and state["phase"] == "complete")
        return None
    require(run_number > state["run_number"] and run_id != state["run_id"])
    if state["started_at"] is not None:
        require(now >= operations._time(state["started_at"]))
    result = deepcopy(state)
    result.update(
        run_number=run_number,
        run_id=run_id,
        phase="running",
        stage="pending",
        drift_report=None,
        started_at=now.isoformat(),
    )
    return validate(result)


def commit(
    state: dict[str, Any],
    observations: dict[str, dict[str, Any]],
    *,
    now: datetime,
    heartbeat_seconds: int,
    delivery: bool,
) -> dict[str, Any]:
    validate(state)
    require(
        state["phase"] == "running"
        and type(heartbeat_seconds) is int
        and 1 <= heartbeat_seconds <= 3600
        and type(delivery) is bool
        and set(observations) == SOURCES
        and now >= operations._time(state["started_at"])
    )
    result = deepcopy(state)
    for name, incoming in observations.items():
        source(incoming["available"], incoming["values"], incoming["evidence"])
        old = state["sources"][name]
        merged = dict(incoming["values"]) if incoming["available"] else dict(old["values"])
        available = incoming["available"]
        if available:
            for key, previous in old["values"].items():
                if key not in merged and previous != "normal":
                    merged[key] = previous
                    available = False  # absence cannot resolve a known incident
                elif merged.get(key) == "unknown" and previous == "critical":
                    merged[key] = previous
                    available = False
        result["sources"][name] = source(
            available, merged, incoming["evidence"] if available else old["evidence"]
        )
    late = state["next_due_at"] is not None and now > operations._time(state["next_due_at"])
    counts: dict[str, dict[str, int]] = {}
    for name, record in result["sources"].items():
        counts[name] = {
            level: sum(v == level for v in record["values"].values()) for level in LEVELS
        }
        if not record["available"]:
            counts[name]["unknown"] += 1
    if late:
        counts["drift"]["unknown"] += 1
    severity = max(
        (k for totals in counts.values() for k, n in totals.items() if n), key=LEVELS.__getitem__
    )
    signature = operations.digest(
        dict(
            sources={
                k: {"available": v["available"], "values": v["values"]}
                for k, v in result["sources"].items()
            },
            late=late,
        )
    )
    changed = signature != state["summary_sha256"]
    activation = delivery and not state["delivery_enabled"] and state["generation"] > 0
    if (changed and (severity != "normal" or state["severity"] != "normal")) or activation:
        result["generation"] += 1
        event = dict(
            id=operations.digest(
                dict(
                    unit=state["unit"],
                    binding=state["binding"],
                    generation=result["generation"],
                    summary=signature,
                )
            ),
            generation=result["generation"],
            run_id=state["run_id"],
            unit=state["unit"],
            at=now.isoformat(),
            severity=severity,
            transition="baseline"
            if activation
            else "recovery"
            if severity == "normal"
            else "open"
            if state["severity"] == "normal"
            else "change",
            counts=counts,
        )
        result["last_transition"] = event
        if delivery:
            require(len(result["pending"]) < 128)
            result["pending"].append(event)
    result.update(
        phase="complete",
        stage="complete",
        last_observed_at=now.isoformat(),
        next_due_at=(now + timedelta(seconds=heartbeat_seconds)).isoformat(),
        severity=severity,
        summary_sha256=signature,
        delivery_enabled=delivery,
    )
    return validate(result)


def normalize(
    name: str,
    report: dict[str, Any] | None,
    *,
    unit: str,
    scope_hash: str | None,
    commit: str,
    now: datetime,
    max_age_seconds: int,
) -> dict[str, Any]:
    """Closed producer adapters: timestamps cannot be refreshed by wrapping a result."""
    try:
        require(
            name in SOURCES
            and report is not None
            and report["unit"] == unit
            and 0 < max_age_seconds <= 900
        )
        assert report is not None
        require(type(report["schema_version"]) is int and report["schema_version"] == 1)
        if name != "drift":
            require(
                report["deployment_authorized"] is False
                and report["remediation_authorized"] is False
            )

        def fresh(raw: object) -> None:
            age = (now - timestamp(raw, "observation clock")).total_seconds()
            require(0 <= age <= max_age_seconds)

        values: dict[str, str] = {}

        def add(key: str, value: str) -> None:
            require(type(key) is str and 0 < len(key) <= 512 and value in LEVELS)
            identity = operations.digest(dict(source=name, key=key))
            require(identity not in values)
            values[identity] = value

        if name == "cost":
            require(
                report["kind"] == "operational-findings" and report["scope_sha256"] == scope_hash
            )
            fresh(report["evaluated_at"])
            fresh(report["source_clocks"]["observed_at"])
            for row in report["findings"]:
                add(row["id"], row["status"])
        elif name == "health":
            require(
                report["kind"] == "infrastructure-health"
                and report["scope_sha256"] == scope_hash
                and report["mode"] == "observe"
                and report["cluster_isolation_verified"] is False
            )
            fresh(report["completed_at"])
            for row in [*report["endpoints"], *report["cluster"]]:
                status = {"healthy": "normal", "unhealthy": "critical", "unknown": "unknown"}[
                    row["status"]
                ]
                try:
                    fresh(
                        row["observed_at"]
                        if row["source"] == "operator-supplied"
                        else row["completed_at"]
                    )
                except (ValueError, KeyError, TypeError):
                    status = "unknown"
                add(row["id"], status)
        else:
            require(
                report["kind"] == "isolated-drift"
                and report["commit"] == commit
                and report["remediation_authorized"] is False
                and report["production_state_write_authorized"] is False
            )
            fresh(report["started_at"])
            fresh(report["completed_at"])
            require(
                timedelta(0)
                <= timestamp(report["completed_at"], "end")
                - timestamp(report["started_at"], "start")
                <= timedelta(seconds=305)
            )
            status = {"clean": "normal", "drifted": "critical", "unknown": "unknown"}[
                report["status"]
            ]
            if status != "unknown":
                require(
                    report["source_unchanged"] is True
                    and report["local_checkpoint_unchanged"] is True
                    and operations._hash(report["journal_head"])
                    and operations._hash(report["approval_sha256"])
                )
            add("drift", status)
        provenance = {"report_sha256": operations.digest(report)}

        def clocks(prefix: str, mapping: dict[str, Any]) -> None:
            for key, value in mapping.items():
                if value is None:
                    continue
                label = prefix + key
                try:
                    if key == "month":
                        require(
                            type(value) is str
                            and re.fullmatch(r"[0-9]{4}-(0[1-9]|1[0-2])", value) is not None
                        )
                    else:
                        timestamp(value, "source clock")
                    provenance[label] = value
                except (ValueError, TypeError):
                    pass

        clocks(
            "report/",
            {k: report[k] for k in ("started_at", "completed_at", "evaluated_at") if k in report},
        )
        for key in ("source_clocks", "cluster_source_clocks"):
            if type(report.get(key)) is dict:
                clocks(key + "/", report[key])
        if name == "cost":
            windows = report.get("usage_windows", {})
            clocks("usage/", {k: v for k, v in windows.items() if type(v) is not dict})
            for key, value in windows.items():
                if type(value) is dict:
                    clocks("usage/" + key + "/", value)
        return source(True, values, provenance)
    except (ValueError, KeyError, TypeError):
        return source(False, {})


class Store:
    def __init__(self, root: Path, unit: str):
        require(unit in UNITS)
        self.path = root.absolute() / ".infra/monitoring/state" / (unit + ".json")
        require(not any(p.is_symlink() for p in (self.path, *self.path.parents)))

    @contextmanager
    def locked(self) -> Iterator["Store"]:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock = self.path.with_suffix(".lock")
        with os.fdopen(os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600), "a") as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError(MESSAGE) from None
            yield self

    def _read(self) -> bytes:
        with self.path.open("rb") as stream:
            return stream.read(operations.MAX_BYTES + 1)

    def read(self, binding: str) -> dict[str, Any]:
        value = (
            validate(parsed(self._read())) if self.path.exists() else empty(self.path.stem, binding)
        )
        require(value["binding"] == binding and value["unit"] == self.path.stem)
        return value

    def save(self, state: dict[str, Any]) -> None:
        payload = operations.encoded(validate(state))
        require(len(payload) <= operations.MAX_BYTES)
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.path.parent, delete=False) as stream:
                temporary = stream.name
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            raise RuntimeError(PERSISTENCE) from None
        finally:
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)

    def deliver(
        self, state: dict[str, Any], send: Callable[[dict[str, Any]], None]
    ) -> dict[str, Any]:
        validate(state)
        while state["pending"]:
            try:
                send(deepcopy(state["pending"][0]))
            except Exception:
                state = deepcopy(state)
                state["delivery_error"] = True
                self.save(state)
                raise ValueError(MESSAGE) from None
            state = deepcopy(state)
            state["pending"].pop(0)
            state["delivery_error"] = False
            self.save(state)  # lost acknowledgement leaves the previous event retryable
        return state
