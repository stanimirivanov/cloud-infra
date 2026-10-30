"""Protected monitor composition; scheduled calls retain signed drift admission."""

import argparse
import io
import os
import re
from collections.abc import Callable, Mapping
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infra_core import administration, health, operational_findings, operations
from infra_core import incidents as i
from infra_core.administration import private_path
from infra_core.backup import host_id
from infra_core.cutover import repository_state
from infra_core.monitor_delivery import GitHub

POLICY = "config/monitoring-runner.json"


def settings(root: Path) -> dict[str, Any]:
    value = i.parsed((root / POLICY).read_bytes())
    i.require(
        set(value)
        == {
            "schema_version",
            "enabled",
            "delivery_enabled",
            "repository",
            "repository_id",
            "heartbeat_seconds",
            "notification_actor_id",
            "notification_actor_login",
            "scheduled_actor_id",
            "scheduled_actor_login",
            "state_host_sha256",
        }
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["enabled"] is True
        and operations._hash(value["state_host_sha256"])
        and type(value["delivery_enabled"]) is bool
        and type(value["repository"]) is str
        and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value["repository"]) is not None
        and type(value["repository_id"]) is int
        and value["repository_id"] > 0
        and type(value["heartbeat_seconds"]) is int
        and 1 <= value["heartbeat_seconds"] <= 3600
    )
    if value["delivery_enabled"]:
        i.require(
            type(value["notification_actor_id"]) is int
            and value["notification_actor_id"] > 0
            and type(value["notification_actor_login"]) is str
            and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", value["notification_actor_login"]) is not None
        )
    return value


def gate(root: Path, source: Mapping[str, str], *, watchdog: bool = False) -> dict[str, Any]:
    value = settings(root)
    i.require(
        source["GITHUB_REF"] == "refs/heads/main"
        and source["GITHUB_REPOSITORY"] == value["repository"]
        and source["GITHUB_REPOSITORY_ID"] == str(value["repository_id"])
        and re.fullmatch("[a-f0-9]{40}", source["GITHUB_SHA"]) is not None
        and repository_state(root) == (source["GITHUB_SHA"], True)
    )
    event = source["GITHUB_EVENT_NAME"]
    i.require(event in {"workflow_dispatch", "schedule"})
    if event == "workflow_dispatch":
        i.require(source["GITHUB_ACTOR"] == source["GITHUB_REPOSITORY_OWNER"])
    else:
        i.require(
            type(value["scheduled_actor_id"]) is int
            and value["scheduled_actor_id"] > 0
            and source["GITHUB_ACTOR_ID"] == str(value["scheduled_actor_id"])
            and source["GITHUB_ACTOR"] == value["scheduled_actor_login"]
        )
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_NUMBER"):
        i.require(re.fullmatch(r"[0-9]{1,20}", source[key]) is not None and int(source[key]) > 0)
    environment = "monitor-watchdog" if watchdog else source["MONITOR_UNIT"] + "-monitor"
    i.require(source["MONITOR_ENVIRONMENT"] == environment)
    if not watchdog:
        i.require(source["MONITOR_UNIT"] in i.UNITS and host_id() == value["state_host_sha256"])
    administration.collect_operation_environment(
        root,
        repository=value["repository"],
        repository_id=value["repository_id"],
        environment=environment,
        commit=source["GITHUB_SHA"],
    )
    return value


def read(root: Path, name: str | Path) -> dict[str, Any]:
    path = private_path(root, Path(name))
    with path.open("rb") as stream:
        return i.parsed(stream.read(operations.MAX_BYTES + 1))


def catalog(root: Path, source: Mapping[str, str]) -> tuple[dict[str, Any], str, dict[str, str]]:
    value = read(root, source["MONITOR_INDEX"])
    i.require(
        set(value)
        == {
            "schema_version",
            "unit",
            "cost_index",
            "health_index",
            "drift_bundle",
            "max_age_seconds",
        }
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["unit"] == source["MONITOR_UNIT"]
        and type(value["max_age_seconds"]) is int
        and 0 < value["max_age_seconds"] <= 900
    )
    cost, healthy = (read(root, value[k]) for k in ("cost_index", "health_index"))
    cs, hs = cost["scope"], healthy["scope"]
    i.require(cs["unit"] == hs["unit"] == value["unit"] and cs["account_id"] == hs["account_id"])
    i.require(
        cs["scope_id"] == (hs["region"] if value["unit"].startswith("oci-") else hs["scope_id"])
    )
    scopes = dict(cost=operations.digest(cs), health=operations.digest(hs))
    if value["drift_bundle"] is not None:
        private_path(root, Path(value["drift_bundle"]))
    binding = operations.digest(
        dict(unit=value["unit"], scopes=scopes, repository_id=int(source["GITHUB_REPOSITORY_ID"]))
    )
    return value, binding, scopes


def drift_args(
    source: Mapping[str, str], index: dict[str, Any], *, checking: bool
) -> argparse.Namespace:
    return argparse.Namespace(
        unit=index["unit"],
        commit=source["GITHUB_SHA"],
        actor=source["GITHUB_ACTOR"],
        environment=source["MONITOR_ENVIRONMENT"],
        bundle=Path(index["drift_bundle"]),
        journal=Path(".infra/operations/" + index["unit"] + ".json"),
        check=checking,
        allow_local_writes=not checking,
    )


def initialize(root: Path, source: Mapping[str, str]) -> None:
    gate(root, source)
    i.require(
        source["GITHUB_EVENT_NAME"] == "workflow_dispatch"
        and source.get("MONITOR_ALLOW_INITIALIZE") == "true"
    )
    index, binding, _ = catalog(root, source)
    with i.Store(root, index["unit"]).locked() as store:
        i.require(not store.path.exists())
        store.save(i.empty(index["unit"], binding))


def preflight(root: Path, source: Mapping[str, str]) -> dict[str, Any]:
    gate(root, source)
    index, binding, _ = catalog(root, source)
    operational_findings.check(root, Path(index["cost_index"]))
    health.check(root, Path(index["health_index"]), network=False)
    store = i.Store(root, index["unit"])
    i.require(store.path.is_file())
    state = store.read(binding)  # read-only: no lock/file creation
    i.require(int(source["GITHUB_RUN_NUMBER"]) >= state["run_number"])
    if int(source["GITHUB_RUN_NUMBER"]) == state["run_number"]:
        i.require(state["run_id"] == source["GITHUB_RUN_ID"] and state["phase"] == "complete")
        return dict(drift_admitted=False, duplicate=True)
    admitted = False
    if index["drift_bundle"] is not None:
        from infra_program import drift

        try:
            drift.check(root, drift_args(source, index, checking=True))
            admitted = True
        except Exception:
            pass  # unavailable approval is a visible unknown, never credential admission
    return dict(drift_admitted=admitted, duplicate=False)


def run_drift(
    root: Path, source: Mapping[str, str], credentials: Callable[[], dict[str, str]]
) -> dict[str, Any]:
    gate(root, source)
    index, binding, _ = catalog(root, source)
    i.require(index["drift_bundle"] is not None)
    with i.Store(root, index["unit"]).locked() as store:
        i.require(store.path.is_file())
        state = store.read(binding)
        started = i.begin(
            state, int(source["GITHUB_RUN_NUMBER"]), source["GITHUB_RUN_ID"], datetime.now(UTC)
        )
        if started is None:
            return state
        store.save(started)
        report = None
        if index["drift_bundle"] is not None:
            from infra_program import drift

            output = None
            try:
                bundle = read(root, index["drift_bundle"])
                output = private_path(root, Path(bundle["output"]))
                i.require(not output.exists())
                rejected = False
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    try:
                        drift.execute(root, drift_args(source, index, checking=False), credentials)
                    except ValueError:
                        rejected = True  # only explicit unknown reports may survive rejection
                if output.exists():
                    report = read(root, output)
                    i.require(not rejected or report["status"] == "unknown")
            except Exception:
                report = None
        started["stage"] = "drift-complete"
        if report is not None:
            safe = {
                "schema_version",
                "kind",
                "unit",
                "commit",
                "remediation_authorized",
                "production_state_write_authorized",
                "started_at",
                "completed_at",
                "status",
                "source_unchanged",
                "local_checkpoint_unchanged",
                "journal_head",
                "approval_sha256",
            }
            started["drift_report"] = {k: v for k, v in report.items() if k in safe}
        store.save(started)
        return started


def _health(root: Path, index: str) -> dict[str, Any]:
    hidden = {}
    for key in list(os.environ):
        if key.startswith(("AWS_", "OCI_", "PULUMI_")) or any(
            word in key.upper()
            for word in ("TOKEN", "SECRET", "PASSWORD", "PASSPHRASE", "CREDENTIAL")
        ):
            hidden[key] = os.environ.pop(key)
    try:
        return health.check(root, Path(index), network=True)
    finally:
        os.environ.update(hidden)


def collect(root: Path, source: Mapping[str, str]) -> dict[str, Any]:
    config = gate(root, source)
    index, binding, scopes = catalog(root, source)
    with i.Store(root, index["unit"]).locked() as store:
        i.require(store.path.is_file())
        state = store.read(binding)
        started: dict[str, Any] | None
        if state["phase"] == "running" and state["run_id"] == source["GITHUB_RUN_ID"]:
            i.require(
                state["run_number"] == int(source["GITHUB_RUN_NUMBER"])
                and state["stage"] == "drift-complete"
            )
            started = state
        else:
            started = i.begin(
                state, int(source["GITHUB_RUN_NUMBER"]), source["GITHUB_RUN_ID"], datetime.now(UTC)
            )
        if started is None:
            return state  # duplicate run never repeats provider/network work
        started["stage"] = "collecting"
        store.save(started)  # interrupted observation cannot be replayed under this run identity
        reports: dict[str, dict[str, Any] | None] = {key: None for key in i.SOURCES}
        reports["drift"] = started["drift_report"]
        readers: tuple[tuple[str, Callable[[], dict[str, Any]]], ...] = (
            ("cost", lambda: operational_findings.check(root, Path(index["cost_index"]))),
            ("health", lambda: _health(root, index["health_index"])),
        )
        for name, call in readers:
            try:
                reports[name] = call()
            except Exception:
                reports[name] = None
        now = datetime.now(UTC)
        observations = {
            name: i.normalize(
                name,
                report,
                unit=index["unit"],
                scope_hash=scopes.get(name),
                commit=source["GITHUB_SHA"],
                now=now,
                max_age_seconds=index["max_age_seconds"],
            )
            for name, report in reports.items()
        }
        state = i.commit(
            started,
            observations,
            now=now,
            heartbeat_seconds=config["heartbeat_seconds"],
            delivery=config["delivery_enabled"]
            and source.get("MONITOR_DELIVERY_ENABLED") == "true",
        )
        store.save(state)
        return state


def deliver(root: Path, source: Mapping[str, str], token: Callable[[], str]) -> dict[str, Any]:
    config = gate(root, source)
    i.require(config["delivery_enabled"] and source.get("MONITOR_DELIVERY_ENABLED") == "true")
    index, binding, _ = catalog(root, source)
    with i.Store(root, index["unit"]).locked() as store:
        i.require(store.path.is_file())
        state = store.read(binding)
        if not state["pending"]:
            return state
        sink = GitHub(root, config, token())
        return store.deliver(state, sink.send)


def watchdog(
    root: Path,
    source: Mapping[str, str],
    *,
    delivery: bool = False,
    token: Callable[[], str] | None = None,
) -> dict[str, str]:
    config = gate(root, source, watchdog=True)
    now = datetime.now(UTC)
    reader = GitHub(root, config, source["GH_TOKEN"])
    latest: dict[str, str]
    try:
        latest = reader.heartbeats(now=now, max_age_seconds=config["heartbeat_seconds"])
    except Exception:
        latest = {unit: "unknown" for unit in sorted(i.UNITS)}
    if delivery:
        i.require(
            config["delivery_enabled"]
            and source.get("MONITOR_DELIVERY_ENABLED") == "true"
            and token is not None
        )
        assert token is not None
        sender = GitHub(root, config, token())
        for unit, status in latest.items():
            # The remote issue's open/closed state groups repeated missing-run signals.
            event = dict(
                id=operations.digest(dict(channel="watchdog", unit=unit, status=status)),
                generation=1,
                run_id=source["GITHUB_RUN_ID"],
                unit=unit,
                at=now.isoformat(),
                severity=status,
                transition="recovery" if status == "normal" else "open",
                counts={
                    name: {level: int(name == "drift" and level == status) for level in i.LEVELS}
                    for name in i.SOURCES
                },
            )
            sender.send(event, channel="watchdog")
    return latest


def credentials(source: Mapping[str, str], unit: str) -> dict[str, str]:
    names = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "PULUMI_CONFIG_PASSPHRASE"}
    if unit.startswith("oci-"):
        names |= {"OCI_USER_OCID", "OCI_FINGERPRINT", "OCI_PRIVATE_KEY_PATH"}
    if source.get("AWS_SESSION_TOKEN"):
        names.add("AWS_SESSION_TOKEN")
    return {name: source[name] for name in names}
