"""In-memory GitHub REST fixture; never creates actual notifications or issues."""

from copy import deepcopy
from datetime import timedelta

import pytest
from infra_core import incidents as i
from infra_core.monitor_delivery import GitHub
from test_incidents import BINDING, NOW, UNIT, cycle

POLICY = dict(
    repository="owner/repo",
    repository_id=42,
    notification_actor_id=7,
    notification_actor_login="monitor-bot",
)


class Remote:
    def __init__(self):
        self.issues = []
        self.comments = {}
        self.writes = []
        self.fail_after_write = False
        self.actor = dict(id=7, login="monitor-bot")

    def call(self, method, endpoint, payload=None):
        if endpoint == "user":
            return self.actor
        if endpoint == "repos/owner/repo":
            return dict(id=42, full_name="owner/repo")
        if method == "GET":
            if "/comments?" in endpoint:
                return deepcopy(
                    self.comments.get(int(endpoint.split("/issues/")[1].split("/")[0]), [])
                )
            if "/issues?" in endpoint:
                return deepcopy(self.issues)
            pytest.fail("unexpected GET")
        self.writes.append((method, endpoint, payload))
        if method == "POST" and endpoint.endswith("/issues"):
            result = dict(
                number=len(self.issues) + 1,
                user=self.actor.copy(),
                body=payload["body"],
                state="open",
            )
            self.issues.append(result)
        elif method == "POST":
            number = int(endpoint.split("/issues/")[1].split("/")[0])
            result = dict(user=self.actor.copy(), body=payload["body"])
            self.comments.setdefault(number, []).append(result)
        else:
            number = int(endpoint.rsplit("/", 1)[1])
            result = next(v for v in self.issues if v["number"] == number)
            result.update(payload)
        if self.fail_after_write:
            self.fail_after_write = False
            raise TimeoutError("PRIVATE lost acknowledgement")
        return deepcopy(result)


@pytest.fixture
def remote(tmp_path, monkeypatch):
    api = GitHub(tmp_path, POLICY, "synthetic-token")
    service = Remote()
    monkeypatch.setattr(api, "call", service.call)
    return api, service


def event(level="critical"):
    return cycle(i.empty(UNIT, BINDING), level)["pending"][0]


def test_grouping_dedup_and_recovery_create_comment_close(remote):
    api, service = remote
    first = event()
    api.send(first)
    assert len(service.issues) == 1
    before = len(service.writes)
    api.send(first)
    assert len(service.writes) == before
    state = cycle(i.empty(UNIT, BINDING), "critical")
    next_state = cycle(state, "normal", seconds=2)
    api.send(next_state["pending"][-1])
    assert len(service.issues) == 1 and service.issues[0]["state"] == "closed"
    assert len(service.comments[1]) == 1
    assert "PRIVATE" not in service.issues[0]["body"]


@pytest.mark.parametrize("change", [False, True])
def test_lost_acknowledgement_is_found_before_repeating_write(remote, change):
    api, service = remote
    current = event()
    if change:
        api.send(current)
        current = cycle(cycle(i.empty(UNIT, BINDING), "warning"), "critical", seconds=2)["pending"][
            -1
        ]
    service.fail_after_write = True
    with pytest.raises(TimeoutError):
        api.send(current)
    before = len(service.writes)
    api.send(current)
    assert len(service.writes) == before
    assert len(service.issues) == 1


def test_wrong_actor_and_duplicate_owned_issues_fail_before_writes(remote):
    api, service = remote
    service.actor = dict(id=999, login="imposter")
    with pytest.raises(ValueError):
        api.send(event())
    assert not service.writes
    service.actor = dict(id=7, login="monitor-bot")
    api.send(event())
    service.issues.append(dict(service.issues[0], number=2))
    before = len(service.writes)
    with pytest.raises(ValueError):
        api.send(event())
    assert len(service.writes) == before


def test_incomplete_pagination_never_creates_issue(tmp_path, monkeypatch):
    api = GitHub(tmp_path, POLICY, "synthetic-token")

    def call(method, endpoint, payload=None):
        assert method == "GET"
        if endpoint == "user":
            return dict(id=7, login="monitor-bot")
        if endpoint == api.base:
            return dict(id=42, full_name="owner/repo")
        return [
            dict(number=n, user=dict(id=99, login="other"), body="unrelated") for n in range(100)
        ]

    monkeypatch.setattr(api, "call", call)
    with pytest.raises(ValueError):
        api.send(event())


def test_watchdog_does_not_repeat_missing_and_recovery_transitions(remote):
    api, service = remote
    alarm = event("unknown")
    api.send(alarm, channel="watchdog")
    before = len(service.writes)
    api.send(alarm, channel="watchdog")
    assert len(service.writes) == before
    recovery = cycle(cycle(i.empty(UNIT, BINDING), "unknown"), "normal", seconds=2)["pending"][-1]
    api.send(recovery, channel="watchdog")
    api.send(alarm, channel="watchdog")
    assert (
        service.issues[0]["state"] == "open"
    )  # a recurring outage is not suppressed by an old marker
    api.send(recovery, channel="watchdog")
    assert service.issues[0]["state"] == "closed"


def job(unit, clock=None, conclusion="success"):
    clock = clock or NOW.isoformat()
    return dict(
        name="Observe (" + unit + ")",
        run_id=100,
        head_sha="a" * 40,
        steps=[
            dict(
                name="Persist admitted monitoring snapshot",
                status="completed",
                conclusion=conclusion,
                started_at=clock,
                completed_at=clock,
            )
        ],
    )


@pytest.mark.parametrize(
    "fault", [None, "missing", "failed", "queued", "stale", "future", "truncated", "wrong-sha"]
)
def test_hosted_watchdog_requires_successful_fresh_persistence(tmp_path, monkeypatch, fault):
    api = GitHub(tmp_path, POLICY, "synthetic-token")
    jobs = [job(unit) for unit in sorted(i.UNITS)]
    if fault == "missing":
        jobs = []
    elif fault == "failed":
        jobs[0]["steps"][0]["conclusion"] = "failure"
    elif fault == "queued":
        jobs[0]["steps"] = []
    elif fault == "stale":
        jobs[0]["steps"][0]["completed_at"] = (NOW - timedelta(seconds=61)).isoformat()
        jobs[0]["steps"][0]["started_at"] = (NOW - timedelta(seconds=61)).isoformat()
    elif fault == "future":
        jobs[0]["steps"][0]["completed_at"] = (NOW + timedelta(seconds=1)).isoformat()
    elif fault == "wrong-sha":
        jobs[0]["head_sha"] = "b" * 40

    def call(method, path, payload=None):
        assert method == "GET"
        if path == api.base:
            return dict(id=42, full_name="owner/repo")
        if "/workflows/" in path:
            return dict(
                workflow_runs=[
                    dict(
                        id=100,
                        repository=dict(id=42),
                        head_branch="main",
                        event="schedule",
                        head_sha="a" * 40,
                        path=".github/workflows/monitor.yml",
                    )
                ]
            )
        return dict(total_count=len(jobs) + (1 if fault == "truncated" else 0), jobs=jobs)

    monkeypatch.setattr(api, "call", call)
    if fault in {"future", "wrong-sha", "truncated"}:
        with pytest.raises(ValueError):
            api.heartbeats(now=NOW, max_age_seconds=60)
    else:
        result = api.heartbeats(now=NOW, max_age_seconds=60)
        assert set(result) == i.UNITS
        assert (
            all(s == "normal" for s in result.values())
            if fault is None
            else "unknown" in result.values()
        )


def test_gh_transport_never_puts_tokens_in_argv_or_inherits_proxy(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from infra_core import monitor_delivery as module

    monkeypatch.setenv("HTTPS_PROXY", "https://PRIVATE.example")
    seen = []

    def run(args, **options):
        seen.append((args, options))
        return SimpleNamespace(returncode=0, stdout=b'{"id":42,"full_name":"owner/repo"}')

    monkeypatch.setattr(module.subprocess, "run", run)
    api = GitHub(tmp_path, POLICY, "PRIVATE-token")
    api.verify()
    args, options = seen[0]
    assert "PRIVATE" not in str(args) and options["env"]["GH_TOKEN"] == "PRIVATE-token"
    assert "HTTPS_PROXY" not in options["env"] and options["timeout"] <= 20
