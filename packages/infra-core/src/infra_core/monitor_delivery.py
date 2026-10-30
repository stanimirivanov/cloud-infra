"""One explicit GitHub issue sink with owned markers and bounded REST enumeration."""

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from infra_core import incidents as i
from infra_core import operations
from infra_core.governance.contracts import timestamp


class GitHub:
    def __init__(self, root: Path, policy: dict[str, Any], token: str):
        i.require(type(token) is str and bool(token) and len(token) <= 4096)
        self.root, self.policy, self.token = root, policy, token
        self.base = "repos/" + policy["repository"]
        self.deadline = time.monotonic() + 180

    def call(self, method: str, endpoint: str, payload: dict[str, Any] | None = None) -> Any:
        i.require(
            method in {"GET", "POST", "PATCH"}
            and (endpoint.startswith(self.base) or (method == "GET" and endpoint == "user"))
            and 0 < len(endpoint) < 1024
            and time.monotonic() < self.deadline
        )
        env = dict(
            PATH=os.environ.get("PATH", os.defpath),
            GH_TOKEN=self.token,
            GH_HOST="github.com",
            GH_PROMPT_DISABLED="1",
            NO_COLOR="1",
        )
        args = [
            "gh",
            "api",
            "--hostname",
            "github.com",
            "--method",
            method,
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            endpoint,
        ]
        if payload is not None:
            args += ["--input", "-"]
        completed = subprocess.run(
            args,
            input=operations.encoded(payload) if payload is not None else None,
            cwd=self.root,
            env=env,
            capture_output=True,
            timeout=min(20, max(0.01, self.deadline - time.monotonic())),
            check=False,
        )
        i.require(completed.returncode == 0 and len(completed.stdout) <= 8 * operations.MAX_BYTES)
        import json

        value = json.loads(completed.stdout, object_pairs_hook=operations._pairs)
        operations.encoded(value)
        return value

    def verify(self) -> None:
        repo = self.call("GET", self.base)
        i.require(
            repo["id"] == self.policy["repository_id"]
            and repo["full_name"].lower() == self.policy["repository"].lower()
        )

    def pages(self, endpoint: str) -> list[dict[str, Any]]:
        rows = []
        for page in range(1, 6):
            values = self.call(
                "GET", endpoint + ("&" if "?" in endpoint else "?") + f"per_page=100&page={page}"
            )
            i.require(
                type(values) is list and len(values) <= 100 and all(type(v) is dict for v in values)
            )
            rows += values
            if len(values) < 100:
                return rows
        raise ValueError(i.MESSAGE)  # never create/update from an incomplete search

    def owned(self, value: dict[str, Any]) -> bool:
        return bool(
            value.get("user", {}).get("id") == self.policy["notification_actor_id"]
            and value.get("user", {}).get("login") == self.policy["notification_actor_login"]
        )

    def send(self, event: dict[str, Any], *, channel: str = "observations") -> None:
        i._event(event)
        i.require(
            type(self.policy["notification_actor_id"]) is int
            and self.policy["notification_actor_id"] > 0
            and type(self.policy["notification_actor_login"]) is str
            and bool(self.policy["notification_actor_login"])
        )
        actor = self.call("GET", "user")
        i.require(
            actor["id"] == self.policy["notification_actor_id"]
            and actor["login"] == self.policy["notification_actor_login"]
        )
        i.require(channel in {"observations", "watchdog"})
        self.verify()
        key = operations.digest(
            dict(repository_id=self.policy["repository_id"], unit=event["unit"], channel=channel)
        )
        marker = "<!-- cloud-infra-monitor:" + key + " -->"
        event_marker = "<!-- cloud-infra-event:" + event["id"] + " -->"
        candidates = [
            v
            for v in self.pages(self.base + "/issues?state=all&sort=created&direction=desc")
            if "pull_request" not in v
            and self.owned(v)
            and type(v.get("body")) is str
            and v["body"].splitlines()[:1] == [marker]
        ]
        i.require(len(candidates) <= 1)
        heading = f"Monitoring {event['unit']} ({channel})"
        lines = [
            marker,
            event_marker,
            f"{event['transition']}: {event['severity']}",
            "Observed: " + event["at"],
            f"Run: https://github.com/{self.policy['repository']}/actions/runs/{event['run_id']}",
        ]
        for name, counts in sorted(event["counts"].items()):
            lines.append(name + ": " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        body = "\n\n".join(lines)
        # Normal recovery without an existing incident needs no new issue.
        if not candidates:
            if event["severity"] == "normal":
                return
            created = self.call("POST", self.base + "/issues", dict(title=heading, body=body))
            i.require(
                self.owned(created) and type(created["number"]) is int and created["number"] > 0
            )
            return
        issue = candidates[0]
        number = issue["number"]
        i.require(type(number) is int and number > 0 and issue["state"] in {"open", "closed"})
        endpoint = self.base + "/issues/" + str(number)
        comments = self.pages(endpoint + "/comments")
        seen = event_marker in issue["body"].splitlines() or any(
            self.owned(c) and event_marker in str(c.get("body", "")).splitlines() for c in comments
        )
        if not seen:
            posted = self.call("POST", endpoint + "/comments", dict(body=body))
            i.require(self.owned(posted) and event_marker in posted["body"].splitlines())
        desired = "closed" if event["severity"] == "normal" else "open"
        if issue["state"] != desired:
            updated = self.call("PATCH", endpoint, dict(state=desired, body=body))
            i.require(updated["state"] == desired)

    def heartbeats(self, *, now: Any, max_age_seconds: int) -> dict[str, str]:
        """Independent hosted read sensor; only completed persistence steps count."""
        self.verify()
        runs = self.call(
            "GET", self.base + "/actions/workflows/monitor.yml/runs?branch=main&per_page=10&page=1"
        )
        i.require(type(runs.get("workflow_runs")) is list and len(runs["workflow_runs"]) <= 10)
        latest: dict[str, Any] = {}
        for run in runs["workflow_runs"]:
            i.require(
                type(run["id"]) is int
                and run["id"] > 0
                and run["repository"]["id"] == self.policy["repository_id"]
                and run["head_branch"] == "main"
                and run["event"] in {"schedule", "workflow_dispatch"}
                and re.fullmatch("[a-f0-9]{40}", run["head_sha"]) is not None
                and run["path"].split("@")[0] == ".github/workflows/monitor.yml"
            )
            jobs = self.call(
                "GET",
                self.base + f"/actions/runs/{run['id']}/jobs?filter=all&per_page=100&page=1",
            )
            i.require(
                type(jobs["jobs"]) is list and jobs["total_count"] == len(jobs["jobs"]) <= 100
            )
            for job in jobs["jobs"]:
                if job["name"] not in {"Observe (" + unit + ")" for unit in i.UNITS}:
                    continue
                i.require(job["run_id"] == run["id"] and job["head_sha"] == run["head_sha"])
                unit = job["name"][9:-1]
                steps = [
                    s for s in job["steps"] if s["name"] == "Persist admitted monitoring snapshot"
                ]
                if (
                    len(steps) != 1
                    or steps[0]["conclusion"] != "success"
                    or steps[0]["status"] != "completed"
                ):
                    continue
                clock = timestamp(steps[0]["started_at"], "persistence step start")
                completed = timestamp(steps[0]["completed_at"], "persistence step completion")
                i.require(clock <= completed <= now)
                latest[unit] = max(latest.get(unit, clock), clock)
        return {
            unit: "normal"
            if unit in latest and 0 <= (now - latest[unit]).total_seconds() <= max_age_seconds
            else "unknown"
            for unit in sorted(i.UNITS)
        }
