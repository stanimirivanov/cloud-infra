"""Synthetic evidence constructors; never valid operational observations."""

from copy import deepcopy


def upgrade_inventory(inventory, home):
    identity = inventory["account_id"]
    inventory.update(
        schema_version=2,
        collection_started_at=inventory["observed_at"],
        collection_completed_at=inventory["observed_at"],
        coverage={
            "regions": [home],
            "compartments": [identity],
            "availability_domains": {home: ["synthetic-ad"]},
            "queries": [
                {
                    "operation": op,
                    "region": home,
                    "compartment": identity,
                    "availability_domain": ad,
                    # Raw resource counts include terminated records discarded by fixtures.
                    "count": 1
                    if op in {"regions", "ads"}
                    else 0
                    if op in {"compartments", "virtual_pools"}
                    else 100,
                }
                for op, ad in [
                    ("regions", None),
                    ("compartments", None),
                    ("ads", None),
                    ("instances", None),
                    ("volumes", None),
                    ("clusters", None),
                    ("virtual_pools", None),
                    ("boots", "synthetic-ad"),
                ]
            ],
        },
    )
    if inventory.get("usage"):
        inventory["usage"]["covered_through"] = inventory["usage"]["observed_at"]


def recovery_metrics():
    return {
        "checkpoint_sha256": "a" * 64,
        "checkpoint_bytes": 100,
        "backup_age_seconds": 0.1,
        "restore_seconds": 0.1,
    }


def administration_responses(policy, commit):
    """Synthetic metadata shared by the standalone and signed cutover harnesses."""
    base = "https://api.github.com/repos/" + policy["repository"]
    responses = {
        "repository": {
            "id": policy["repository_id"],
            "full_name": policy["repository"],
            "default_branch": "main",
        },
        "branch": {"name": "main", "protected": True, "commit": {"sha": commit}},
        "protection": {
            "url": base + "/branches/main/protection",
            "enforce_admins": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
            "required_status_checks": {
                "strict": True,
                "checks": deepcopy(policy["required_checks"]),
            },
            "required_pull_request_reviews": {
                "required_approving_review_count": 1,
                "dismiss_stale_reviews": True,
                "require_last_push_approval": True,
            },
        },
        "environment": {
            "id": 11,
            "name": policy["environment"],
            "url": base + "/environments/" + policy["environment"],
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [{"type": "User", "reviewer": {"id": 7}}],
                }
            ],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        },
        "branches": {
            "total_count": 1,
            "branch_policies": [{"id": 9, "name": "main", "type": "branch"}],
        },
        "checks": {
            item["context"]: {
                "total_count": 1,
                "check_runs": [
                    {
                        "id": index + 100,
                        "name": item["context"],
                        "head_sha": commit,
                        "app": {"id": item["app_id"]},
                        "check_suite": {"id": 21},
                        "status": "completed",
                        "conclusion": "success",
                        "started_at": "2026-01-01T00:00:01Z",
                        "completed_at": "2026-01-01T00:00:02Z",
                    }
                ],
            }
            for index, item in enumerate(policy["required_checks"])
        },
        "workflow_runs": {
            "total_count": 1,
            "workflow_runs": [
                {
                    "id": 22,
                    "workflow_id": policy["workflow"]["id"],
                    "path": policy["workflow"]["path"],
                    "head_sha": commit,
                    "head_branch": "main",
                    "event": "push",
                    "check_suite_id": 21,
                    "repository": {"id": policy["repository_id"]},
                    "head_repository": {"id": policy["repository_id"]},
                    "status": "completed",
                    "conclusion": "success",
                    "created_at": "2026-01-01T00:00:00Z",
                    "run_started_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:03Z",
                }
            ],
        },
    }
    pull = {
        "id": 30,
        "number": 31,
        "state": "closed",
        "merged": True,
        "merge_commit_sha": commit,
        "base": {
            "ref": "main",
            "repo": {"id": policy["repository_id"], "full_name": policy["repository"]},
        },
        "head": {"sha": "b" * 40},
        "user": {"id": 32, "type": "User"},
        "merged_by": {"id": 33, "type": "User"},
        "created_at": "2025-12-31T23:58:00Z",
        "merged_at": "2025-12-31T23:59:00Z",
        "closed_at": "2025-12-31T23:59:00Z",
    }
    responses["pull_requests"] = {"items": [deepcopy(pull)]}
    responses["pull_request"] = pull
    responses["reviews"] = {
        "items": [
            {
                "id": 40,
                "user": {"id": 34, "type": "User"},
                "state": "APPROVED",
                "author_association": "COLLABORATOR",
                "commit_id": pull["head"]["sha"],
                "pull_request_url": base + "/pulls/31",
                "submitted_at": "2025-12-31T23:58:30Z",
            }
        ]
    }
    return responses
