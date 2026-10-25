"""Synthetic evidence constructors; never valid operational observations."""


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
