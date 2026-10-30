"""Offline Supabase staging inputs; no provider registration or activation authority."""

import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infra_core import encrypted_configuration, service_evidence
from infra_core.cutover import repository_state
from infra_core.foundation import load_foundation
from infra_core.readiness import digest, parsed, private, read

UNIT = "supabase-database"
MESSAGE = "STAGE001: Supabase staging input rejected; private diagnostics withheld"


def require(condition: bool) -> None:
    if not condition:
        raise ValueError(MESSAGE)


def check(
    root: Path,
    configuration: Path,
    evidence: Path,
    encrypted: Path,
    *,
    account_id: str,
    scope_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    try:
        return _check(
            root, configuration, evidence, encrypted, account_id, scope_id, now or datetime.now(UTC)
        )
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
    root: Path,
    configuration: Path,
    evidence: Path,
    encrypted: Path,
    account_id: str,
    scope_id: str,
    now: datetime,
) -> dict[str, Any]:
    commit, clean = repository_state(root)
    require(clean)
    paths = [
        private(root, str(path))
        for path in (configuration, evidence, encrypted, Path(str(evidence) + ".envelope.json"))
    ]
    require(len(set(paths)) == len(paths))
    paths += [
        root / name
        for name in (
            "config/quotas/profiles.toml",
            "config/pulumi.toml",
            "config/service-apply.json",
        )
    ]
    captured = {path: read(path) for path in paths}
    proposal = parsed(captured[paths[0]])
    require(
        proposal["provider"] == "supabase"
        and proposal["unit"] == UNIT
        and type(account_id) is str
        and bool(account_id)
        and proposal["account_id"] == account_id
        and type(scope_id) is str
        and bool(scope_id)
        and proposal["scope_id"] == scope_id
    )
    profiles = tomllib.loads(captured[paths[4]].decode())["profiles"]
    service_evidence.validate_service_evidence(
        proposal,
        profiles["supabase-free"],
        captured[paths[1]],
        captured[paths[3]],
        commit=commit,
        now=now,
    )
    keys = {UNIT + ":token"} | {
        UNIT + ":databasePassword-" + row["key"] for row in proposal["resources"]
    }
    encrypted_configuration.validate(captured[paths[2]], keys)
    foundation = load_foundation(root)
    unit = next(u for u in foundation.units if u.name == UNIT)
    gate = parsed(captured[paths[6]])
    require(
        set(gate) == {"schema_version", "units"}
        and type(gate["schema_version"]) is int
        and gate["schema_version"] == 2
        and type(gate["units"]) is dict
        and set(gate["units"]) == {"cloudflare-edge", UNIT}
        and all(type(value) is bool for value in gate["units"].values())
    )
    require(repository_state(root) == (commit, True))
    require(all(read(path) == raw for path, raw in captured.items()))
    return {
        "schema_version": 1,
        "status": "pending",
        "unit": UNIT,
        "commit": commit,
        "staging_evidence": "inputs-consistent",
        "proposal_sha256": digest(captured[paths[0]]),
        "encrypted_configuration_sha256": digest(captured[paths[2]]),
        "foundation_sha256": foundation.digest,
        "profiles_sha256": digest(captured[paths[4]]),
        "preview_enabled": unit.preview_enabled,
        "apply_enabled": gate["units"][UNIT],
        "remaining_reviews": [
            "live organization/Free eligibility, token scope and password custody/readback",
            "protected execution, qualified backend, independent backup and writer exclusion",
            "verified parameterized provider, exact saved plan and signed operation admission",
            "post-state project reconciliation; application data, schema and RLS review separately",
        ],
        "activation_authorized": False,
        "execution_authorized": False,
        "live_controls_verified": False,
    }
