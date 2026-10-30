"""Offline account evidence consistency; never entitlement or deployment authority."""

import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infra_core import inventory_evidence, service_evidence
from infra_core.cutover import repository_state
from infra_core.governance.audit import audit
from infra_core.readiness import digest, parsed, private, read

PROVIDERS = {
    "oci-network": "oci",
    "oci-oke": "oci",
    "cloudflare-edge": "cloudflare",
    "supabase-database": "supabase",
}
MESSAGE = "AREADY001: account readiness input rejected; private diagnostics withheld"


def require(condition: bool) -> None:
    if not condition:
        raise ValueError(MESSAGE)


def check(
    root: Path,
    evidence: Path | None = None,
    *,
    unit: str,
    account_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    try:
        return _check(root, evidence, unit, account_id, now or datetime.now(UTC))
    except (
        ValueError,
        RuntimeError,
        OSError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        OverflowError,
    ) as error:
        raise ValueError(MESSAGE) from error


def _check(
    root: Path, evidence: Path | None, unit: str, account_id: str, now: datetime
) -> dict[str, Any]:
    require(
        unit in PROVIDERS
        and type(account_id) is str
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}", account_id) is not None
    )
    commit, clean = repository_state(root)
    require(clean)
    captures: dict[Path, bytes] = {}

    def capture(path: Path) -> bytes:
        raw = read(path)
        if path in captures:
            require(captures[path] == raw)
        captures[path] = raw
        return raw

    profiles_raw = capture(root / "config/quotas/profiles.toml")
    profiles = tomllib.loads(profiles_raw.decode())["profiles"]
    provider = PROVIDERS[unit]
    profile = profiles[provider + "-free"]
    status = "pending"
    if evidence is not None:
        index = parsed(capture(private(root, str(evidence))))
        require(
            set(index)
            == {"schema_version", "unit", "commit", "configuration", "observation", "proposal"}
            and type(index["schema_version"]) is int
            and index["schema_version"] == 1
            and index["unit"] == unit
            and index["commit"] == commit
        )
        require(type(index["configuration"]) is str and type(index["observation"]) is str)
        paths = [
            index["configuration"],
            index["observation"],
            index["observation"] + ".envelope.json",
        ]
        if provider == "oci":
            require(type(index["proposal"]) is str)
            paths.append(index["proposal"])
        else:
            require(index["proposal"] is None)
        require(len(set(paths)) == len(paths) and str(evidence) not in paths)
        raw = {path: capture(private(root, path)) for path in paths}
        configuration = parsed(raw[index["configuration"]])
        require(configuration["account_id"] == account_id and configuration["provider"] == provider)
        payload, envelope = raw[index["observation"]], raw[index["observation"] + ".envelope.json"]
        if provider == "oci":
            require(configuration["profile"] == "oci-free")
            proposal = parsed(raw[index["proposal"]])
            require(
                type(proposal["units"]) is list
                and unit in {row["name"] for row in proposal["units"]}
                and {row["name"] for row in proposal["units"]} <= {"oci-network", "oci-oke"}
            )
            inventory = inventory_evidence.validate_inventory_evidence(
                configuration,
                profile,
                payload,
                envelope,
                commit=commit,
                now=now,
            )
            audit(configuration, profile, inventory, proposal, now=now)
        else:
            require(configuration["unit"] == unit)
            service_evidence.validate_service_evidence(
                configuration,
                profile,
                payload,
                envelope,
                commit=commit,
                now=now,
            )
        status = "account-evidence-consistent"
    require(repository_state(root) == (commit, True))
    require(all(read(path) == raw for path, raw in captures.items()))
    return {
        "schema_version": 1,
        "status": "pending",
        "unit": unit,
        "provider": provider,
        "commit": commit,
        "profiles_sha256": digest(profiles_raw),
        "account_evidence": status,
        "remaining_reviews": [
            "independent live free-tier entitlement and other-service/billing review",
            "effective read-only credentials and complete account/organization coverage",
            "original usage watermarks, billing-cycle anchors and source authenticity",
            "reviewed proposed growth, replacement peaks and shared-account reservations",
        ],
        "account_ready": False,
        "execution_authorized": False,
        "activation_authorized": False,
        "live_controls_verified": False,
    }
