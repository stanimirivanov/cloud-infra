"""Configuration-backed library factory; normal program/deployment remains disabled."""

from copy import deepcopy
from typing import Any

import pulumi
from infra_core.service_evidence import validate_service_evidence

from infra_program.services.components import Services, register_services


def register_services_from_config(
    config: dict[str, Any],
    evidence: bytes,
    profile: dict[str, Any],
    *,
    envelope: bytes,
    commit: str,
) -> Services:
    """Audit before lookup; require every secret before delegating to composition."""
    frozen_config, frozen_profile = deepcopy((config, profile))
    proposal = validate_service_evidence(
        frozen_config, frozen_profile, evidence, envelope, commit=commit
    )
    secrets = pulumi.Config(proposal["unit"])
    token = secrets.require_secret("token")
    passwords = (
        {
            item["key"]: secrets.require_secret("databasePassword-" + item["key"])
            for item in proposal["resources"]
        }
        if proposal["provider"] == "supabase"
        else {}
    )
    # Recheck frozen evidence immediately before registration; secret lookup grants no authority.
    return register_services(
        frozen_config, evidence, frozen_profile, token, passwords, envelope=envelope, commit=commit
    )
