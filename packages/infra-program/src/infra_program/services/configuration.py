"""Configuration-backed library factory; normal program/deployment remains disabled."""

from copy import deepcopy
from typing import Any

import pulumi
from infra_core.services.governance import audit

from infra_program.services.components import Services, register_services


def register_services_from_config(
    config: dict[str, Any], evidence: dict[str, Any], profile: dict[str, Any]
) -> Services:
    """Audit before lookup; require every secret before delegating to composition."""
    frozen_config, frozen_evidence, frozen_profile = deepcopy((config, evidence, profile))
    proposal = audit(frozen_config, frozen_evidence, frozen_profile)
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
    return register_services(frozen_config, frozen_evidence, frozen_profile, token, passwords)
