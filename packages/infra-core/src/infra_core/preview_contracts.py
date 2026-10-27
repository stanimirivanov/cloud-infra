"""Pure preview descriptions, not execution permits or operational approval."""

import hashlib
import json
import re
from dataclasses import asdict, dataclass

from infra_core.foundation import FoundationConfig


@dataclass(frozen=True)
class PreviewContract:
    """Versioned binding for later preview consumers; contains no credentials.

    Configuration digest binds backend, encryption, flags and the complete DAG.
    Dependency identities describe required committed stacks, not their outputs.
    Later admission must validate live evidence and dependency output contents.
    """

    schema_version: int
    unit: str
    stack_identity: str
    dependency_stacks: tuple[str, ...]
    configuration_sha256: str
    commit_sha: str
    preview_enabled: bool

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("PREVIEW001: unsupported preview contract schema")
        if not re.fullmatch(r"[a-f0-9]{40}", self.commit_sha):
            raise ValueError("PREVIEW001: explicit full commit SHA required")
        if not re.fullmatch(r"[a-f0-9]{64}", self.configuration_sha256):
            raise ValueError("PREVIEW001: explicit configuration SHA-256 required")
        # Reuse the closed foundation identity rules without granting authority.
        prefix = "organization/free-infrastructure/"
        names = {"oci-network", "oci-oke", "cloudflare-edge", "supabase-database"}
        dependencies = (prefix + "oci-network",) if self.unit == "oci-oke" else ()
        if (
            self.unit not in names
            or self.stack_identity != prefix + self.unit
            or self.dependency_stacks != dependencies
            or type(self.preview_enabled) is not bool
        ):
            raise ValueError("PREVIEW001: invalid stack identity, dependencies or preview flag")

    @property
    def digest(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()


def describe_preview(config: FoundationConfig, unit_name: str, commit_sha: str) -> PreviewContract:
    """Describe even a disabled unit; callers must never treat this as admission."""
    units = {unit.name: unit for unit in config.units}
    if unit_name not in units:
        raise ValueError("PREVIEW001: unknown preview unit")
    unit = units[unit_name]
    return PreviewContract(
        schema_version=1,
        unit=unit.name,
        stack_identity=unit.stack_identity,
        dependency_stacks=tuple(units[name].stack_identity for name in unit.depends_on),
        configuration_sha256=config.digest,
        commit_sha=commit_sha,
        preview_enabled=unit.preview_enabled,
    )
