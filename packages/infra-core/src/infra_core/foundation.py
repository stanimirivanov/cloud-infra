"""Explicit backend configuration and disabled stack identities; no network calls."""

import hashlib
import json
import re
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

from infra_core.config import Provider


@dataclass(frozen=True)
class BackendConfig:
    bucket: str
    prefix: str
    region: str
    endpoint: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", self.bucket):
            raise ValueError("backend bucket must be an explicit safe S3 bucket name")
        if not re.fullmatch(r"pulumi(?:/[a-z0-9-]+)*", self.prefix):
            raise ValueError("backend prefix must be pulumi or a child; external state is excluded")
        if not re.fullmatch(r"[a-z]{2}-[a-z]+-[1-9][0-9]*", self.region):
            raise ValueError("backend region must be an explicit OCI region")
        endpoint = urlsplit(self.endpoint)
        if (
            endpoint.scheme != "https"
            or endpoint.netloc != endpoint.hostname
            or endpoint.path
            or endpoint.query
            or endpoint.fragment
            or not re.fullmatch(
                rf"[a-z0-9]+\.compat\.objectstorage\.{re.escape(self.region)}\.oraclecloud\.com",
                endpoint.hostname or "",
            )
        ):
            raise ValueError(
                "backend endpoint must be the regional OCI HTTPS S3-compatible endpoint"
            )

    def url(self, run_id: str | None = None) -> str:
        prefix = self.prefix
        if run_id is not None:
            if not re.fullmatch(r"[a-f0-9]{32}", run_id):
                raise ValueError("qualification run ID must be a generated UUID hex value")
            prefix += f"/qualification/{run_id}"
        query = urlencode(
            {
                "endpoint": urlsplit(self.endpoint).hostname,
                "region": self.region,
                "s3ForcePathStyle": "true",
            }
        )
        return f"s3://{self.bucket}/{prefix}?{query}"


@dataclass(frozen=True)
class DeploymentUnit:
    name: str
    provider: Provider
    stack: str
    project: str
    preview_enabled: bool
    depends_on: tuple[str, ...]

    @property
    def stack_identity(self) -> str:
        """Project-scoped DIY backend identity; never an ambient stack selection."""
        return f"organization/{self.project}/{self.stack}"


@dataclass(frozen=True)
class FoundationConfig:
    backend: BackendConfig
    pulumi_version: str
    qualification_ttl_hours: int
    units: tuple[DeploymentUnit, ...]
    secrets_provider: str
    project: str

    def __post_init__(self) -> None:
        if self.secrets_provider != "passphrase":
            raise ValueError("SECRET001: only explicit passphrase encryption is supported")
        if self.project != "free-infrastructure":
            raise ValueError("STACK001: unsupported Pulumi project identity")
        _validate_units(self.units, self.project)

    @property
    def digest(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()


def load_foundation(root: Path) -> FoundationConfig:
    with (root / "config/pulumi.toml").open("rb") as stream:
        data = tomllib.load(stream)
    if set(data) != {
        "schema_version",
        "pulumi_version",
        "qualification_ttl_hours",
        "secrets_provider",
        "backend",
        "units",
        "project",
    }:
        raise ValueError("unexpected/missing foundation configuration fields")
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != 3
        or not isinstance(data["pulumi_version"], str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", data["pulumi_version"])
    ):
        raise ValueError("unsupported foundation schema or unpinned Pulumi CLI version")
    ttl = data["qualification_ttl_hours"]
    if type(ttl) is not int or not 1 <= ttl <= 24:
        raise ValueError("qualification TTL must be between 1 and 24 hours")
    backend_data = data["backend"]
    if (
        not isinstance(backend_data, dict)
        or set(backend_data) != {"bucket", "prefix", "region", "endpoint"}
        or not all(isinstance(value, str) for value in backend_data.values())
    ):
        raise ValueError("backend fields must be the four reviewed strings")
    if not isinstance(data["units"], dict):
        raise ValueError("units must be named configuration tables")
    units = []
    for name, unit in data["units"].items():
        _validate_unit(name, unit)
        units.append(
            DeploymentUnit(
                name,
                Provider(unit["provider"]),
                unit["stack"],
                data["project"],
                unit["preview_enabled"],
                tuple(unit["depends_on"]),
            )
        )
    return FoundationConfig(
        BackendConfig(**backend_data),
        data["pulumi_version"],
        ttl,
        tuple(units),
        data["secrets_provider"],
        data["project"],
    )


def _validate_unit(name: str, unit: dict[str, Any]) -> None:
    if not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", name):
        raise ValueError("invalid deployment unit name")
    if (
        not isinstance(unit, dict)
        or set(unit) != {"provider", "stack", "enabled", "preview_enabled", "depends_on"}
        or unit["enabled"] is not False
    ):
        raise ValueError("STACK001: all resource deployment units must remain explicitly disabled")
    if unit["stack"] != name:
        raise ValueError("stack must equal the reviewed unit identity")
    if (
        type(unit["preview_enabled"]) is not bool
        or not isinstance(unit["depends_on"], list)
        or any(not isinstance(value, str) for value in unit["depends_on"])
    ):
        raise ValueError("STACK001: preview_enabled must be boolean and depends_on a string array")
    Provider(unit["provider"])


def _validate_units(units: tuple[DeploymentUnit, ...], project: str) -> None:
    expected = {
        "oci-network": Provider.OCI,
        "oci-oke": Provider.OCI,
        "cloudflare-edge": Provider.CLOUDFLARE,
        "supabase-database": Provider.SUPABASE,
    }
    by_name = {unit.name: unit for unit in units}
    if len(by_name) != len(units) or set(by_name) != set(expected):
        raise ValueError("STACK001: exactly the four reviewed distinct units are required")
    if len({unit.stack_identity for unit in units}) != len(units):
        raise ValueError("STACK001: duplicate stack identities")
    for unit in units:
        if (
            unit.project != project
            or unit.stack != unit.name
            or unit.provider != expected[unit.name]
            or type(unit.preview_enabled) is not bool
            or not isinstance(unit.depends_on, tuple)
            or any(not isinstance(name, str) for name in unit.depends_on)
        ):
            raise ValueError("STACK001: invalid reviewed unit identity or preview fields")
        if len(set(unit.depends_on)) != len(unit.depends_on) or any(
            name not in by_name for name in unit.depends_on
        ):
            raise ValueError("STACK002: unknown or duplicate dependency")

    visited: set[str] = set()
    active: set[str] = set()

    def visit(name: str) -> None:
        if name in active:
            raise ValueError("STACK002: dependency cycle")
        if name not in visited:
            active.add(name)
            for dependency in by_name[name].depends_on:
                visit(dependency)
            active.remove(name)
            visited.add(name)

    for name in sorted(by_name):
        visit(name)
    for unit in units:
        dependencies = ("oci-network",) if unit.name == "oci-oke" else ()
        if unit.depends_on != dependencies:
            raise ValueError("STACK002: only OKE may depend on the network stack")


def deny_deployment(config: FoundationConfig, unit_name: str) -> None:
    if unit_name not in {unit.name for unit in config.units}:
        raise ValueError("unknown deployment unit")
    raise RuntimeError(
        f"{unit_name}: resource preview/deployment is disabled; backend qualification, "
        "governance and adoption PRs are required. Qualification is not deployment authorization."
    )
