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


@dataclass(frozen=True)
class FoundationConfig:
    backend: BackendConfig
    pulumi_version: str
    qualification_ttl_hours: int
    units: tuple[DeploymentUnit, ...]
    secrets_provider: str

    def __post_init__(self) -> None:
        if self.secrets_provider != "passphrase":
            raise ValueError("SECRET001: only explicit passphrase encryption is supported")

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
    }:
        raise ValueError("unexpected/missing foundation configuration fields")
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != 2
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
        units.append(DeploymentUnit(name, Provider(unit["provider"]), unit["stack"]))
    if not units or len({unit.stack for unit in units}) != len(units):
        raise ValueError("deployment stack identities must be nonempty and distinct")
    return FoundationConfig(
        BackendConfig(**backend_data),
        data["pulumi_version"],
        ttl,
        tuple(units),
        data["secrets_provider"],
    )


def _validate_unit(name: str, unit: dict[str, Any]) -> None:
    if not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", name):
        raise ValueError("invalid deployment unit name")
    if (
        not isinstance(unit, dict)
        or set(unit) != {"provider", "stack", "enabled"}
        or unit["enabled"] is not False
    ):
        raise ValueError("all resource deployment units must remain explicitly disabled in PR 2")
    if unit["stack"] != name:
        raise ValueError("stack must equal the reviewed unit identity")
    Provider(unit["provider"])


def deny_deployment(config: FoundationConfig, unit_name: str) -> None:
    if unit_name not in {unit.name for unit in config.units}:
        raise ValueError("unknown deployment unit")
    raise RuntimeError(
        f"{unit_name}: resource preview/deployment is disabled; backend qualification, "
        "governance and adoption PRs are required. Qualification is not deployment authorization."
    )
