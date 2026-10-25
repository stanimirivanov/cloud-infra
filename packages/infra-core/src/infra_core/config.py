"""Small shared configuration contracts; no cloud lookups or environment access."""

import re
from dataclasses import dataclass
from enum import StrEnum


class Provider(StrEnum):
    OCI = "oci"
    CLOUDFLARE = "cloudflare"
    SUPABASE = "supabase"
    AWS = "aws"
    GCP = "gcp"


def _identifier(value: str, field: str) -> None:
    if not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", value):
        raise ValueError(f"{field} must use lowercase letters, digits and single hyphens")


@dataclass(frozen=True, slots=True)
class AccountConfig:
    """Logical account reference; secrets and entitlements belong to later phases."""

    name: str
    provider: Provider
    account_id: str
    home_region: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.name, "account name")
        if not isinstance(self.provider, Provider):
            raise ValueError("provider must be a Provider enum value")
        if not self.account_id.strip() or self.account_id != self.account_id.strip():
            raise ValueError("account_id must be a nonempty identifier without outer whitespace")
        if self.provider == Provider.OCI and not self.home_region:
            raise ValueError("OCI account requires an explicit home_region")
        if self.home_region is not None:
            _identifier(self.home_region, "home_region")


@dataclass(frozen=True, slots=True)
class UnitConfig:
    """One deployment unit belongs to one account and provider."""

    name: str
    account: AccountConfig

    def __post_init__(self) -> None:
        _identifier(self.name, "unit name")
