"""Closed source capability catalog; no SDK imports, discovery or execution authority."""

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from infra_core.foundation import load_foundation

PROVIDERS = (
    "oci",
    "cloudflare",
    "supabase",
    "aws",
    "gcp",
    "neon",
    "flyio",
    "render",
    "vercel",
    "netlify",
)


@dataclass(frozen=True, slots=True)
class Capability:
    provider: str
    sdk_binding: str | None
    classification: tuple[str, ...]
    collection: tuple[str, ...]
    components: tuple[str, ...]
    units: tuple[str, ...]
    limitations: tuple[str, ...]


CATALOG = (
    Capability(
        "oci",
        "pulumi-oci",
        ("A1 compute", "boot/block volumes", "Basic OKE", "reviewed networking"),
        ("tenancy compute/volume inventory", "backend posture", "usage observations"),
        ("network", "Basic OKE node pools"),
        ("oci-network", "oci-oke"),
        (
            "Usage observations do not establish an authoritative completeness watermark.",
            "Object storage, backups and other ancillary costs require separate review.",
            "No standalone VM or application bucket component.",
        ),
    ),
    Capability(
        "cloudflare",
        "pulumi-cloudflare",
        ("DNS-only A/AAAA/CNAME records",),
        ("existing-zone DNS inventory",),
        ("records in an existing zone",),
        ("cloudflare-edge",),
        (
            "Free-plan entitlement requires independent review.",
            "Zone creation, Workers, Pages, R2 and Tunnel are unsupported.",
        ),
    ),
    Capability(
        "supabase",
        "pulumi-supabase",
        ("Nano projects in existing Free organizations",),
        ("management project inventory",),
        ("Free projects",),
        ("supabase-database",),
        (
            "Database sizes and usage need supplemental operator observations.",
            "Branches, SQL migrations and application integration are unsupported.",
        ),
    ),
    *(
        Capability(
            name,
            None,
            (),
            (),
            (),
            (),
            ("No reviewed SDK binding, classification, collector or component.",),
        )
        for name in PROVIDERS[3:]
    ),
)


def validate_catalog(catalog: tuple[Capability, ...]) -> None:
    """Reject inconsistent source metadata before producing any partial report."""
    if (
        type(catalog) is not tuple
        or any(type(item) is not Capability for item in catalog)
        or len(catalog) != len(PROVIDERS)
        or {item.provider for item in catalog} != set(PROVIDERS)
    ):
        raise ValueError("CAP001: invalid provider capability catalog")
    units: set[str] = set()
    for item in catalog:
        groups = (
            item.classification,
            item.collection,
            item.components,
            item.units,
            item.limitations,
        )
        if (
            any(
                type(group) is not tuple or any(type(v) is not str or not v.strip() for v in group)
                for group in groups
            )
            or any(len(set(group)) != len(group) for group in groups)
            or not item.limitations
            or (
                item.sdk_binding is not None
                and (
                    type(item.sdk_binding) is not str or not item.sdk_binding.startswith("pulumi-")
                )
            )
            or (bool(item.components) != bool(item.units))
            or (item.components and (not item.sdk_binding or not item.classification))
            or (item.sdk_binding is None and any(groups[:4]))
            or units.intersection(item.units)
        ):
            raise ValueError("CAP001: inconsistent provider capability metadata")
        units.update(item.units)


def inspect(root: Path, provider: str | None = None) -> dict[str, Any]:
    """Report source support and validated foundation flags, not live readiness."""
    validate_catalog(CATALOG)
    if provider is not None and provider not in PROVIDERS:
        raise ValueError("CAP002: unknown provider selection")
    foundation = load_foundation(root)
    expected = {unit: item.provider for item in CATALOG for unit in item.units}
    if expected != {unit.name: unit.provider.value for unit in foundation.units}:
        raise ValueError("CAP001: capability catalog and configured units disagree")
    entries = []
    for item in CATALOG:
        if provider is not None and item.provider != provider:
            continue
        entry = asdict(item)
        entry["support"] = "partial" if item.components else "unsupported"
        entry["units"] = [
            {
                "name": unit.name,
                "stack": unit.stack,
                # load_foundation rejects any enabled value other than False.
                "foundation_enabled": False,
                "preview_enabled": unit.preview_enabled,
                "depends_on": list(unit.depends_on),
            }
            for unit in foundation.units
            if unit.name in item.units
        ]
        entries.append(entry)
    return {
        "schema_version": 1,
        "kind": "provider-capabilities",
        "basis": "repository-source-and-foundation-configuration",
        "sdk_installation_checked": False,
        "live_controls_verified": False,
        "execution_authorized": False,
        "activation_authorized": False,
        "providers": entries,
    }
