"""Explicit, reviewed OCI inputs. No latest-version or image fallback lookups."""

import ipaddress
import re
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from infra_core.governance.contracts import require, timestamp


@dataclass(frozen=True, slots=True)
class ImageEvidence:
    image_id: str
    region: str
    architecture: str
    kubernetes_version: str
    reviewed_at: str
    source: str

    def validate(self, region: str, version: str, now: datetime) -> None:
        require(
            self.image_id.startswith("ocid1.image.")
            and self.region == region
            and self.architecture == "aarch64"
            and self.kubernetes_version == version
            and bool(self.source.strip()),
            "OCI020",
            "explicit reviewed OKE ARM image must match region and Kubernetes version",
        )
        age = now - timestamp(self.reviewed_at, "image review")
        require(timedelta(0) <= age <= timedelta(days=30), "OCI020", "image review expired")


@dataclass(frozen=True, slots=True)
class FoundationConfig:
    name: str
    region: str
    compartment_id: str
    administrator_cidrs: tuple[str, ...]
    service_id: str
    service_cidr: str
    availability_domains: tuple[str, ...]
    kubernetes_version: str
    supported_versions: tuple[str, ...]
    image: ImageEvidence
    nodes: int = 2
    ocpus_per_node: int = 1
    memory_gb_per_node: int = 6
    boot_gb_per_node: int = 50
    max_pods_per_node: int = 10
    vcn_cidr: str = "10.0.0.0/16"
    api_cidr: str = "10.0.0.0/28"
    worker_cidr: str = "10.0.10.0/24"
    pod_cidr: str = "10.0.20.0/24"
    services_cidr: str = "10.96.0.0/16"

    def validate(self, *, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        require(now.tzinfo is not None, "OCI001", "review clock must have an explicit timezone")
        now = now.astimezone(UTC)
        require(
            all(
                isinstance(value, str)
                for value in (
                    self.name,
                    self.region,
                    self.compartment_id,
                    self.service_id,
                    self.service_cidr,
                    self.kubernetes_version,
                    self.vcn_cidr,
                    self.api_cidr,
                    self.worker_cidr,
                    self.pod_cidr,
                    self.services_cidr,
                )
            ),
            "OCI001",
            "identity/network fields must be strings",
        )
        for values in (
            self.administrator_cidrs,
            self.availability_domains,
            self.supported_versions,
        ):
            require(
                isinstance(values, tuple) and all(isinstance(value, str) for value in values),
                "OCI001",
                "reviewed lists must contain explicit strings",
            )
        require(isinstance(self.image, ImageEvidence), "OCI020", "reviewed image evidence required")
        require(
            bool(re.fullmatch(r"[a-z][a-z0-9-]{0,10}", self.name)),
            "OCI001",
            "name must be a DNS-safe prefix of at most eleven characters",
        )
        require(
            bool(re.fullmatch(r"[a-z]+-[a-z]+-\d+", self.region))
            and self.compartment_id.startswith("ocid1.compartment."),
            "OCI001",
            "explicit region and compartment OCID required",
        )
        require(
            self.service_id.startswith("ocid1.service.")
            and bool(
                re.fullmatch(
                    r"all-[a-z0-9]+-services-in-oracle-services-network", self.service_cidr
                )
            ),
            "OCI001",
            "supply the reviewed regional All Services ID and CIDR label",
        )
        require(
            bool(self.availability_domains)
            and len(set(self.availability_domains)) == len(self.availability_domains)
            and all(isinstance(ad, str) and bool(ad.strip()) for ad in self.availability_domains),
            "OCI001",
            "explicit unique availability domain names required",
        )
        require(
            bool(re.fullmatch(r"v\d+\.\d+\.\d+", self.kubernetes_version))
            and self.kubernetes_version in self.supported_versions,
            "OCI020",
            "pin a version present in reviewed OKE cluster/node-pool options",
        )
        self.image.validate(self.region, self.kubernetes_version, now)
        for value in (
            self.nodes,
            self.ocpus_per_node,
            self.memory_gb_per_node,
            self.boot_gb_per_node,
            self.max_pods_per_node,
        ):
            require(
                type(value) is int and value > 0,
                "OCI001",
                "capacity must be known positive integers",
            )
        require(
            self.nodes * self.ocpus_per_node <= 4
            and self.nodes * self.memory_gb_per_node <= 24
            and self.nodes * self.boot_gb_per_node <= 200
            and self.boot_gb_per_node >= 50
            and self.max_pods_per_node <= 10,
            "OCI001",
            "capacity exceeds reviewed maximum; account profile may be stricter",
        )
        try:
            vcn, api, workers, pods, services = [
                ipaddress.IPv4Network(value, strict=True)
                for value in (
                    self.vcn_cidr,
                    self.api_cidr,
                    self.worker_cidr,
                    self.pod_cidr,
                    self.services_cidr,
                )
            ]
            private = [
                ipaddress.IPv4Network(value)
                for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
            ]
            require(any(vcn.subnet_of(block) for block in private), "OCI010", "VCN must be RFC1918")
            subnets = (api, workers, pods)
            require(
                all(subnet.subnet_of(vcn) for subnet in subnets)
                and all(
                    not a.overlaps(b)
                    for index, a in enumerate(subnets)
                    for b in subnets[index + 1 :]
                )
                and not services.overlaps(vcn),
                "OCI010",
                "subnets must be disjoint within VCN; services must not overlap VCN",
            )
            require(
                api.num_addresses >= 16
                and workers.num_addresses >= self.nodes + 3
                and pods.num_addresses >= self.nodes * (self.max_pods_per_node + 1) + 3,
                "OCI010",
                "subnet capacity is insufficient for nodes and reserved pod IPs",
            )
            require(
                0 < len(self.administrator_cidrs) <= 16,
                "OCI010",
                "explicit bounded administrator CIDRs required",
            )
            for cidr in self.administrator_cidrs:
                admin = ipaddress.IPv4Network(cidr, strict=True)
                require(
                    admin.prefixlen >= 24
                    and not admin.is_multicast
                    and not admin.is_loopback
                    and not admin.is_unspecified,
                    "OCI010",
                    "administrator CIDRs must be unicast /24 or narrower",
                )
        except ValueError as error:
            raise ValueError(
                "OCI010: invalid network, overlap, size or administrator range"
            ) from error


def load_config(path: Path) -> FoundationConfig:
    """Strict TOML boundary; reject accidental/misspelled configuration keys."""
    return parse_config(tomllib.loads(path.read_text(encoding="utf-8")))


def parse_config(value: dict[str, Any]) -> FoundationConfig:
    """Validate already captured TOML, including hash-bound cutover evidence."""
    from dataclasses import fields

    from infra_core.governance.contracts import fields as exact_fields

    data = exact_fields(
        value,
        {"foundation", "image"},
        "OCI configuration",
    )
    values = exact_fields(
        data["foundation"],
        {field.name for field in fields(FoundationConfig)} - {"image"},
        "OCI foundation",
    )
    image = exact_fields(
        data["image"], {field.name for field in fields(ImageEvidence)}, "image review"
    )
    require(
        all(isinstance(value, str) for value in image.values()),
        "OCI020",
        "image review fields must be explicit strings",
    )
    for key in ("administrator_cidrs", "availability_domains", "supported_versions"):
        require(isinstance(values[key], list), "OCI001", "reviewed lists must be arrays")
        values[key] = tuple(values[key])
    config = FoundationConfig(**values, image=ImageEvidence(**image))
    config.validate()
    return config
