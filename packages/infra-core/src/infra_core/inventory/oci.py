"""Read/list-only OCI inventory. Missing permissions never yield a partial success."""

import importlib
from datetime import UTC, datetime
from typing import Any, Protocol

from infra_core.foundation import FoundationConfig
from infra_core.governance.contracts import GovernanceError, require
from infra_core.governance.coverage import validate_coverage
from infra_core.governance.resources import BOOT, CLUSTER, INSTANCE, INVENTORY_TYPES, VOLUME


class Reader(Protocol):
    def list(
        self,
        operation: str,
        *,
        region: str,
        compartment: str,
        availability_domain: str | None = None,
    ) -> list[dict[str, Any]]: ...


class OCIReader:
    """SDK boundary; the only dispatched methods are the reviewed list operations."""

    def __init__(self, config_file: str, profile: str, tenancy: str) -> None:
        try:
            self.sdk = importlib.import_module("oci")
        except ImportError:
            raise GovernanceError(
                "GOV040: install the optional inventory-oci extra with uv"
            ) from None
        self.config = self.sdk.config.from_file(config_file, profile)
        require(
            self.config.get("tenancy") == tenancy,
            "GOV007",
            "OCI credentials target another tenancy",
        )
        self.clients: dict[tuple[str, str], Any] = {}

    def list(
        self,
        operation: str,
        *,
        region: str,
        compartment: str,
        availability_domain: str | None = None,
    ) -> list[dict[str, Any]]:
        methods = {
            "regions": ("identity", "IdentityClient", "list_region_subscriptions"),
            "compartments": ("identity", "IdentityClient", "list_compartments"),
            "ads": ("identity", "IdentityClient", "list_availability_domains"),
            "instances": ("core", "ComputeClient", "list_instances"),
            "boots": ("core", "BlockstorageClient", "list_boot_volumes"),
            "volumes": ("core", "BlockstorageClient", "list_volumes"),
            "clusters": ("container_engine", "ContainerEngineClient", "list_clusters"),
            "virtual_pools": (
                "container_engine",
                "ContainerEngineClient",
                "list_virtual_node_pools",
            ),
        }
        require(operation in methods, "GOV040", "inventory operation is not a reviewed list call")
        module, client_name, method = methods[operation]
        try:
            key = (client_name, region)
            if key not in self.clients:
                self.clients[key] = getattr(getattr(self.sdk, module), client_name)(
                    self.config | {"region": region}, timeout=(10, 30)
                )
            kwargs: dict[str, Any] = {"compartment_id": compartment}
            if operation == "regions":
                kwargs = {"tenancy_id": compartment}
            elif operation == "compartments":
                kwargs.update(compartment_id_in_subtree=True, access_level="ANY")
            if availability_domain is not None:
                kwargs["availability_domain"] = availability_domain
            response = self.sdk.pagination.list_call_get_all_results(
                getattr(self.clients[key], method), **kwargs
            )
            return [self.sdk.util.to_dict(item) for item in response.data]
        except Exception:
            # SDK exceptions may embed credential paths, request data or account details.
            raise GovernanceError(
                f"GOV040: OCI {operation} scan failed; no complete snapshot produced"
            ) from None

    def backend_posture(self, config: FoundationConfig) -> dict[str, Any]:
        started = datetime.now(UTC).isoformat()
        try:
            client = self.sdk.object_storage.ObjectStorageClient(
                self.config | {"region": config.backend.region}, timeout=(10, 30)
            )
            namespace = client.get_namespace(compartment_id=self.config["tenancy"]).data
            require(
                namespace == config.backend.endpoint.split("//")[1].split(".")[0],
                "BACKEND001",
                "OCI namespace does not match backend",
            )
            bucket = self.sdk.util.to_dict(client.get_bucket(namespace, config.backend.bucket).data)
            retention = self.sdk.pagination.list_call_get_all_results(
                client.list_retention_rules, namespace, config.backend.bucket
            ).data
            grants = self.sdk.pagination.list_call_get_all_results(
                client.list_preauthenticated_requests, namespace, config.backend.bucket
            ).data
            return {
                "schema_version": 1,
                "configuration_sha256": config.digest,
                "account_id": self.config["tenancy"],
                "namespace": namespace,
                "bucket": bucket["name"],
                "region": config.backend.region,
                "collection_started_at": started,
                "collection_completed_at": datetime.now(UTC).isoformat(),
                **{
                    key: bucket[key]
                    for key in ("public_access_type", "versioning", "storage_tier", "is_read_only")
                },
                "lifecycle_policy_etag": bucket["object_lifecycle_policy_etag"],
                "retention_rule_count": len(retention),
                "preauthenticated_request_count": len(grants),
            }
        except Exception:
            raise GovernanceError(
                "BACKEND005: read-only bucket posture collection failed; raw details withheld"
            ) from None


def collect(
    reader: Reader,
    account_id: str,
    home_region: str,
    *,
    usage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    observed_at = datetime.now(UTC).isoformat()
    queries = []
    domains = {}

    def scan(
        operation: str, *, region: str, compartment: str, availability_domain: str | None = None
    ) -> list[dict[str, Any]]:
        result = reader.list(
            operation,
            region=region,
            compartment=compartment,
            availability_domain=availability_domain,
        )
        queries.append(
            {
                "operation": operation,
                "region": region,
                "compartment": compartment,
                "availability_domain": availability_domain,
                "count": len(result),
            }
        )
        return result

    regions = scan("regions", region=home_region, compartment=account_id)
    require(
        bool(regions) and all(region.get("status") == "READY" for region in regions),
        "GOV041",
        "every subscribed region must be READY and scanned",
    )
    require(
        [region["region_name"] for region in regions if region.get("is_home_region") is True]
        == [home_region],
        "GOV010",
        "configured home region does not match OCI",
    )
    compartments = scan("compartments", region=home_region, compartment=account_id)
    ids = [account_id] + [
        item["id"] for item in compartments if item.get("lifecycle_state") != "DELETED"
    ]
    require(len(ids) == len(set(ids)), "GOV009", "duplicate compartment evidence")
    resources = []
    for subscription in regions:
        region = subscription["region_name"]
        ads = scan("ads", region=region, compartment=account_id)
        require(bool(ads), "GOV041", "availability-domain coverage is missing")
        domains[region] = [ad["name"] for ad in ads]
        for compartment in ids:
            for item in scan("instances", region=region, compartment=compartment):
                if item.get("lifecycle_state") == "TERMINATED":
                    continue
                shape = item.get("shape_config") or {}
                resources.append(
                    _record(
                        item,
                        INSTANCE,
                        region,
                        {
                            "shape": item.get("shape"),
                            "shapeConfig": {
                                "ocpus": shape.get("ocpus"),
                                "memoryInGbs": shape.get("memory_in_gbs"),
                            },
                        },
                    )
                )
            for ad in ads:
                for item in scan(
                    "boots", region=region, compartment=compartment, availability_domain=ad["name"]
                ):
                    if item.get("lifecycle_state") != "TERMINATED":
                        resources.append(_volume(item, BOOT, region))
            for item in scan("volumes", region=region, compartment=compartment):
                if item.get("lifecycle_state") != "TERMINATED":
                    resources.append(_volume(item, VOLUME, region))
            for item in scan("clusters", region=region, compartment=compartment):
                if item.get("lifecycle_state") != "DELETED":
                    resources.append(_record(item, CLUSTER, region, {"type": item.get("type")}))
            require(
                not scan("virtual_pools", region=region, compartment=compartment),
                "GOV022",
                "virtual node pools are not free-tier classified",
            )
    resource_ids = [item["id"] for item in resources]
    require(
        len(resource_ids) == len(set(resource_ids)),
        "GOV009",
        "duplicate resources in regional scan",
    )
    snapshot = {
        "schema_version": 2,
        "provider": "oci",
        "account_id": account_id,
        "observed_at": observed_at,
        "collection_started_at": observed_at,
        "collection_completed_at": datetime.now(UTC).isoformat(),
        "coverage": {
            "regions": [item["region_name"] for item in regions],
            "compartments": ids,
            "availability_domains": domains,
            "queries": queries,
        },
        "complete": True,
        "all_regions": True,
        "all_compartments": True,
        "covered_types": sorted(INVENTORY_TYPES),
        "resources": sorted(resources, key=lambda item: item["id"]),
        "usage": usage,
    }

    validate_coverage(snapshot, home_region, datetime.now(UTC))
    return snapshot


def _record(item: dict[str, Any], kind: str, region: str, props: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(item.get("id"), str), "GOV041", "inventory resource ID is missing")
    # Freeform tags are not ownership proof. No subtraction is allowed from collector-only evidence.
    return {
        "id": item["id"],
        "type": kind,
        "region": region,
        "owner": None,
        "retained": kind in (BOOT, VOLUME),
        "props": props,
    }


def _volume(item: dict[str, Any], kind: str, region: str) -> dict[str, Any]:
    return _record(
        item,
        kind,
        region,
        {
            "sizeInGbs": item.get("size_in_gbs"),
            "vpusPerGb": item.get("vpus_per_gb"),
            "isAutoTuneEnabled": item.get("is_auto_tune_enabled"),
        },
    )
