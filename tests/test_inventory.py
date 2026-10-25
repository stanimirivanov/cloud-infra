"""OCI adapter coverage, pagination dispatch and errors without cloud credentials."""

from types import SimpleNamespace

import pytest
from infra_core.governance.contracts import GovernanceError
from infra_core.inventory.oci import OCIReader, collect


class FakeReader:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.virtual = False
        self.duplicate = False

    def list(self, operation, *, region, compartment, availability_domain=None):
        self.calls.append((operation, region, compartment, availability_domain))
        if operation == self.fail:
            raise PermissionError("synthetic denied operation")
        if operation == "regions":
            return [
                {"region_name": "home", "status": "READY", "is_home_region": True},
                {"region_name": "other", "status": "READY", "is_home_region": False},
            ]
        if operation == "compartments":
            return [{"id": "child", "lifecycle_state": "ACTIVE"}]
        if operation == "ads":
            return [{"name": "ad1"}, {"name": "ad2"}]
        if operation == "instances" and (region == "home" or self.duplicate):
            return [
                {
                    "id": compartment + "-instance",
                    "lifecycle_state": "STOPPED",
                    "shape": "VM.Standard.A1.Flex",
                    "shape_config": {"ocpus": 1, "memory_in_gbs": 6},
                    "freeform_tags": {"owner": "untrusted-tag"},
                }
            ]
        if operation == "boots":
            return [
                {
                    "id": f"{region}-{compartment}-{availability_domain}-boot",
                    "lifecycle_state": "AVAILABLE",
                    "size_in_gbs": 50,
                    "vpus_per_gb": 10,
                    "is_auto_tune_enabled": False,
                }
            ]
        if operation == "virtual_pools" and self.virtual:
            return [{"id": "paid-virtual-pool"}]
        return []


def test_all_regions_compartments_domains_and_unmanaged_retained_storage():
    reader = FakeReader()
    inventory = collect(reader, "tenancy", "home")
    assert inventory["complete"] is True
    assert inventory["usage"] is None  # A listing cannot establish consumed monthly usage.
    assert len(inventory["resources"]) == 10
    assert all(item["owner"] is None for item in inventory["resources"])
    assert all(item["retained"] for item in inventory["resources"] if "boot" in item["id"])
    for region in ("home", "other"):
        for compartment in ("tenancy", "child"):
            assert ("instances", region, compartment, None) in reader.calls
            assert ("clusters", region, compartment, None) in reader.calls
            assert ("volumes", region, compartment, None) in reader.calls
            for ad in ("ad1", "ad2"):
                assert ("boots", region, compartment, ad) in reader.calls


@pytest.mark.parametrize("operation", ["compartments", "instances", "boots", "clusters"])
def test_missing_permissions_never_return_partial_success(operation):
    reader = FakeReader()
    reader.fail = operation
    with pytest.raises(PermissionError):
        collect(reader, "tenancy", "home")


def test_virtual_pools_and_duplicate_ids_fail_closed():
    reader = FakeReader()
    reader.virtual = True
    with pytest.raises(GovernanceError, match="GOV022"):
        collect(reader, "tenancy", "home")
    reader.virtual = False
    reader.duplicate = True
    with pytest.raises(GovernanceError, match="GOV009"):
        collect(reader, "tenancy", "home")


def test_sdk_dispatch_is_paginated_read_only_and_sanitizes_failures(monkeypatch):
    calls = []

    class Client:
        def __init__(self, config, **kwargs):
            calls.append((config, kwargs))

        def list_compartments(self, **kwargs):
            pass

    def paginate(method, **kwargs):
        calls.append((method.__name__, kwargs))
        return SimpleNamespace(data=[{"id": "first-page"}, {"id": "last-page"}])

    sdk = SimpleNamespace(
        config=SimpleNamespace(from_file=lambda path, profile: {"tenancy": "tenancy"}),
        identity=SimpleNamespace(IdentityClient=Client),
        pagination=SimpleNamespace(list_call_get_all_results=paginate),
        util=SimpleNamespace(to_dict=lambda value: value),
    )
    monkeypatch.setattr("infra_core.inventory.oci.importlib.import_module", lambda name: sdk)
    reader = OCIReader("synthetic-config", "DEFAULT", "tenancy")
    result = reader.list("compartments", region="home", compartment="tenancy")
    assert len(result) == 2
    assert calls[-1] == (
        "list_compartments",
        {
            "compartment_id": "tenancy",
            "compartment_id_in_subtree": True,
            "access_level": "ANY",
        },
    )
    with pytest.raises(GovernanceError, match="GOV040"):
        reader.list("delete_instance", region="home", compartment="tenancy")
    sdk.pagination.list_call_get_all_results = lambda *args, **kwargs: 1 / 0
    with pytest.raises(GovernanceError, match="GOV040: OCI compartments scan failed"):
        reader.list("compartments", region="home", compartment="tenancy")
    with pytest.raises(GovernanceError, match="GOV007"):
        OCIReader("synthetic-config", "DEFAULT", "another-tenancy")


def test_collection_records_scope_queries_and_distinct_clocks():
    reader = FakeReader()
    inventory = collect(reader, "tenancy", "home")
    assert inventory["schema_version"] == 2
    assert inventory["observed_at"] == inventory["collection_started_at"]
    assert inventory["collection_completed_at"] >= inventory["collection_started_at"]
    coverage = inventory["coverage"]
    assert coverage["regions"] == ["home", "other"]
    assert coverage["compartments"] == ["tenancy", "child"]
    assert coverage["availability_domains"] == {"home": ["ad1", "ad2"], "other": ["ad1", "ad2"]}
    assert [
        (row["operation"], row["region"], row["compartment"], row["availability_domain"])
        for row in coverage["queries"]
    ] == reader.calls
    assert len(coverage["queries"]) == 28
    assert sum(row["count"] for row in coverage["queries"]) == 17


def test_bucket_posture_adapter_reads_only_metadata_and_sanitizes_errors(monkeypatch):
    from pathlib import Path

    from infra_core.backend_posture import validate_posture
    from infra_core.foundation import load_foundation

    config = load_foundation(Path(__file__).resolve().parents[1])
    namespace = config.backend.endpoint.split("//")[1].split(".")[0]
    calls = []

    class Storage:
        fail = False

        def __init__(self, credentials, **kwargs):
            calls.append(("client", credentials["region"]))

        def get_namespace(self, **kwargs):
            calls.append(("namespace", kwargs))
            return SimpleNamespace(data=namespace)

        def get_bucket(self, ns, bucket):
            calls.append(("bucket", ns, bucket))
            if self.fail:
                raise RuntimeError("SECRET_KEY_MUST_NOT_ESCAPE")
            return SimpleNamespace(
                data={
                    "name": bucket,
                    "public_access_type": "NoPublicAccess",
                    "versioning": "Enabled",
                    "storage_tier": "Standard",
                    "is_read_only": False,
                    "object_lifecycle_policy_etag": None,
                }
            )

        def list_retention_rules(self, *args):
            calls.append(("retention", args))
            return SimpleNamespace(data=[])

        def list_preauthenticated_requests(self, *args):
            calls.append(("PARs", args))
            return SimpleNamespace(data=[])

    sdk = SimpleNamespace(
        config=SimpleNamespace(from_file=lambda path, profile: {"tenancy": "tenancy"}),
        object_storage=SimpleNamespace(ObjectStorageClient=Storage),
        pagination=SimpleNamespace(list_call_get_all_results=lambda method, *args: method(*args)),
        util=SimpleNamespace(to_dict=lambda data: data),
    )
    monkeypatch.setattr("infra_core.inventory.oci.importlib.import_module", lambda name: sdk)
    reader = OCIReader("synthetic-config", "DEFAULT", "tenancy")
    posture = reader.backend_posture(config)
    assert validate_posture(config, posture)["deployment_authorized"] is False
    assert [call[0] for call in calls] == ["client", "namespace", "bucket", "retention", "PARs"]
    Storage.fail = True
    with pytest.raises(GovernanceError, match="BACKEND005") as error:
        reader.backend_posture(config)
    assert "SECRET_KEY" not in str(error.value)


def test_removing_scope_and_its_queries_cannot_hide_discovered_regions():
    from datetime import UTC, datetime

    from infra_core.governance.coverage import validate_coverage

    inventory = collect(FakeReader(), "tenancy", "home")
    coverage = inventory["coverage"]
    coverage["regions"].remove("other")
    del coverage["availability_domains"]["other"]
    coverage["queries"] = [row for row in coverage["queries"] if row["region"] != "other"]
    with pytest.raises(GovernanceError, match="GOV042"):
        validate_coverage(inventory, "home", datetime.now(UTC))
