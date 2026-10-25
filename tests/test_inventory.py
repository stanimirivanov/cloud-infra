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
