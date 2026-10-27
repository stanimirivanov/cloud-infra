"""Usage queries are investigations, never proof of complete fresh billing data."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from infra_core.governance.contracts import GovernanceError
from infra_core.inventory import oci_usage
from infra_core.inventory.oci import OCIReader

NOW = datetime(2026, 10, 3, 12, 5, tzinfo=UTC)
START = NOW.replace(day=1, hour=0, minute=0)
CUTOFF = START + timedelta(hours=2)


def row(sku="B93297", unit="OCPU Per Hour", quantity="0.1", start=START):
    return {
        "tenant_id": "tenancy",
        "sku_part_number": sku,
        "unit": unit,
        "computed_quantity": quantity,
        "time_usage_started": start.isoformat(),
        "time_usage_ended": (start + timedelta(hours=1)).isoformat(),
    }


class Reader:
    def __init__(self, pages=None):
        self.pages = pages or [({"items": []}, None)]
        self.calls = []

    def usage_page(self, **kwargs):
        self.calls.append(kwargs)
        return deepcopy(self.pages.pop(0))


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    monkeypatch.setattr(oci_usage, "_now", lambda: NOW)


def collect(reader, cutoff=CUTOFF):
    return oci_usage.collect_usage(reader, "tenancy", "eu-frankfurt-1", cutoff=cutoff)


def test_windows_pages_and_decimal_sums_keep_coverage_unproven():
    reader = Reader(
        [
            ({"items": [row()]}, "next"),
            (
                {
                    "items": [
                        row(quantity="0.2", start=START + timedelta(hours=1)),
                        row("B93298", "Gigabyte Per Hour", "0"),
                        row("B91961", "Gigabyte Storage Capacity Per Month", "1.25"),
                        row("B91445", "Gigabyte Storage Capacity Per Month", "2.50"),
                    ]
                },
                None,
            ),
            ({"items": []}, None),
        ]
    )
    cutoff = START + timedelta(hours=40)
    result = collect(reader, cutoff)
    assert [(c["started"], c["ended"], c["page"]) for c in reader.calls] == [
        (START, START + timedelta(hours=36), None),
        (START, START + timedelta(hours=36), "next"),
        (START + timedelta(hours=36), cutoff, None),
    ]
    assert dict(result.totals) == {
        "a1_ocpu_hours": "0.3",
        "a1_memory_gb_hours": "0",
        "block_gb_months": "3.75",
    }
    assert result.covered_through is None and result.query_ended_at == cutoff
    assert all(
        o.collection_started_at == o.collection_finished_at == NOW for o in result.observations
    )
    assert len({o.request_sha256 for o in result.observations}) == 3


def test_empty_queries_do_not_invent_zero_or_watermark():
    result = collect(Reader())
    assert dict(result.totals) == dict.fromkeys(
        ("a1_ocpu_hours", "a1_memory_gb_hours", "block_gb_months")
    )
    assert result.covered_through is None
    assert result.observations[0].collection_started_at == NOW


@pytest.mark.parametrize(
    "change",
    [
        {"tenant_id": "other"},
        {"sku_part_number": "unknown"},
        {"unit": "OCPU"},
        {"computed_quantity": None},
        {"computed_quantity": -1},
        {"computed_quantity": True},
        {"computed_quantity": "NaN"},
        {"computed_quantity": "Infinity"},
        {"computed_quantity": "1e99"},
        {"time_usage_ended": (START + timedelta(hours=3)).isoformat()},
        {"time_usage_started": (START - timedelta(hours=1)).isoformat()},
    ],
)
def test_scope_units_quantities_and_intervals_fail_closed(change):
    with pytest.raises(GovernanceError):
        collect(Reader([({"items": [row() | change]}, None)]))


@pytest.mark.parametrize(
    "cutoff",
    [
        START,
        START - timedelta(hours=1),
        NOW + timedelta(hours=1),
        CUTOFF.replace(tzinfo=None),
        CUTOFF + timedelta(seconds=1),
    ],
)
def test_cutoff_must_be_an_explicit_elapsed_hour(cutoff):
    reader = Reader()
    with pytest.raises(GovernanceError, match="USAGE002"):
        collect(reader, cutoff)
    assert not reader.calls


def test_duplicate_rows_and_pagination_fail_without_partial_results():
    for pages in (
        [({"items": [row(), row()]}, None)],
        [({"items": []}, "same"), ({"items": []}, "same")],
    ):
        with pytest.raises(GovernanceError):
            collect(Reader(pages))


@pytest.mark.parametrize("bound", ["MAX_PAGES", "MAX_ROWS", "MAX_BYTES"])
def test_collection_budgets_fail_closed(monkeypatch, bound):
    monkeypatch.setattr(oci_usage, bound, 0)
    with pytest.raises(GovernanceError, match="budget"):
        collect(Reader([({"items": [row()]}, None)]))


def test_denied_page_does_not_leak_or_return_partial_success():
    class Denied(Reader):
        def usage_page(self, **kwargs):
            if self.calls:
                raise PermissionError("private-token")
            return super().usage_page(**kwargs)

    with pytest.raises(GovernanceError, match="raw details withheld") as error:
        collect(Denied([({"items": [row()]}, "page2")]))
    assert "private-token" not in str(error.value)


def test_sdk_dispatch_is_closed_read_only_and_sanitized(monkeypatch):
    calls = []

    class Client:
        def __init__(self, config, **kwargs):
            assert config["region"] == "eu-frankfurt-1" and kwargs["timeout"] == (10, 30)
            assert kwargs["retry_strategy"] == "no-retries"

        def request_summarized_usages(self, details, **kwargs):
            calls.append((details, kwargs))
            return SimpleNamespace(
                status=200, data={"items": []}, headers={"opc-next-page": "page2"}
            )

    sdk = SimpleNamespace(
        config=SimpleNamespace(from_file=lambda *a: {"tenancy": "tenancy"}),
        usage_api=SimpleNamespace(
            UsageapiClient=Client,
            models=SimpleNamespace(RequestSummarizedUsagesDetails=lambda **kw: kw),
        ),
        retry=SimpleNamespace(NoneRetryStrategy=lambda: "no-retries"),
        util=SimpleNamespace(to_dict=lambda data: data),
    )
    monkeypatch.setattr("infra_core.inventory.oci.importlib.import_module", lambda _: sdk)
    reader = OCIReader("fixture", "DEFAULT", "tenancy")
    kwargs = dict(
        account_id="tenancy", region="eu-frankfurt-1", started=START, ended=CUTOFF, page=None
    )
    assert reader.usage_page(**kwargs) == ({"items": []}, "page2")
    details, options = calls[0]
    assert details == dict(
        tenant_id="tenancy",
        time_usage_started=START,
        time_usage_ended=CUTOFF,
        granularity="HOURLY",
        query_type="USAGE_ONLY",
        is_aggregate_by_time=False,
        group_by=["tenantId", "skuPartNumber", "unit"],
    )
    assert options == dict(page=None, limit=1000, retry_strategy="no-retries")
    with pytest.raises(GovernanceError, match="mismatch"):
        reader.usage_page(**(kwargs | {"account_id": "other"}))

    def fail(*a, **kw):
        raise PermissionError("private-token")

    monkeypatch.setattr(Client, "request_summarized_usages", fail)
    with pytest.raises(GovernanceError, match="raw details withheld") as error:
        reader.usage_page(**kwargs)
    assert "private-token" not in str(error.value)
