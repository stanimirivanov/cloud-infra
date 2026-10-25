"""Read-only backend metadata assessment; never changes bucket/IAM settings."""

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from infra_core.foundation import FoundationConfig
from infra_core.governance.contracts import fields, require, text, timestamp


def validate_posture(
    config: FoundationConfig, evidence: dict[str, Any], *, now: datetime | None = None
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    fields(
        evidence,
        {
            "schema_version",
            "configuration_sha256",
            "account_id",
            "namespace",
            "bucket",
            "region",
            "collection_started_at",
            "collection_completed_at",
            "public_access_type",
            "versioning",
            "storage_tier",
            "is_read_only",
            "lifecycle_policy_etag",
            "retention_rule_count",
            "preauthenticated_request_count",
        },
        "backend posture",
    )
    namespace = str(urlsplit(config.backend.endpoint).hostname).split(".")[0]
    require(
        type(evidence["schema_version"]) is int
        and evidence["schema_version"] == 1
        and evidence["configuration_sha256"] == config.digest
        and evidence["namespace"] == namespace
        and evidence["bucket"] == config.backend.bucket
        and evidence["region"] == config.backend.region,
        "BACKEND001",
        "posture does not bind to the configured backend",
    )
    text(evidence["account_id"], "posture tenancy")
    start = timestamp(evidence["collection_started_at"], "posture start")
    end = timestamp(evidence["collection_completed_at"], "posture completion")
    require(
        now - timedelta(hours=1) <= start <= end <= now,
        "BACKEND002",
        "posture must be fresh and ordered",
    )
    require(
        evidence["public_access_type"] == "NoPublicAccess"
        and evidence["versioning"] == "Enabled"
        and evidence["storage_tier"] == "Standard"
        and evidence["is_read_only"] is False,
        "BACKEND003",
        "backend must be private, versioned, Standard and writable",
    )
    require(
        evidence["lifecycle_policy_etag"] is None
        and all(
            type(evidence[key]) is int and evidence[key] == 0
            for key in ("retention_rule_count", "preauthenticated_request_count")
        ),
        "BACKEND004",
        "retention, public access grants or lifecycle policies require separate review",
    )
    return {"status": "within-reviewed-backend-posture", "deployment_authorized": False}
