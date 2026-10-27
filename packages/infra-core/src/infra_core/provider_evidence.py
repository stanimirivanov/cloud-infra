"""Observation bindings only; no claim of source authenticity or usage coverage."""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

MAX_OBSERVATION_BYTES = 1024 * 1024


class ObservationError(ValueError):
    """Safe diagnostics; never include response bodies, tokens or request values."""


@dataclass(frozen=True, slots=True)
class Observation:
    provider: str
    request_sha256: str
    response_sha256: str
    collection_started_at: datetime
    collection_finished_at: datetime
    response: bytes = field(repr=False)


def record_observation(
    provider: str, request: bytes, response: bytes, *, started: datetime, finished: datetime
) -> Observation:
    """Hash exact bytes and preserve caller clocks, including the first retry start.

    Request bytes must describe the source operation without authentication data.
    OCI SDK collectors may use this binding without using the HTTPS GET transport.
    Consumers must separately establish scope, pagination, completeness and coverage.
    """
    if (
        not isinstance(provider, str)
        or provider not in {"oci", "cloudflare", "supabase"}
        or type(request) is not bytes
        or not 1 <= len(request) <= 8192
        or type(response) is not bytes
        or len(response) > MAX_OBSERVATION_BYTES
    ):
        raise ObservationError("OBS001: invalid provider or bounded immutable observation bytes")
    if (
        not isinstance(started, datetime)
        or not isinstance(finished, datetime)
        or started.utcoffset() is None
        or finished.utcoffset() is None
        or finished < started
    ):
        raise ObservationError("OBS002: observation clocks require ordered explicit timezones")
    return Observation(
        provider,
        hashlib.sha256(request).hexdigest(),
        hashlib.sha256(response).hexdigest(),
        started,
        finished,
        response,
    )
