"""Closed-host HTTPS GET boundary; no redirects, proxy discovery or raw errors."""

import http.client
import json
import re
import ssl
import time
from datetime import UTC, datetime
from urllib.parse import unquote, urlsplit

from infra_core.provider_evidence import (
    MAX_OBSERVATION_BYTES,
    Observation,
    ObservationError,
    record_observation,
)

_SOURCES = {
    "cloudflare": ("api.cloudflare.com", "/client/v4/"),
    "supabase": ("api.supabase.com", "/v1/"),
}
_RETRYABLE = {429, 502, 503, 504}
_ATTEMPTS = 3
_SOCKET_TIMEOUT = 10


def _target(provider: str, target: str, token: str) -> str:
    if not isinstance(provider, str) or provider not in _SOURCES:
        raise ObservationError("HTTP001: unsupported observation provider")
    if (
        not isinstance(target, str)
        or not 1 <= len(target) <= 4096
        or not target.isascii()
        or not target.startswith(_SOURCES[provider][1])
        or re.search(r"[\x00-\x20\x7f\\]", target)
    ):
        raise ObservationError("HTTP001: invalid observation target")
    parsed = urlsplit(target)
    decoded = unquote(parsed.path)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or not parsed.path.startswith(_SOURCES[provider][1])
        or any(part in {".", ".."} for part in decoded.split("/"))
        or re.search(r"[\x00-\x20\x7f\\%]", decoded)
    ):
        raise ObservationError("HTTP001: target must remain in the reviewed API prefix")
    if not isinstance(token, str) or not re.fullmatch(r"[!-~]{1,4096}", token):
        raise ObservationError("HTTP001: explicit bounded bearer credential required")
    return _SOURCES[provider][0]


def observe_get(provider: str, target: str, *, token: str) -> Observation:
    """Read one bounded response; higher layers own pagination and run deadlines.

    Direct HTTPSConnection intentionally ignores ambient proxy configuration.
    Socket timeout bounds individual waits, not slow-drip total execution time.
    No network-error retries, credential discovery, caller headers or custom TLS.
    """
    host = _target(provider, target, token)
    started = datetime.now(UTC)
    descriptor = f"GET https://{host}{target}".encode("ascii")
    for attempt in range(_ATTEMPTS):
        connection = None
        try:
            connection = http.client.HTTPSConnection(
                host, timeout=_SOCKET_TIMEOUT, context=ssl.create_default_context()
            )
            connection.request(
                "GET",
                target,
                headers={
                    "Authorization": "Bearer " + token,
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
            )
            response = connection.getresponse()
            if response.status in _RETRYABLE and attempt < _ATTEMPTS - 1:
                # Never trust unbounded Retry-After; close before a fixed backoff.
                connection.close()
                time.sleep(attempt + 1)
                continue
            if response.status != 200:
                raise ObservationError("HTTP002: observation request failed; no complete response")
            if (
                response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
                != "application/json"
                or response.getheader("Content-Encoding", "identity").lower() != "identity"
            ):
                raise ObservationError("HTTP003: expected uncompressed JSON response")
            length = response.getheader("Content-Length")
            if length is not None and (
                not re.fullmatch(r"[0-9]{1,10}", length) or int(length) > MAX_OBSERVATION_BYTES
            ):
                raise ObservationError("HTTP003: invalid or oversized response length")
            body = response.read(MAX_OBSERVATION_BYTES + 1)
            if len(body) > MAX_OBSERVATION_BYTES or (
                length is not None and len(body) != int(length)
            ):
                raise ObservationError("HTTP003: oversized or incomplete observation response")
            json.loads(body.decode("utf-8"))
            return record_observation(
                provider, descriptor, body, started=started, finished=datetime.now(UTC)
            )
        except ObservationError:
            raise
        except Exception:
            # Exceptions can embed URLs, request headers, response bodies or credentials.
            raise ObservationError(
                "HTTP004: HTTPS observation failed; raw diagnostics withheld"
            ) from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    raise ObservationError(
                        "HTTP004: HTTPS cleanup failed; raw diagnostics withheld"
                    ) from None
    raise ObservationError("HTTP002: observation retry limit exhausted")
