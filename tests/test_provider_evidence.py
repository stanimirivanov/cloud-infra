"""Credential-free transport failures must never become usable observations."""

import hashlib
import ssl
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from infra_core.inventory import http
from infra_core.provider_evidence import MAX_OBSERVATION_BYTES, ObservationError, record_observation

TOKEN = "synthetic-private-token"
NOW = datetime(2026, 10, 27, tzinfo=UTC)


class Reply:
    def __init__(self, status=200, body=b'{"items": []}', **headers):
        self.status = status
        self.body = body
        self.headers = {"Content-Type": "application/json", **headers}

    def getheader(self, key, default=None):
        return self.headers.get(key, default)

    def read(self, limit):
        assert limit == MAX_OBSERVATION_BYTES + 1
        return self.body[:limit]


@pytest.fixture
def network(monkeypatch):
    state = SimpleNamespace(replies=[Reply()], connections=[], requests=[], sleeps=[], failure=None)

    class Connection:
        def __init__(self, host, *, timeout, context):
            assert host in {"api.cloudflare.com", "api.supabase.com"}
            assert timeout == 10
            assert context.verify_mode == ssl.CERT_REQUIRED
            assert context.check_hostname is True
            self.closed = False
            state.connections.append(self)

        def request(self, method, target, *, headers):
            state.requests.append((method, target, headers))
            if state.failure:
                raise state.failure

        def getresponse(self):
            return state.replies.pop(0)

        def close(self):
            self.closed = True

    monkeypatch.setattr(http.http.client, "HTTPSConnection", Connection)
    monkeypatch.setattr(http.time, "sleep", state.sleeps.append)
    clocks = iter((NOW, NOW + timedelta(seconds=5)))
    monkeypatch.setattr(http, "datetime", SimpleNamespace(now=lambda _: next(clocks)))
    return state


@pytest.mark.parametrize(
    "provider,target",
    [
        ("cloudflare", "/client/v4/zones?page=2"),
        ("supabase", "/v1/organizations"),
    ],
)
def test_fixed_host_get_and_exact_byte_clock_binding(network, provider, target):
    observation = http.observe_get(provider, target, token=TOKEN)
    assert observation.response == b'{"items": []}'
    assert observation.response_sha256 == hashlib.sha256(observation.response).hexdigest()
    host = "api.cloudflare.com" if provider == "cloudflare" else "api.supabase.com"
    assert (
        observation.request_sha256
        == hashlib.sha256(f"GET https://{host}{target}".encode()).hexdigest()
    )
    assert observation.collection_started_at == NOW
    assert observation.collection_finished_at == NOW + timedelta(seconds=5)
    assert network.requests == [
        (
            "GET",
            target,
            {
                "Authorization": "Bearer " + TOKEN,
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            },
        )
    ]
    assert all(c.closed for c in network.connections)
    assert TOKEN not in repr(observation) and "items" not in repr(observation)
    with pytest.raises(FrozenInstanceError):
        observation.provider = "other"


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.invalid/v1/projects",
        "https://[invalid/v1/projects",
        "//evil.invalid/v1/projects",
        "/other",
        "/v1/../secret",
        "/v1/%2e%2e/secret",
        "/v1/%252e%252e/secret",
        "/v1/projects#fragment",
        "/v1/\r\nInjected:value",
        "/v1/\\evil",
        "/v1/é",
        "/v1/%00",
        "/v1/" + "x" * 4096,
    ],
)
def test_unsafe_targets_never_open_a_connection(network, target):
    with pytest.raises(ObservationError, match="HTTP001"):
        http.observe_get("supabase", target, token=TOKEN)
    assert not network.connections


@pytest.mark.parametrize(
    "provider,token",
    [
        ("oci", TOKEN),
        ("supabase", ""),
        ("supabase", "bad\r\nvalue"),
        ("supabase", "two words"),
        ("supabase", "x" * 4097),
    ],
)
def test_explicit_provider_and_credential_required(network, provider, token):
    with pytest.raises(ObservationError, match="HTTP001"):
        http.observe_get(provider, "/v1/projects", token=token)
    assert not network.connections


def test_transient_retries_keep_original_start_and_close_before_backoff(network, monkeypatch):
    network.replies = [Reply(429, **{"Retry-After": "999999"}), Reply(503), Reply()]

    def pause(seconds):
        assert network.connections[-1].closed
        network.sleeps.append(seconds)

    monkeypatch.setattr(http.time, "sleep", pause)
    result = http.observe_get("supabase", "/v1/projects", token=TOKEN)
    assert result.collection_started_at == NOW
    assert network.sleeps == [1, 2]
    assert len(network.connections) == 3 and all(c.closed for c in network.connections)


@pytest.mark.parametrize(
    "status", [301, 302, 307, 308, 400, 401, 403, 404, 500, 429, 502, 503, 504]
)
def test_failures_never_follow_redirect_or_return_observation(network, status):
    network.replies = [Reply(status, TOKEN.encode(), Location="https://evil.invalid")] * 3
    with pytest.raises(ObservationError, match="HTTP002") as error:
        http.observe_get("supabase", "/v1/projects", token=TOKEN)
    assert TOKEN not in str(error.value)
    assert len(network.requests) == (3 if status in {429, 502, 503, 504} else 1)
    assert all(c.closed for c in network.connections)


@pytest.mark.parametrize(
    "reply",
    [
        Reply(**{"Content-Type": "text/html"}),
        Reply(**{"Content-Encoding": "gzip"}),
        Reply(**{"Content-Length": str(MAX_OBSERVATION_BYTES + 1)}),
        Reply(**{"Content-Length": "-1"}),
        Reply(**{"Content-Length": "2, 2"}),
        Reply(**{"Content-Length": "999"}),
        Reply(body=b"x" * (MAX_OBSERVATION_BYTES + 1)),
        Reply(body=b"private malformed JSON"),
        Reply(body=b"\xff"),
    ],
)
def test_malformed_incomplete_compressed_or_large_reply_fails_closed(network, reply):
    network.replies = [reply]
    with pytest.raises(ObservationError):
        http.observe_get("supabase", "/v1/projects", token=TOKEN)
    assert all(c.closed for c in network.connections)


@pytest.mark.parametrize("failure", [TimeoutError(TOKEN), OSError(TOKEN), ssl.SSLError(TOKEN)])
def test_network_errors_are_sanitized_without_retries(network, failure):
    network.failure = failure
    with pytest.raises(ObservationError, match="HTTP004") as error:
        http.observe_get("supabase", "/v1/projects", token=TOKEN)
    assert TOKEN not in str(error.value) and error.value.__suppress_context__
    assert len(network.connections) == 1 and network.connections[0].closed


@pytest.mark.parametrize("stage", ["constructor", "getresponse", "read", "close"])
def test_setup_read_and_cleanup_failures_remain_sanitized(network, monkeypatch, stage):
    def fail(*args, **kwargs):
        raise OSError(TOKEN)

    if stage == "constructor":
        monkeypatch.setattr(http.http.client, "HTTPSConnection", fail)
    elif stage == "read":
        monkeypatch.setattr(Reply, "read", fail)
    else:
        monkeypatch.setattr(http.http.client.HTTPSConnection, stage, fail)
    with pytest.raises(ObservationError, match="HTTP004") as error:
        http.observe_get("supabase", "/v1/projects", token=TOKEN)
    assert TOKEN not in str(error.value) and error.value.__suppress_context__
    assert not network.sleeps


def test_exact_byte_limit_succeeds_with_matching_length(network):
    body = b"{}" + b" " * (MAX_OBSERVATION_BYTES - 2)
    network.replies = [Reply(body=body, **{"Content-Length": str(len(body))})]
    assert http.observe_get("supabase", "/v1/projects", token=TOKEN).response == body


def test_sdk_observation_preserves_original_clocks_and_has_no_coverage_claim():
    observation = record_observation(
        "oci", b"reviewed usage request", b"{}", started=NOW, finished=NOW
    )
    assert observation.collection_started_at == observation.collection_finished_at == NOW
    assert not hasattr(observation, "covered_through")
    for started, finished in ((NOW.replace(tzinfo=None), NOW), (NOW, NOW - timedelta(seconds=1))):
        with pytest.raises(ObservationError, match="OBS002"):
            record_observation("oci", b"request", b"{}", started=started, finished=finished)
    for provider, request, response in (
        ("other", b"r", b"{}"),
        ("oci", b"", b"{}"),
        ("oci", b"r", bytearray(b"{}")),
        ("oci", b"r", b"x" * (MAX_OBSERVATION_BYTES + 1)),
    ):
        with pytest.raises(ObservationError, match="OBS001"):
            record_observation(provider, request, response, started=NOW, finished=NOW)
