"""Bounded unauthenticated probes and attributed readiness; no external endpoint calls."""

import json
import multiprocessing
import socket
import threading
import time
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from infra_core import health as h

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 29, tzinfo=UTC)


def scope(unit="oci-oke"):
    return dict(unit=unit, account_id="PRIVATE-ACCOUNT", scope_id="PRIVATE-CLUSTER", region="home")


def target(kind="dns"):
    value = dict(id="fixture", kind=kind, host="localhost", addresses=["127.0.0.1"])
    if kind != "dns":
        value["port"] = 443
    if kind == "http":
        value.update(scheme="http", path="/ready", statuses=[200])
    return value


def policy(unit="oci-oke", targets=None):
    return dict(
        schema_version=1,
        enabled=True,
        timeout_seconds=2,
        max_run_seconds=8,
        max_response_bytes=1024,
        max_evidence_age_seconds=900,
        min_tls_validity_seconds=3600,
        expected_oke_nodes=2 if unit == "oci-oke" else None,
        targets=[] if targets is None else targets,
    )


def evidence():
    instant = NOW.isoformat()
    return dict(
        schema_version=1,
        scope=scope(),
        source="operator-supplied",
        observed_at=instant,
        collection_started_at=instant,
        collection_completed_at=instant,
        checks=dict(
            nodes=dict(observed_at=instant, expected_nodes=2, ready_nodes=2),
            **{k: dict(observed_at=instant, healthy=True) for k in ("api", "cni", "dns")},
        ),
    )


def test_oke_records_are_scoped_read_only_attributed_and_clock_preserving():
    raw = evidence()
    before = deepcopy(raw)
    report = h.observe(scope(), policy(), raw, now=NOW)
    assert raw == before
    assert report["status"] == "healthy" and report["complete"]
    assert (
        report["deployment_authorized"]
        is report["remediation_authorized"]
        is report["cluster_isolation_verified"]
        is False
    )
    assert report["cluster_source_clocks"]["observed_at"] == raw["observed_at"]
    assert all(r["source"] == "operator-supplied" for r in report["cluster"])
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize(
    "fault", ["missing", "stale", "future", "scope", "order", "schema", "source", "extra"]
)
def test_bad_cluster_header_is_unknown(fault):
    raw = evidence()
    if fault == "missing":
        raw = None
    elif fault == "stale":
        raw["observed_at"] = (NOW - timedelta(seconds=901)).isoformat()
    elif fault == "future":
        raw["collection_completed_at"] = (NOW + timedelta(seconds=1)).isoformat()
    elif fault == "scope":
        raw["scope"]["scope_id"] = "OTHER-PRIVATE"
    elif fault == "order":
        raw["collection_started_at"] = (NOW - timedelta(seconds=1)).isoformat()
    elif fault == "schema":
        raw["schema_version"] = True
    elif fault == "source":
        raw["source"] = "remote-probe"
    else:
        raw["checks"]["pod-isolation"] = dict(healthy=True)
    report = h.observe(scope(), policy(), raw, now=NOW)
    assert report["status"] == "unknown" and not report["complete"]
    assert all(r["status"] == "unknown" for r in report["cluster"])
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("check", h.CHECKS)
@pytest.mark.parametrize("bad", [False, None, "missing", "future"])
def test_readiness_failures_and_partial_evidence_are_not_healthy(check, bad):
    raw = evidence()
    if bad == "missing":
        del raw["checks"][check]
    elif bad == "future":
        raw["checks"][check]["observed_at"] = (NOW + timedelta(seconds=1)).isoformat()
    elif check == "nodes":
        raw["checks"][check]["ready_nodes"] = 1 if bad is False else None
    else:
        raw["checks"][check]["healthy"] = bad
    values = {r["check"]: r for r in h.cluster(scope(), policy(), raw, now=NOW)}
    assert values[check]["status"] == ("unhealthy" if bad is False else "unknown")
    assert all(r["status"] == "healthy" for k, r in values.items() if k != check)


def test_missing_nodes_cannot_shrink_expected_cluster_and_recovery_is_stable():
    raw = evidence()
    raw["checks"]["nodes"].update(expected_nodes=1, ready_nodes=1)
    first = h.observe(scope(), policy(), raw, now=NOW)
    assert first["status"] == "unknown"
    repaired = h.observe(scope(), policy(), evidence(), now=NOW)
    assert repaired["status"] == "healthy"
    assert [r["id"] for r in first["cluster"]] == [r["id"] for r in repaired["cluster"]]


def test_check_only_never_resolves_or_starts_process(monkeypatch):
    monkeypatch.setattr(h, "_bounded", lambda *a: pytest.fail("worker in check-only mode"))
    report = h.observe(scope(), policy(targets=[target()]), evidence(), now=NOW)
    assert report["status"] == "unknown" and report["endpoints"][0]["reason"] == "not_observed"
    assert all(r["status"] == "healthy" for r in report["cluster"])


@pytest.mark.parametrize(
    "fault",
    [
        "disabled",
        "null",
        "float",
        "bool",
        "timeout",
        "run",
        "size",
        "age",
        "nodes",
        "extra",
        "url",
        "userinfo",
        "literal",
        "address",
        "metadata",
        "mapped",
        "duplicate",
        "path",
        "query",
        "redirect-status",
        "header",
    ],
)
def test_unreviewed_destination_and_policy_shapes_rejected(fault):
    t = target("http")
    value = policy(targets=[t])
    if fault == "disabled":
        value["enabled"] = False
    elif fault == "null":
        value["max_run_seconds"] = None
    elif fault == "float":
        value["timeout_seconds"] = 1.5
    elif fault == "bool":
        value["schema_version"] = True
    elif fault == "timeout":
        value["timeout_seconds"] = 11
    elif fault == "run":
        value["max_run_seconds"] = 121
    elif fault == "size":
        value["max_response_bytes"] = 65537
    elif fault == "age":
        value["max_evidence_age_seconds"] = 901
    elif fault == "nodes":
        value["expected_oke_nodes"] = 0
    elif fault == "extra":
        value["credentials"] = "PRIVATE"
    elif fault == "url":
        t["host"] = "https://example.com"
    elif fault == "userinfo":
        t["host"] = "user:PRIVATE@example.com"
    elif fault == "literal":
        t["host"] = "127.0.0.1"
    elif fault == "address":
        t["addresses"] = ["0.0.0.0"]
    elif fault == "metadata":
        t["addresses"] = ["169.254.169.254"]
    elif fault == "mapped":
        t["addresses"] = ["::ffff:7f00:1"]
    elif fault == "duplicate":
        value["targets"].append(deepcopy(t))
    elif fault == "path":
        t["path"] = "/../private"
    elif fault == "query":
        t["path"] = "/?token=PRIVATE"
    elif fault == "redirect-status":
        t["statuses"] = [302]
    else:
        t["headers"] = {"Authorization": "PRIVATE"}
    with pytest.raises(ValueError):
        h.policy(value, scope())


def test_example_stays_disabled_and_cost_policy_unmodified():
    with pytest.raises(ValueError):
        h.policy(json.loads((ROOT / "config/health.example.json").read_bytes()), scope())
    assert "targets" not in json.loads((ROOT / "config/monitoring.example.json").read_bytes())


@pytest.fixture
def server():
    state = dict(status=200, body=b"PRIVATE-BODY", headers={}, delay=0, requests=[])

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"].append(dict(path=self.path, headers=dict(self.headers)))
            time.sleep(state["delay"])
            try:
                self.send_response(state["status"])
                for key, value in state["headers"].items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(state["body"])
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd, state
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=2)


def local_target(server):
    httpd, _ = server
    t = target("http")
    t["port"] = httpd.server_port
    t["addresses"] = sorted(
        {
            row[4][0]
            for row in socket.getaddrinfo(
                "localhost", 0, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
            )
        }
    )
    return t


@pytest.mark.parametrize(
    "fault",
    [None, "status", "redirect", "oversized", "declared-size", "incomplete", "encoding", "headers"],
)
def test_real_local_http_and_failed_responses(server, fault, monkeypatch):
    _, state = server
    if fault == "status":
        state["status"] = 503
    elif fault == "redirect":
        state.update(status=302, headers={"Location": "http://169.254.169.254/PRIVATE"})
    elif fault == "oversized":
        state["body"] = b"x" * 1025
    elif fault == "declared-size":
        state["headers"]["Content-Length"] = "1000000"
    elif fault == "incomplete":
        state["headers"]["Content-Length"] = "100"
    elif fault == "encoding":
        state["headers"]["Content-Encoding"] = "gzip"
    elif fault == "headers":
        state["headers"]["PRIVATE"] = "x" * 65537
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1/PRIVATE")
    result = h._probe(local_target(server), policy())
    assert result["status"] == (
        "healthy"
        if fault is None
        else "unhealthy"
        if fault in {"status", "redirect"}
        else "unknown"
    )
    assert len(state["requests"]) == 1 and state["requests"][0]["path"] == "/ready"
    assert "Authorization" not in state["requests"][0]["headers"]
    assert "PRIVATE" not in json.dumps(result)


def test_dns_scope_mismatch_never_connects(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.5", 443))],
    )
    monkeypatch.setattr(socket, "socket", lambda *a: pytest.fail("connect after DNS escape"))
    assert h._probe(target("tls"), policy()) == dict(
        status="unknown", reason="destination_mismatch"
    )


@pytest.mark.parametrize("fault", [None, "missing-answer", "failure"])
def test_dns_results_are_explicit_and_bounded(monkeypatch, fault):
    t = target()
    if fault == "missing-answer":
        t["addresses"].append("::1")

    def resolve(*a, **kw):
        if fault == "failure":
            raise socket.gaierror("PRIVATE resolver error")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    value = h._probe(t, policy())
    assert value["status"] == (
        "healthy" if fault is None else "unhealthy" if fault == "missing-answer" else "unknown"
    )
    assert "PRIVATE" not in json.dumps(value)


def test_process_transport_success_timeout_and_cleanup(server):
    t = local_target(server)
    before = {p.pid for p in multiprocessing.active_children()}
    assert h._bounded(t, policy(), 3)["status"] == "healthy"
    server[1]["delay"] = 2
    started = time.monotonic()
    assert h._bounded(t, policy(), 0.5) == dict(status="unknown", reason="timeout")
    assert time.monotonic() - started < 2
    assert {p.pid for p in multiprocessing.active_children()} == before


def test_stalled_resolution_is_killed_before_network_timeout(server):
    # A spawn startup/deadline is bounded too: there is no unbounded DNS thread
    # in the parent. Resolver blocking itself is covered by the worker below.
    before = {p.pid for p in multiprocessing.active_children()}
    assert h._bounded(local_target(server), policy(), 0.001)["status"] == "unknown"
    assert {p.pid for p in multiprocessing.active_children()} == before


@pytest.fixture
def tls_server(server, tmp_path):
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    httpd, state = server
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    ca = tmp_path / "fixture-cert.pem"
    private = tmp_path / "fixture-key.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca, private)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    return server, ca


@pytest.mark.parametrize("kind", ["tls", "http"])
@pytest.mark.parametrize("fault", [None, "trust", "hostname", "expiry", "insecure"])
def test_real_local_tls_verification_sni_and_expiry(tls_server, monkeypatch, kind, fault):
    import ssl

    server, ca = tls_server
    t = local_target(server)
    t["kind"] = kind
    if kind == "http":
        t["scheme"] = "https"
    config = policy()
    if fault == "trust":
        context = h._tls_context()
    else:
        context = ssl.create_default_context(cafile=str(ca))
    if fault == "hostname":
        t["host"] = "wrong.example"
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *a, **kw: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", t["port"]))
            ],
        )
    if fault == "expiry":
        config["min_tls_validity_seconds"] = 3 * 86400
    if fault == "insecure":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    monkeypatch.setattr(h, "_tls_context", lambda: context)
    result = h._probe(t, config)
    assert result["status"] == (
        "healthy" if fault is None else "unknown" if fault == "insecure" else "unhealthy"
    )
    if fault in {"trust", "hostname"}:
        assert result["reason"] == "tls_invalid"
    if fault == "expiry":
        assert result["reason"] == "tls_expiring"
    if fault is None:
        assert result["validity_seconds"] > 86400
    assert "PRIVATE" not in json.dumps(result)


def _stalled_resolver_worker(target, config, channel):
    def resolve(*args, **kwargs):
        Path(target["marker"]).write_text("entered resolver")
        time.sleep(30)
        return []

    socket.getaddrinfo = resolve
    h._worker(target, config, channel)


def test_actual_stalled_dns_resolver_is_reaped(server, tmp_path, monkeypatch):
    t = local_target(server)
    t["marker"] = str(tmp_path / "resolver-entered")
    before = {p.pid for p in multiprocessing.active_children()}
    monkeypatch.setattr(h, "_worker", _stalled_resolver_worker)
    started = time.monotonic()
    assert h._bounded(t, policy(), 2) == dict(status="unknown", reason="timeout")
    assert Path(t["marker"]).read_text() == "entered resolver"
    assert time.monotonic() - started < 4
    assert {p.pid for p in multiprocessing.active_children()} == before


def test_unreachable_local_endpoint_is_unknown(server):
    t = local_target(server)
    server[0].shutdown()
    server[0].server_close()
    assert h._probe(t, policy()) == dict(status="unknown", reason="connect_failed")


def test_run_budget_exhaustion_retains_all_targets(monkeypatch):
    targets = [dict(target(), id="endpoint-" + str(i)) for i in range(3)]
    config = policy("cloudflare-edge", targets=targets)
    clock = [0.0]
    monkeypatch.setattr(h.time, "monotonic", lambda: clock[0])
    calls = []

    def probe(t, c, seconds):
        calls.append(t["id"])
        clock[0] = 10
        return dict(status="healthy", reason="observed")

    monkeypatch.setattr(h, "_bounded", probe)
    result = h.observe(scope("cloudflare-edge"), config, network=True)
    assert calls == ["endpoint-0"]
    assert result["status"] == "unknown" and len(result["endpoints"]) == 3
    assert all(v["reason"] == "run_budget_exhausted" for v in result["endpoints"][1:])


@pytest.fixture
def bundle(tmp_path):
    from infra_core import operations

    private = tmp_path / ".infra"
    private.mkdir()
    raw = evidence()
    instant = datetime.now(UTC).isoformat()
    for key in ("observed_at", "collection_started_at", "collection_completed_at"):
        raw[key] = instant
    for row in raw["checks"].values():
        row["observed_at"] = instant
    for name, value in (("policy", policy()), ("cluster", raw)):
        (private / (name + ".json")).write_bytes(operations.encoded(value))
    index = dict(
        schema_version=1,
        scope=scope(),
        policy=".infra/policy.json",
        cluster_evidence=".infra/cluster.json",
    )
    path = private / "index.json"
    path.write_bytes(operations.encoded(index))
    return tmp_path, path


def test_check_cli_is_offline_hash_bound_and_does_not_write(bundle, monkeypatch, capsys):
    from infra_core import cli

    root, path = bundle
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    monkeypatch.setattr(h, "_bounded", lambda *a: pytest.fail("unexpected probe"))
    monkeypatch.setattr(cli, "find_repository", lambda root: bundle[0])
    assert cli.main(["monitoring", "health", "--evidence", str(path), "--check"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "healthy" and report["mode"] == "check"
    assert set(report["inputs_sha256"]) == {"index", "policy", "cluster"}
    assert report["cluster_isolation_verified"] is False
    assert "PRIVATE" not in json.dumps(report)
    assert before == {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize(
    "fault",
    ["mode", "both-modes", "path", "symlink", "size", "duplicate", "nan", "extra", "cross-unit"],
)
def test_bad_cli_and_private_inputs_are_redacted(bundle, monkeypatch, capsys, fault):
    from infra_core import cli

    root, path = bundle
    monkeypatch.setattr(cli, "find_repository", lambda root: bundle[0])
    args = ["monitoring", "health", "--evidence", str(path)]
    if fault in {"mode", "both-modes"}:
        with pytest.raises(SystemExit):
            cli.main(args + (["--check", "--observe"] if fault == "both-modes" else []))
        return
    index = json.loads(path.read_bytes())
    if fault == "path":
        index["policy"] = "config/health.example.json"
    elif fault == "symlink":
        (root / ".infra/link.json").symlink_to(ROOT / "config/health.example.json")
        index["policy"] = ".infra/link.json"
    elif fault == "size":
        (root / ".infra/policy.json").write_bytes(b"PRIVATE" * 200000)
    elif fault == "duplicate":
        path.write_bytes(b'{"PRIVATE":1,"PRIVATE":2}')
    elif fault == "nan":
        path.write_bytes(b'{"PRIVATE":NaN}')
    elif fault == "extra":
        index["credential"] = "PRIVATE"
    else:
        index["scope"]["unit"] = "cloudflare-edge"
    if fault not in {"duplicate", "nan"}:
        path.write_text(json.dumps(index))
    assert cli.main(args + ["--check"]) == 1
    output = capsys.readouterr()
    assert "HLT001" in str(output) and "PRIVATE" not in str(output)


def test_observe_cli_is_explicit_and_does_not_discover_credentials(bundle, monkeypatch, capsys):
    from infra_core import cli

    root, path = bundle
    cfg = policy(targets=[target()])
    (root / ".infra/policy.json").write_text(json.dumps(cfg))
    monkeypatch.setattr(cli, "find_repository", lambda root: bundle[0])
    called = []

    def probe(*args):
        called.append(True)
        return dict(status="healthy", reason="observed")

    monkeypatch.setattr(h, "_bounded", probe)
    assert cli.main(["monitoring", "health", "--evidence", str(path), "--observe"]) == 0
    assert called == [True] and json.loads(capsys.readouterr().out)["mode"] == "observe"


def _bad_worker(target, config, channel):
    import os

    fault = target["fault"]
    if fault == "exit":
        channel.close()
        return
    if fault == "partial":
        os.write(channel.fileno(), (100).to_bytes(4, "big") + b"{")
        time.sleep(30)
    elif fault == "oversized":
        channel.send_bytes(b"PRIVATE" * 1000)
    elif fault == "malformed":
        channel.send_bytes(b"{}")
    elif fault == "contradiction":
        channel.send_bytes(b'{"status":"healthy","reason":"tls_invalid"}')
    else:
        channel.send_bytes(b'{"status":"healthy","reason":"observed"}')
        time.sleep(30)
    channel.close()


@pytest.mark.parametrize(
    "fault", ["exit", "oversized", "malformed", "contradiction", "stuck-after-success", "partial"]
)
def test_worker_failure_and_lost_exit_never_become_healthy(fault, monkeypatch):
    t = dict(target(), fault=fault)
    before = {p.pid for p in multiprocessing.active_children()}
    monkeypatch.setattr(h, "_worker", _bad_worker)
    result = h._bounded(t, policy(), 1)
    assert result["status"] == "unknown"
    assert "PRIVATE" not in json.dumps(result)
    assert {p.pid for p in multiprocessing.active_children()} == before


def test_cluster_age_is_rechecked_at_end_of_observation(monkeypatch):
    raw = evidence()
    start = NOW + timedelta(seconds=899)
    from collections import deque

    values = deque([start, start, start + timedelta(seconds=2), start + timedelta(seconds=2)])

    class Clock:
        @classmethod
        def now(cls, *args):
            return values.popleft() if values else start + timedelta(seconds=2)

    monkeypatch.setattr(h, "datetime", Clock)
    monkeypatch.setattr(h, "_bounded", lambda *a: dict(status="healthy", reason="observed"))
    report = h.observe(scope(), policy(targets=[target()]), raw, network=True)
    assert report["endpoints"][0]["status"] == "healthy"
    assert report["status"] == "unknown" and all(
        v["status"] == "unknown" for v in report["cluster"]
    )
