"""Explicit bounded endpoint observations and separately attributed OKE attestations."""

import hashlib
import http.client
import ipaddress
import json
import multiprocessing
import os
import re
import socket
import ssl
import time
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any

from infra_core import operations
from infra_core.administration import private_path
from infra_core.governance.contracts import fields, timestamp

MESSAGE = "HLT001: invalid health observation inputs; diagnostics withheld"
UNITS = {"oci-network", "oci-oke", "cloudflare-edge", "supabase-database"}
CHECKS = ("nodes", "api", "cni", "dns")
REASONS = {
    "observed",
    "dns_mismatch",
    "destination_mismatch",
    "dns_failed",
    "connect_failed",
    "tls_invalid",
    "tls_expiring",
    "tls_failed",
    "http_status",
    "redirect",
    "oversized",
    "incomplete",
    "unsupported_encoding",
    "protocol_failed",
    "timeout",
    "not_observed",
    "worker_failed",
    "run_budget_exhausted",
}


def require(value: bool) -> None:
    if not value:
        raise ValueError(MESSAGE)


def _address(value: object) -> str:
    require(type(value) is str and "%" not in value)
    assert isinstance(value, str)
    address = ipaddress.ip_address(value)
    require(
        str(address) == value
        and not (address.is_link_local or address.is_multicast or address.is_unspecified)
        and not (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None)
    )
    return str(address)


def policy(value: dict[str, Any], scope: dict[str, Any]) -> None:
    fields(scope, {"unit", "account_id", "scope_id", "region"}, "health scope")
    require(
        all(type(v) is str and 0 < len(v) <= 256 for v in scope.values()) and scope["unit"] in UNITS
    )
    fields(
        value,
        {
            "schema_version",
            "enabled",
            "timeout_seconds",
            "max_run_seconds",
            "max_response_bytes",
            "max_evidence_age_seconds",
            "min_tls_validity_seconds",
            "expected_oke_nodes",
            "targets",
        },
        "health policy",
    )
    require(
        type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["enabled"] is True
    )
    for key, ceiling in dict(
        timeout_seconds=10,
        max_run_seconds=120,
        max_response_bytes=65536,
        max_evidence_age_seconds=900,
        min_tls_validity_seconds=31536000,
    ).items():
        require(type(value[key]) is int and 0 < value[key] <= ceiling)
    require(value["timeout_seconds"] <= value["max_run_seconds"])
    require(
        (type(value["expected_oke_nodes"]) is int and 0 < value["expected_oke_nodes"] <= 100)
        if scope["unit"] == "oci-oke"
        else value["expected_oke_nodes"] is None
    )
    targets = value["targets"]
    require(
        type(targets) is list
        and len(targets) <= 16
        and (bool(targets) or scope["unit"] == "oci-oke")
    )
    names: set[str] = set()
    for target in targets:
        kind = target.get("kind") if type(target) is dict else None
        require(kind in {"dns", "tls", "http"})
        keys = {"id", "kind", "host", "addresses"} | ({"port"} if kind != "dns" else set())
        if kind == "http":
            keys |= {"scheme", "path", "statuses"}
        fields(target, keys, "health target")
        name = target["id"]
        require(
            type(name) is str
            and re.fullmatch(r"[a-z][a-z0-9-]{0,62}", name) is not None
            and name not in names
        )
        names.add(name)
        host = target["host"]
        require(
            type(host) is str
            and len(host) <= 253
            and (
                host == "localhost"
                or (
                    "." in host
                    and all(
                        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                        for label in host.split(".")
                    )
                )
            )
        )
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError(MESSAGE)
        addresses = target["addresses"]
        require(type(addresses) is list and 0 < len(addresses) <= 16)
        require(len({_address(v) for v in addresses}) == len(addresses))
        if kind != "dns":
            require(type(target["port"]) is int and 1 <= target["port"] <= 65535)
        if kind == "http":
            require(target["scheme"] in {"http", "https"})
            path = target["path"]
            require(
                type(path) is str
                and len(path) <= 1024
                and re.fullmatch(r"/[A-Za-z0-9/_~.-]*", path) is not None
                and not path.startswith("//")
                and not any(p in {".", ".."} for p in path.split("/"))
            )
            statuses = target["statuses"]
            require(
                type(statuses) is list
                and 0 < len(statuses) <= 10
                and all(type(s) is int and 200 <= s < 300 for s in statuses)
                and len(set(statuses)) == len(statuses)
            )


class _Failure(Exception):
    def __init__(self, status: str, reason: str):
        self.status, self.reason = status, reason


def _tls_context() -> ssl.SSLContext:
    # Select the OpenSSL system paths explicitly; ignore ambient SSL_CERT_* overrides.
    paths = ssl.get_default_verify_paths()
    cafile = paths.openssl_cafile if Path(paths.openssl_cafile).is_file() else None
    capath = paths.openssl_capath if Path(paths.openssl_capath).is_dir() else None
    require(cafile is not None or capath is not None)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=cafile, capath=capath)
    return context


def _probe(target: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """Private worker transport: resolve once, connect to a checked numeric address."""
    connection: socket.socket | None = None
    response: http.client.HTTPResponse | None = None
    stage = "dns_failed"
    details: dict[str, Any] = {}
    try:
        answers = socket.getaddrinfo(
            target["host"], target.get("port", 0), type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
        addresses = {_address(row[4][0]) for row in answers}
        if not addresses or not addresses <= set(target["addresses"]):
            raise _Failure("unknown", "destination_mismatch")
        if target["kind"] == "dns":
            return dict(
                status="healthy" if addresses == set(target["addresses"]) else "unhealthy",
                reason="observed" if addresses == set(target["addresses"]) else "dns_mismatch",
            )
        selected = sorted(addresses, key=lambda a: (ipaddress.ip_address(a).version, a))[0]
        stage = "connect_failed"
        connection = socket.socket(
            socket.AF_INET6 if ":" in selected else socket.AF_INET, socket.SOCK_STREAM
        )
        connection.settimeout(config["timeout_seconds"])
        connection.connect((selected, target["port"]))
        if target["kind"] == "tls" or target.get("scheme") == "https":
            stage = "tls_failed"
            context = _tls_context()
            require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED)
            connection = context.wrap_socket(connection, server_hostname=target["host"])
            certificate = connection.getpeercert()
            require(certificate is not None)
            assert certificate is not None
            expiry = datetime.fromtimestamp(
                ssl.cert_time_to_seconds(str(certificate["notAfter"])), UTC
            )
            remaining = int((expiry - datetime.now(UTC)).total_seconds())
            details = dict(certificate_expires_at=expiry.isoformat(), validity_seconds=remaining)
            if remaining < config["min_tls_validity_seconds"]:
                raise _Failure("unhealthy", "tls_expiring")
        if target["kind"] == "tls":
            return dict(status="healthy", reason="observed", **details)
        stage = "protocol_failed"
        host = target["host"] + ":" + str(target["port"])
        request = (
            f"GET {target['path']} HTTP/1.1\r\nHost: {host}\r\n"
            "Connection: close\r\nAccept-Encoding: identity\r\n"
            "User-Agent: cloud-infra-health/1\r\n\r\n"
        )
        connection.sendall(request.encode("ascii"))
        response = http.client.HTTPResponse(connection)
        response.begin()
        details["http_status"] = response.status
        if 300 <= response.status < 400:
            raise _Failure("unhealthy", "redirect")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise _Failure("unknown", "unsupported_encoding")
        lengths = response.headers.get_all("Content-Length", [])
        transfer = response.headers.get_all("Transfer-Encoding", [])
        if (
            len(lengths) > 1
            or len(transfer) > 1
            or (transfer and (lengths or transfer[0].lower() != "chunked"))
        ):
            raise _Failure("unknown", "protocol_failed")
        if lengths and not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
            raise _Failure("unknown", "protocol_failed")
        maximum = config["max_response_bytes"]
        if lengths and int(lengths[0]) > maximum:
            raise _Failure("unknown", "oversized")
        body = response.read(maximum + 1)
        if len(body) > maximum:
            raise _Failure("unknown", "oversized")
        if lengths and len(body) != int(lengths[0]):
            raise _Failure("unknown", "incomplete")
        return dict(
            status="healthy" if response.status in target["statuses"] else "unhealthy",
            reason="observed" if response.status in target["statuses"] else "http_status",
            **details,
        )
    except _Failure as error:
        return dict(status=error.status, reason=error.reason, **details)
    except ssl.SSLCertVerificationError:
        return dict(status="unhealthy", reason="tls_invalid")
    except TimeoutError:
        return dict(status="unknown", reason="timeout")
    except Exception:
        return dict(status="unknown", reason=stage)
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()


def _worker(target: dict[str, Any], config: dict[str, Any], channel: Connection) -> None:
    try:
        with open(os.devnull, "wb") as quiet:
            os.dup2(quiet.fileno(), 1)
            os.dup2(quiet.fileno(), 2)
        result = _probe(target, config)
        channel.send_bytes(operations.encoded(result))
    except BaseException:
        try:
            channel.send_bytes(b'{"status":"unknown","reason":"worker_failed"}')
        except (OSError, ValueError):
            pass
    finally:
        channel.close()


def _bounded(target: dict[str, Any], config: dict[str, Any], seconds: float) -> dict[str, Any]:
    context = multiprocessing.get_context("spawn")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(target, config, writer), daemon=True)
    deadline = time.monotonic() + seconds
    try:
        process.start()
        writer.close()
        if not reader.poll(max(0, deadline - time.monotonic())):
            return dict(status="unknown", reason="timeout")
        # EOF after exit makes even a partially written frame safe to read.
        process.join(max(0, deadline - time.monotonic()))
        if process.exitcode is None or time.monotonic() > deadline:
            return dict(status="unknown", reason="timeout")
        result = json.loads(reader.recv_bytes(maxlength=4096))
        require(
            process.exitcode == 0
            and type(result) is dict
            and set(result)
            <= {"status", "reason", "certificate_expires_at", "validity_seconds", "http_status"}
        )
        require(
            result["status"] in {"healthy", "unhealthy", "unknown"} and result["reason"] in REASONS
        )
        require(result["status"] != "healthy" or result["reason"] == "observed")
        if "http_status" in result:
            require(type(result["http_status"]) is int and 100 <= result["http_status"] <= 599)
        if "certificate_expires_at" in result:
            timestamp(result["certificate_expires_at"], "certificate expiry")
            require(type(result.get("validity_seconds")) is int)
        assert isinstance(result, dict)
        return result
    except Exception:
        return dict(status="unknown", reason="worker_failed")
    finally:
        reader.close()
        writer.close()
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
                process.join(0.2)
            if process.is_alive():
                process.kill()
                process.join(0.5)
            process.close()


def cluster(
    scope: dict[str, Any], config: dict[str, Any], evidence: dict[str, Any] | None, *, now: datetime
) -> list[dict[str, Any]]:
    """Validate operator-recorded readiness; this never discovers a cluster or isolation."""
    try:
        require(evidence is not None)
        assert evidence is not None
        fields(
            evidence,
            {
                "schema_version",
                "scope",
                "source",
                "observed_at",
                "collection_started_at",
                "collection_completed_at",
                "checks",
            },
            "cluster evidence",
        )
        require(
            type(evidence["schema_version"]) is int
            and evidence["schema_version"] == 1
            and evidence["scope"] == scope
            and evidence["source"] == "operator-supplied"
            and type(evidence["checks"]) is dict
            and set(evidence["checks"]) <= set(CHECKS)
        )
        start, end, observed = (
            timestamp(evidence[k], "cluster clock")
            for k in ("collection_started_at", "collection_completed_at", "observed_at")
        )
        require(
            start == observed <= end <= now
            and 0 <= (now - start).total_seconds() <= config["max_evidence_age_seconds"]
        )
    except (ValueError, KeyError, TypeError):
        return [
            dict(
                check=k,
                status="unknown",
                reason="missing_stale_or_invalid_evidence",
                source="operator-supplied",
            )
            for k in CHECKS
        ]
    findings = []
    for name in CHECKS:
        try:
            row = evidence["checks"][name]
            fields(
                row,
                {"observed_at", "expected_nodes", "ready_nodes"}
                if name == "nodes"
                else {"observed_at", "healthy"},
                "cluster check",
            )
            clock = timestamp(row["observed_at"], "cluster check clock")
            require(
                start <= clock <= end
                and 0 <= (now - clock).total_seconds() <= config["max_evidence_age_seconds"]
            )
            if name == "nodes":
                require(
                    type(row["expected_nodes"]) is int
                    and row["expected_nodes"] == config["expected_oke_nodes"]
                    and type(row["ready_nodes"]) is int
                    and 0 <= row["ready_nodes"] <= row["expected_nodes"]
                )
                healthy = row["ready_nodes"] == row["expected_nodes"]
            else:
                require(type(row["healthy"]) is bool)
                healthy = row["healthy"]
            findings.append(
                dict(
                    check=name,
                    status="healthy" if healthy else "unhealthy",
                    reason="recorded_readiness",
                    source="operator-supplied",
                    observed_at=row["observed_at"],
                )
            )
        except (ValueError, KeyError, TypeError):
            findings.append(
                dict(
                    check=name,
                    status="unknown",
                    reason="missing_stale_or_invalid_evidence",
                    source="operator-supplied",
                )
            )
    return findings


def observe(
    scope: dict[str, Any],
    config: dict[str, Any],
    evidence: dict[str, Any] | None = None,
    *,
    network: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    policy(config, scope)
    require(not network or now is None)
    require(type(network) is bool and (scope["unit"] == "oci-oke" or evidence is None))
    started = now or datetime.now(UTC)
    require(started.tzinfo is not None)
    started = started.astimezone(UTC)
    deadline = time.monotonic() + config["max_run_seconds"]
    rows = []
    scope_hash = operations.digest(scope)
    for target in config["targets"]:
        began = started if now is not None else datetime.now(UTC)
        remaining = min(config["timeout_seconds"], deadline - time.monotonic())
        if not network:
            result = dict(status="unknown", reason="not_observed")
        elif remaining <= 0:
            result = dict(status="unknown", reason="run_budget_exhausted")
        else:
            result = _bounded(target, config, remaining)
        rows.append(
            dict(
                id=scope_hash + "/endpoint/" + target["id"],
                kind=target["kind"],
                source="remote-probe",
                target_sha256=operations.digest(target),
                started_at=began.isoformat(),
                completed_at=(began if now is not None else datetime.now(UTC)).isoformat(),
                **result,
            )
        )
    completed = datetime.now(UTC) if now is None else started
    cluster_rows = (
        cluster(scope, config, evidence, now=completed) if scope["unit"] == "oci-oke" else []
    )
    for row in cluster_rows:
        row["id"] = scope_hash + "/cluster/" + row["check"]
    all_rows = rows + cluster_rows
    status = next(
        (s for s in ("unknown", "unhealthy") if any(v["status"] == s for v in all_rows)), "healthy"
    )
    original_clocks: dict[str, str | None] = {}
    if scope["unit"] == "oci-oke":
        for key in ("observed_at", "collection_started_at", "collection_completed_at"):
            value = (evidence or {}).get(key)
            try:
                timestamp(value, "source clock")
                original_clocks[key] = value
            except (ValueError, TypeError):
                original_clocks[key] = None
    return dict(
        schema_version=1,
        kind="infrastructure-health",
        scope_sha256=scope_hash,
        unit=scope["unit"],
        mode="observe" if network else "check",
        started_at=started.isoformat(),
        completed_at=completed.isoformat(),
        status=status,
        complete=all(v["status"] != "unknown" for v in all_rows),
        endpoints=rows,
        cluster=cluster_rows,
        cluster_source_clocks=original_clocks,
        deployment_authorized=False,
        remediation_authorized=False,
        cluster_isolation_verified=False,
    )


def check(root: Path, index: Path, *, network: bool = False) -> dict[str, Any]:
    try:

        def read(path: Path) -> bytes:
            require(path.is_file() and 0 < path.stat().st_size <= operations.MAX_BYTES)
            raw = path.read_bytes()
            require(0 < len(raw) <= operations.MAX_BYTES)
            return raw

        def parse(raw: bytes) -> dict[str, Any]:
            value = json.loads(raw, object_pairs_hook=operations._pairs)
            json.dumps(value, allow_nan=False)
            require(type(value) is dict)
            assert isinstance(value, dict)
            return value

        raw = {"index": read(private_path(root, index))}
        item = parse(raw["index"])
        fields(item, {"schema_version", "scope", "policy", "cluster_evidence"}, "health index")
        require(type(item["schema_version"]) is int and item["schema_version"] == 1)
        raw["policy"] = read(private_path(root, Path(item["policy"])))
        evidence = None
        if item["cluster_evidence"] is not None:
            raw["cluster"] = read(private_path(root, Path(item["cluster_evidence"])))
            evidence = parse(raw["cluster"])
        result = observe(item["scope"], parse(raw["policy"]), evidence, network=network)
        result["inputs_sha256"] = {k: hashlib.sha256(v).hexdigest() for k, v in raw.items()}
        return result
    except Exception:
        raise ValueError(MESSAGE) from None
