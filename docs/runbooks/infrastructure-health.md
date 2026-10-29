# Bounded infrastructure health observations (M05-PR13)

The health observer performs explicitly allowlisted DNS, TLS and HTTP checks and
separately validates operator-supplied OKE readiness evidence. It does not discover
resources, read credentials/kubeconfig, install controllers or write state/journals.
A healthy endpoint is a point observation, not an application SLO, authenticated
cluster inspection, cutover admission or proof of network isolation.

```sh
uv run --locked infra monitoring health --evidence .infra/health/index.json --check
uv run --locked infra monitoring health --evidence .infra/health/index.json --observe
```

`--check` validates private inputs and OKE evidence without resolving names,
starting workers or sending requests. Configured remote targets remain unknown
with reason `not_observed`. `--observe` explicitly permits the configured probes.
The two modes are mutually exclusive and one is required. Both emit JSON; only a
healthy report exits zero. Unhealthy/unknown reports exit one. Malformed policy,
index or unreadable inputs return redacted `HLT001` diagnostics instead of a report.

## Private configuration

Copy `config/health.example.json` into `.infra/health/policy.json`, and supply
reviewed bounds and explicit targets. The public example is disabled and incomplete;
it authorizes no probes. It is a sibling of PR12's cost policy because that strict
schema remains unchanged. A private health policy does not enable deployment or
any other operational gate. No actual endpoint or operational thresholds are
provided by this feature. Review destinations and permitted traffic before use.

The schema-1 private index contains exactly:

```json
{
  "schema_version": 1,
  "scope": {
    "unit": "oci-oke",
    "account_id": "replace-with-reviewed-account",
    "scope_id": "replace-with-reviewed-cluster-id",
    "region": "replace-with-reviewed-region"
  },
  "policy": ".infra/health/policy.json",
  "cluster_evidence": ".infra/health/cluster.json"
}
```

The unit is one of the existing four identities. For other units, scope_id names
the independently reviewed network/zone/organization and cluster_evidence must be
null. OKE missing evidence produces four unknown readiness results. Index, policy
and evidence must be JSON resolving below this checkout's `.infra`, each at most
1 MiB; symlinks cannot escape it. Exact input bytes are SHA-256 bound in the report.
This establishes consistency, not authenticity of a private policy or attestation.
Only run trusted reviewed code/configuration. This library is not an authorization
boundary against arbitrary same-user Python callers or filesystem tampering.

The health policy has exactly these fields:

| Field | Contract |
| --- | --- |
| schema_version / enabled | Integer 1 / boolean true for an explicitly configured private run |
| timeout_seconds | Integer 1–10 per target, including worker startup, DNS and response reads |
| max_run_seconds | Integer 1–120 shared by all remote targets; at least timeout_seconds |
| max_response_bytes | Integer 1–65536 response-body bytes; no decompression |
| max_evidence_age_seconds | Integer 1–900, applied to original OKE collection/check clocks |
| min_tls_validity_seconds | Integer 1–31536000 remaining certificate validity required |
| expected_oke_nodes | Integer 1–100 for OKE; null for other units; an expectation, never a quota allowance |
| targets | At most 16 unique explicit targets; nonempty except for OKE evidence-only checks |

A target contains a safe nonsensitive `id` label (lowercase letter followed by up
to 62 lowercase letters/digits/hyphens), `kind` (dns/tls/http), lowercase ASCII DNS
`host`, and 1–16 unique canonical IP `addresses`. Hosts must be fully qualified
without a trailing dot; localhost is allowed for explicit local fixtures. IP literal
hosts, userinfo/URLs, wildcard names, scoped/mapped IPv6 and unspecified,
link-local or multicast addresses are rejected. Private/loopback destinations
require explicit addresses just like public ones; private OKE endpoints require
appropriate independently provisioned runner reachability.

TLS and HTTP targets additionally require integer `port` (1–65535). HTTP requires
`scheme` (http/https), `path` (a bounded absolute ASCII path without query,
fragment, escaping or dot segments), and unique `statuses` (1–10 expected 2xx
codes). TLS/DNS targets accept no HTTP fields. No arbitrary URL, header, request
body, credential, custom CA, insecure TLS option or redirect allowance is accepted.
Plain HTTP is explicit and unauthenticated; use HTTPS when confidentiality matters.

## Probe boundaries and results

The worker resolves the hostname once through the system resolver. All returned
addresses must belong to the explicit address set; no connection is attempted on
a mismatch. DNS probes require the complete answer set to equal that set. TLS/HTTP
accept a nonempty subset and connect to one deterministic checked numeric address
(IPv4 first), preserving the original hostname for SNI, certificate and HTTP Host
checks. There is no second hostname resolution, address fallback or automatic retry.
Review address changes before changing the allowlist; this is not a general-purpose
load-balancer or arbitrary endpoint discovery client.

Each probe runs in a fresh spawned process. Parent deadlines cover blocking DNS,
TCP/TLS and slow-drip response handling; overdue workers are terminated/killed and
reaped, with up to roughly 0.7 seconds additional cleanup wait. Exhausted run budgets
leave remaining targets explicitly unknown. Successful result bytes are bounded
to 4 KiB and the worker must also exit successfully. Partial messages, crashes or
a success message followed by a stalled worker cannot establish health.

TLS always requires system trust and matching hostname, then checks certificate
expiry against the explicit minimum. The transport selects compiled OpenSSL system
CA paths rather than ambient SSL_CERT_FILE/SSL_CERT_DIR overrides. HTTP uses a direct
socket and ignores ambient proxy settings; it sends only GET, Host, Connection,
Accept-Encoding and a fixed User-Agent. Redirect responses are unhealthy and never
followed, even to another allowlisted address. Compressed responses, ambiguous
framing and oversized/incomplete bodies are unknown. Python's HTTP parser also
bounds header lines/count; the policy byte limit applies to the body. Raw bodies,
headers, certificate subjects, endpoint addresses and exception diagnostics are
never copied into reports; worker stdout/stderr are discarded.

Endpoint results have stable scope/target-label identities, target digests,
start/completion clocks, source remote-probe and fixed reasons. TLS may additionally
report certificate expiry/remaining seconds; HTTP may report status code.

- Healthy: the configured DNS answer set, verified TLS validity, or bounded expected
  HTTP response was positively observed.
- Unhealthy: a known DNS answer omission, certificate rejection/approaching expiry,
  redirect or unexpected HTTP status was observed.
- Unknown: DNS/network failure, disallowed destination, timeout, invalid/incomplete
  response, worker failure, exhausted budget or an unperformed probe.

Unknown takes precedence over unhealthy in report status; individual known failures
remain visible. `complete` is false if any endpoint/readiness result is unknown.
Deployment/remediation authority and cluster_isolation_verified remain false.
Scheduling, persisted incidents, notification delivery and missing-run handling
remain M05-PR14. There is no implicit retry, remediation or incident-state write.

## Operator-supplied OKE readiness

Cluster evidence schema 1 has exactly `scope` (identical to the index), `source`
(`operator-supplied`), `observed_at`, `collection_started_at`,
`collection_completed_at`, and `checks`, in addition to `schema_version`.
Original collection start must equal observation, precede completion, and be fresh
and not in the future. Freshness is rechecked at the end of endpoint observation.
Checks may contain only nodes, api, cni and dns; a missing check remains unknown.

The nodes record has observed_at, expected_nodes and ready_nodes, with integer
counts and expected_nodes equal to policy. Zero-ready or partially ready clusters
are unhealthy; shrinking the expected count to hide a missing node is invalid.
API, CNI and DNS records each contain observed_at and an explicit healthy boolean.
False is unhealthy; absent/null/invalid data is unknown. Each check clock must lie
within the original collection interval and remain within the age bound. Original
header/check clocks are preserved; wrapping or rerunning the evaluator cannot
refresh them. Malformed clock values never appear as raw diagnostics.

Collect this evidence independently using authorized operator procedures. No
Kubernetes API client, authenticated API probe, kubeconfig discovery or controller
is introduced. These attestations are separately labeled operator-supplied, even
when endpoint probes succeed. They do not replace the broader signed health,
admission/isolation and recovery reviews required by the existing cutover gate.

## Verification

```sh
uv run --locked pytest -q tests/test_health.py tests/test_operational_findings.py
uv run --locked infra verify
```

Credential-free tests use loopback fixture servers and temporary test certificates.
They exercise real DNS/HTTP/TLS transport, trust/hostname/expiry failure, redirect
escape, oversized responses, stalled DNS/response workers, process cleanup and
scope/clock/readiness rejection. They contact no external endpoints. Live runner
reachability, actual allowlists/trust and attestation authenticity remain separate
operator acceptance. No new dependency, daemon, resource or workflow is added.
Reverting this interface requires no state migration.
