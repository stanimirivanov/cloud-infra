# Shared security evidence sidecars

M03-PR6 adds infra_core.evidence as a pure consistency API. Its intended backend
posture, service, OCI and cutover consumer migrations are complete. The
[M03 closeout](../m03-closeout.md) separates these repository deliverables from
administrator-owned activation prerequisites and later engineering.

## Contract

### Provider observations (M04-PR3)

`infra_core.inventory.http.observe_get` accepts only relative API targets for the
fixed Cloudflare/Supabase HTTPS hosts and explicit bearer credentials. It uses
verified TLS without ambient proxies, redirects, caller-controlled headers or
credential discovery. Only 429/502/503/504 retry, with at most three attempts and
fixed one/two-second waits; Retry-After cannot increase the wait. Response bodies
are bounded to 1 MiB and must be uncompressed UTF-8 JSON. Failed/partial responses
produce sanitized errors, never observations. Keep raw response bytes private.

`infra_core.provider_evidence.record_observation` also accepts OCI SDK observation
bytes. Its immutable result hashes the exact request description and response
and preserves the original timezone-aware collection interval. Descriptions must
exclude authentication data. Response bytes are omitted from object repr; the
transport does not log requests, headers or bodies. This in-memory binding is not
a persisted sidecar, signed attestation, account entitlement, pagination completion,
billing coverage watermark or operational approval. Existing sidecar schemas stay
unchanged; later collectors must validate scope and coverage independently.

Ten-second socket timeouts bound individual waits, not total slow-drip execution
or DNS resolution. Later collectors must bound page counts/aggregate bytes, and
protected orchestration must impose a whole-process deadline. Do not expose this
primitive as an operational preview path before those admission controls exist.

### Sidecar format

The [in-toto Statement v1 pattern](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
is adapted with closed repository-specific predicates (Apache-2.0 specification;
no copied implementation or new dependency). This is an unsigned sidecar, not a
signed attestation. Predicate URIs are identifiers, not downloadable schemas.

create_envelope returns deterministic UTF-8 JSON bytes; validate_envelope returns
None on success or raises EvidenceError. Both require kind, artifacts (logical
role -> immutable bytes), scope, now (aware datetime), and positive max_age
(timedelta). Creation also requires producer name/version and explicit original
collection_started_at/collection_completed_at ISO timestamps; it never restamps.

- Statement fields: _type, subject, predicateType, predicate. Each unique subject
  has name and digest.sha256. Roles start with a lowercase letter and contain only
  lowercase letters, digits, underscores or hyphens (64 characters maximum).
- Closed kinds: backend-posture, backend-recovery, oci-inventory, service-usage,
  cutover-review. Each predicate URI ends in /v1; predicate fields are scope,
  producer, collection_started_at, collection_completed_at. Unknown fields fail.
- Scope requires exact account_id, region, unit, commit and configuration_sha256.
  Commit is 40/64 lowercase hex; configuration digest is 64 lowercase hex. Other
  scope and producer labels are bounded identifiers; no empty/wildcard scope.
- Limits: 64 KiB envelope, 1-17 subjects, 10 MiB per artifact, 16 MiB aggregate.
  Duplicate JSON fields, nonfinite constants, invalid UTF-8 and excessive nesting fail.
- The consumer supplies expected kind, full subject set, scope, clock and TTL from
  its own policy. Freshness measures collection start; start <= end <= now. Usage
  coverage remains a separate subject-payload/domain check. JSON reformatting
  changes the SHA256: preserve exact captured bytes, including whitespace/newlines.

## Consumer obligations and limits

Keep sidecars/artifacts under ignored .infra; never attach private payloads to PRs.
Callers must bound file reads before capture, preserve scope from trusted inputs,
and independently validate payload schemas, completeness, source coverage and
semantics after binding. EVID001-EVID004 identify schema/subject/scope/clock failures;
errors omit private values. No filesystem, subprocess, network or cloud I/O occurs.
A producer label is a claim; an attacker able to replace artifact and sidecar can
recompute hashes. This proves neither source authenticity, IAM visibility, semantic
truth nor operational authority. Cutover role envelopes now require configured-key
DSSE signatures; the other transport sidecars remain unsigned. Independent source
authentication and active deployment-policy enforcement remain later activation
work. No existing evidence is upgraded by wrapping or restamping.


Backend posture is the first migrated consumer: the private payload retains schema 1,
with an adjacent filename ending in .json.envelope.json. See the
[backend handoff](pulumi-backend.md#read-only-backend-posture) for independent
account/commit expectations, exact-byte transport and strict migration. Service,
OCI and cutover migrations are described below. Pure accounting dictionary APIs
and schema-3 synthetic recovery receipts intentionally retain their own validators;
the reserved backend-recovery kind does not claim a signed or migrated receipt.

The [service CLI handoff](independent-services.md#cli-evidence-sidecars-m03-pr11-transport-slice)
uses service-usage sidecars over original schema-5 service payloads, with independently
reviewed proposal/profile and commit binding. Both Pulumi factories now require
that same immutable payload/sidecar contract before effects, with a caller-supplied
independent expected commit. Pure service accounting still accepts dictionaries;
the factories do not discover Git. The CLI independently enforces clean HEAD.

The [OCI handoff](free-tier-governance.md#oci-inventory-sidecars-m03-pr11-cli-slice)
now binds collection/audit to original inventory bytes and account/profile/clean
HEAD. Both OCI library gates require that same payload/sidecar with an independently
supplied expected commit before callbacks or resource registration; library calls
do not discover Git. Pure accounting retains dictionaries. The schema-5
[cutover bundle](kubernetes-cutover.md#commit-bound-cutover-evidence) now requires
and validates an explicit inventory_envelope role from the same hashed snapshot;
four role-specific cutover-review sidecars now bind the entire captured review set
and tracked quota/reviewer/administrative-policy bytes, including the original
private schema-5 administrative snapshot. Administrative semantics are recomputed
from that same immutable snapshot; no GitHub collection or file reopen occurs. Four mandatory DSSE/Ed25519 signature
artifacts authenticate role-authorized keys against the disabled-by-default repository
policy. Independent enrollment/custody and live administrative acceptance are
administrator-owned activation prerequisites. They are not additional M03 framework
features; new consumers require separately approved scope. No signature grants
operational authority, and deployment/cutover remain disabled.
