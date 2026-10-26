# Shared security evidence sidecars

M03-PR6 adds infra_core.evidence as a pure consistency API. M03-PR9 migrates
backend posture; M03-PR11 also migrates the service CLI and library factories. Other
formats and validators retain their existing contracts
until their consuming PRs explicitly migrate them.

## Contract

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
- Limits: 64 KiB envelope, 1-16 subjects, 10 MiB per artifact, 16 MiB aggregate.
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
truth nor operational authority. Signatures/trusted provenance and deployment
policy remain later work; no existing evidence is upgraded by wrapping or restamping.


Backend posture is the first migrated consumer: the private payload retains schema 1,
with an adjacent filename ending in .json.envelope.json. See the
[backend handoff](pulumi-backend.md#read-only-backend-posture) for independent
account/commit expectations, exact-byte transport and strict migration. Other
consumers remain on their existing contracts until their own migration PRs.

The [service CLI handoff](independent-services.md#cli-evidence-sidecars-m03-pr11-transport-slice)
uses service-usage sidecars over original schema-4 service payloads, with independently
reviewed proposal/profile and commit binding. Both Pulumi factories now require
that same immutable payload/sidecar contract before effects, with a caller-supplied
independent expected commit. Pure service accounting still accepts dictionaries;
the factories do not discover Git. The CLI independently enforces clean HEAD.

The [OCI handoff](free-tier-governance.md#oci-inventory-sidecars-m03-pr11-cli-slice)
now binds collection/audit to original inventory bytes and account/profile/clean
HEAD. Both OCI library gates require that same payload/sidecar with an independently
supplied expected commit before callbacks or resource registration; library calls
do not discover Git. Pure accounting retains dictionaries. The schema-4
[cutover bundle](kubernetes-cutover.md#commit-bound-cutover-evidence) now requires
and validates an explicit inventory_envelope role from the same hashed snapshot;
four role-specific cutover-review sidecars now bind the entire captured review set
and tracked quota/reviewer-policy bytes. Four mandatory DSSE/Ed25519 signature
artifacts authenticate role-authorized keys against the disabled-by-default repository
policy. Enrollment/custody, administrative provenance and other evidence consumers
remain separate work; no signature grants operational authority.
