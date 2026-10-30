# Operational acceptance records (M06-PR1)

`uv run --locked infra readiness --unit oci-network --evidence .infra/readiness.json`
reports private acceptance assertions for the ten M05 closeout gates. It reads local
files and Git metadata only. It does not collect credentials, contact providers or
GitHub, change settings, write artifacts, advance journals or execute operations.

An `accepted` result means that the current, exact supplied evidence has a valid
reviewer assertion within its signed acceptance window. It does **not** establish
that the asserted live controls actually exist. Every report has
`execution_authorized: false`, `activation_authorized: false` and
`live_controls_verified: false`, even when all gates are accepted. Existing protected
operation approvals are still required and cannot consume this report as a permit.
Producer-specific semantic validation and operational collection belong to later
M06 slices; matching hashes are not independent live validation.

## Private input contract

Keep the index, record, signatures, configuration and referenced evidence under the
checkout's ignored `.infra` directory. All paths must be canonical repository-relative
JSON paths, with no parent traversal or symlinks. The index and its four referenced
files must be distinct. Evidence cannot alias any of these control inputs. Each
file is bounded to 1 MiB and unique loaded inputs together to 12 MiB. Missing or
malformed control inputs produce the redacted `READY001` error.

The index is a closed schema-1 object:

```json
{
  "schema_version": 1,
  "record": ".infra/acceptance.json",
  "operator": ".infra/acceptance-operator.json",
  "approver": ".infra/acceptance-approver.json",
  "configuration": ".infra/reviewed-configuration.json"
}
```

The record contains exactly:

- `schema_version`: integer 1.
- `unit`: the requested existing unit (`oci-network`, `oci-oke`, `cloudflare-edge`,
  or `supabase-database`). A record never spans multiple units.
- `commit`: the full 40-character reviewed Git SHA. The checkout must still be clean
  at that commit for any gate to be accepted.
- `configuration_sha256`: SHA-256 of the exact private configuration bytes named
  by the index. Operators must supply the actual configuration selected for review,
  not a replacement document representing a different configuration.
- `policy_sha256`: SHA-256 of the exact current `config/operations-policy.json` bytes.
  Other tracked configuration/code changes are also covered by the commit/clean check.
- `actor`: requester identity, distinct from both verified signers ignoring case.
- `gates`: zero to ten entries, with no duplicate or unknown gate IDs.

Each gate entry contains exactly `gate`, `stage`, `observed_at`, `reviewed_at`,
`expires_at`, `reviewer`, `outcome`, and `evidence`. The first three times are UTC
ISO-8601 strings satisfying `observed_at <= reviewed_at < expires_at`.
`reviewed_at <= now < expires_at` is required for acceptance. Preserve the original
observation time when reviewing evidence; never substitute the report generation time.
The reviewers explicitly choose the expiration appropriate to that gate's evidence;
this slice introduces no default observation lifetime, SLO or recovery objective.
Later producer-specific checks may impose stricter freshness requirements.

`reviewer` must equal the verified approver identity, ignoring case. `outcome` is
`accepted` or `failed`. There is no passed-by-default, waiver or not-applicable outcome.
An absent gate is missing. For services, owner-handoff records the reviewed current
service ownership basis; it does not imply an OCI-style transfer took place.

`evidence` has one to eight entries, each exactly `path` and `sha256`. Each hash
binds the exact bytes, not reserialized JSON. Duplicate paths within a gate are
rejected. An artifact can support multiple gates. Matching artifacts must be valid
JSON; an explicit top-level `unit` must match the requested unit. Unscoped artifacts
and nested provider-specific structures remain the signers' scope responsibility;
this generic report does not infer their semantics or authenticate their producer.

| Gate | Fixed stage |
| --- | --- |
| `protected-execution` | `readiness` |
| `backend-readiness` | `readiness` |
| `account-readiness` | `readiness` |
| `writer-exclusion` | `readiness` |
| `controlled-apply` | `activation` |
| `owner-handoff` | `activation` |
| `drift-health` | `acceptance` |
| `monitoring-delivery` | `acceptance` |
| `backup-recovery` | `readiness` |
| `state-recovery` | `acceptance` |

Stages classify assertions; they do not initiate transitions or grant permission
for a later stage. All ten gates must be accepted for the aggregate to be accepted.
A deferred production recovery exercise therefore leaves the report incomplete.

## Signature and trust boundary

Both DSSE envelopes authenticate the exact record bytes under the distinct payload
type `application/vnd.cloud-infra.readiness.v1+json`. Use the existing verifier and
the enrolled `operator` and `approver` roles in `config/operations-policy.json`.
The principals must be distinct from one another and the requester. The existing
operation and cutover payload types cannot substitute for a readiness signature.

This command never signs records, enrolls keys or enables policy. Current repository
trust is disabled/empty; it cannot authenticate acceptance until separately reviewed
enrollment in M06-PR2. A disabled or invalid trust policy, wrong role, changed payload
or unverifiable signature makes present gates `failed/review_unverified`.
Historical trust does not survive a policy-byte change automatically. Regenerate and
review evidence at the new commit/policy; no fallback to old keys is provided.
A malicious authorized reviewer or hostile same-user filesystem writer is outside
this local evidence-checking trust boundary.

## Report and failure behavior

The sanitized schema-1 report includes `kind: operational-readiness`, unit,
evaluation time, record digest and ten ordered gate results. It omits artifact
paths, content, requester and reviewer identities. Gate statuses are:

- `missing`: no entry, or an accepted assertion's evidence file is unavailable.
- `stale`: changed checkout/configuration/policy/evidence or evaluation outside the
  acceptance window.
- `failed`: unverified reviewer, explicit failed decision or cross-unit artifact.
- `accepted`: an authenticated assertion with current bindings and available evidence.

Precedence for a present entry is unverified review, conflicting explicit artifact
scope, changed context, acceptance window, changed evidence, explicit failure,
missing evidence, then acceptance. Thus a signed failed outcome never becomes
accepted because its evidence disappeared. Malformed input is an error rather than
a partial report. Inputs and checkout identity are rechecked at the end; detected
changes during evaluation invalidate the whole report. This is not a filesystem
snapshot or distributed lock, and observations can become outdated after return.

Exit code 0 means all ten assertions are accepted. Exit code 1 means either a valid
incomplete JSON report on stdout or a redacted `READY001` input error on stderr.
Neither exit code is execution authority. Missing index/signature/configuration
files are input errors; missing referenced evidence is a reported gate condition.

## Verification

Focused checks: `uv run --locked pytest -q tests/test_readiness.py`.
Shared checks: `uv run --locked infra verify`.
Package checks: `uv build --all-packages`.

Tests generate ephemeral signing keys and synthetic private evidence for all four
units. They cover unsigned/forged decisions, different payload types and roles,
changed bindings, clocks, duplicate gates, missing/changed/cross-unit evidence,
path bounds, input replacement and CLI exit/redaction behavior. Read-only behavior
is checked against the fixture files. No live acceptance is performed by these tests.
