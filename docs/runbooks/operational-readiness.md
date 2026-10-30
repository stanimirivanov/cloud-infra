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
Producer-specific consistency checks and staged procedures are reconciled in the
[M06 closeout](../m06-closeout.md). Their implementation does not complete live
acceptance; matching hashes are not independent live validation.

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
enrollment. M06-PR2 delivered enrollment checks with actual enrollment pending. A disabled or invalid trust policy, wrong role, changed payload
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

## M06 writer-exclusion readiness

M06-PR6 adds an offline check of an external freeze observation against an
independently reviewed writer registry and canonical operation journals. It does
not acquire locks, freeze or release writers, create journals, dispatch workflows
or establish distributed exclusion. OCI network and OKE are checked together;
Cloudflare and Supabase each have their own scope.

From a clean committed checkout:

```sh
uv run --locked infra operations check-readiness --unit oci-network --writers .infra/writers.json
uv run --locked infra operations check-readiness --unit oci-network --writers .infra/writers.json --evidence .infra/writer-freeze.json
```

`--writers` is a separately reviewed private registry, not a list inferred from
candidate freeze evidence. Its closed schema has `schema_version: 1` and `units`:
a mapping from unit names to lists of 1–32 distinct lowercase 64-character identity
hashes. OCI requires exactly `oci-network` and `oci-oke`; a service requires only
its selected unit. The owners must define and retain the canonical identity
material behind each hash privately, covering applicable source/target engines,
manual/admin access and automation. No engine identity or writer ownership is
inferred from tags. A missing source engine does not require an invented identity.

Without `--evidence`, the command validates the registry and reports pending. When
an observation is supplied, it must have exactly these fields:

| Field | Required binding or meaning |
| --- | --- |
| `schema_version` | Integer 1 |
| `commit` | Current clean reviewed commit |
| `foundation_sha256` | Current foundation digest from `uv run --locked infra backend inspect` |
| `writers_sha256` | SHA-256 of the exact registry file bytes |
| `frozen_at`, `observed_at`, `expires_at` | Original UTC clocks; frozen ≤ observed ≤ now < expiry ≤ frozen + 15 minutes |
| `complete`, `other_writers_reviewed` | Both explicitly true; assertions requiring independent review |
| `units` | Exactly the same unit scope as the registry |

Each `units` value contains only `journal_sha256`, `journal_head`, and `writers`.
`journal_sha256` binds the exact bytes of `.infra/operations/<unit>.json`.
`journal_head` is the existing canonical operation-entry digest (as shown by
`uv run --locked infra operations inspect --journal .infra/operations/oci-network.json`), or null for an explicitly supplied empty
journal. There is no caller-selectable journal path: alternate copied journals
cannot stand in for the checkout's canonical location. Custody review must still
establish that this checkout sees the actual authoritative shared storage.

Each writer observation contains only `identity_sha256`, `frozen` and
`active_operations`. Identities must match the entire registered set, without
missing, additional or duplicate entries. Every writer must have `frozen: true`
and integer `active_operations: 0`; booleans are not operation counts.

### Journal and uncertainty gates

The existing operation validator checks every request, hash-chain link, transition,
predecessor and entry clock. Every entry must belong to its file's unit and precede
the freeze. A prepared, admitted or running tail blocks the report. Any historical
`indeterminate` entry, or `failed` after that operation reached `running`, also
blocks it even when later work succeeded: a terminal failure is not proof that a
mutation had no effect. Do not reset, truncate or rewrite history to pass.
Uncertain outcomes require separate reconciliation and a reviewed trust/history
procedure; this checker provides no bypass or automatic reconciliation mechanism.

A failure before launch can be consistent with an idle journal. An explicitly
present empty journal can also be consistent with an initial enrollment assertion,
but cannot prove that prior history was not lost. Missing files are errors when
an observation is supplied; the checker never initializes them. Empty/history
custody acceptance remains pending and must be independently established.

Registry, observation and journals must be distinct canonical relative private
JSON files under `.infra`, with no symlinks. Reads are bounded to 1 MiB per file;
duplicate JSON fields, wrong scope, changed bytes and a changed/dirty checkout
fail with redacted `WREADY001`. The checker rechecks all captured bytes and Git
identity before returning, but does not provide an atomic snapshot or hold locks.
Observations can become stale immediately afterward.

### External exclusion remains pending

A consistent supplied observation reports
`writer_evidence: freeze-assertions-consistent`; without one it reports `pending`.
Every report has `status: pending`, `writers_excluded: false`,
`locks_verified: false`, `writer_release_authorized: false`,
`execution_authorized: false`, `activation_authorized: false` and
`live_controls_verified: false`. The CLI exits 1. These unsigned assertions cannot
replace the operation-specific ownership/recovery freeze contracts, signed
acceptance or an effective external fence.

Source/target owners and the independent reviewer must verify the effective freeze
of all writers, including administrators and non-cooperating processes; common
authoritative journal storage and lock namespace across cooperating runners;
storage durability, retention and initial enrollment; clock/provenance trust;
and continued exclusion between observation and the explicitly authorized action.
GitHub concurrency and advisory local locks do not fence a different host or an
external engine. Writer release remains a separate decision after reconciliation;
this PR performs neither freeze nor release and changes no existing lock behavior.

Focused verification:
`uv run --locked pytest -q tests/test_writer_readiness.py tests/test_operations.py tests/test_ownership.py tests/test_recovery_driver.py`.
The full shared gate remains `uv run --locked infra verify`. No new dependency,
journal format migration, live operation or activation is introduced.
