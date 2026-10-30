# Scheduled monitoring and incident delivery (M05-PR14)

The protected monitor combines isolated drift, captured cost/capacity evidence and
bounded health observations into grouped per-unit incidents. It persists local
state before attempting GitHub issue delivery. A separate GitHub-hosted watchdog
checks successful persistence steps without depending on the operations runner.
No resource remediation, production state acceptance, new collector, signing
service or monitoring daemon is introduced.

## Disabled defaults and activation review

`config/monitoring-runner.json` ships with enabled/delivery_enabled false and unset
heartbeat, host and actor enrollment. All existing operational gates stay unchanged.
The workflow also requires the repository variable MONITORING_ENABLED=true.
Therefore adding its scheduled trigger does not activate observations or delivery.

The example cadence is every fifteen minutes (UTC minutes 7/22/37/52); GitHub can
queue or delay jobs. This is not a detection SLO. Review cadence, runner reachability,
notification subscriptions, durable storage, credentials and missed-run thresholds
before enabling anything. Start with delivery disabled and inspect reports/state.
Both tracked delivery_enabled and MONITOR_DELIVERY_ENABLED=true are required to send.
No notification or live observation was performed to implement this feature.

Policy fields are closed schema 1: enabled, delivery_enabled, repository,
repository_id, heartbeat_seconds (integer 1–3600), state_host_sha256,
scheduled_actor_id/login, notification_actor_id/login, and schema_version. Enroll the
actual dedicated runner's existing backup.host_id() digest, never its raw machine
identifier. This fingerprint detects accidental runner changes, not cloned machines
or hostile host tampering. Provision one durable runner in service-operations, or
review an equivalent POSIX storage/identity arrangement; a pool of disposable
machines cannot substitute for persistent state.

Scheduled calls require the enrolled actor ID and login, real schedule context,
main, the pinned repository identity, clean exact HEAD and freshly observed protected
environment controls. Manual dispatch requires the repository owner and an explicit
commit equal to the dispatch SHA. The watchdog uses monitor-watchdog protection;
unit jobs use the existing unit-monitor environments. Main-only branches, independent
reviewers, no bypass, runner isolation and real admission are administrator settings;
YAML or environment assertions alone do not establish them. Ordinary drift CLI
admission remains manual-only. The new scheduler calls its library through this
separate protected composition and never pretends a schedule is workflow_dispatch.

## Inputs and first initialization

Set each unit environment's MONITOR_INDEX to a private JSON index below .infra:

```json
{
  "schema_version": 1,
  "unit": "oci-network",
  "cost_index": ".infra/monitoring/cost-index.json",
  "health_index": ".infra/monitoring/health-index.json",
  "drift_bundle": ".infra/monitoring/drift-bundle.json",
  "max_age_seconds": 900
}
```

References consume the existing [findings](operational-findings.md),
[health](infrastructure-health.md) and [drift](drift-observation.md) formats. Cost
and health scopes must match the unit/account, and match region for OCI or the
zone/organization for services. Unit, scopes and repository identity bind the
retained state. Changing scope requires reviewed state migration, never a silent
reset. Indexes/captures remain private, bounded JSON; no private artifacts are uploaded.
An unset drift_bundle is accepted only as a visible unknown drift source.
max_age_seconds is an explicit positive integer at most 900; original producer
clocks are rechecked at final reconciliation after the longer drift operation.

Initial state creation is a distinct owner workflow_dispatch with initialize=true.
It creates an empty, mode-0600 per-unit file only if absent, after host/context and
environment checks. Existing state is never overwritten. The initial empty file
establishes no observation/heartbeat. Subsequent runs require that file to exist;
a lost disk/file must halt monitoring, not erase a known incident by bootstrapping.
After a loss, restore/reconcile reviewed durable state. Never use initialize as a
recovery shortcut. A partially initialized matrix can refuse already initialized
units while finishing previously absent ones; use a normal dispatch afterward.

State lives at .infra/monitoring/state/UNIT.json with a nonblocking per-unit lock,
atomic replace, file/directory fsync and a 1 MiB bound. Preserve it and the existing
operation journals across checkout; the workflow deliberately uses clean=false.
Keep filesystem permissions, off-host retention and single-runner placement reviewed.
Local locking/host hashes are evidence mechanisms, not distributed fencing or an
anti-tampering sandbox. MON002 means persistence is uncertain: inspect state before
retrying. Do not delete a full or uncertain state file to make a job pass.

## Execution and credential boundaries

The dedicated workflow runs the full shared verification first, then these explicit
script modes through the locked workspace runtime:

```sh
uv run --locked python .github/scripts/monitor.py --check
uv run --locked python .github/scripts/monitor.py --drift
uv run --locked python .github/scripts/monitor.py --collect
uv run --locked python .github/scripts/monitor.py --deliver
```

These are protected job entry points, not commands that manufacture GitHub context
for an interactive shell. The workflow's explicit initialization mode is --initialize.

1. Credential-free preflight checks private inputs and reports signed drift
   admission separately. Missing/expired drift approval is unavailable, not clean.
2. Only an admitted drift step receives explicit backend/provider credentials.
   It first persists a run-intent marker, then reuses the original drift check/CAS,
   runtime, journal and read-only credential review. Every cycle needs its own fresh
   operation/backup/signatures/configuration/checkpoint. No signature is minted,
   extended or replayed; their preparation/custody remains external. Without fresh
   material, scheduling reports unknown rather than becoming autonomous authority.
3. A later credential-free collect step runs the existing cost and health adapters,
   rechecks original timestamps, groups results and persists the incident/outbox.
   Provider secrets are absent from that step; known token/secret/provider environment
   variables are also removed while spawning health workers and restored afterward.
4. Delivery has a separate explicit notification token and no cloud credentials.
   Pending delivery can retry even when new preflight/collection fails; current
   main/environment/host/scope and delivery gates must still pass.

The read-only OPERATION_OBSERVATION_TOKEN is used only for GitHub observations.
Cloud credentials appear only in the isolated drift step, with OCI-specific values
empty for service units. The original source/local credential separation stays in
that driver. MONITOR_DELIVERY_TOKEN must be an independently reviewed dedicated bot
user token with repository Issues write, metadata and any required Actions read;
GET user must prove its exact enrolled ID/login before a write. Installation tokens
without that user identity endpoint are unsupported. No token is placed in argv,
raw logs or issue bodies. The default GITHUB_TOKEN has no Issues write permission.

GitHub workflow concurrency matches existing per-service and shared OCI writer
concurrency, with local operation locks retained. A nonblocking incident lock rejects
overlap. A monotonic workflow run number plus run ID rejects stale/replayed work.
Complete duplicates skip observations and preserve their old heartbeat; unfinished
stages cannot automatically repeat drift or network collection. A new run may record
unknowns, but underlying operation journals still require explicit reconciliation.
Delivery resumes the pending outbox without re-running providers.

## Incident transitions and delivery

Sources retain hashed finding identities and normal/warning/unknown/critical states.
Accepted producer digests, original collection clocks and coverage watermarks remain
in private evidence metadata; clock-only changes are excluded from transition keys.
Missing sources/metrics cannot clear known active findings; a previous critical
condition remains visible through uncertain observations. Only fresh positive
normal evidence resolves it. Retiring an active metric/scope requires reviewed
migration; omission is not an acknowledgement. Critical outranks unknown, warning,
then normal for grouping, and per-source counts retain all uncertainty.

One grouped event is emitted on opening, meaningful finding/severity change or
recovery, not on timestamp-only repeats. A missed local deadline is visible on
resumption and clears on the next timely run. Report-only transitions are recorded
without accumulating suppressed messages; enabling delivery seeds the current
baseline. Pending messages from earlier enabled periods are retained until acked.
The outbox caps at 128 events; saturation halts new transitions without dropping
messages. Deliver/reconcile the queue under reviewed gates before resuming.

The sole sink is GitHub issues in the pinned repository: one bot-owned marker per
unit/channel (observations or watchdog). Events contain counts, unit, timestamps and
a run link, never raw resource IDs, hostnames, response bodies, checkpoints or secrets.
Changes/recoveries use marker-bound comments and issue open/closed transitions.
Unchanged events are deduplicated. Sender identity, exact markers and full bounded
REST enumeration must match before editing; duplicate bot-owned markers fail closed.
Delivery failure remains pending with delivery_error=true. Lost acknowledgements
are reconciled against existing event markers before repeating writes. GitHub REST
has no atomic client idempotency key: ambiguous creation plus delayed visibility
can still produce a duplicate; duplicate matches then require operator reconciliation.
Do not claim exactly-once delivery or silently acknowledge a network error.

API operations use the existing gh executable, explicit github.com host, explicit
token, bounded time/output and no inherited proxies. Enumerations cap at five
100-item pages for issues/comments; incomplete searches fail rather than guessing.
Review issue history/rotation and token/bot changes before reaching those bounds.
A manually closed active incident remains locally active; the next meaningful
transition can reopen it. Closing an issue is not positive health evidence.

## Independent missing-run watchdog

The GitHub-hosted job shares verification but does not wait for the dedicated
observe jobs and needs no local private inputs, state mount or cloud credentials.
It reads at most ten main workflow runs and all jobs within a bounded 100-job page.
Only a successful completed Persist admitted monitoring snapshot step from the
matching run/head counts. Its start time is the conservative heartbeat watermark;
completion must be ordered and not in the future. Queued/failed/skipped/missing
steps never advance a heartbeat. All attempts are examined; duplicate reruns skip
the persistence step and cannot make an old capture fresh.

Missing/old observations or incomplete/failed API collection produce unknowns.
Report-only watchdog prints fixed statuses; explicit --watchdog --allow-delivery
rechecks current metadata and sends a separately grouped issue channel. Repeated
missing signals and recovery transitions deduplicate through owned remote markers
and issue state. This is independent of an offline operations runner, not independent
of GitHub itself. GitHub scheduling/API/notification outages can prevent both checks
and delivery; an out-of-platform monitor is required for that stronger guarantee.
No history on first activation is unknown until a real persistence step succeeds.

## Verification and acceptance limits

```sh
uv run --locked pytest -q tests/test_incidents.py tests/test_monitor_delivery.py tests/test_monitoring.py
uv run --locked infra verify
```

Tests use in-memory GitHub responses and spies for orchestration; existing health
fixtures remain loopback-only. They cover duplicate/stale/overlapping runs, conservative
recovery, missing heartbeats, delivery failure/lost ack, atomic persistence faults,
interrupted stages, enrollment, initialization, workflow permissions and credential
separation. No GitHub notification, workflow dispatch or external cloud operation
is a verification step. Native provider read semantics, fresh signature production,
runner/storage custody, live GitHub protections, notification subscriptions and real
cadence/detection objectives remain explicit operational acceptance prerequisites.
Reverting code stops future behavior, but preserve/reconcile pending local and remote
incident state; never treat git revert as queue deletion or infrastructure rollback.

The adapter follows the documented GitHub REST contracts for
[workflow jobs](https://docs.github.com/en/rest/actions/workflow-jobs),
[issues](https://docs.github.com/en/rest/issues/issues) and
[comments](https://docs.github.com/en/rest/issues/comments). Grouping/deduplication
and recovery adapt the approved Alertmanager pattern without deploying a service.

## M06 monitoring readiness and staged commissioning

M06-PR11 delivers checks and the staged procedure; activation remains pending.
`config/monitoring-runner.json` still disables monitoring and delivery, with actor,
host and heartbeat enrollment unset. This change does not modify repository
variables, run workflows, initialize state, collect observations or send issues.

### Offline durable-state check

On a clean reviewed checkout, inspect each unit with:

```sh
uv run --locked infra monitoring check-readiness --unit oci-network --binding-sha256 EXPECTED_SCOPE_SHA256 --heartbeat-seconds 1800
```

The unit must be one of the four existing deployment units. Independently review
the expected scope binding and heartbeat threshold; do not copy a digest from a
possibly misplaced state file just to make it pass. The existing scheduler catalog
computes that binding with `operations.digest` over the mapping containing `unit`,
`scopes` and numeric `repository_id`; `scopes` contains `cost` and `health`, each the
canonical digest of its respective index's `scope` object. Canonical digests use
sorted compact JSON as defined by `operations.digest`. Confirm the account and
OCI region or service zone/organization relationship before approving the binding.
This command accepts that independently reviewed digest, not arbitrary producer
indexes; it does not re-audit those producers or discover their live scopes.

The heartbeat threshold must be an integer from 1 to 3600 seconds. The example
1800 seconds is illustrative, not an accepted detection objective. The check uses
the earlier of the retained `next_due_at` and observation time plus the supplied
threshold, so a looser new threshold cannot erase a previously missed deadline.
No observation time or deadline is refreshed by reading it.

Only `.infra/monitoring/state/UNIT.json` is read. The existing incident validator
checks the bounded closed state/outbox schema; private paths, parent symlinks,
duplicate JSON keys, oversize files, future lifecycle/event clocks and mismatched
unit/binding are rejected with redacted `MONREADY001` diagnostics. Clean commit
and exact captured bytes (or continuing absence) are rechecked before returning.
A normal report contains hashes, lifecycle/severity and pending-event count, never
finding IDs, raw scopes, event bodies or private paths. No lock file is created.
This is a point-in-time inspection of an atomic snapshot, not writer exclusion or
authentication against same-user tampering.

The schema-1 report always says `status: pending` and denies execution, activation
and live-control verification. Its `gaps` distinguish missing/unobserved state,
unfinished run, missing/overdue heartbeat, unavailable sources, unknown findings,
active incidents, pending outbox and delivery errors. Exit zero means the supplied
snapshot has no such gaps; it does **not** mean commissioning is accepted. Gaps or
invalid input exit nonzero. Missing state is not created. An empty initialized
state is unobserved, never healthy. A fresh normal state still leaves custody,
watchdog, recipient and actual delivery acceptance pending.

### Staged operational procedure

1. Independently accept repository protection, the durable runner's identity and
   storage custody, enrolled schedule/notification actors, provider Read IAM and
   isolated credentials. Review all four cost/health scopes, original producer
   clocks, thresholds and the heartbeat objective. Preserve per-unit state and
   operation journals across checkout and runner restarts; verify off-host retention
   and restore access. A host digest or repository check cannot prove custody.
2. Prepare the existing private monitor indexes and fresh producer evidence.
   Review a sustainable external process for fresh drift approvals, backup,
   checkpoint and operation UUID on every cycle. Missing or expired approval must
   stay unknown; never reuse signatures or weaken admission to make a schedule run.
   Verify the environment controls for each unit-monitor job and monitor-watchdog.
3. In a separately authorized tracked/configuration change, enroll the actual host,
   actors and cadence and enable observations only. Keep tracked delivery and
   `MONITOR_DELIVERY_ENABLED` false. Enabling the workflow additionally requires
   `MONITORING_ENABLED=true`; neither variable is changed by this PR. Recollect
   commit-bound evidence after the reviewed configuration change.
4. If state has never existed, use the existing owner-only initialization dispatch
   once for absent units. Inspect the resulting unobserved state, then run a normal
   report-only cycle and the offline command above for each unit. Existing or lost
   state is never overwritten/recreated to clear incidents. A missing file after
   commissioning requires restore and reconciliation, not initialization.
5. Independently observe report-only normal, warning/critical, unknown and recovery
   behavior. Verify absent sources cannot clear known incidents, unchanged findings
   do not create repeated transitions, and positive fresh evidence is required for
   recovery. Do not inject synthetic evidence into production as real observations;
   use the existing credential-free suites for mechanics and separately authorize
   any live operational rehearsal.
6. Review the dedicated bot's exact user ID/login and effective repository Issues
   write/metadata/Actions read access, token custody and recipient subscriptions.
   GitHub issues in this repository remain the only sink. In a separate authorized
   delivery stage, enable both delivery gates and verify an actual recipient sees
   the baseline/open, meaningful change and recovery on the bot-owned marker.
   A successful REST write or an issue number is not proof of human receipt.
   The checker itself never performs this probe or posts a test issue.
7. Rehearse a dedicated-runner outage and a missing/failed persistence step while
   observing the independent GitHub-hosted watchdog. Queued, skipped, failed and
   replayed attempts must not refresh a heartbeat; recovery requires a real new
   persistence step. Verify the local stale deadline is also visible on resumption.
   GitHub platform/API outages can disable both watchdog and sink; an independent
   external service is still needed for an out-of-GitHub availability guarantee.
8. Rehearse delivery failure and lost acknowledgement with reviewed incident-state
   retention. Reconcile remote event markers before retrying; preserve pending
   events and delivery errors until acknowledgement. Duplicate owned markers,
   outbox saturation or bounded enumeration exhaustion require operator review.
   Closing an issue manually does not resolve a local incident. Never claim
   exactly-once delivery or empty an outbox to make readiness pass.
9. Retain the private reports, exact state/configuration hashes and independently
   reviewed live evidence for the existing M06 acceptance record. Scheduled
   observation, recipient acceptance and resource/writer activation are distinct
   decisions; no monitoring result grants apply/import/recovery authority.

### Stop and rollback

Stop commissioning on scope mismatch, interrupted stages, uncertain persistence,
lost state, stale/unknown observations or failed recipient/watchdog acceptance.
Disable new scheduling/delivery admission as appropriate while preserving journals,
state files, pending events and remote markers for reconciliation. Disabling flags
cannot cancel in-flight work, retract sent messages or acknowledge pending events.
Do not change scopes or bot identities without reviewing retained local/remote
state and marker ownership. Reverting this read-only checker requires no state
migration and does not replace the existing runtime schema or gates.

Focused verification:
`uv run --locked pytest -q tests/test_monitoring_readiness.py tests/test_incidents.py tests/test_monitor_delivery.py tests/test_monitoring.py`.
Run `uv run --locked infra verify` and `uv build --all-packages` for the shared gate
and packaging. Tests use private synthetic files and fake delivery responses; no
notification, workflow dispatch or live observation is part of verification.
