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
