# M06 engineering closeout and pending operational acceptance

M06 covers operational readiness and staged activation of M05 capabilities, using
the [M05 live acceptance checklist](m05-closeout.md#administrator-owned-live-acceptance)
as its scope. The owner directed delivery of checks and staged procedures with
enrollment/activation pending. This record reconciles that engineering scope; it
**does not declare operational readiness or live activation complete**.

The verified baseline is [PR #180](https://github.com/stanimirivanov/cloud-infra/pull/180),
merged on 2026-10-30 at `b04c453e3282c03c02d148df0180ec590ed0d210`.
M06-PR1 through PR12 are merged. PR13 is this documentation closeout, tracked by
[issue #181](https://github.com/stanimirivanov/cloud-infra/issues/181); its engineering
completion requires its own required CI and merge. Closing a GitHub milestone is a
separate owner action. No extra engineering slice or future milestone is invented
by this record; outstanding live decisions remain explicit below.

M05's fixed 16-task implementation ended with
[PR #156](https://github.com/stanimirivanov/cloud-infra/pull/156), merged at `bec4f8c`.
Its closeout remains the historical engineering/failure-rehearsal record. M06 adds
readiness checks and staged procedures; it does not retroactively turn M05's
synthetic tests or M06's consistent input reports into production acceptance.

## Fixed-scope delivery map

All test paths below are under [tests/](../tests/). Links name actual implementation
PRs, while M06-PR identifiers name the slices. Each delivered slice has one coherent
PR; there are no outstanding interface stubs to retire in this closeout.

| Slice | Merged implementation | Repository evidence and retained boundary |
| --- | --- | --- |
| M06-PR1: acceptance records | [#158](https://github.com/stanimirivanov/cloud-infra/pull/158) | `test_readiness.py`; authenticated ten-gate assertions with current bindings; no execution authority |
| M06-PR2: trust and runner enrollment | [#160](https://github.com/stanimirivanov/cloud-infra/pull/160) | `test_enrollment.py`; offline trust/environment/custody gaps; actual enrollment pending |
| M06-PR3: backend readiness | [#162](https://github.com/stanimirivanov/cloud-infra/pull/162) | `test_backend_readiness.py`; qualification/posture/existing-stack consistency; live IAM and custody pending |
| M06-PR4: independent backup readiness | [#164](https://github.com/stanimirivanov/cloud-infra/pull/164) | `test_backup_readiness.py`; exact pair/snapshot and off-host rehearsal evidence; physical independence/key custody pending |
| M06-PR5: account readiness | [#166](https://github.com/stanimirivanov/cloud-infra/pull/166) | `test_account_readiness.py`; existing OCI/service audits, original coverage/clocks; entitlement and live scope review pending |
| M06-PR6: writer exclusion | [#168](https://github.com/stanimirivanov/cloud-infra/pull/168) | `test_writer_readiness.py`; canonical journals and external freeze assertions; no distributed fencing or writer release |
| M06-PR7: Cloudflare preparation | [#170](https://github.com/stanimirivanov/cloud-infra/pull/170) | `test_service_activation.py`; independent schema-2 service gates; Cloudflare and Supabase both disabled |
| M06-PR8: Supabase staging | [#172](https://github.com/stanimirivanov/cloud-infra/pull/172) | `test_supabase_staging.py`; exact account/organization, existing usage audit and shared encrypted-key shape checks; no project creation |
| M06-PR9: OCI network staging | [#174](https://github.com/stanimirivanov/cloud-infra/pull/174) | `test_oci_activation.py`; independent per-unit apply/import gates, all disabled; native import and paired handoff pending |
| M06-PR10: OKE staging | [#176](https://github.com/stanimirivanov/cloud-infra/pull/176) | `test_oke_staging.py`; network interface and Kubernetes scope/capacity/control consistency; live admission/isolation pending |
| M06-PR11: monitoring commissioning | [#178](https://github.com/stanimirivanov/cloud-infra/pull/178) | `test_monitoring_readiness.py`; durable snapshot, heartbeat/incident/outbox gaps; no initialization, collection or issue delivery |
| M06-PR12: recovery staging | [#180](https://github.com/stanimirivanov/cloud-infra/pull/180) | `test_recovery_staging.py`; current/historical pair compatibility through executor contracts; no key access or state writes |
| M06-PR13: reconciliation | Issue [#181](https://github.com/stanimirivanov/cloud-infra/issues/181), this PR | This map, ten-gate disposition, remaining capability gaps and operational sequence; conditional on CI/merge |

All thirteen engineering slices are accounted for. Live activation and acceptance
are intentionally undelivered under the owner's checks-only direction; they are
not silently counted as completed work or assigned an invented next milestone.

## Observed tracked baseline

At the implementation baseline, these repository files retain safe defaults:

- [Pulumi units](../config/pulumi.toml): all four unit `enabled` and
  `preview_enabled` values are false.
- [Operation trust](../config/operations-policy.json): disabled, with no reviewers.
- [Service apply](../config/service-apply.json): schema 2; Cloudflare and Supabase false.
- [OCI apply](../config/oci-apply.json) and [resource import](../config/resource-import.json):
  schema 2; network and OKE false in both, independently selected by action/unit.
- [Owner handoff](../config/ownership-handoff.json), [drift](../config/drift.json)
  and [state recovery](../config/state-recovery.json): disabled.
- [Monitoring runner](../config/monitoring-runner.json): observations/delivery false,
  host/actors/heartbeat unset.

This is an observation of tracked configuration, not a fresh audit of GitHub
settings, repository variables, runner custody, credentials or live infrastructure.
No such external acceptance is claimed or changed by this PR. The schema-2 service
and OCI gate migrations reject legacy global policies; code/configuration must be
deployed together, and rollback must never restore enabled global switches.

## Ten-gate operational disposition

Every row is **pending live acceptance**. No private signed acceptance packet or
actual activation result is supplied by this closeout. The owners below are roles,
not claims that named people or keys have been enrolled.

| Acceptance gate | Delivered checks/procedure | Remaining finite evidence and responsible role |
| --- | --- | --- |
| `protected-execution` | PR1–2; [trust and runner enrollment](runbooks/github-administration.md#m06-repository-trust-and-runner-enrollment-checks) | Repository administrator: actual required checks/reviews, main-only protected environments, bypass controls, distinct enrolled signer/requester identities, runner/token/key custody |
| `backend-readiness` | PR3; [backend readiness](runbooks/pulumi-backend.md#m06-backend-readiness-checks) | Backend/key custodian: fresh remote qualification/posture, existing exact stack identities, least-privilege access, namespace/retention and recovery access |
| `account-readiness` | PR5; [account readiness](runbooks/free-tier-governance.md#m06-account-readiness) | Provider/account owner: live eligibility, complete account-wide inventory/usage, original billing watermarks and reviewed scope/peak capacity |
| `writer-exclusion` | PR6; [writer exclusion](runbooks/operational-readiness.md#m06-writer-exclusion-readiness) | Source/target owners: effective external freeze, shared authoritative journals/locks, zero active or unresolved operations, unrelated/admin writer review |
| `controlled-apply` | PR7–10; [Cloudflare](runbooks/independent-services.md#m06-cloudflare-staged-activation-preparation), [Supabase](runbooks/independent-services.md#m06-supabase-staging-checks-and-procedure), [network](runbooks/kubernetes-cutover.md#m06-oci-network-adoption-staging), [OKE](runbooks/kubernetes-cutover.md#m06-oke-staging-checks-and-procedure) | Operator/approver: separate per-unit authorization, exact saved plan and current state, credentialed no-delete/no-replacement preview/apply and post-state reconciliation; imports do not satisfy apply proof |
| `owner-handoff` | PR9–10 plus existing M05 signed handoff | Both owners/approver: native import compatibility, exact mappings and no-op equivalence, network-before-OKE dependency, independent recovery, continuous idle freeze and independently evidenced source release; services need their own ownership basis |
| `drift-health` | PR5/10–11 plus existing [drift](runbooks/drift-observation.md) and [health](runbooks/infrastructure-health.md) contracts | Provider/Kubernetes owners: effective Read IAM including historical credentials, no source mutation, actual endpoint observations and live OKE admission/isolation/ARM scheduling acceptance |
| `monitoring-delivery` | PR11; [monitoring commissioning](runbooks/scheduled-monitoring.md#m06-monitoring-readiness-and-staged-commissioning) | Operations owner: durable runner/actors, initial state, reviewed cadence/thresholds, real recipient delivery/recovery, independent watchdog and runner/persistence outage rehearsal |
| `backup-recovery` | PR4/12; [independent backup readiness](runbooks/pulumi-backend.md#m06-independent-backup-readiness) | Backup/key custodian: physical failure-domain independence, separate keys/access, production transport/retention, exact selected snapshot and measured per-unit age/restore objectives |
| `state-recovery` | PR12; [recovery staging](runbooks/state-recovery.md#m06-recovery-staging-checks-and-procedure) | Recovery operator/approver: separate request/signatures, current safety backup, matching resources, owner/freeze/history, actual readback/config publication and no-op reconciliation; configuration activation and writer release reviewed separately |

The [acceptance record contract](runbooks/operational-readiness.md) remains
unchanged: all ten assertions must be accepted, with no waiver/not-applicable
shortcut. `accepted` authenticates the current reviewer assertion, not live truth.
Every aggregate report denies execution/activation authority. Producer consistency
checks may exit zero while reporting pending; those results cannot fill an accepted
row without the independent live evidence and signatures required by that contract.
A deferred recovery exercise leaves aggregate acceptance incomplete.

## Remaining capability gaps and scope decisions

These are existing limits exposed by staging, not implemented by this closeout:

- Exact executor saved-plan production still requires a separately reviewed path;
  the preview CLI does not produce that saved plan. Do not improvise a live mutation
  or edit signed artifacts to bridge this gap.
- Resource import requires an existing target stack, exact protected parent/provider
  metadata and committed network interface. It cannot bootstrap missing metadata,
  root outputs or state. Native OCI import compatibility still needs live proof.
- OKE import can consume an equivalent successful network import; ordinary OKE
  apply retains its network-apply prerequisite. Network-only adoption cannot admit
  the paired handoff. Import success must not be relabeled as apply success.
- Kubernetes controls are rendered/audited, not installed. Actual policy-engine
  compatibility, accounting, all allow rules, admission rejection, ARM scheduling
  and endpoint readiness require live review. DNS/egress exceptions need separate
  design; do not weaken default deny as a commissioning workaround.
- Backup uses the existing pre-initialized local/mounted restic repository. Different
  paths/host hashes are not physical independence proof. Production transport,
  custody, retention and objective acceptance remain owner decisions.
- Recovery is checkpoint plus encrypted configuration for existing matching stacks
  and managed properties, not missing/corrupt-stack bootstrap, resource rollback,
  database contents, object storage or persistent-volume recovery. Conservative
  ciphertext equality and historical trust migration limits remain intact.
- Monitoring needs fresh external evidence and signed drift material each cycle.
  The GitHub-hosted watchdog is independent of the durable runner, not GitHub;
  platform-wide outage detection needs another service. Issue delivery does not
  prove human receipt or exactly-once behavior. Keep scopes, queues and bot-owned
  markers during outage/retry reconciliation.
- External fencing, source release, configuration activation and writer release are
  operator-owned. Local journals/locks and hashes are not distributed consensus or
  tamper-proof authority. Uncertain launches stay under freeze; no automatic retry,
  compensation, history reset or flag rollback can undo a state/cloud mutation.

No new infrastructure, provider, dependency, workflow, runtime abstraction or
cross-milestone implementation is introduced here. New capability work needs
separately reviewed scope rather than an implicit extension of M06.

## Operational next-step order

1. Review the remaining decisions and acceptance owners. Enroll trust and runner
   custody, then accept backend/account/independent-backup evidence. Keep all gates
   disabled until their separately reviewed activation change.
2. Establish external writer exclusion and preserve authoritative journals and
   checkpoints. Resolve target metadata, saved-plan production and native-provider
   prerequisites before scheduling an operation.
3. Review each intended service independently. For OCI adoption, complete network
   before OKE, then evaluate the separate paired owner decision/source release.
   Recollect and sign commit/configuration-bound evidence after every reviewed gate
   change; never restamp old observations or treat this closeout as permission.
4. Commission monitoring report-only before separately authorizing real delivery;
   verify recipient and watchdog/outage behavior. Rehearse exact backup access and
   separately authorize any production recovery exercise under its own freeze and
   signed request. Keep writer release separate from every successful receipt.
5. Retain private measured evidence and exact policy/configuration/commit bindings
   in per-unit acceptance packets. Use the existing readiness report to evaluate
   assertions; do not manufacture a packet merely to mark a milestone complete.
   The owner decides operational acceptance and milestone closure separately.

## Verification boundary

The required shared command is `uv run --locked infra verify`; packaging uses
`uv build --all-packages`. The shared gate validates local links and documented CLI
arguments, architecture, secrets/artifacts, workflows, lint, format, types and the
existing regression tests. This prose-only closeout adds no tests or runtime changes.

Existing opt-in synthetic protocol/engine and failure-rehearsal gates remain described
in [M05 closeout](m05-closeout.md#required-engineering-gates); this PR does not change
or replace them. No live provider test, credential enrollment, acceptance signature,
resource/state operation, notification or milestone closure is performed. Passing
local verification is engineering evidence only; this PR still needs required CI
and merge before its documentation scope is complete.
