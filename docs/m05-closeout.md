# M05 engineering closeout

M05 is Controlled cutover and reliable operations. This is the finite reconciliation
of the approved 16-task plan. Engineering completion is conditional on **this
M05-PR16's required CI passing and merge**; the repository owner may then close the
milestone separately. No live acceptance, flag activation, ownership transfer or
production recovery is authorized by this document or passing tests.

The implementation baseline is [PR #154](https://github.com/stanimirivanov/cloud-infra/pull/154),
merged at `f1a19ee`, after the owner reported it merged. This PR needs its own CI.
Operational contracts, preview identities, reviewer enrollment and delivery remain
disabled/unset in tracked configuration. Live acceptance below is **not performed**.
There are no further M05 engineering PRs, cross-milestone additions or interface
stubs in this fixed plan. New operational requirements need separate reviewed scope.

## Fixed-scope reconciliation

Task IDs identify the approved plan; linked numbers identify actual GitHub PRs.
PR6's four implementation PRs are historical; PR16 is delivered as one coherent PR.
Test paths below are under [tests/](../tests/). Existing contracts and limitations
remain authoritative in the linked runbooks and [HARNESS.md](../HARNESS.md).

| Task | Implementation | Repository evidence and boundary |
| --- | --- | --- |
| PR1: requests and durable journal | [#120](https://github.com/stanimirivanov/cloud-infra/pull/120) | `test_operations.py`; closed action/unit identity, CAS, fsync, terminal/replay rules; journals are assertions, not authority |
| PR2: mutation protocol compatibility | [#122](https://github.com/stanimirivanov/cloud-infra/pull/122) | `test_operation_protocol.py`; synthetic SDK transport and actual component-only local engine; no native resource import proof |
| PR3: encrypted backup capture | [#124](https://github.com/stanimirivanov/cloud-infra/pull/124) | `test_backup.py`; immutable three-file encrypted pair, exact manifests/receipts, explicit existing local repository |
| PR4: independent restore rehearsal | [#126](https://github.com/stanimirivanov/cloud-infra/pull/126) | `test_recovery_rehearsal.py`, `test_recovery_rejection.py`; snapshot/key readback and measured objectives; no production restore |
| PR5: approval/environment admission | [#128](https://github.com/stanimirivanov/cloud-infra/pull/128) | `test_operation_admission.py`; fresh two-role DSSE, exact request/context and protected-environment evidence |
| PR6: controlled service apply | [#133](https://github.com/stanimirivanov/cloud-infra/pull/133), [#134](https://github.com/stanimirivanov/cloud-infra/pull/134), [#135](https://github.com/stanimirivanov/cloud-infra/pull/135), [#136](https://github.com/stanimirivanov/cloud-infra/pull/136) | `test_operation_runtime.py`, `test_service_apply.py`, `test_service_apply_runtime.py`; closed saved-plan runtime, execution-bound preflight, journaled driver and protected CLI/workflow |
| PR7: ordered OCI apply | [#138](https://github.com/stanimirivanov/cloud-infra/pull/138) | `test_oci_apply.py`; shared dependency lock, committed network output checks and separate OCI admission |
| PR8: ownership preparation | [#140](https://github.com/stanimirivanov/cloud-infra/pull/140) | `test_ownership.py`; exact source/target mapping and idle freeze review, no transfer authority |
| PR9: protected resource import | [#142](https://github.com/stanimirivanov/cloud-infra/pull/142) | `test_import_driver.py`; reviewed protected existing IDs, post-import equivalence, no source-engine editing |
| PR10: owner handoff | [#144](https://github.com/stanimirivanov/cloud-infra/pull/144) | `test_ownership_handoff.py`; signed historical scope and source-release attestations, no automatic writer activation |
| PR11: drift | [#146](https://github.com/stanimirivanov/cloud-infra/pull/146) | `test_drift.py`, `test_drift_runtime.py`; isolated refresh/desired comparison, source-state unchanged, read-only IAM external |
| PR12: operational findings | [#148](https://github.com/stanimirivanov/cloud-infra/pull/148) | `test_operational_findings.py`; cost/capacity/age findings preserve unknown coverage and original clocks |
| PR13: bounded health | [#150](https://github.com/stanimirivanov/cloud-infra/pull/150) | `test_health.py`; offline OKE evidence and bounded DNS/TLS/HTTP; no live network isolation or continuous availability proof |
| PR14: scheduling and incidents | [#152](https://github.com/stanimirivanov/cloud-infra/pull/152) | `test_monitoring.py`, `test_incidents.py`, `test_monitor_delivery.py`; durable outbox, independent hosted watchdog and default-disabled repository issue delivery |
| PR15: authorized state recovery | [#154](https://github.com/stanimirivanov/cloud-infra/pull/154) | `test_recovery_driver.py`, `test_recovery_runtime.py`; current safety pair plus independently rehearsed selected snapshot, explicit checkpoint import/config publication and no writer release |
| PR16: failure rehearsal and acceptance | Issue [#155](https://github.com/stanimirivanov/cloud-infra/issues/155), this PR | `test_operations_integration.py`; bounded cross-process crashes/restarts and finite engineering/live reconciliation; conditional on CI/merge |

All fixed-scope repository deliverables are covered by this map. The unresolved
operational decisions and excluded work below are explicitly not counted as live
acceptance. No SLO, RPO, RTO, billing eligibility or effective IAM result is inferred
from the map.

## Failure rehearsal evidence

The new suite runs under the existing `operation_integration` opt-in marker and
uses the real production lifecycle, advisory locks, CAS journal, recovery signature
admission, incident state and outbox persistence. Linux forked children inherit
synthetic fixture adapters, clear their environment, terminate at deliberate durable
boundaries and are bounded/reaped by the parent. Fresh processes then inspect or
attempt restart against the same persisted files. No cloud credentials or APIs,
production backends, provider plugins, GitHub writes or live flags are used.

| Sequence | Required result |
| --- | --- |
| Apply or resource import takes effect, then acknowledgement is lost | One durable synthetic effect, `running` journal, no success receipt; restart rejects before credentials or another effect |
| Mutation succeeds and success journal persists, then receipt publication is interrupted | `succeeded` journal survives without a receipt; restart still cannot replay the request |
| Recovery is reviewed in one process, then the signed admission clock expires in another | No credentials, checkpoint import or journal advancement |
| Signed recovery completes or terminates immediately after checkpoint import | Exact external freeze input remains unchanged; complete path verifies/configures a receipt denying release; crash path remains `running` with no published pair receipt/config and restart denied |
| Monitor is interrupted after saving its running stage | Same run cannot reobserve/collect; the last observation, known critical incident and pending notification survive restart |
| Independent watchdog transport is unavailable | Every unit is unknown; it cannot refresh the failed runner's observation watermark |
| Notification reaches a synthetic remote sink, then acknowledgement is lost | Pending event survives; restart reconciles its durable ID and acknowledges without duplicating the synthetic remote effect or clearing the incident |

The external effects in these cases are explicitly **simulated**. Apply/import
admission fixtures replace semantic preflight, provider tools and runtime callbacks;
recovery retains actual two-role cryptographic verification, signed historical OCI
owner scope, freeze and execution-profile checks while replacing provider/runtime
and remote environment discovery. The watchdog transport failure and remote issue
sink are synthetic too. These are process/persistence composition tests, not proof
of a full credentialed operation. Existing `test_monitor_delivery.py` separately
checks GitHub marker lookup, pagination, grouping and acknowledgement semantics
with fake HTTP responses.

The older operation integration suites separately run the pinned Pulumi CLI/SDK,
component-only disposable filesystem stacks, mandatory-policy event transport,
encrypted checkpoint import/readback and local restic capture/retrieval. They do
not run a native OCI/Cloudflare/Supabase mutation. Their passing result cannot prove
provider Read is harmless, historical credentials are scoped, external fencing is
effective or production storage is independently recoverable.

A process killed after launch can leave `running` without a receipt. Treat that as
**indeterminate operationally**, never as a fresh prepared request. The driver cannot
record a terminal state after it has died. A durable `succeeded` journal without a
receipt also does not authorize replay. Reconcile the real backend and journal
privately under freeze before any separately authorized next operation; never
manually reset history to make a request pass or automate compensation.

## Administrator-owned live acceptance

All rows are **not run**. Keep a private acceptance record per intended unit and
operation, containing owner, UTC time, reviewed main commit, exact configuration and
policy digests, immutable evidence/approval IDs, journal heads, actual measured
results and the independent review decision. Never place raw state, secrets or
private account evidence in this closeout or public issues. A checked row needs its
own retained evidence, not a link to passing engineering CI.

| Gate | Finite evidence required before acceptance | Owner |
| --- | --- | --- |
| Protected execution and custody | Required checks/reviews/bypass rules, main-only environments, distinct enrolled signers/requester and audited runner/token/key custody; independently inspect actual settings | Repository administrator |
| Backend readiness | Fresh configuration-bound qualification/posture; existing four project-scoped stacks; least-privilege S3 identity; reviewed backend namespace, encryption, retention and recovery access | Backend/key custodian |
| Free-tier and account readiness | Fresh eligibility, complete account-wide inventory/usage, original watermarks/billing cycles, independent provider entitlement review; unknown/late data blocks activation | Provider/account owner |
| Writer exclusion | Effective external freeze, zero active operations, authoritative journals/locks shared by cooperating runners and review of unrelated/admin writers; local locks and YAML cannot fence another host | Source and target owners |
| Controlled apply | Explicit authorization for each intended unit, approved exact saved plan/current state, successful no-delete/no-replacement credentialed preview/apply and private post-state reconciliation; network before OKE, exact committed dependency | Operator and independent approver |
| Adoption and owner handoff | Reviewed exact ID/provider/parent mapping, native import compatibility, unchanged source state under freeze, post-import no-op equivalence, independent source-release evidence and separate signed owner decision; writer activation reviewed separately | Both state owners and approver |
| Read-only drift and health | Effective provider Read IAM including credentials sealed in historical state; no source state mutation; scoped fresh findings; actual DNS/TLS/HTTP and OKE admission/network-isolation evidence for claimed readiness | Provider/Kubernetes owners |
| Scheduled monitoring and delivery | Enrolled durable runner and actors, explicit initial state, reviewed interval/thresholds, actual repository issue recipient permissions/delivery, outage and missing-persistence observation through independent hosted watchdog; unknown never treated as healthy | Operations owner |
| Backup and recovery custody | Independent host/storage access, separately held keys, reviewed production transport/retention and measured per-unit backup age/restore objectives; selected exact snapshot plus current safety backup, successful independent rehearsal | Backup/key custodian |
| Production state recovery | Explicit separate recovery request/approval, existing matching resource identities/properties, current owner/freeze and historical trust, exact readback/config publication plus no-op reconciliation; retain freeze until separate review of config activation and writer release | Recovery operator and approver |

A real operation needs an explicitly reviewed tracked-gate change and fresh
configuration-bound evidence. Gate activation, secrets enrollment, environment changes,
workflow dispatch and milestone closure are separate owner actions, not this PR.
Do not dispatch production work merely to fill out this checklist.

## Scope decisions and remaining limitations

- Initial recovery is Pulumi checkpoint plus encrypted configuration. Database
  contents, object storage and Kubernetes persistent volumes are excluded.
- The selected backup destination is an existing local repository. Production
  transport, independent storage failure domains, retention and credential custody
  remain unaccepted decisions. A different path alone proves no physical independence.
- Recovery requires existing valid stacks and matching managed identities/properties;
  it rejects missing/corrupt stacks, pending operations and changed recorded managed
  properties, including resealed property ciphertext. It is not general bootstrap DR.
  Its existing driver admits an explicit objective of at most 300 seconds; that is a
  bounded execution contract, not a measured production RTO or an agreed SLO.
- Effective source-state release is operator-assisted. No external source engine
  removal commands or automatic rollback, retry, replacement, delete or writer
  release are implemented. Git revert cannot undo a cloud mutation or restore.
- Kubernetes controller/policy-engine deployment, monitoring-stack installation and
  application recovery are excluded. Evidence consumption does not establish these
  services exist or enforce policy in a live cluster.
- Monitoring is periodic; no continuous availability or tight detection SLO is
  claimed. The hosted watchdog observes successful persistence-step clocks, not all
  runner internals or independent cloud health; GitHub outages are unknown too.
- Journals/outboxes are bounded local durable files, not a distributed consensus or
  tamper-proof authority. Host loss, journal retention, hostile same-user writers and
  cross-host fencing require operational controls. Historical reviewer/policy/key
  rotation requires reviewed trust migration; no automatic bypass is provided.
- Repository delivery uses GitHub issues by the owner's choice. Real recipient
  enrollment, notification permissions and schedules remain disabled/unaccepted.

## Required engineering gates

The shared credential-free gate is `uv run --locked infra verify`; workflow syntax
can also be checked with `uv run --locked infra security workflows`. Package builds
use `uv build --all-packages`.

The complete local operation gate remains
`RUN_OPERATION_INTEGRATION=1 uv run --locked pytest -q -m operation_integration`.
CI explicitly splits this into the existing protocol/engine suite (excluding
`tests/test_operations_integration.py`) and the new required failure suite:
`RUN_OPERATION_INTEGRATION=1 uv run --locked pytest -q tests/test_operations_integration.py -m operation_integration`.
Both steps are unconditional and credential-free; each scenario executes once.
Normal shared verification checks CI wiring and skips the opt-in process cases.
No additional executable, dependency, production activation or live test is added.
