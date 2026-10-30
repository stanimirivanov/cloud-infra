# Repository harness

## Start here

This uv workspace contains Pulumi Python component libraries and offline
free-tier governance. Tracked resource previews, deployment, production stack initialization
and ownership transfer are disabled. A passing check is not deployment authority.

| Location | Responsibility |
| --- | --- |
| [AGENTS.md](AGENTS.md) | Short agent entry point and Plan -> Execute -> Verify workflow |
| [packages/AGENTS.md](packages/AGENTS.md) | Python ownership and dependency boundaries |
| [packages/infra-core/src/infra_core/](packages/infra-core/src/infra_core/) | CLI, pure contracts, governance, optional inventory and verification |
| [packages/infra-program/src/infra_program/](packages/infra-program/src/infra_program/) | Pulumi adapters, protected components and disabled program |
| [sdks/AGENTS.md](sdks/AGENTS.md) | Generated Supabase SDK provenance and editing restrictions |
| [config/AGENTS.md](config/AGENTS.md) | Public examples, evidence freshness and disabled deployment identities |
| [.github/AGENTS.md](.github/AGENTS.md) | Credential-free verification and protected qualification boundaries |
| [policies/](policies/) | Mandatory resource-local Pulumi policy pack |
| [tests/](tests/) | Negative contracts, CLI, SDK serialization and qualification tests |
| [docs/runbooks/](docs/runbooks/) | Operator procedures and detailed contracts |

Read the nearest scoped guide for OCI, Kubernetes or independent services when
working in that directory. [The harness audit](docs/harness-audit.md) distinguishes
documented intentions from their mechanical enforcement.

## Architecture and ownership

| Boundary | Contract |
| --- | --- |
| infra-core -> standard library / own pure modules | No Pulumi or infra-program dependency |
| inventory adapters -> optional OCI SDK | Explicit read-only credentials, complete pagination, sanitized errors |
| infra-program -> infra-core + Pulumi SDKs | Complete preflight before provider/resource registration |
| OCI network -> OKE | Versioned identity/CIDR outputs; no reverse dependency |
| Cloudflare / Supabase | Separate scope, provider, evidence and reserved stack identity |
| Kubernetes governance | Offline closed manifest subset; no cluster client or installation |
| cutover preparation | Read/hash private evidence and Git metadata; never grant authority |

AST fitness checks enforce first-party imports: infra-core cannot import Pulumi or
infra-program; pure domains may import only reviewed standard-library modules,
their own domain and governance. Only inventory/oci.py may import the optional OCI
SDK. Relative, lazy and literal dynamic imports follow the same rules; unresolved
dynamic imports fail. Generated SDKs are excluded. This is a static dependency
sensor, not an OS sandbox or proof that Python code cannot perform I/O.
Component factories compose libraries; they do not implement separate-stack deployment orchestration.
The infra console entry point belongs to infra-program, which injects preview
orchestration into core's parser. Offline commands load no Pulumi runtime. Core-only
installations no longer install the infra console script; normal workspace sync
installs the composition entry point. Core's direct CLI API still denies previews
without the explicitly injected adapter. See [the PR14 contract](docs/m04-plan.md#pr14-cli-orchestration).

## Setup and verification

Use Git and Python 3.11+ on Linux x64. The reviewed installer verifies uv
**0.12.5**, Pulumi **3.272.0**, Gitleaks **8.30.1** and actionlint **1.7.12**
release archives before extraction. The shared .python-version pins Python **3.12.14**.
GitHub CLI is needed for the issue/PR workflow. Pulumi CLI **3.272.0** is required
for explicit backend integration tests and qualification, matching the locked SDK.

In a POSIX shell session:

```shell
python3 .github/scripts/install-tools.py
export PATH="$PWD/.infra/tools/uv:$PWD/.infra/tools/pulumi:$PATH"
uv sync --locked --all-groups
uv run --locked pre-commit install
uv run --locked infra verify
```

The root pyproject.toml owns tool configuration and uv.lock owns resolution across
all three workspace members. Runtime dependencies belong in member manifests;
development tools belong in the root dev group. Never install packages at runtime,
add member lockfiles, or edit sys.path to repair imports.

| Purpose | Existing command |
| --- | --- |
| Workflow syntax/expressions | `uv run --locked infra security workflows` |
| Complete shared gate | `uv run --locked infra verify` |
| Lint | `uv run --locked ruff check .` |
| Format check | `uv run --locked ruff format --check .` |
| Strict typing | `uv run --locked mypy` |
| Regression tests | `uv run --locked pytest` |
| Package build | `uv build --all-packages` |
| Inspect disabled backend configuration | `uv run --locked infra backend inspect` |

The complete gate checks tracked private artifacts, verified Gitleaks scans, and
architecture/documentation fitness and verified actionlint, then lint, format,
types and tests.
Documentation checks cover root Markdown, docs/,
first-party package/config/workflow guides and sdks/AGENTS.md: local inline and
reference links (including ATX Markdown heading anchors) must resolve inside the repo.
Document full infra invocations in inline code or sh/bash/shell/console fences;
examples are checked against the real argparse parser, never executed. Other tool
commands, remote URLs, HTML links and documentation freshness are not validated.
The gate uses a temporary pytest directory/cache and propagates subprocess errors
with a five-minute timeout. It needs no cloud credentials, provider plugins or
deployed-state access. Generated SDK code is excluded from Ruff/mypy traversal;
actual adapter serialization is exercised using the generated SDK in mocks.

Default tests skip opt-in backend/policy-host/provider and synthetic process
integration tests. CI requires the real SDK/subprocess/loopback RPC test gate with
RUN_SYNTHETIC_PREVIEW_INTEGRATION=1 on Linux; its CLI worker and events are
synthetic, with no engine/provider/cloud execution. See [the M04 closeout](docs/m04-closeout.md).
CI explicitly
sets RUN_PULUMI_LOCAL_QUALIFICATION=1 and runs the backend_integration marker with the
pinned CLI on disposable local storage. This tests encryption, locking, recovery
and policy protocol behavior without creating provider/cloud resources. Recovery
now includes synthetic stack loss and fresh-workspace/HOME restore with measured
backup age, restore duration and encrypted checkpoint size/hash. Schema-v3 receipts
also require wrong-key rejection for config/checkpoint reads before correct-key
readback; old receipts must be regenerated.

## Domain commands and runbooks

- [Backend qualification and recovery](docs/runbooks/pulumi-backend.md):
  explicit backend identity, synthetic checkpoints, receipt limits and operator recovery.
- [Free-tier governance](docs/runbooks/free-tier-governance.md):
  account-wide capacity, retained resources, replacement peak, monthly usage and inventory.
- [OCI components](docs/runbooks/oci-components.md):
  reviewed ARM images/versions, network boundaries and adoption evidence.
- [Kubernetes and cutover](docs/runbooks/kubernetes-cutover.md):
  namespace/workload budgets, live-evidence prerequisites and exclusive ownership.
- [Independent services](docs/runbooks/independent-services.md):
  Cloudflare DNS-only and Supabase Free proposal/secret boundaries.

Examples intentionally lack verified private evidence. Keep account, inventory,
usage, ownership and qualification documents in ignored .infra. Never manufacture
freshness or entitlement merely to pass a check.

## CI and operational limits

The [trusted-toolchain runbook](docs/runbooks/trusted-toolchain.md) describes
reviewed Action SHA pins, archive/binary verification, mandatory redacted current,
staged and reachable-history scans, and tool update/incident procedures. The gate
fails on missing/tampered scanners or shallow clones and never downloads tools.

The Harness workflow runs the same complete gate and package build on Linux for
every PR and main push, without secrets or deployment environments.
The pre-commit hook invokes the same gate; it is convenience, not remote enforcement.

The manual Pulumi foundation workflow depends on shared verification, checks out
the dispatch commit, restricts execution to main/owner, serializes qualification
and uses pulumi-backend-qualification. Only the qualification step receives HMAC
credentials and a passphrase. Only its sanitized receipt is uploaded.
Resource preview/deployment requests still fail.
The [manual service-preview workflow](.github/workflows/service-preview.yml) adds
separate protected service handoffs after verification and a credential-free
enabled-contract gate. Current flags deny that gate. See [PR15's input and admin
contract](docs/m04-plan.md#pr15-protected-service-preview-workflow); no live
activation or environment protection is established by this YAML.
The [OCI preview workflow](.github/workflows/oci-preview.yml) reuses the handoff in
explicit OCI mode, with separate backend/resource signing inputs and required
committed network evidence for OKE. [PR16's contract](docs/m04-plan.md#pr16-protected-oci-preview-workflow)
lists the administrator prerequisites; tracked flags still block credential admission.

Required status checks, reviewer rules, main-only environment branches, effective
IAM scope and bucket retention must be verified outside this YAML. Inspection for
issue #31 reported no effective main rules and no classic branch protection; the
qualification-environment endpoint returned 404 (absent or inaccessible). Workflow
checks cannot replace administrator-owned required checks and approvals. There is
no documentation freshness check, scheduled drift monitor or measured performance
budget yet.

The [administrative sensor](docs/runbooks/github-administration.md) now collects
read-only classic main and qualification environment settings and checks short-lived private
snapshots against the clean checkout and policy bytes. It neither changes settings
nor proves administrator bypass, reviewer independence/custody or protected-commit provenance.

## Milestones and retained ownership

- M01 - Terraform OCI OKE: executable implementation retired; source remains in Git history.
- M02 - Pulumi foundation: current libraries, offline governance and qualification.
- M03 - Security and evidence hardening: engineering implemented; final documentation
  closeout is defined in [the closeout record](docs/m03-closeout.md). Activation remains blocked.
- [M04 - Independent stacks and protected previews](docs/m04-plan.md): explicit
  identities, protected execution and synthetic integration implemented;
  [engineering closeout](docs/m04-closeout.md) requires PR17 CI/merge, with live
  acceptance separately blocked.
- M05: controlled cutover and reliable operations.

Retirement removes repository execution paths, not cloud resources, local private
artifacts or external state ownership. The configured backend identity/prefix stays
unchanged. Never reuse or delete externally owned state during verification.
Supabase's pinned Terraform-provider bridge is part of the Pulumi SDK, not a
repository deployment workflow. External ownership fields remain necessary in the
read-only cutover evidence contract.


## Measured-evidence follow-up

Issue #33 adds schema-v2 independent recovery receipts, read-only backend posture
collection/checks and inventory scope/query/clock validation. Remote qualification
requires fresh private posture evidence; #45 replaces the manual protected
handoff with read-only same-job collection.
Regenerate old receipts/inventories and supply usage covered_through; never restamp
old data. See the backend and governance runbooks above for exact contracts.
These are bounded synthetic/read-only sensors. Trusted source attestations, live
least-privilege/coverage proof, production recovery SLOs, protected previews and
operational drift/cost/availability monitors remain prerequisites for activation.

## M03 implementation status

The reconciled Security and evidence hardening scope is implemented through
issue #77 / PR #78. This documentation-only closeout records the final dispositions;
its CI and merge are required before owner-managed milestone closure. Resource
operations stay disabled. See [M03 closeout](docs/m03-closeout.md) for the fixed scope,
administrator-owned activation prerequisites and M04/M05 boundaries.

| Planned task | Implementation / remaining work |
| --- | --- |
| PR1: trusted CI chain | SHA pins/installer in #31; verified actionlint and workflow CLI in #35 |
| PR2: secret scanning | #31: current, staged and reachable history; no exceptions/baseline supported |
| PR3-PR5: legacy ingress/capacity/image changes | Superseded by retirement in #27; live adoption checks still required |
| PR6: shared evidence envelopes | #37: unsigned exact-byte/scope/clock sidecars; intended backend, service, OCI and cutover consumers migrated in #43/#49/#51/#53/#55/#57/#63/#71 |
| PR7: secret ingestion/encryption contracts | #39: explicit passphrase policy, config-backed secret factory and custody/migration guidance |
| PR8: independent recovery | #33/#39/#41: isolated restore, explicit encryption/custody guidance and required wrong-key rejection; same-host synthetic scope only |
| PR9: backend posture | #33/#43: read-only collection/checks and exact-byte envelopes bound to independent tenancy, clean commit and backend configuration |
| PR10: protected backend audit workflow | #45: protected read-only audit and same-job qualification handoff; temporary signing credentials, sanitized summary and cleanup; admin/IAM settings remain prerequisites |
| PR11: usage coverage | #33: OCI coverage; #47: service collection clocks/per-metric coverage; #49: service CLI exact-byte envelopes bound to proposal/profile and clean HEAD; #51: factory envelopes before secret lookup/registration; #53: OCI collector/audit envelopes; #55: OCI preflight/composer envelopes; #57: cutover inventory consumer; #59: Supabase anniversary billing periods; #61: mandatory cumulative storage GB-hours and remaining-cycle budgets; source collection/authenticity and runtime cost controls remain prerequisites |
| PR12: cutover evidence | #57: inventory consumer; #63: exact review-input envelopes; #65: DSSE/Ed25519 configured-key authentication; #67: read-only classic main administrative observations; #69: schema-2 environment reviewer/branch observations; #71: signed cutover administrative snapshot/policy consumption; #73: successful required checks linked to the pinned main workflow; #75: canonical merged-PR/HEAD linkage; #77: distinct non-author final-head review observations; repository validators complete; administrator-owned last-push independence, key enrollment/custody, bypass and historical protection remain activation gates |

These implementation references are issue numbers. Completion of source checks
cannot establish live backend/IAM posture, billing eligibility or deployment authority.

The [shared evidence contract](docs/runbooks/security-evidence.md) now gates backend
posture collection/checks, remote qualification, service CLI audits and both service
factory entry points, OCI inventory collection/audit and OCI pre-registration.
Schema-5 cutover bundles validate that inventory pair and schema-5 administrative
observations, schema-3 policy, required-check execution, merged-PR linkage and final-head review observations, four review-input sidecars and four DSSE signatures against
a disabled-by-default reviewer policy. All 17 subjects use the captured bytes.
Pure accounting APIs and synthetic recovery receipts retain their existing contracts
by design. The closeout enumerates these boundaries; no blanket future migration is
an unfinished M03 task. Deployment and cutover authorization remain false.

## Offline operation evidence (M05-PR1)

`uv run --locked infra operations inspect --request config/operations.example.json`
validates schema-1 requests without running an operation or writing files. The
public example is deliberately expired and uses placeholder digests. Private
requests and journals belong under ignored .infra. To validate a journal and show
its current head, use `uv run --locked infra operations inspect --journal .infra/operations.json`.
Neither inspection result grants execution authority.

infra_core.operations.request validates and detaches a closed request mapping:
a canonical UUID, one of apply/import/recovery/monitor, an existing unit name,
a 40-character Git commit, configuration/checkpoint SHA-256 digests, UTC expiry,
and expected_predecessor (null for an empty journal, otherwise the previous head).
Request digests use sorted compact JSON. Digests bind supplied bytes/identities;
this stage does not establish their provenance, approvals or correspondence to live state.

The library journal(root, path, request, state, predecessor=...) appends only beneath
.infra using a local advisory lock, atomic replacement and file/directory fsync.
The caller supplies the observed head for compare-and-swap. prepared may advance
to admitted or failed; admitted to running or failed; running to succeeded, failed
or indeterminate. All three outcomes are terminal. A new UUID/request bound to the
previous head is required for the next operation. Request contents cannot change
within a lifecycle; admission/start must precede expiry, while a late outcome may
still be recorded. Timestamp regression, replay and malformed history fail closed.

These states are caller assertions, not operational permission. Local locking is
not distributed writer fencing; same-user tampering and hostile concurrent path
replacement are outside this evidence mechanism. Interrupted persistence reports
OPS002: inspect the journal before deciding whether to retry. Lost acknowledgements
must not trigger automatic operation replay. The journal has a 1 MiB bound and no
automatic rotation or deletion; full journals require a reviewed retention procedure.
No executor, credential admission or signing service is introduced by this slice.

## Mutation protocol compatibility (M05-PR2)

The explicit local gate is
`RUN_OPERATION_INTEGRATION=1 uv run --locked pytest -q -m operation_integration`.
CI requires it after shared verification, with no cloud credentials. Normal tests
check its workflow wiring and skip these opt-in subprocess/engine cases.

The synthetic operation worker exercises the installed SDK's saved-plan/update
argument shapes, loopback event transport, protected resource-import mapping and
failure/timeout cleanup. Synthetic success is transport evidence only. The real
pinned CLI test creates a disposable filesystem backend and a component-only stack:
it saves/applies a plan, observes events, round-trips a checkpoint and rejects an
additional unplanned component. No resource provider plugin or cloud resource is used.
The SDK omits an explicit --refresh=false argument when passed refresh=False;
future admission wrappers must enforce their own CLI flag policy.
SDK summary events omit isPreview; callbacks alone cannot establish preview/update
admission. The existing preview-only runtime is unchanged.

The installed SDK export_stack API forces --show-secrets. The real test uses only
synthetic secret data and contrasts SDK plaintext export with encrypted CLI export.
Future backup code must deliberately select encrypted export instead of blindly
reusing this SDK method. All checkpoint/plan files remain in disposable test storage.
Resource-import engine/provider behavior, production secret custody, cloud IAM,
crash recovery and distributed writer exclusion remain live acceptance gaps.
The bounded launch helper is test-only and does not constitute an operational executor.

## Operation approval preflight (M05-PR5)

infra_core.operation_admission.admit validates immutable request, approval,
role-signature, backup-receipt/manifest, environment-observation and journal bytes.
Its separately supplied context contains actor, environment, commit, configuration,
checkpoint and plan SHA-256 values, and the observed journal head. Callers must
compute that context from their current trusted inputs, never copy expectations
from an approval. The checkout must be clean at that commit. All deployment flags
remain disabled and no credential, execution or journal mutation API is exposed.

config/operations-policy.json ships disabled with no enrolled reviewers or age
limits. Enabling it requires independent review of keys, principal/role custody,
repository identity, explicit per-action/unit environments and positive age limits
(approval lifetime at most fifteen minutes). Two distinct enrolled operator/approver
principals must verify exact approval bytes; neither may be the requester, including
case variants. Duplicate keys/principals fail. Signing remains external; no signing
service or private key is introduced. Different principal strings do not prove
independent humans or custody.

Operation DSSE payloadType is application/vnd.cloud-infra.operation-approval.v1+json;
existing cutover signatures retain their fixed in-toto profile. The schema-1 approval
contains operation_id, all seven context fields, request_sha256, policy_sha256,
backup_sha256, environment_sha256, issued_at and expires_at. Hashes bind exact
supplied bytes; the backup manifest additionally binds the canonical request hash,
stack, unit, commit and encrypted pair hashes. Approval expiry cannot exceed request
expiry. Current hashes, fresh source-export age and prepared journal head must match.

administration.collect_operation_environment performs four explicit read-only GitHub
queries for repository, main branch, named environment and complete branch policies.
Its separate schema-1 observation must be fresh within fifteen minutes, collected
within five minutes, tied to the expected main commit/repository, and show required
reviewers, prevented self-review, explicit no-admin-bypass and only-main branch
selection. Existing qualification/cutover observation schemas are unchanged. This
checks observed settings, not historical enforcement, approval of the current job,
effective IAM, source authenticity or undisclosed bypass. Callers must establish
protected execution and provenance before exposing credentials.

admission_verified=true is bounded diagnostic evidence; execution_authorized stays
false. Rechecking an unchanged prepared request is idempotent. Advanced journals
reject replay. Future executors must recheck freshness and atomically transition
the observed journal before admitting credentials; this result is not a bearer token
or distributed lock. A monitor request currently requires the same backup bindings;
separate read-only monitoring admission policy remains a later scoped decision.

M05-PR6a adds a closed service operation runtime and exact saved-plan/event validators.
It is a transport foundation, not operational admission. The existing opt-in
operation_integration gate exercises synthetic timeout/failure handling and a
mandatory-policy saved-plan update against disposable provider-free local state.
The separate preflight, executor and operator handoff follow as stacked PR6b–PR6d.

M05-PR6b adds credential-free service_apply.check and the default-disabled
config/service-apply.json switch. Schema-2 operation approvals add the exact
execution_inputs_sha256 binding; schema-1 diagnostic preflight remains supported.
The check validates the reviewed factory graph, current service/backend evidence,
fixed per-unit prepared journal and freshly observed environment controls. It loads
no cloud credentials and executes no resource program. PR6c adds the journaled
executor; PR6d exposes the protected operator handoff.

M05-PR6c adds the separate service_apply.execute and owned child-program lifecycle.
Protected callers supply independent actor/environment context and a lazy credential
loader. Per-unit durable journals are fixed under .infra/operations; callbacks run
only after admission/CAS. The executor verifies tools/providers, compares the current
checkpoint, runs a fresh mandatory-policy preview and rechecks before exact planned
update. Before-launch failures are failed; unresolved launched updates are
indeterminate. No retry/rollback or normal deployment activation is introduced.

M05-PR6d adds the explicit protected service apply/check CLI and manual workflow.
See [the service runbook](docs/runbooks/independent-services.md#controlled-single-service-apply-m05-pr6)
for frozen bundle/signature preparation, fixed durable journals, dedicated runner
requirements and failure reconciliation. All tracked activation switches remain off.
The PR6a -> PR6b -> PR6c -> PR6d stack is the complete M05-PR6 slice.

## Dependency-ordered OCI apply (M05-PR7)

The separate oci_apply adapter reuses the owned service apply lifecycle and the
existing audited network/OKE factories. config/oci-apply.json ships disabled; all
preview/deployment flags and reviewer enrollment remain unchanged. The existing
apply CLI accepts oci-network and oci-oke only through explicit protected composition.
Each operation selects an existing stack and requires its own immutable request,
backup, schema-2 approval and fixed durable journal. OKE additionally requires the
successful network journal/receipt and exact committed outputs/checkpoint. Both
workflow concurrency and a shared local lock serialize the dependency pair.

See [the OCI apply runbook](docs/runbooks/oci-components.md#controlled-oci-apply-m05-pr7)
for input formats, sequencing, custody and limitations. Focused offline tests use
`uv run --locked pytest -q tests/test_oci_apply.py tests/test_service_apply.py`.
The existing opt-in operation integration gate also exercises real local network
checkpoint exports and StackReference saved-plan behavior, without OCI providers
or cloud resources. Run the complete shared gate before delivery.

## Ownership preparation (M05-PR8)

The offline ownership adapter validates one complete OCI unit mapping against
captured Terraform state-v4 instance IDs and an existing encrypted Pulumi checkpoint.
A prepared import journal, matching configuration/checkpoint hashes and a fresh
complete two-writer freeze attestation are mandatory. No state/journal writes,
source release, imports, or writer authorization occur. Existing cutover diagnostics
remain unchanged. The public config/ownership.example.json stays incomplete.
See [the ownership preparation contract](docs/runbooks/kubernetes-cutover.md#ownership-preparation-checkpoints-m05-pr8).

Use `uv run --locked infra ownership prepare --evidence .infra/ownership/index.json`.
Focused regression tests run with
`uv run --locked pytest -q tests/test_ownership.py tests/test_operations.py tests/test_cutover.py`.
The complete gate remains `uv run --locked infra verify`; no new integration marker,
executable or dependency is required for this read-only feature.

## Protected OCI resource import (M05-PR9)

The separate disabled import_driver consumes PR8 preparation plus execution-bound
import approvals through the shared owned driver. It imports only a bounded existing
OCI unit graph with exact IDs and pre-existing protected parent/provider metadata.
It verifies the imported checkpoint and requires a no-op mandatory-policy preview
before success. Source state and writer ownership remain unchanged; launched
uncertainty is indeterminate with no automatic retry. Existing apply/preview gates
remain separate. config/resource-import.json ships disabled.

See [the import contract](docs/runbooks/kubernetes-cutover.md#protected-resource-import-m05-pr9)
for input bindings, existing-target prerequisites and the pinned CLI policy/plan
limitations. The explicit command is
`uv run --locked infra resource-import --check --unit oci-network --commit 0000000000000000000000000000000000000000 --actor owner --environment oci-network-import --bundle .infra/import/bundle.json --journal .infra/operations/oci-network.json`.
Focused tests use `uv run --locked pytest -q tests/test_import_driver.py tests/test_operation_admission.py tests/test_ownership.py`.
The existing operation_integration gate now includes owned synthetic import
subprocess/RPC success, failure, timeout, incomplete-event and post-preview drift
cases. Native OCI import remains separate live acceptance, not a CI operation.

## Signed owner admission (M05-PR10)

The separate ownership handoff gate checks both OCI import journals/checkpoints,
fresh policy no-op previews, committed dependency outputs, measured scoped off-host
recovery and externally recorded source release under a continuous two-writer
freeze. Two distinct non-requester roles must sign the complete action-specific
subject. config/ownership-handoff.json ships disabled and no keys are enrolled.

The existing cutover check remains diagnostic with cutover_authorized=false.
The new read-only command is
`uv run --locked infra cutover handoff --evidence .infra/handoff/index.json --actor owner --environment oci-handoff`.
It returns an expiring owner-admission decision with writer/resource activation
false and writes no state, journal or settings. See
[the full handoff contract](docs/runbooks/kubernetes-cutover.md#signed-owner-handoff-m05-pr10)
and the deliberately incomplete config/ownership-handoff.example.json.

Fresh import receipts now bind the checkpoint actually verified after the no-op
preview. New recovery receipts are schema 2 with scope/host/clock bindings; the new
handoff gate rejects older receipts missing those fields. Existing APIs/defaults
stay unchanged. Focused tests run with
`uv run --locked pytest -q tests/test_ownership_handoff.py tests/test_ownership.py tests/test_cutover.py tests/test_recovery_rehearsal.py tests/test_import_driver.py`.
Run the complete shared gate and existing operation integration gate before delivery.

## Isolated drift observation (M05-PR11)

The separate default-disabled drift adapter (`infra drift --help`) accepts monitor-specific
schema-2 approvals and private four-unit preview/checkpoint inputs. Authoritative
access exposes encrypted export only; refresh preview and mandatory-policy desired
comparison run in a disposable local backend, then re-export source checkpoints
to prove preservation. Clean, drifted and unknown remain distinct; unknown exits
nonzero and no result authorizes state acceptance or remediation.

See [the drift observation contract](docs/runbooks/drift-observation.md) for exact
bundle/signature/credential boundaries, journal outcomes and activation gaps.
Focused tests use
`uv run --locked pytest -q tests/test_drift_results.py tests/test_drift.py tests/test_drift_runtime.py`.
The existing operation integration gate includes synthetic provider errors/deletion
and real pinned provider-free encrypted local drift rehearsals. Scheduling and
notifications remain M05-PR14; native provider/IAM acceptance is separate.

## Cost, capacity, and evidence-age findings (M05-PR12)

The offline `infra monitoring findings --help` interface consumes existing private
OCI account/inventory and Cloudflare/Supabase service evidence. It reuses resource
classification, collection coverage and billing-cycle rules, compares observed
measurements against reviewed profile limits and explicit private thresholds, and
preserves original clocks/watermarks. Missing or incomplete measurements remain
unknown; output never grants admission or changes an allowance, journal or resource.

`config/monitoring.example.json` is disabled and intentionally incomplete. See
[the operational findings contract](docs/runbooks/operational-findings.md) for exact
inputs, outcomes, account-wide scope, CLI exits and evidence limits. Focused checks:
`uv run --locked pytest -q tests/test_operational_findings.py tests/test_governance.py tests/test_services.py`.
The shared gate covers this entirely offline slice; scheduling/incident persistence
and delivery remain M05-PR14. No dependency or provider integration gate is added.

## Bounded infrastructure health observations (M05-PR13)

The explicit `infra monitoring health --help` interface separates offline OKE
readiness validation from allowlisted DNS/TLS/HTTP observation. Remote workers pin
resolved destinations, verify TLS, reject redirects and bound response size/time;
unknown failures never establish health. Operator-supplied node/API/CNI/DNS evidence
retains original scoped clocks and cannot prove network isolation or cutover authority.

`config/health.example.json` stays disabled/incomplete, preserving PR12's independent
cost-policy schema. See [the health contract](docs/runbooks/infrastructure-health.md)
for private inputs, check/observe modes, process cleanup and acceptance limits.
Focused checks use `uv run --locked pytest -q tests/test_health.py tests/test_operational_findings.py`.
The shared gate runs loopback fixtures only; no external endpoint, credential,
Kubernetes client or new integration marker is needed. Scheduling/delivery remain PR14.

## Scheduled monitoring and incident delivery (M05-PR14)

The default-disabled protected monitor composes the existing drift, operational
findings and health adapters into grouped incidents with a durable local outbox.
Fresh signed drift admission remains mandatory. Provider execution and credential-free
health collection use separate steps; a GitHub-hosted watchdog checks persistence
heartbeats independently of the durable runner. No remediation or resource activation
is introduced. GitHub issue delivery is separately gated and initially report-only.

See [the scheduling/outbox contract](docs/runbooks/scheduled-monitoring.md) for actor/host
and recipient enrollment, explicit first initialization, preserved state, unknowns,
retry/acknowledgement limits and missing-run guarantees. config/monitoring-runner.json
ships disabled with no enrolled actors/host or heartbeat target. Focused checks use
`uv run --locked pytest -q tests/test_incidents.py tests/test_monitor_delivery.py tests/test_monitoring.py`.
The shared gate uses fake GitHub responses and existing local fixtures only; no
notifications, workflow dispatch or live observations are part of verification.

## Authorized state recovery (M05-PR15)

The separate default-disabled `infra state-recovery --help` adapter restores an exact
approved checkpoint/configuration pair under an external writer freeze. It requires
fresh schema-2 admission, a current safety backup, authenticated owner provenance,
independent rehearsal and pre/post isolated reconciliation. It never applies resources,
creates a stack, compensates a failed import or releases writers. See
[the recovery contract](docs/runbooks/state-recovery.md) for private inputs, conservative
identity/property limits, immutable config publication and indeterminate outcomes.

Focused checks: `uv run --locked pytest -q tests/test_recovery_driver.py tests/test_recovery_rehearsal.py`.
The shared gate remains `uv run --locked infra verify`. Explicit disposable local-engine
verification uses `RUN_OPERATION_INTEGRATION=1 uv run --locked pytest -q -m operation_integration`;
this includes actual encrypted import/readback, wrong-key rejection, empty-config
rehearsal and exact restic snapshot retrieval. No live recovery is part of verification.

## Failure rehearsal and finite closeout (M05-PR16)

[The M05 closeout](docs/m05-closeout.md) maps all 16 approved tasks to implementation
PRs and gives a finite administrator-owned live acceptance checklist. Its engineering
completion is conditional on PR16 CI and merge; no live activation, SLO or owner
transfer is inferred from passing repository tests.

`tests/test_operations_integration.py` composes production journals/locks, recovery
signature admission and incident/outbox persistence across bounded Linux child
processes. Runtime/provider effects and remote delivery are synthetic. Crashes after
mutation or success journaling, expired recovery approval, frozen recovery, interrupted
monitoring and lost delivery acknowledgement cannot silently permit replay, clear
an incident or release writers. Existing engine suites separately cover actual
pinned CLI/SDK and restic behavior against disposable local state.

Run only these process sequences with
`RUN_OPERATION_INTEGRATION=1 uv run --locked pytest -q tests/test_operations_integration.py -m operation_integration`.
The complete `RUN_OPERATION_INTEGRATION=1 uv run --locked pytest -q -m operation_integration`
remains supported. CI runs the existing protocol/engine cases excluding this file,
then this required failure suite, once each without credentials. The shared gate
checks wiring and skips opt-in cases. Shared verification, workflow checking and
workspace package builds remain required; no executable/dependency or live test is added.

## Read-only operational readiness (M06-PR1)

`uv run --locked infra readiness --unit oci-network --evidence .infra/readiness.json`
reports authenticated reviewer assertions for the ten M05 acceptance gates. Exact
record/evidence/configuration/policy hashes, current clean commit, two distinct
reviewer roles and signed expiry windows determine missing/stale/failed/accepted
results. Every result denies execution and activation authority; live controls
are not independently verified. Existing operation approvals remain separate.

See [the acceptance contract](docs/runbooks/operational-readiness.md) for the private
index, fixed gate/stage schema, signature payload type, report precedence and exit
codes. Current disabled/empty reviewer policy cannot authenticate acceptance;
M06-PR2 owns enrollment. Focused checks use
`uv run --locked pytest -q tests/test_readiness.py`; the shared gate and
`uv build --all-packages` cover this offline, dependency-free addition.

M06-PR2 adds `uv run --locked infra security check-enrollment` with an optional
`--evidence .infra/enrollment.json` index. It reports pending repository trust,
protected-environment and runner custody gaps without network calls or writes;
consistent observations never complete enrollment. See the
[enrollment procedure](docs/runbooks/github-administration.md#m06-repository-trust-and-runner-enrollment-checks).

M06-PR3 adds `uv run --locked infra backend check-readiness --account-id OCID`
with an optional `--evidence .infra/backend-readiness.json` index. It validates
qualification, posture and existing-stack observations offline; independent IAM,
key custody and recovery-access acceptance remains pending. See the
[backend readiness procedure](docs/runbooks/pulumi-backend.md#m06-backend-readiness-checks).

M06-PR4 adds `uv run --locked infra backup check-readiness --unit oci-network --repository-id REPOSITORY_SHA256 --recovery-host-id HOST_SHA256`
with an optional `--evidence .infra/backup-readiness.json` bundle. It checks existing
pair/snapshot/off-host rehearsal evidence without repository access or writes;
physical storage independence and key custody remain pending. See the
[independent backup readiness procedure](docs/runbooks/pulumi-backend.md#m06-independent-backup-readiness).

M06-PR5 adds `uv run --locked infra governance check-readiness --unit oci-network --account-id ACCOUNT_ID`
with an optional `--evidence .infra/account-readiness.json` index. OCI, Cloudflare
and Supabase reuse existing evidence/semantic audits; live entitlement and IAM
acceptance remain pending. See the
[account readiness procedure](docs/runbooks/free-tier-governance.md#m06-account-readiness).

M06-PR6 adds `uv run --locked infra operations check-readiness --unit oci-network --writers .infra/writers.json`
with optional `--evidence .infra/writer-freeze.json`. It checks external freeze
assertions against canonical journals without locking, initializing or releasing
writers. Distributed exclusion remains pending; see the
[writer-exclusion procedure](docs/runbooks/operational-readiness.md#m06-writer-exclusion-readiness).

M06-PR7 separates service apply activation into schema-2 per-unit gates, both
committed disabled. Cloudflare preparation and its saved-plan production gap are
covered in the [staged activation procedure](docs/runbooks/independent-services.md#m06-cloudflare-staged-activation-preparation).
Enabling Cloudflare never implicitly enables Supabase; OCI/import gates are unchanged.

M06-PR8 adds the offline Supabase staging command documented in the
[staged Supabase procedure](docs/runbooks/independent-services.md#m06-supabase-staging-checks-and-procedure).
It checks exact account/organization, existing usage evidence and required encrypted
configuration keys through the shared execution validator. Activation stays pending.

M06-PR9 separates OCI apply/import policies into independent schema-2 per-unit
gates, all committed disabled. See the
[network-adoption staging procedure](docs/runbooks/kubernetes-cutover.md#m06-oci-network-adoption-staging)
for exact mapping, existing-target/plan prerequisites, native-import proof and
paired-handoff boundaries. The shared OCI dependency lock is unchanged.

M06-PR10 adds `uv run --locked infra kubernetes check-staging --account-id TENANCY_OCID --cluster-id CLUSTER_OCID --config .infra/kubernetes.json --oci-config .infra/oci.json --network-outputs .infra/network-outputs.json --inventory .infra/cluster.json --resources .infra/manifests.json`.
It checks recorded OKE network/cluster consistency through the existing validators,
without live access or activation authority. See the
[OKE staging procedure](docs/runbooks/kubernetes-cutover.md#m06-oke-staging-checks-and-procedure)
for private input schemas, live acceptance and separate paired-handoff boundaries.

M06-PR11 adds `uv run --locked infra monitoring check-readiness --unit oci-network --binding-sha256 EXPECTED_SCOPE_SHA256 --heartbeat-seconds 1800`.
It inspects canonical durable incident state without initialization, locking,
collection or delivery; missing/stale/unfinished state and outbox gaps stay visible.
See the [monitoring commissioning procedure](docs/runbooks/scheduled-monitoring.md#m06-monitoring-readiness-and-staged-commissioning).
Scheduling, delivery and live acceptance remain pending.
