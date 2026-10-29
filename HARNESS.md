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
