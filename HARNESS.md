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

Use Git and PowerShell 7 on Linux/Windows x64. The reviewed installer verifies uv
**0.12.5**, Pulumi **3.272.0**, Gitleaks **8.30.1** and actionlint **1.7.12**
release archives before extraction. The shared .python-version pins Python **3.12.14**.
GitHub CLI is needed for the issue/PR workflow. Pulumi CLI **3.272.0** is required
for explicit backend integration tests and qualification, matching the locked SDK.

In a PowerShell 7 session:

```shell
./.github/scripts/install-tools.ps1
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
RUN_SYNTHETIC_PREVIEW_INTEGRATION=1 on both platforms; its CLI worker and events are
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

The Harness workflow runs the same complete gate and package build on Linux and
Windows for every PR and main push, without secrets or deployment environments.
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
