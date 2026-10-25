# Repository harness

## Start here

This uv workspace contains Pulumi Python component libraries and offline
free-tier governance. Resource preview/deployment, production stack initialization
and ownership transfer are disabled. A passing check is not deployment authority.

| Location | Responsibility |
| --- | --- |
| AGENTS.md | Short agent entry point and Plan -> Execute -> Verify workflow |
| packages/AGENTS.md | Python ownership and dependency boundaries |
| packages/infra-core/src/infra_core/ | CLI, pure contracts, governance, optional inventory and verification |
| packages/infra-program/src/infra_program/ | Pulumi adapters, protected components and disabled program |
| sdks/AGENTS.md | Generated Supabase SDK provenance and editing restrictions |
| config/AGENTS.md | Public examples, evidence freshness and disabled deployment identities |
| .github/AGENTS.md | Credential-free verification and protected qualification boundaries |
| policies/ | Mandatory resource-local Pulumi policy pack |
| tests/ | Negative contracts, CLI, SDK serialization and qualification tests |
| docs/runbooks/ | Operator procedures and detailed contracts |

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

The package manifests and selected tests enforce parts of these contracts.
There is no comprehensive Python import-boundary linter yet. Component factories
compose libraries; they do not implement separate-stack deployment orchestration.

## Setup and verification

Install uv **0.12.5** and Git. The shared .python-version pins Python **3.12.14**.
GitHub CLI is needed for the issue/PR workflow. Pulumi CLI **3.272.0** is required
only for explicit backend integration tests and qualification, matching the locked SDK.

```sh
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
| Complete shared gate | uv run --locked infra verify |
| Lint | uv run --locked ruff check . |
| Format check | uv run --locked ruff format --check . |
| Strict typing | uv run --locked mypy |
| Regression tests | uv run --locked pytest |
| Package build | uv build --all-packages |
| Inspect disabled backend configuration | uv run --locked infra backend inspect |

The complete gate checks tracked private artifacts, then lint, format, types and
tests. It uses a temporary pytest directory/cache and propagates subprocess errors
with a five-minute timeout. It needs no cloud credentials, provider plugins or
deployed-state access. Generated SDK code is excluded from Ruff/mypy traversal;
actual adapter serialization is exercised using the generated SDK in mocks.

Default tests skip three opt-in backend/policy-host integration tests. CI explicitly
sets RUN_PULUMI_LOCAL_QUALIFICATION=1 and runs the backend_integration marker with the
pinned CLI on disposable local storage. This tests encryption, locking, recovery
and policy protocol behavior without creating provider/cloud resources.

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

The Harness workflow runs the same complete gate and package build on Linux and
Windows for every PR and main push, without secrets or deployment environments.
The pre-commit hook invokes the same gate; it is convenience, not remote enforcement.

The manual Pulumi foundation workflow depends on shared verification, checks out
the dispatch commit, restricts execution to main/owner, serializes qualification
and uses pulumi-backend-qualification. Only the qualification step receives HMAC
credentials and a passphrase. Only its sanitized receipt is uploaded.
Resource preview/deployment requests still fail.

Required status checks, reviewer rules, main-only environment branches, effective
IAM scope and bucket retention must be verified outside this YAML. Action references
still use mutable version tags. There is no general secret scanner, documentation
health linter, scheduled drift monitor or measured performance budget yet.

## Milestones and retained ownership

- M01 - Terraform OCI OKE: executable implementation retired; source remains in Git history.
- M02 - Pulumi foundation: current libraries, offline governance and qualification.
- M03 - Security and evidence hardening: next milestone; see audit recommendations.
- M04/M05: independent protected workflows, metering, cutover and reliable operations.

Retirement removes repository execution paths, not cloud resources, local private
artifacts or external state ownership. The configured backend identity/prefix stays
unchanged. Never reuse or delete externally owned state during verification.
Supabase's pinned Terraform-provider bridge is part of the Pulumi SDK, not a
repository deployment workflow. External ownership fields remain necessary in the
read-only cutover evidence contract.
