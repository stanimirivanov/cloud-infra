# OCI OKE infrastructure

The repository is transitioning to Pulumi Python. The uv workspace now packages
automation and Pulumi SDK development support; Pulumi provisioning remains
disabled. Backend/secret qualification is opt-in; see the
[backend runbook](docs/runbooks/pulumi-backend.md). Existing Terraform and Terragrunt
configuration describes OCI networking and an OKE Basic cluster with
an Ampere A1 node pool. The current configuration has two nodes, each with one
OCPU and 8 GiB RAM. It targets Always Free sizing but cannot guarantee zero cost,
capacity or tenancy eligibility. Tekton installation is not implemented.

Start with [HARNESS.md](HARNESS.md) for the architecture map, scoped agent guides,
local setup, deterministic checks, CI gates and hardening roadmap.

```text
terraform/root.hcl                    Shared generated backend/provider/variables
terraform/01-infrastructure/vcn.tf    VCN, API/node/pod subnets, routing and NSGs
terraform/01-infrastructure/oke.tf    Basic cluster, OCI lookups and A1 nodes
terraform/01-infrastructure/outputs.tf  cluster_ocid and region
```

## Development verification

Install uv 0.12.5 and the Terraform/Terragrunt pins documented in HARNESS.md,
then run from the repository root:

```sh
uv sync --locked --all-groups
uv run --locked pre-commit install
uv run --locked infra verify
```

Use `uv run --locked infra verify --scope python` for Python-only development
without Terraform/Terragrunt binaries, or `uv run --locked infra check` for focused
HCL architecture checks. The complete command validates formatting, types,
architecture, policy regression tests and provider
schema without OCI credentials or state access. No resources are provisioned.

## State and secrets foundation

`config/pulumi.toml` declares the existing OCI S3-compatible bucket, a separate
Pulumi prefix, pinned CLI and disabled stack identities. Inspect it without
credentials using `uv run --locked infra backend inspect`.

The [backend runbook](docs/runbooks/pulumi-backend.md) documents local qualification,
explicit OCI qualification, protected-environment secrets and recovery. Configure
required reviewers and protected-main branch restrictions before enabling the
manual workflow. Resource preview/deploy intentionally fail until later governance
and adoption PRs; Terraform writes are frozen. Existing Terraform source and state
keys are preserved for reference and credential-free schema validation.

## Account governance

Account-wide OCI capacity, replacement overlap and monthly-usage checks are
available through `infra governance inventory` and `infra governance audit`.
See the [governance runbook](docs/runbooks/free-tier-governance.md) for the
optional read-only SDK, explicit entitlement profiles, evidence contracts and
mandatory Pulumi policy. Passing these checks does not enable provisioning;
other providers remain disabled until their collectors and rules exist.

## OCI components

Protected native Pulumi networking and OKE components are available for offline
development. They share a pure resource graph with governance, require reviewed
versions/ARM images, restrict API/worker ingress and use explicit pod NSGs. See the
[OCI component and adoption runbook](docs/runbooks/oci-components.md). Render a
proposal with `infra oci proposal --config .infra/oci.toml --account-id <tenancy>`.
The template is deliberately incomplete; provisioning and ownership transfer
remain disabled. Existing Terraform resources and state are untouched.

## CI/CD

The Harness workflow runs credential-free checks on every PR and main push, plus
explicit disposable local-backend qualification on Windows and Linux. The legacy
Terraform workflow now verifies only: apply and automatic state recovery are frozen.
The manual Pulumi foundation workflow permits backend inspection and isolated OCI
qualification on protected main; preview/deploy remain readiness failures. No merge
provisions resources. See the backend runbook for required environment settings,
secrets, qualification evidence and operator-run recovery.
