# Repository harness

## Map and design

The repository is migrating to Pulumi Python. This PR establishes the uv workspace,
packaged automation, typed configuration contracts and credential-free SDK tests.
Terraform/Terragrunt still own all existing infrastructure. Pulumi has no resources,
backend, stack configuration or enabled deployment entry point yet. There is no
Tekton installation, Helm release or Kubernetes workload in this baseline.

```text
AGENTS.md                            Agent entry point and issue/PR workflow
HARNESS.md                           Architecture, setup, gates and roadmap
pyproject.toml                       Workspace, dependencies, Ruff/pytest/mypy
uv.lock                              Shared resolved dependencies and hashes
.python-version                      Shared Python patch pin
packages/
  AGENTS.md                          Python ownership and verification constraints
  infra-core/
    pyproject.toml                   infra CLI and HCL parser runtime dependency
    src/infra_core/
      cli.py                         verify/check commands; no provisioning
      repository.py                  Checkout discovery from cwd or --root
      reporting.py                   Legacy deployment execution summary
      config.py                      Immutable account/provider/unit contracts
      policy.py                      Existing parsed-HCL architectural sensors
      verification.py                Python and legacy infrastructure gates
  infra-program/
    pyproject.toml                   Pulumi SDK and infra-core dependency
    src/infra_program/__main__.py    Disabled until later migration PRs
terraform/                           Existing source, scoped guides and provider lock
tests/                               pytest regression, CLI, config and SDK tests
.github/workflows/verify.yml         Linux full gate; Windows Python gate
.pre-commit-config.yaml              Same complete locked CLI gate
```

Root instructions are the map; scoped instructions are the guides. Parsed policy
assertions, formatter exit codes, regression tests and provider-schema validation
are sensors. This follows the guide/sensor distinction in Birgitta Boeckeler's
[article on Martin Fowler's site](https://martinfowler.com/articles/harness-engineering.html)
and the repository-map and mechanical-boundary approach in
[OpenAI's harness engineering account](https://openai.com/index/harness-engineering/).
Agent judgment remains necessary for design and risk assessment; the checks make
specific structural properties repeatable, not the model itself deterministic.

## Ownership and dependency direction

| Owner | Source of truth | State / dependencies |
| --- | --- | --- |
| Shared configuration | terraform/root.hcl | Generates backend.tf, provider.tf, common_variables.tf; no resources |
| Network | 01-infrastructure/vcn.tf | VCN, three subnets, gateway, route table, NSGs; cannot reference OKE |
| Cluster/compute | 01-infrastructure/oke.tf | Depends on network; Basic OKE, A1 node pools, OCI lookups |
| Interface | 01-infrastructure/outputs.tf | cluster_ocid and region; no credentials |
| Future add-ons | Separate unit, design required | Consume cluster outputs; own distinct state; no reverse dependency |
| Verification | infra-core, tests/, verify.yml | Synthetic inputs, temporary files, no state or OCI calls |
| Provisioning | terraform.yml | Existing owner check and oci-infrastructure environment |

Files in the infrastructure unit share one Terraform state and may reference
one another according to these boundaries. Renaming a directory changes the
backend key: `01-infrastructure/terraform.tfstate`. The state bucket and endpoint
remain owned by root.hcl. State movement/recovery is never a validation fix.

## Bootstrap and daily commands

Install **uv 0.12.5**, Terraform **1.15.8**, Terragrunt **0.97.2**, Git and gh on
PATH. uv obtains Python **3.12.14** from .python-version. Use official signed
releases and verify published checksums. Terraform/Terragrunt pins are preserved
from the existing harness; Pulumi CLI/backend setup belongs to the next PR.

From the repository root, identically on PowerShell and POSIX shells:

```sh
uv sync --locked --all-groups
uv run --locked pre-commit install
uv run --locked infra verify
```

No environment activation or pip requirements file is needed. The root is a
non-packaged workspace application that installs both editable member packages.
infra-program depends on infra-core; infra-core does not import Pulumi. One uv.lock
resolves runtime and development dependencies across both members. Keep direct
requirements in pyproject.toml and review uv.lock changes rather than manually
pinning every transitive dependency. Use uv lock for deliberate dependency edits;
ordinary local and CI commands use --locked and never repair a stale lockfile.

The package CLI discovers the checkout from the current directory, including
nested directories. From outside the checkout, use
`uv run --project /path/to/repo --locked infra --root /path/to/repo verify`.
Package imports do not assume their installation directory is the repository.

The existing deployment summary is packaged as
`uv run --locked infra report --directory terraform`. It reads Terragrunt execution
reports from that directory, prints Markdown and appends to GITHUB_STEP_SUMMARY
when set. It reports execution presence, not whether resource changes were planned.
The legacy deployment job uses this CLI instead of a third-party inline Python
action; its provisioning commands, triggers, credentials and state ownership remain
unchanged. Backend and deployment ownership migration belong to subsequent PRs.

No OCI credentials, GitHub secrets, tfvars or backend initialization are needed.
First sync downloads Python dependencies; full verification obtains the locked
OCI provider from the Terraform registry. Credential-free does not mean offline.
Hooks are local convenience; remote verification is the authoritative gate.

| Sensor | Command / assertion | What failure means |
| --- | --- | --- |
| Complete local/hook gate | uv run --locked infra verify | Fix the first failure; no cloud resource/state operations occur |
| Python-only gate | uv run --locked infra verify --scope python | Lint/format/type/tests only; explicitly reports infrastructure was not checked |
| Python static lint | uv run --locked ruff check . | Fix the reported code issue |
| Python formatting | uv run --locked ruff format --check . | Run uv run --locked ruff format . |
| Python typing | uv run --locked mypy | Strict checks on both package source trees |
| Regression suite | uv run --locked pytest | Existing negative policies, config/CLI, isolation and Pulumi mock runtime |
| Focused architecture | uv run --locked infra check | Stable ARCH/COST/NET/SECRET diagnostic identifies the boundary |
| Terraform format | terraform fmt -check -recursive terraform | Run terraform fmt -recursive terraform |
| Terragrunt format | terragrunt hcl fmt --check --working-dir terraform | Run the same command without --check |
| Shared configuration | terragrunt render --json --disable-dependent-modules | Fix include, generation or input evaluation |
| Provider schema/types | terraform init -backend=false -input=false -lockfile=readonly; terraform validate -no-color | Fix HCL/types/provider schema; backend is disabled |

The Pulumi SDK mock test runs in a separate process with synthetic runtime
settings. It exercises Output evaluation and imports both workspace packages,
rejects provider calls/resource registration, and uses no Pulumi CLI or backend.
The development program raises before any deployment. These tests demonstrate SDK
and packaging readiness, not provider integration or deployment correctness.

The Python test stage uses a fresh temporary directory and cache per verification
run, avoiding shared pytest state. Subprocesses have a five-minute timeout.
The last two stages run in a disposable copy containing the real root.hcl and
unit configuration, with fake inputs and cloud/CLI override environment variables
removed. Only the reviewed generated filenames are materialized. The checkout
is not initialized and no plan, apply or state command is run. Temporary data is
cleaned up on exit. This is operational isolation, not a sandbox for hostile code.
Never supply secrets to an untrusted checkout, including through credential files.

For fast iteration run the affected sensor directly; run the complete entry point
before delivery. Read the first failing diagnostic, correct the cause, then
rerun. A missing tool/download is an environment failure, not a skipped pass.
Record commands/results and limitations in the PR. Do not repeatedly run the
same checks if neither code nor relevant environment changed.

## Enforced constraints and limits

- Parsed HCL resource ownership and a closed resource-type allowlist protect the
  network -> OKE boundary. No modules, provisioners, duplicated provider/variable
  definitions or resource-level count/for_each/dynamic blocks without policy review.
- Exactly one Basic cluster and literal A1 node pool sizes; aggregate configured
  capacity cannot exceed 4 OCPUs / 24 GiB. Current size is 2 OCPUs / 16 GiB total.
  This cannot measure resources outside this state, storage charges, quotas or
  current Oracle eligibility. It does not guarantee zero cost.
- Literal subnet CIDRs remain disjoint within 10.0.0.0/16. Ingress permits known
  subnet references or exact reviewed public-rule bodies. New sources/rules fail.
- Generated/sensitive artifact names cannot be tracked; credential outputs fail.
  This is a targeted sensor, not a comprehensive secret scanner.
- Provider versions and platform checksums are committed. Ordinary init uses
  readonly lock mode. Upgrades explicitly regenerate the lock in an isolated
  initialized unit with `terraform providers lock -platform=linux_amd64
  -platform=windows_amd64 -platform=darwin_arm64`, then run all gates and review
  schema/release notes. Keep main.tf and setup tool pins in sync with verification.py.

## CI integration and repository settings

The Harness matrix runs on all PRs and main pushes without actor/path exclusions
or secrets. Ubuntu runs the complete `uv run --locked infra verify` gate. Windows
runs `uv run --locked infra verify --scope python`, checking both editable packages,
console entry points, strict typing and the SDK mock runtime without installing
infrastructure binaries. Both matrix results are prerequisites for deployment.
The deployment workflow also calls the matrix as a required prerequisite, preserving the existing deployment event/path filters and
owner/environment controls. Infrastructure events consequently run the gate in
both workflows; this keeps deployment gating explicit and standalone coverage
unconditional. Neither workflow grants write access to PR validation.

Repository administrators should require both standalone Harness matrix checks
in main's branch protection/ruleset, block direct pushes and require review for harness,
workflow and policy-baseline changes. Configure required reviewers on the
oci-infrastructure environment. These settings are not enabled by this PR.
A workflow file alone cannot prevent privileged bypass or changes to its own rules.
The existing credentialed plan remains owner-only; static validation on forks is
complete without it. Apply, destroy and state recovery require separate explicit
operational authorization. This harness task does not provision resources.

## Approved Pulumi migration sequence

1. Delivered here: uv workspace, packaged CLI, pytest, strict mypy, shared hook/CI,
   typed account/unit contracts and Pulumi SDK development support.
2. Next: qualify a separate Pulumi backend, secrets, stack identities and protected
   deployment controls. Do not import or change ownership in this PR.
3. Add account-aware quota/inventory governance and mandatory resource policies.
4. Implement OCI networking and OKE components with reviewed adoption contracts.
5. Add Kubernetes resource governance and execute a separately authorized cutover.
6. Add independent Cloudflare/Supabase services; AWS/GCP remain optional later work.

The legacy 4 OCPU / 24 GiB policy is retained as a regression baseline, not verified
account eligibility. Current Oracle documentation distinguishes free-tenancy
2 OCPU / 12 GB allowances from paid-tenancy monthly allowances. Existing source
uses 2 OCPUs / 16 GB. Account-aware limits and remediation belong to the governance
and compute PRs; a green development harness does not establish zero billing.
See [Oracle Always Free resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
and the [OCI price list](https://www.oracle.com/cloud/price-list/).

## Progressive hardening and known debt

| Stage | Current status / next work | Acceptance evidence |
| --- | --- | --- |
| 1: Map and guides | Delivered: scoped AGENTS, ownership matrix, PEV and issue/PR workflow | Reviewer can locate an owner and verification command without broad reads |
| 2: Mechanical baseline | Delivered: lint/format, AST policies, negative tests, real render and locked schema validation in hooks/CI | Shared command passes; unsafe mutation tests fail as expected |
| 3: Required governance | Administrator action: branch rules, environment approval, immutable action SHA pins and verified binary installs | Settings and pinned supply-chain references reviewed; blocked bad PR demonstrated |
| 4: Security and cost | Follow-up: remove unrestricted worker ingress; restrict public API; eliminate non-ARM image fallback; explicit supported Kubernetes/image selection; add secret scanning and OCI-aware security scan with narrow expiring waivers | Negative tests plus approved credentialed plan; no wildcard scan suppression |
| 5: Behavioral evidence | Follow-up: Pulumi preview policies and provider integration tests for cost, CNI, IAM, ingress; move any future Tekton bootstrap to its own state unit | Fixture mutation tests; credentialed plan in protected environment |
| 6: Operational confidence | Follow-up: disposable tenancy integration tests, capacity/billing monitoring, drift detection, recovery rehearsal | Authorized lifecycle run, cost budget evidence, successful reviewed recovery |

The baseline intentionally records four existing public ingress rules: API
TCP/6443, API/worker ICMP fragmentation messages and unrestricted worker traffic.
The last rule is a serious existing security gap; a matching snapshot is not an
endorsement. Removing a rule or replacing its source with a known internal subnet is allowed.
Other changes, including narrower public CIDRs, require review and updating the
baseline, never a blanket suppression.

Other inherited limitations: Kubernetes/image selection depends on live OCI
lookups and can select a non-ARM fallback; README previously claimed unimplemented
Tekton support and different node sizing. Deployment recovery uploads/pushes state
and its failure/environment handling needs a separate operational review. Static
validation cannot prove those behaviors. No cloud plan or deployment is performed
by the harness or implied by its green status.
