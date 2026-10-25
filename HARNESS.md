# Repository harness

## Map and design

This is HCL infrastructure, not an application service. Terraform owns a single
OCI resource graph; Terragrunt generates shared configuration and owns state
addressing. There is no application language, package build, test suite, Tekton
installation, Helm release or Kubernetes workload in the baseline. Python 3.12
is tooling only. Do not impose application layers or introduce a framework here.

```text
AGENTS.md                            # lean agent entry point and PEV loop
HARNESS.md                           # architecture, setup, gates and roadmap
terraform/
  AGENTS.md                          # shared generation and state constraints
  root.hcl                           # backend/provider/variable generation
  terraform.tfvars.example            # illustrative non-secret inputs
  01-infrastructure/
    AGENTS.md                        # network -> cluster boundaries and budget
    .terraform.lock.hcl              # reviewed provider selection/checksums
    main.tf                          # Terraform and OCI version constraints
    vcn.tf                           # VCN, subnets, gateway, routes and NSGs
    oke.tf                           # OCI lookups, Basic cluster and A1 pools
    outputs.tf                       # public unit outputs
    terragrunt.hcl                   # includes root; no hooks or state reads
scripts/
  AGENTS.md                          # verification implementation constraints
  requirements.txt                   # pinned Python tooling and dependencies
  policy.py                          # parsed-HCL architectural sensors
  verify.py                          # shared local/hook/CI entry point
tests/
  test_policy.py                     # mutation tests for unsafe changes
  public_ingress_baseline.json        # explicit existing debt, not a safe default
.github/
  AGENTS.md                          # credential and deployment boundaries
  workflows/verify.yml               # secret-free PR/push + reusable gate
  workflows/terraform.yml            # deployment depends on reusable gate
  actions/setup-tools/action.yml      # pinned deployment tools
.pre-commit-config.yaml               # calls the complete shared gate
ruff.toml                            # Python static lint and formatting
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
| Verification | scripts/, tests/, verify.yml | Synthetic inputs, temporary files, no state or OCI calls |
| Provisioning | terraform.yml | Existing owner check and oci-infrastructure environment |

Files in the infrastructure unit share one Terraform state and may reference
one another according to these boundaries. Renaming a directory changes the
backend key: `01-infrastructure/terraform.tfstate`. The state bucket and endpoint
remain owned by root.hcl. State movement/recovery is never a validation fix.

## Bootstrap and daily commands

Install Terraform **1.15.8**, Terragrunt **0.97.2**, Git and gh on PATH. CI uses
Python **3.12.12**; Python 3.12 patch updates are compatible with this tooling.
Use official signed releases and verify their published checksums. The local
runner refuses different Terraform/Terragrunt versions. These are reviewed pins,
not assertions that these releases are the latest available.

From the repository root (PowerShell):

```powershell
python -m venv .venv
.venv/Scripts/Activate.ps1
python -m pip install -r scripts/requirements.txt
pre-commit install
python scripts/verify.py
```

On POSIX shells, activate with `source .venv/bin/activate`. No OCI credentials,
GitHub secrets, tfvars or existing backend initialization are needed. First run
needs network access to obtain the locked provider from the Terraform registry;
credential-free does not mean offline. Hooks are optional local convenience;
remote verification is the authoritative gate.

| Sensor | Exact command / assertion | What failure means |
| --- | --- | --- |
| Python static lint | python -m ruff check scripts tests | Fix reported import, unused-name or code issue |
| Python formatting | python -m ruff format --check scripts tests | Run python -m ruff format scripts tests |
| Policy regression suite | python -m unittest discover -s tests -v | Fix the sensor or regression; never remove a test to pass |
| Architecture | scripts/policy.py via verify.py | Stable ARCH/COST/NET/SECRET ID explains violated boundary |
| Terraform format | terraform fmt -check -recursive terraform | Run terraform fmt -recursive terraform |
| Terragrunt format | terragrunt hcl fmt --check --working-dir terraform | Run same command without --check |
| Shared configuration | terragrunt render --json --disable-dependent-modules | Fix include, generation or input evaluation |
| Provider schema/types | terraform init -backend=false -input=false -lockfile=readonly; terraform validate -no-color | Fix HCL, types or pinned-provider schema; no backend accessed |

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
  schema/release notes. Keep main.tf and setup tool pins in sync with verify.py.

## CI integration and repository settings

`Harness / Credential-free verification` runs on all PRs and main pushes, without
actor/path exclusions or secrets. The deployment workflow also calls it as a
required prerequisite, preserving the existing deployment event/path filters and
owner/environment controls. Infrastructure events consequently run the gate in
both workflows; this keeps deployment gating explicit and standalone coverage
unconditional. Neither workflow grants write access to PR validation.

Repository administrators should require the standalone Harness check in main's
branch protection/ruleset, block direct pushes and require review for harness,
workflow and policy-baseline changes. Configure required reviewers on the
oci-infrastructure environment. These settings are not enabled by this PR.
A workflow file alone cannot prevent privileged bypass or changes to its own rules.
The existing credentialed plan remains owner-only; static validation on forks is
complete without it. Apply, destroy and state recovery require separate explicit
operational authorization. This harness task does not provision resources.

## Progressive hardening and known debt

| Stage | Current status / next work | Acceptance evidence |
| --- | --- | --- |
| 1: Map and guides | Delivered: scoped AGENTS, ownership matrix, PEV and issue/PR workflow | Reviewer can locate an owner and verification command without broad reads |
| 2: Mechanical baseline | Delivered: lint/format, AST policies, negative tests, real render and locked schema validation in hooks/CI | Shared command passes; unsafe mutation tests fail as expected |
| 3: Required governance | Administrator action: branch rules, environment approval, immutable action SHA pins and verified binary installs | Settings and pinned supply-chain references reviewed; blocked bad PR demonstrated |
| 4: Security and cost | Follow-up: remove unrestricted worker ingress; restrict public API; eliminate non-ARM image fallback; explicit supported Kubernetes/image selection; add secret scanning and OCI-aware security scan with narrow expiring waivers | Negative tests plus approved credentialed plan; no wildcard scan suppression |
| 5: Behavioral evidence | Follow-up: mocked Terraform plan tests and plan-JSON policies for cost, CNI, IAM, ingress; move any future Tekton bootstrap to its own state unit | Fixture mutation tests; credentialed plan in protected environment |
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
