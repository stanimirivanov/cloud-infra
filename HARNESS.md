# Repository harness

## Map and design

The repository is migrating to Pulumi Python. This PR establishes the uv workspace,
packaged automation, typed configuration contracts and credential-free SDK tests.
Existing Terraform configuration and cloud ownership are preserved, but Terraform
apply/recovery are frozen. Pulumi backend configuration, disabled stack identities
and isolated qualification tooling are now available; resource deployment is blocked. There is no
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
      foundation.py                  Explicit backend and disabled stack identities
      backend.py                     Opt-in isolated qualification and evidence
      governance/                    Pure account-wide cost/usage evaluator
      inventory/oci.py               Optional paginated read-only tenancy scanner
      oci/                           Pure reviewed OCI inputs, graph and security rules
      kubernetes/                    Offline namespace controls and workload/capacity sensors
      cutover.py                     Read-only, commit-bound evidence consistency checks
      services/                      Independent DNS/database proposals and scope-aware preflight
      policy.py                      Existing parsed-HCL architectural sensors
      verification.py                Python and legacy infrastructure gates
  infra-program/
    pyproject.toml                   Pulumi SDK and infra-core dependency
    Pulumi.yaml                     Shared runtime entry point, no implicit backend
    src/infra_program/__main__.py    Resource deployment disabled
    src/infra_program/qualification.py  Synthetic secret only, no cloud resources
    src/infra_program/governance.py   Pre-registration gate and mandatory policy
    src/infra_program/oci/            Protected native networking/OKE component library
    src/infra_program/services/       Protected explicit-provider DNS/database components
sdks/supabase/                        Pinned generated SDK, uv workspace member
config/quotas/profiles.toml           Dated published entitlement profiles
policies/                            Mandatory Pulumi Python cost policy pack
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
| Provisioning | pulumi.yml | Manual protected qualification only; resource operations disabled |

Files in the infrastructure unit share one Terraform state and may reference
one another according to these boundaries. Renaming a directory changes the
backend key: `01-infrastructure/terraform.tfstate`. The state bucket and endpoint
remain owned by root.hcl. State movement/recovery is never a validation fix.

## Bootstrap and daily commands

Install **uv 0.12.5**, Terraform **1.15.8**, Terragrunt **0.97.2**, Git and gh on
PATH. uv obtains Python **3.12.14** from .python-version. Use official signed
releases and verify published checksums. Terraform/Terragrunt pins are preserved
from the existing harness. Pulumi CLI **3.272.0** must match its locked Python SDK.
Default verification needs no Pulumi CLI; opt-in local qualification and its CI
step install/use this exact version.

From the repository root, identically on PowerShell and POSIX shells:

```sh
uv sync --locked --all-groups
uv run --locked pre-commit install
uv run --locked infra verify
```

No environment activation or pip requirements file is needed. The root is a
non-packaged workspace application that installs both editable member packages.
The generated Supabase SDK is a third editable workspace member with the same lock.
infra-program depends on infra-core; infra-core does not import Pulumi. One uv.lock
resolves runtime and development dependencies across both members. Keep direct
requirements in pyproject.toml and review uv.lock changes rather than manually
pinning every transitive dependency. Use uv lock for deliberate dependency edits;
ordinary local and CI commands use --locked and never repair a stale lockfile.

The package CLI discovers the checkout from the current directory, including
nested directories. From outside the checkout, use
`uv run --project /path/to/repo --locked infra --root /path/to/repo verify`.
Package imports do not assume their installation directory is the repository.

The historical deployment summary remains packaged as
`uv run --locked infra report --directory terraform`. It reads Terragrunt execution
reports from that directory, prints Markdown and appends to GITHUB_STEP_SUMMARY
when set. It reports execution presence, not whether resource changes were planned.
The legacy deployment writer and automatic recovery are now removed; the report
command remains available for historical execution reports. Backend qualification and recovery are described in
[the backend runbook](docs/runbooks/pulumi-backend.md); ownership migration is deferred.

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

The Harness matrix runs on all PRs and main pushes without secrets. Ubuntu runs
full verification; Windows runs the Python gate. Both also explicitly run the real,
disposable filesystem-backend integration test using the pinned Pulumi CLI. This
is local-only and creates no provider/cloud resources. Default local verification
skips that opt-in test. The manual Pulumi workflow depends on the verification matrix.

The legacy Terraform workflow is verification-only, without cloud credentials,
apply, imports or automatic state recovery. The Pulumi foundation workflow has only
a manual dispatch trigger, main/owner guards, non-cancelling concurrency, and the
pulumi-backend-qualification environment. Only the qualification step receives
S3 HMAC credentials/passphrase; resource preview/deploy remain deliberate failures.
It uploads only sanitized qualification evidence. No PR code receives those secrets.

Administrators must configure environment reviewers, main-only deployment branches
and required Harness status checks. A named environment alone does not prove these
settings exist. See the backend runbook for the administrative prerequisites,
permissions, storage/retention boundaries, recovery and evidence limitations.

## Approved Pulumi migration sequence

1. Delivered here: uv workspace, packaged CLI, pytest, strict mypy, shared hook/CI,
   typed account/unit contracts and Pulumi SDK development support.
2. Delivered: validated backend/stack identities, encrypted secret/checkpoint and
   locking/recovery qualification tooling, manual protected workflow, and legacy
   writer freeze. Actual OCI qualification remains an explicit credentialed gate.
3. Delivered: account-aware capacity, peak and monthly usage evaluator, read-only
   OCI inventory and mandatory resource policy; see the
   [governance runbook](docs/runbooks/free-tier-governance.md). Live account
   eligibility, usage and external-service review remain explicit operator gates.
4. Delivered: protected native OCI networking/OKE components, pure graph-to-SDK
   equivalence tests, reviewed image/version inputs, hardened NSGs and an
   [adoption contract](docs/runbooks/oci-components.md). No state transfer or
   resource activation; separate stack orchestration remains a cutover prerequisite.
5. Delivered: Kubernetes namespace/workload governance and read-only cutover
   evidence preparation; see the [runbook](docs/runbooks/kubernetes-cutover.md).
   All deployment/state transitions remain disabled. Separate-stack orchestration,
   live admission/network validation and explicit operational authorization are
   still required before any actual cutover.
6. Delivered: independent Cloudflare DNS-only and Supabase Nano component libraries,
   account/scope-aware offline preflight, secret/protected SDK adapters and mandatory
   classifiers; see the [runbook](docs/runbooks/independent-services.md). Evidence
   collection is an explicit operator review; no deployment or data-plane activation.
   Runtime monitoring, live credential/account checks and protected stack orchestration
   remain operational prerequisites. AWS/GCP remain optional later work.

The legacy 4 OCPU / 24 GiB policy is retained as a regression baseline, not verified
account eligibility. Current Oracle documentation distinguishes free-tenancy
2 OCPU / 12 GB allowances from paid-tenancy monthly allowances. Existing source
uses 2 OCPUs / 16 GB. The new governance engine rejects that memory total for the
free profile. Resizing/adoption belongs to the compute PR; a green development
harness does not establish zero billing.
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
Tekton support and different node sizing. The former automatic recovery writer
is removed; future deployed-state recovery requires the reviewed operator runbook. Static
validation cannot prove those behaviors. No cloud plan or deployment is performed
by the harness or implied by its green status.
