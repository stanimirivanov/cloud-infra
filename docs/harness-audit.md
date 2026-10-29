# Harness drift review

Reviewed 25 October 2026 as the prerequisite to M03, after retiring repository-owned
Terraform/Terragrunt execution. This is a source/workflow and local-verification
review; GitHub administration, OCI IAM, bucket settings and deployed resources were
not inspected. No cloud or state operation is authorized by this report.

## Follow-up: architecture and documentation fitness

Issue #29 implements upgrade 1 through infra verify. Static first-party import rules
now reject forbidden package/domain edges, including relative/lazy and literal
dynamic imports; nonliteral dynamic imports fail. Local guide links/Markdown
anchors and full infra examples are checked without executing examples. Mutation
tests exercise each failure path. The remaining findings below describe the
original review: runtime capability isolation, remote-link/freshness checks and
external enforcement remain outside these sensors.

## Follow-up: trusted execution chain

Issue #31 pins external Actions, replaces tool setup Actions with checksum-verified
release archives, and adds mandatory Gitleaks scans of current/staged content and
all locally reachable history. Binary verification precedes scanner execution;
missing tools and shallow clones fail closed. Negative fixtures cover tampered
archives, planted/deleted secrets and unsafe workflow changes. See the
[trusted-toolchain runbook](runbooks/trusted-toolchain.md) for provenance and limits.
Read-only GitHub inspection reported no classic main protection or effective main
rules; the qualification-environment endpoint returned 404. These external gaps
remain administrator prerequisites. The original assessment below predates these
code changes; the measured-evidence follow-up below addresses the first part of upgrade 3;
operational activation remains outstanding.

## Follow-up: measured evidence before operations

Issue #33 adds fresh-session synthetic recovery after stack loss, measured restore
and backup-age timings, encrypted checkpoint size/hash, read-only bucket posture
checks, and inventory/usage coverage clocks with an exact successful-query matrix.
Old receipts and inventories fail closed. Remote qualification requires fresh
posture through a manually protected evidence handoff. These measurements remain
unsigned and do not prove production/data recovery, IAM completeness or live
operational readiness. Protected previews, trusted provenance, recovery SLOs and
operational monitoring remain later activation work. No resource operations are enabled.

## Assessment

The repository has a useful deterministic development baseline: one locked gate,
strict typing, negative governance tests, SDK serialization mocks, disabled deployment
entry points and isolated backend tests. Its main weakness is the difference between
domain behavior that tests exercise and architectural boundaries that prose merely
requests. It is not yet an operationally verified deployment harness.

The review applies [Birgitta Boeckeler's guides/sensors and computational/inferential
distinction](https://martinfowler.com/articles/harness-engineering.html) and
[OpenAI's repository-map, dependency-boundary and verification approach](https://openai.com/index/harness-engineering/).
It also applies [Hashimoto's harness practice](https://mitchellh.com/writing/my-ai-adoption-journey#step-5-engineer-the-harness):
recurring failures should lead to clearer guides and programmed verification.
Guides steer an agent; independently enforced sensors check the result. A policy
definition, document, or named environment does not alone prove enforcement.

## Harness drift report

Classification: **Deterministic** means executable checks exist and run through the
shared gate or an explicit integration path; **Agent-enforced** means compliance
depends on following instructions/review; **Unverified** means the relevant external
condition or runtime behavior has not been established. Mixed rows separate these.

| Stated intent | Actual mechanism / evidence | Classification and gap |
| --- | --- | --- |
| Give agents a lean map | Short root AGENTS.md, HARNESS.md map, scoped package/config/workflow/domain guides | Agent-enforced navigation. No link, command, owner or documentation-freshness sensor |
| One reproducible environment | Root uv.lock, required uv version, workspace member contracts, locked CI commands | Deterministic resolution and membership checks; downloaded tool authenticity is a separate concern |
| Enforce style and types | Ruff check/format and strict mypy in infra verify | Deterministic for first-party Python; generated SDKs are excluded intentionally |
| Keep infra-core independent of Pulumi/infra-program | packages/AGENTS.md and dependency-declaration assertion in test_config.py | Partly deterministic manifest check; source imports, transitive layer edges and dynamic imports have no general architecture sensor |
| Keep governance pure and SDK access in adapters | Directory guides, optional inventory package, explicit list dispatch and adapter tests | Deterministic for tested adapters; no comprehensive ban on network/process/SDK access from pure modules |
| Audit before registration | Factories audit first; OCI/service mocks forbid registration on failed preflight and compare serialized inputs | Deterministic selected factory paths; no active production stack executor exists |
| Network depends forward on OCI outputs | Typed network outputs, graph ordering/reference tests, exact SDK graph comparisons | Deterministic graph/interface fixtures; no live separate-stack wiring yet |
| Secrets stay encrypted and out of diagnostics | Secret Outputs; qualification requires passphrase, tests encrypted sentinel/config/checkpoint and safe errors | Deterministic selected paths. No general content/history secret scanner or production rotation/recovery proof |
| Private state/config never tracked | git ls-files artifact-name checks before other verification; .gitignore | Deterministic targeted names, not content detection or a comprehensive secret guarantee |
| PR code receives no cloud credentials | verify.yml has contents:read, no secrets/environment, persistent checkout credentials disabled; workflow regression tests | Deterministic YAML assertions. This is not a sandbox for arbitrary trusted local code or a proof about all external runners |
| Resource operations remain disabled | Normal program raises; CLI denies preview/deploy; configuration rejects enabled units; negative tests | Deterministic for provided entry points, not an OS-level restriction on an agent's shell |
| Protected qualification only | Manual trigger, main/owner guards, dependency on verification, serialized job and isolated UUID namespace | Deterministic source controls/tests; actual reviewers, branch rules, IAM scope and backend privacy are Unverified |
| Enforce complete account cost budgets | Closed resource classifiers, full inventory/usage requirements, peak/monthly tests and mandatory policy definitions | Deterministic offline model; entitlement/completeness booleans and manual evidence can be fabricated. No active deployment path attaches the policy |
| Bound Kubernetes cost and privilege | Closed resource subset, quota/rollout checks and negative manifest tests | Deterministic offline checks. CNI/admission enforcement, scheduling and application behavior are Unverified |
| Agent must Plan -> Execute -> Verify and correct failures | AGENTS.md workflow; shared hook/CI; check=True, visible diagnostics, subprocess/CI timeouts | Gate execution/failure is deterministic; truthful agent interpretation, issue discipline and completion claims remain Agent-enforced |
| Reliable recovery | Opt-in local tests exercise lock contention and synthetic checkpoint restore | Deterministic synthetic checks; independent production/resource/data recovery is Unverified |
| Catch performance and operational drift | Five-minute subprocess timeout and 15-minute CI job limit | Only execution ceilings are deterministic. No throughput/latency/memory budget, runtime metrics, billing monitor or scheduled drift check |

The hardening level is **deterministic development checks with bounded synthetic
integration**, before verified operational controls. No branch-protection or live
backend guarantee should be inferred from a green local suite.

## Vulnerability breakdown

1. **High before activation: architecture depends on prompts.** An accidental import
   from a pure governance module into an SDK or Pulumi package can remain type-correct
   and pass existing tests. Checking dependency declarations is not checking imports.
   Python constructor permits prevent accidental misuse, not deliberate bypass.

2. **High before activation: external evidence is a trust boundary.** Digests and
   timestamps bind content; unsigned receipts and complete/verified flags cannot
   establish trustworthy origin. Backend receipts bind configuration/tool version,
   not the exact source commit. Live account, ownership, usage coverage and policy
   attachment are still operational prerequisites, not properties proved by mocks.

3. **Medium: the CI trust chain is incomplete.** Mutable Action tags and unverified
   repository/environment protections leave code-controlled checks dependent on
   external settings. Credential-free PR jobs reduce exposure but do not constrain
   arbitrary agent shell capabilities or validate effective cloud permissions.

4. **Medium: documentation can drift without a failing sensor.** Retirement exposed
   obsolete tool requirements, commands and claims in the root README/HARNESS.
   These have been refreshed, but no automated command/link/ownership check prevents
   recurrence. Scoped instructions still rely on the agent loading the right files.

5. **Medium: behavioral and operational evidence is narrow.** Real SDK serialization
   and negative tests are stronger than implementation-mirroring assertions, but they
   do not establish provider availability, free-tier eligibility, live policy behavior,
   recovery objectives or scaling performance. Test counts alone are not coverage.

## Three actionable upgrades

1. **Make package and guide boundaries executable.** Add a Python AST/import fitness
   check with mutation fixtures: reject infra-core -> infra-program/Pulumi imports,
   reject SDK/network access from pure governance/OCI/Kubernetes modules, and allow
   reviewed inventory adapters explicitly. Add local documentation-link and CLI
   command-reference validation without executing operator examples. Run these from
   infra verify on both CI platforms; a deliberate forbidden import and a removed
   documented command must both fail. Implemented in issue #29 within the static scope documented above; no runtime sandbox is claimed.

2. **Harden the trusted execution chain.** Implement M03's reviewed Action SHA pins,
   verified tool installs and redacted tracked-content/history secret scanning.
   Preserve credential-free PR verification and test workflow permissions/triggers.
   Independently verify required checks, protected environments and least-privilege
   credentials. Require the current Harness matrix and review any required checks
   referencing retired workflows; report unavailable protections as blockers instead
   of treating an environment name as evidence. Make deliberate unsafe workflow/secret fixtures fail.

3. **Add measured evidence before enabling operations.** Implement M03's independent
   recovery rehearsal, backend posture audit and distinct collection/coverage times.
   In M04/M05, require trusted account-wide preflight plus mandatory policy on every
   protected preview, and add drift/cost/availability monitoring with operator reactions.
   Establish an agreed synthetic large-inventory benchmark and measured runtime
   budgets; retain process timeouts as safety ceilings, not performance claims.
   A newly fetched but stale usage report must remain insufficient evidence.

## Retirement and milestone impact

Removed: tracked Terraform/Terragrunt source and provider lock, pipeline/setup action,
HCL parser and policy, historical execution-report helper, obsolete tests and CLI
check/report/scope branches. CI now runs one complete Python/artifact gate on both
platforms. README is a current-project overview; operational detail lives in runbooks.

Retained deliberately: external ownership/address evidence in cutover preparation,
the unchanged Pulumi backend identity and namespace restriction, defensive exclusions
for private state/credentials, and Supabase's generated provider-bridge metadata.
Removing source does not destroy resources or extinguish external ownership.
Ignored local state/caches are not recursively deleted.

Previously planned M03-PR3/PR4/PR5 target the removed legacy source and are now
superseded; do not recreate that implementation to perform those tasks. Their live
network/capacity/image concerns remain explicit operational checks before adoption.
M03-PR1 must drop removed workflow/tool paths. M03-PR12 should consume this current
Pulumi-only map. The new architecture/documentation fitness work above needs a
reviewed M03 plan adjustment; it has not been implemented in this prerequisite.

## Verification boundary

The PR records the exact verification commands and results. Normal verification
checks code and tracked artifacts without provider plugins or cloud/state access.
The three backend_integration tests require explicit opt-in and the pinned Pulumi
CLI; a default skipped test is not a passed integration test. No credentialed
qualification, cloud preview, state transfer or deployment was run for this review.

Historical local audit results: `uv run --locked infra verify` passed lint,
format, strict typing and 313 tests; three explicit backend integration tests were
skipped. `uv build --all-packages` built all three source distributions and wheels.
`git diff --check` passed. Linux execution and live provider behavior were not
verified locally.

## M03-PR1 completion follow-up

Issue #35 supplies the missing verified actionlint syntax/expression sensor from
original M03-PR1. It runs through infra verify and the focused security workflows
CLI, alongside #31's Action/credential boundary tests. See the
[toolchain runbook](runbooks/trusted-toolchain.md#workflow-syntax-sensor) for exact
coverage and the [M03 status map](../HARNESS.md#m03-implementation-status) for
remaining work. Workflow shell behavior and administrative protections remain
outside this syntax sensor's evidence.

## M03 closeout follow-up: 27 October 2026

The [M03 engineering closeout](m03-closeout.md) reconciles the retained twelve-task
map and accepted issue criteria through merged PR #78. It records implemented
controls, superseded legacy tasks and completed intended evidence migrations.
This final documentation-only PR requires its own CI and merge before the owner
closes the milestone. The original dated findings and verification results above
remain historical observations, not a fresh live-administration assessment.

Engineering completion leaves deployment and cutover disabled. Actual GitHub
protections/bypass, reviewer independence and key custody, cloud/backend IAM and
account/ownership evidence remain administrator-owned activation prerequisites.
Separate-stack execution, trusted live collection, operational monitoring and
production recovery belong to separately approved M04/M05 planning. No additional
M03 runtime feature PRs are planned by this closeout.
