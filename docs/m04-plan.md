# M04 - Independent stacks and protected previews

Engineering completion requires synthetic integration and the existing CI gates.
Live acceptance is tracked separately against administrator prerequisites. A
passing test or preview description grants no operational authority. Deployment
and cutover remain disabled throughout M04.

## Fixed implementation sequence

| Task | Scope | Depends on |
| --- | --- | --- |
| M04-PR1 | Explicit stack identities and preview contracts | None |
| M04-PR2 | Behavior-preserving OCI registration extraction | None |
| M04-PR3 | Bounded provider observation transport | PR1 |
| M04-PR4 | OCI usage collection and honest coverage | PR3 |
| M04-PR5 | Cloudflare zone/DNS evidence collection | PR3 |
| M04-PR6 | Supabase management evidence collection | PR3 |
| M04-PR7 | Verified native provider executables | None |
| M04-PR8 | Verified Supabase bridge provider cache | PR7 |
| M04-PR9 | Preview-only program admission/service dispatch | PR1 |
| M04-PR10 | Independent network stack | PR2, PR9 |
| M04-PR11 | OKE reference and dependency validation | PR10 |
| M04-PR12 | Preview result and policy evidence contract | PR1 |
| M04-PR13a | Verified runtime and bounded SDK command/event transport | PR8, PR11, PR12 |
| M04-PR13b | Constrained executor admission and owned bootstrap | PR13a |
| M04-PR14 | Enforced CLI preview orchestration | PR4, PR5, PR6, PR13b |
| M04-PR15 | Protected service preview workflows | PR14 |
| M04-PR16 | Protected OCI preview workflow | PR15 |
| M04-PR17 | Synthetic integration and engineering closeout | PR16, PR13a |

All tasks are in scope; there are no cross-milestone stubs. Tests accompany each
implementation. Apply/import, foreign-state adoption, monitoring and production
recovery belong to M05. Reassess PR boundaries explicitly if a slice exceeds the
agreed review size; do not silently extend milestone closeout.

PR13 is explicitly split into **two** finite slices with owner approval: PR13a's
runtime foundation is consumed by PR13b's executor and PR17's SDK integration
harness. PR13 remains incomplete until both slices are merged; this adds one PR
to the fixed sequence and does not expand milestone scope.

## Implementation record

- M04-PR1: issue #81 / PR #82, merged with all checks passing.
- M04-PR2: issue #83 extracts private network/OKE graph builders, provider
  registration and network-output construction/validation. The existing
  `register_foundation` entry point still validates and audits the entire frozen
  proposal before any provider or component registration. Resource graph, names,
  ordering, parent/provider/protection options and version-1 outputs are preserved.
  Independent stack factories remain in PR10/PR11; this refactor enables no
  preview or deployment path and performs no state migration.
- M04-PR3: issue #85 adds a standard-library fixed-host HTTPS GET transport for
  Cloudflare/Supabase and shared exact-byte observation bindings usable by OCI.
  Verified TLS, no redirects/proxies, 1 MiB response limit, ten-second socket waits
  and at most three attempts for reviewed transient statuses are enforced. Collection
  clocks start before the first attempt; response digests imply neither authenticity
  nor completeness/billing coverage. Provider collectors and protected execution
  remain later tasks. No new dependency, evidence-schema migration or activation.
- M04-PR4: issue #87 adds bounded, unfiltered tenancy-wide OCI Usage API queries
  and Decimal classification. Query completion never supplies a billing watermark;
  missing metrics remain unknown and collected results stay investigative. Manual
  `--usage` input, audit freshness and deployment/cutover restrictions are unchanged.
- M04-PR5: issue #89 collects scoped Cloudflare zone/DNS observations with bounded,
  unfiltered pagination and existing service evidence/envelopes. Free entitlement
  and other-service approval remain independently reviewed; no activation path added.
- M04-PR6: issue #91 collects Supabase user/organization/plan/entitlement and Free
  project identities. Explicit operator supplements supply all usage windows and
  per-project DB samples, reconciled against complete membership without restamping.
  Missing visibility/data blocks evidence; no deployment or cutover activation.
- M04-PR7: issue #93 pins native provider archives and verifies executable members
  in an explicit private home. Binary hashes derive from reverified pinned archives;
  CI checks both platforms' real assets. Downstream Supabase cache remains PR8;
  no provider execution or resource-operation activation is added.
- M04-PR8: issue #95 pins the Supabase downstream ZIP and verifies its exact bridge
  cache layout and SDK parameterization. A CI-only offline schema probe checks the
  cache-hit path; registry fallback is guarded by preflight, not claimed disabled
  in upstream code. No SDK rewrite or preview/deployment/cutover activation.
- M04-PR9: issue #97 adds explicit in-process service preview admission and dispatch
  through existing configuration-backed factories. SDK dry-run and runtime
  organization/project/stack must match the enabled, configuration/commit-bound
  contract before service evidence validation, secret lookup or registration.
  Standalone execution, CLI operations and OCI dispatch remain blocked.
- M04-PR10: issue #99 adds the governed network-only graph/factory and explicit
  in-process `oci-network` preview dispatch. Account-wide inventory/usage auditing
  still precedes the provider and all registrations; the existing combined factory
  is unchanged. Stack exports are `network` (existing schema 1) and
  `network_stack_identity` (full source identity). OKE dispatch remains PR11.
- M04-PR11: issue #101 adds the fixed read-only network StackReference, closed
  committed-output validation and OKE-only dispatch/exports. Initial preflight
  precedes the read; the exact resolved OKE proposal is audited again before any
  managed registration. Unknown/secret/missing/mismatched dependency values fail.
  Policy permits only that exact full reference; operations remain disabled.
- M04-PR12: issue #103 adds canonical schema-1 preview result bytes and strict
  result validation. Bounded CLI wire records must show positive policy checks,
  one successful preview summary and terminal completion with zero exit status.
  Exact input/contract digests, counts and clocks are retained; private event
  content is discarded. No executor, CLI activation or operational authority added.
- M04-PR13a: issue #105 adds archive-verified CLI companions, fresh reverified
  provider homes, exact select/preview command gates and bounded private raw gRPC
  event capture. No executor or bootstrap is exposed. PR13b still owns clean-commit,
  backend/contract/input admission, ciphertext configuration, dependency binding,
  source rechecks, workspace cleanup and PR12 receipt production.
- M04-PR13b: issue #107 adds the library-only executor and owned bootstrap for
  all four units, with clean expected-head/contract/version admission, encrypted
  configuration, frozen input binding and actual OKE dependency-digest checks.
  It consumes PR13a and produces PR12 receipts only after completion/source/runtime
  rechecks. PR13's engineering implementation is complete after this slice's CI
  and merge; CLI/workflow activation remains PR14-PR16.
- M04-PR14: issue #109 adds explicit CLI composition, same-invocation backend and
  provider collection, frozen-input rechecks and private sanitized receipt output.
  Tracked preview flags and deployment/cutover remain false; protected workflow
  wiring remains PR15/16 and live acceptance remains administrator-owned.

## PR14 CLI orchestration

Issue #109 connects the four collectors to the existing executor without adding
workflow activation or changing any tracked preview flag. The infra console
composition moves from infra-core to infra-program; workspace sync installs the
new entry point with no new dependency or lock resolution. **Compatibility:** a
core-only installation no longer provides the console script; its direct CLI API
retains offline behavior and denies previews unless a callback is explicitly injected.

The preview parser accepts `--unit`, `--commit` (independently approved full SHA)
and `--request` (private JSON). For example:

```shell
uv run --locked --extra inventory-oci infra preview --unit cloudflare-edge --commit 0000000000000000000000000000000000000000 --request .infra/preview-request.json
```

The placeholder cannot pass live admission. Schema-1 requests have exactly these
common fields: schema_version (integer 1), configuration, encrypted_configuration,
qualification, cli_archive, provider_home, backend_account_id, backend_oci_config,
output. All but schema_version/backend_account_id are explicit checkout .infra
paths. No symlink/junction ancestors or resolved path escapes are accepted.
Small input files are captured once (1 MiB each); CLI archives/provider caches are
verified by the executor. Output must be a new path and is created exclusively.

| Unit | Additional request fields / file formats |
| --- | --- |
| cloudflare-edge | review: independent schema-1 Cloudflare review JSON; configuration: service JSON |
| supabase-database | supplement: original classified operator supplement JSON; organizations: complete array of organization slugs; configuration: service JSON |
| oci-network | account: account TOML; usage: independent monthly usage JSON with original covered_through; usage_cutoff: explicit elapsed whole-hour timestamp; oci_config: signing config; configuration: OCI TOML |
| oci-oke | All network fields plus dependency_outputs: captured committed network object JSON, checked against actual StackReference by PR13b |

Backend and resource OCI signing files use the explicit DEFAULT profile. Backend
tenancy is independent of resource/service scope. A fresh schema-3 OCI qualification
receipt must match the foundation. Same-invocation read-only backend collection
creates and validates posture bytes/sidecar in memory. AWS_ACCESS_KEY_ID,
AWS_SECRET_ACCESS_KEY, PULUMI_CONFIG_PASSPHRASE (at least twenty characters) and optional
AWS_SESSION_TOKEN are copied explicitly. Service collection additionally requires
CLOUDFLARE_API_TOKEN or SUPABASE_API_TOKEN; the executor receives only the permitted
backend environment and decrypts its provider secrets from encrypted_configuration.
OCI provider identity/key path comes from the resource signing config; inline and
passphrase-protected resource keys are rejected by this adapter. Never place tokens
or plaintext passwords in the request, proposals, receipt or command arguments.

Service collectors retain entitlement and supplemental source clocks. OCI usage
queries cannot supply a watermark: independent evidence remains mandatory, every
metric must be known, and independent totals cannot understate observed totals.
Its original clocks/watermark remain unchanged; usage source text binds the
original supplement and query observation digests. Existing account/evidence
preflight still runs before any provider/resource registration.

Clean expected HEAD, foundation, captured small inputs, profiles, qualification and
posture are rechecked before/after the executor. Failures emit only PREVIEW006;
raw observations/events/configuration remain private and no failed new receipt is
retained. Success writes a bounded schema-1 preview-orchestration wrapper containing
the PR12 preview_result, request/qualification/posture/sidecar hashes and false
deployment/cutover authorization. An existing output is never overwritten or reused.
Digests prove consistency, not source authenticity, review approval or IAM scope.
Source review, protected environments, least privilege and custody remain external
activation gates; PR15/16 add workflow wiring. No live operation is part of CI.
Collection retains the individual collectors' existing limits; PR13's 300-second
execution budget begins after collection. Protected workflow job timeouts must
bound the entire invocation. This cooperative CLI is not a hostile-host sandbox.

Focused gate: `uv run --locked pytest tests/test_preview_orchestration.py tests/test_verification.py tests/test_preview_contracts.py -q`.

## PR13b executor and bootstrap

`infra_program.preview_driver.run_preview` requires the actual checkout and its
locked venv/Python version, clean exact expected HEAD, matching foundation/backend/
project/unit contract and an enabled preview flag. It freezes caller inputs and
runs existing semantic evidence/account preflight before selecting any stack.
Installed Pulumi/provider/policy versions are checked against committed pins/lock
before execution, in the child and after completion. Approval, required checks,
environment/IAM/backend posture and custody remain upstream operational prerequisites;
HEAD cleanliness does not establish review approval or source authenticity.

The API accepts an explicit encrypted stack-configuration **JSON byte object** with
only encryptionsalt and config, with ciphertext values preserved as YAML-compatible JSON in the private
workspace. Only the exact per-unit token/password keys may appear, each wrapped
in a v1 secure ciphertext object; OCI config is empty. Plaintext, extra/missing
keys and duplicate JSON fields fail. Credentials are explicit, unit-scoped process
environment inputs; the passphrase retains the existing twenty-character minimum.
No config decrypt/set/export helpers, stack creation, imports or state moves occur.

Receipt inputs bind canonical frozen configuration/profile/account data and a
proposal capsule containing configuration plus ciphertext settings. Original
evidence/envelope/dependency bytes remain exact; toolchain bytes and a policy/
executor/lock source-digest bundle are also bound. `preview_input_digests` validates
these budgets before execution. The owned JSON bootstrap reconstructs only known
context classes, revalidates actual inputs and dispatches through SDK dry-run guards;
it accepts no arbitrary callable, pickle, sys.path change or inherited Python/proxy
environment. OKE requires a captured dependency object; its canonical digest must
match the actual non-secret committed reference before managed registration.

Preparation and commands share a 300-second budget, with PR13a's bounded process
termination attempts. Private TemporaryDirectory ownership encloses the CLI,
provider home, ciphertext and bootstrap. Before returning a PR12 receipt, the
executor rechecks all owned files, source/head, installed versions, runtime/provider
bytes and input digests. Failures return only PREVIEW005 and no receipt; normal
success/failure paths remove the private workspace. This is cooperative isolation,
not an OS sandbox or protection against a hostile concurrent host/filesystem.

`run_preview` is a library API, not operational authorization. Tracked flags,
standalone program/CLI operations, deployment and cutover remain disabled. Existing
composition APIs remain compatible; the OKE expected-digest argument defaults to
None for old library callers, while this executor always supplies it. No new
dependency or state/configuration migration is introduced. Revert removes the
executor without changing backend ownership. Live acceptance remains separate.

Focused tests: `uv run --locked pytest tests/test_preview_driver.py tests/test_preview_results.py -q`.

## PR13a runtime foundation

`cli_runtime` verifies the pinned original CLI archive before materialization and
again afterward, then returns a guarded `CliRuntime` inventory. CLI and companion
files are rehashed before/after every command; links, extra files and altered bytes
fail. Archives must be local: no installer download, SDK install or PATH lookup.
`materialize_home` revalidates provider archives/binaries and populates a fresh
invocation home, including the fixed Supabase cache when requested.

`Command` accepts only exact fully scoped stack selection and the fixed preview
argument vector, the checked-out local policy pack, an explicit configuration path,
one-way refresh=false and no output callbacks. It enforces a closed environment,
private HOME/temp/Pulumi paths, verified CLI/venv PATH, no proxy/debug/reattach
injection and plugin acquisition restrictions. Unknown commands/options fail.
Command failures are static PREVIEW005 errors; stdout/stderr go to the null device.
The shared command deadline is 300 seconds, followed by bounded process-tree kill
and wait attempts. OS permissions still govern descendant cleanup; this is not an
OS sandbox and does not constrain arbitrary Python callers.

The pinned SDK uses gRPC event transport. The adapter retains original JSON within
PR12 byte/count limits and forwards summaries without the SDK's raw-event warning
path. `Stack.select` preserves this hook instead of constructing the SDK base class.
These bounded raw records remain private; PR13b must invoke PR12 validation before
publishing any receipt, clean its owned workspace and establish operational admission.
This foundation alone grants no preview authority. Tracked preview flags, standalone
program/CLI operations, deployment and cutover remain disabled.
The privileged primitives do not attest caller-created programs, provider homes,
backend identity or clean source; PR13b must combine their verification and admission.

Focused tests: `uv run --locked pytest tests/test_preview_runtime.py tests/test_provider_tools.py tests/test_supabase_provider_cache.py -q -m "not provider_integration"`.

## PR12 result and policy evidence

`infra_core.preview_results.create_preview_result` consumes explicit immutable
artifact bytes and raw CLI event records; `validate_preview_result` checks the
result against independently supplied contract/artifacts and current clock. The
common artifacts are proposal, profile, evidence, envelope, toolchain,
provider_toolchain and policy; OCI also requires account, and OKE requires
dependency_outputs. Callers must capture the complete reviewed inputs/policy source
bundle and verify their actual use. Digests alone do not establish that they ran.

Schema 1 records unit/stack/commit/configuration/preview-contract identity, exact
input hashes, start/end clocks, operation counts, event count/digest and policy
source/version digests plus positive-check count. Deployment/cutover authorization
are always false. It contains no stdout/stderr, messages, properties, URNs, policy
version strings or secret config. Do not supply credentials as input artifacts.

Limits: 10,000 events, 256 KiB per record, 16 MiB aggregate input/event budgets,
64 KiB result, fifteen-minute duration and result freshness. JSON rejects duplicate
keys/nonfinite values; sequences strictly increase and wire timestamps must lie
within the captured run's clock interval. One successful, non-corrupt
`isPreview` summary, the expected policy pack/rule, positive analysis, no violations
and a final cancel-event marker are required. Update/canceled/failed summaries,
error diagnostics, remediation, unknown events and truncated streams fail closed.
Event hashing frames each exact record with its eight-byte big-endian byte length.

The [pinned CLI wire protocol](https://github.com/pulumi/pulumi/blob/v3.272.0/sdk/go/common/apitype/events.go)
includes isPreview/result and policy-analysis events omitted by the Python SDK
adapter. PR13 must preserve raw wire evidence before SDK cleanup; an SDK summary
or zero exit status is insufficient. This unsigned contract checks consistency,
not result authenticity, enforcement-mode attestation or complete policy coverage.
Protected execution/channel and administrator-owned live acceptance remain separate.
No existing schema/state migration or dependency addition; rollback removes these
new APIs without activating or modifying infrastructure.

Focused tests: `uv run --locked pytest tests/test_preview_results.py tests/test_preview_contracts.py -q`.

## PR1 contracts and compatibility

Foundation schema **3** replaces schema 2 without automatic migration. It pins
`project = "free-infrastructure"`, retains the four stack names and existing
backend URL, and requires each unit's `preview_enabled` boolean and `depends_on`
array. All tracked preview flags are false; `enabled` must always be false.
Only `oci-oke` depends on `oci-network`; services and network are independent.
Unknown/missing units, provider substitutions, duplicate identities/dependencies,
unknown dependencies and cycles fail closed.

The DIY identity is `organization/free-infrastructure/STACK`; `organization` is
the DIY backend namespace, not a Pulumi Cloud organization. No stack is selected,
initialized, renamed or moved by loading configuration. Existing legacy backend
namespace layout must be assessed before later live use; no automatic upgrade.

`describe_preview` returns an immutable schema-1 description with an explicit full
Git commit SHA, exact stack/dependency identities and foundation SHA-256. The digest
binds backend, project, encryption, flags and dependency graph. It contains neither
secrets nor live observations. It can describe disabled units and is **not** an
admission token: standalone program and CLI preview/deployment continue to fail even
if a private configuration sets a preview flag true. Later consumers must check
evidence, freshness, verified tools and committed dependency output contents.

**BREAKING configuration/evidence change:** regenerate qualification receipts and
other configuration-bound evidence after updating schema 2 inputs. Do not restamp
old evidence. Reverting this PR restores the earlier configuration contract and
requires matching evidence; it does not reverse a state migration because none
occurs. No new dependency is added; project-scoped identities adapt the existing
[Pulumi stack model](https://www.pulumi.com/docs/iac/concepts/stacks/).

Focused tests: `uv run --locked pytest tests/test_config.py tests/test_preview_contracts.py tests/test_backend.py -q -m "not backend_integration"`.
Full checks/build and opt-in local integration run in the existing credential-free
CI workflow. User preference is to leave heavy checks on CI.

## PR9 admission boundary

**BEHAVIOR-ADJACENT:** `infra_program.__main__.main(context)` accepts a
`ServicePreviewContext` from a reviewed in-process caller. No default, environment
variable or file loader constructs that context. The adapter checks the expected
full commit independently supplied by the caller, recomputes the preview contract
from foundation configuration, requires its preview flag and matches SDK runtime
identity and `is_dry_run()`. It then snapshots service inputs and dispatches only
Cloudflare/Supabase to the existing evidence-first, per-unit `require_secret`
factory. The context carries immutable evidence/envelope bytes; it is neither a
credential container nor proof of checkout/backend/tool authorization.

This is a cooperative program guard, not a sandbox against a Python caller able
to change runtime settings. PR13 must establish clean checkout, verified tools,
backend and bounded execution; PR14-PR16 provide protected orchestration. OCI
dispatch is added incrementally in PR10/PR11. There is no new stack creation, state migration,
apply/import path or workflow activation. Reverting restores unconditional
program denial without changing state or configuration. Tracked preview flags
and deployment/cutover authorization remain false.

Focused tests: `uv run --locked pytest tests/test_preview_program.py tests/test_pulumi.py tests/test_services.py -q`.

## Administrator-owned live acceptance

Protected environments/reviewers/required checks and bypass controls; least-privilege
provider/backend credentials and encryption custody; fresh account eligibility,
complete inventory and usage observations; approved project-scoped stack metadata;
compatible committed network outputs for OKE; explicit authorization for live
preview. Missing billing coverage or outputs blocks acceptance. Supplemental
observations keep their original clocks; query completion does not prove billing
coverage. These prerequisites are separate from engineering completion.
