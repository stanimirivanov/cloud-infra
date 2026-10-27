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
| M04-PR13 | Constrained Automation API driver | PR8, PR11, PR12 |
| M04-PR14 | Enforced CLI preview orchestration | PR4, PR5, PR6, PR13 |
| M04-PR15 | Protected service preview workflows | PR14 |
| M04-PR16 | Protected OCI preview workflow | PR15 |
| M04-PR17 | Synthetic integration and engineering closeout | PR16 |

All tasks are in scope; there are no cross-milestone stubs. Tests accompany each
implementation. Apply/import, foreign-state adoption, monitoring and production
recovery belong to M05. Reassess PR boundaries explicitly if a slice exceeds the
agreed review size; do not silently extend milestone closeout.

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
admission token: current CLI/program preview and deployment continue to fail even
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

## Administrator-owned live acceptance

Protected environments/reviewers/required checks and bypass controls; least-privilege
provider/backend credentials and encryption custody; fresh account eligibility,
complete inventory and usage observations; approved project-scoped stack metadata;
compatible committed network outputs for OKE; explicit authorization for live
preview. Missing billing coverage or outputs blocks acceptance. Supplemental
observations keep their original clocks; query completion does not prove billing
coverage. These prerequisites are separate from engineering completion.
