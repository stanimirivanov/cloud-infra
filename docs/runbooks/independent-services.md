# Independent Cloudflare and Supabase services

This library adds offline service preflight and protected Pulumi components. It
does not activate deployments. `config/pulumi.toml` identities remain disabled;
the normal program, `infra preview --unit NAME` and `infra deploy --unit NAME` still reject provisioning.
There is no Terraform adoption, OCI output dependency, Kubernetes integration,
DNS zone creation or SQL migration here. Read-only management collection is a library
API; there is no collection CLI/workflow activation yet. Configuration lookup
is explicit through the library factory described below.

## Ownership and map

### Supabase management collection (M04-PR6)

`infra_core.inventory.supabase.collect_management(account_id, organizations, token=...)`
requires an independent expected user and complete tuple of visible organization
slugs. It checks profile gotrue_id, exact membership, organization IDs/plans and
Free-organization entitlement metadata; Free projects use unfiltered offset/limit
pagination with stable counts (100/page). Paused projects count; branches fail as
unclassified. Known paid organizations are observed but excluded from the Free
project count. Because the API does not prove Owner/Administrator roles, all visible
Free projects are counted conservatively. Limits: 32 organizations, 128 calls,
10,000 projects, 16 MiB total and 15 minutes from the first observation.

`capture_supabase_evidence` in infra_core.service_evidence requires immutable
supplement JSON bytes: schema_version=1, classification="supplemental-operator-observations",
evidence=the existing complete schema-4 service evidence, and database_observations
(one per observed Free project, with id, scope_id, as_of, source). Database MB stays
in evidence.resources; each source clock must lie in the original supplemental
collection interval. All five metric windows, billing anchor, review flags and
database sizes must pass existing audit before the join. API identities must match
every supplemental project, including projects outside the target organization.
The output uses the earliest original start/latest completion, retaining original
verification and metric clocks and binding exact supplement/API digests in source.
No data-plane calls, SQL, scraping, disk-to-usage conversion or billing synthesis.

See the [public OpenAPI contract](https://api.supabase.com/api/v1-json) and
[organization projects](https://supabase.com/docs/reference/api/v1-get-all-projects-for-organization).
Keep raw profile/project observations and supplements private under .infra. Effective
full membership visibility, role/entitlement review, source authenticity and fresh
authoritative usage remain administrator-owned live prerequisites. Pagination is
not a transactional snapshot; whole-process deadlines remain orchestration work.
No dependency, existing evidence schema, quota, freshness or activation change.

### Cloudflare observation collection (M04-PR5)

`infra_core.inventory.cloudflare.collect_zone(account_id, zone_id, zone_name, token=...)`
requires independent 32-hex account/zone IDs, an expected domain and an explicit
zone-scoped token with Zone Read and DNS Read permissions. It uses PR3 transport
for zone details and unfiltered DNS pagination (100 records/page), checking scope,
active status, stable totals, page sizes and duplicate IDs. All types count,
including TXT, SRV and wildcard/underscore names. Limits: 100 DNS pages, 10,000
records, 16 MiB response bytes and a 15-minute original collection interval.

`infra_core.service_evidence.capture_cloudflare_evidence` joins this collection to
the reviewed proposal/profile and a separate closed schema-1 review: account_id,
scope_id, scope_name, profile_revision, verified, verified_at, plan,
other_services_reviewed and source. It produces the existing schema-4 payload and
sidecar, preserving verification/collection clocks and binding observation digests
in source. No API success or deprecated zone-plan field can supply entitlement;
observed non-Free plan metadata blocks Free evidence. Raw DNS content stays out of
the normalized payload; keep observations/reviews private under ignored .infra.
See [zone details](https://developers.cloudflare.com/api/resources/zones/methods/get/)
and [DNS pagination](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/).
Pagination is not a transactional snapshot or proof of token visibility; confirm
effective scope and concurrent-change controls before live acceptance. Whole-process
deadlines belong to protected orchestration. Quotas and deployment freeze are unchanged.


### Cloudflare collection command (M07-PR6)

After separately authorizing read-only access, use `infra services collect-cloudflare --help`
to join the existing collector and independent review. It adds no provider dependency,
API writes, DNS types, entitlement discovery or deployment authority. Proposal schema 2,
review schema 1, payload schema 4 and the existing unsigned sidecar remain unchanged.

Work from a clean reviewed commit. Put the completed proposal, independent review and
credential under ignored `.infra` without symlinks. The command loads the tracked
`cloudflare-free` profile; no caller-supplied quota override is accepted. Review must
match proposal account/zone and expected domain, current profile revision, Free plan,
other-service review and an original verification timestamp no older than 30 days.
API success cannot set these fields. The closed review JSON contains exactly:

```json
{
  "schema_version": 1,
  "account_id": "REPLACE_WITH_32_HEX_ACCOUNT_ID",
  "scope_id": "REPLACE_WITH_32_HEX_ZONE_ID",
  "scope_name": "example.com",
  "profile_revision": 1,
  "verified": false,
  "verified_at": "REPLACE_WITH_ORIGINAL_VERIFICATION_TIMESTAMP",
  "plan": "free",
  "other_services_reviewed": false,
  "source": "REPLACE_WITH_INDEPENDENT_REVIEW_REFERENCE"
}
```

Complete the independent checks before setting either review flag true. This template
intentionally fails validation. Do not turn a collection timestamp into a new review.
The token needs only Zone Read and DNS Read for the exact reviewed zone. Have your
protected credential mechanism write `.infra/cloudflare-read.token`, owned by the
current user, owner-readable with no group/other permissions (normally 0600 or 0400),
containing just the bearer token and optionally
one final newline. Symlinks, hardlinked credentials, nonregular files and group/other
permissions are rejected. No token value, environment fallback or endpoint override
is accepted through CLI arguments. Keep proposals/reviews owner-private as well.

Create the output directory first, then select a new filename for each attempt:

```shell
umask 077
mkdir -p .infra/cloudflare-evidence
uv run --locked infra services collect-cloudflare \
  --config .infra/cloudflare.json \
  --review .infra/cloudflare-review.json \
  --token-file .infra/cloudflare-read.token \
  --output .infra/cloudflare-evidence/run-001.json
uv run --locked infra services audit \
  --config .infra/cloudflare.json \
  --evidence .infra/cloudflare-evidence/run-001.json
```

All four paths must stay under this checkout's `.infra`; output must be a new `.json`
file in an existing directory, distinct from every input and its derived sidecar.
The command validates review/scope before credential use and network calls, then
rechecks captured inputs and clean commit before publication. Both output files
are mode 0600. The sidecar is published first and payload last using no-overwrite
links on the same filesystem. Existing evidence is preserved, including orphan
sidecars; choose a fresh name rather than deleting prior evidence automatically.
On a caught write/collection failure, no usable new pair is published and only this
invocation's created outputs are removed. A killed process can leave a private
staging directory or sidecar alone; inspect it privately before manual cleanup.
Two-file publication is not a filesystem transaction or a power-loss durability claim.

Exit 0 means collection and evidence checks succeeded. Exit 1 gives redacted
`COLLECT001`; neither raw provider errors nor tokens are printed. Missing/expired
review, scope mismatch, incomplete pagination, changed inputs/checkout or destination
conflicts require correction and a fresh collection. Preserve original review and API
clocks. The collector's existing request/page/byte/freshness limits still apply;
this CLI adds no whole-process deadline. Use an independently bounded protected
runner for live collection. Pagination cannot prove transactional consistency,
complete token visibility, invoice safety or source authenticity. Results remain
unsigned consistency evidence and never enable a preview or deployment gate.

Focused gate:
`uv run --locked pytest -q tests/test_service_collection.py tests/test_cloudflare_collection.py tests/test_service_envelopes.py`.

```text
config/{cloudflare,supabase}.example.json        Additive service inputs
config/service-evidence.example.json            Deliberately invalid evidence
config/quotas/profiles.toml                      Dated service terms/revisions
packages/infra-core/src/infra_core/services/     Pure validation/accounting
packages/infra-program/src/infra_program/services/  Protected SDK adapter
sdks/supabase/                                  Pinned generated provider SDK
tests/test_services.py                          Negative rules and real SDK mocks
```

`cloudflare-edge` owns only new DNS-only A/AAAA/CNAME records in an existing zone.
`supabase-database` owns only new Nano projects in an existing Free organization.
They have independent state identities and explicit providers; neither depends on
an OCI component, cluster, kubeconfig or the other's lifecycle. This is a component
library, not stack orchestration. A future deployment entry point must bind the
selected account, unit, stack, complete real preview and approved backend receipt.

## Reviewed limits (25 October 2026)

| Service | Billing scope | Mechanical boundary |
| --- | --- | --- |
| Cloudflare Free DNS | Existing Free zone | At most 200 existing plus proposed records; DNS-only A/AAAA/CNAME, explicit TTL 60–86400 seconds; names inside the zone |
| Supabase Free projects | All Free organizations owned/administered by the user | At most two existing plus proposed projects; Nano only, existing Free organization, no paid add-ons or legacy API keys |
| Supabase database | Each existing project | Database size at most 500 MB; new projects start empty; this adapter creates no tables/data |
| Supabase egress | Target organization/current billing cycle | Consumed plus remaining-cycle budget at most 5000 MB uncached and 5000 MB cached |
| Supabase file storage capacity | Target organization | Current plus growth at most 1000 MB |
| Supabase storage billing | Target organization/current billing cycle | Consumed plus remaining-cycle budget at most 744 GB-hours |
| Supabase monthly active users | Target organization/current billing cycle | Consumed plus budget at most 50,000 |

Cloudflare documents 200 records for newer Free zones and 1000 for older ones;
this profile conservatively uses 200, counting records added by other services.
See [Cloudflare DNS quotas](https://developers.cloudflare.com/dns/manage-dns-records/).
Supabase's Free project cap spans organizations where the user is Owner or
Administrator; usage allowances generally belong to the organization, while
database size belongs to the project. See
[billing scopes](https://supabase.com/docs/guides/platform/billing-on-supabase),
[pricing](https://supabase.com/pricing) and
[Nano compute](https://supabase.com/docs/guides/platform/compute-and-disk).
We conservatively count paused projects too; no pause/delete credit is available.
The Free service may pause for inactivity and provides no production SLA.

The service profiles enable **offline classification only**. They do not enable
configured units or extend OCI's account audit to other providers. AWS/GCP profiles
remain disabled. New resource types, limits or regions require an explicit review,
profile revision where limits change, policy changes and negative tests.

## Offline preflight

Copy the examples into ignored `.infra`, fill the private identifiers and collect
current evidence and its adjacent sidecar. The checked-in evidence intentionally fails validation.

```sh
uv run --locked infra services audit --config .infra/cloudflare.json --evidence .infra/cloudflare-evidence.json
uv run --locked infra services audit --config .infra/supabase.json --evidence .infra/supabase-evidence.json
```

Output is the exact validated additive proposal, projected counts/usage and
`deployment_authorized: false`. Inputs are JSON; neither command imports a cloud
SDK, discovers credentials, queries a provider nor writes state. No token/password
field is accepted in a proposal. Do not store sensitive record content in it;
proposal output is intended for review and contains record names/addresses.

Evidence must bind schema 4, provider, account/user identity, zone/organization and
profile revision. `verified`, `complete`, `other_services_reviewed` must be true,
and `plan` must be `free`. Record a private review reference in `source`.
Entitlement evidence expires in 30 days, inventory/usage in 15 minutes, published
terms in 90 days. Future observation timestamps fail. Supabase must supply the
current organization billing period below; Cloudflare must set billing_period=null.

### CLI evidence sidecars (M03-PR11 transport slice)

**BREAKING CLI migration:** services audit now requires the original evidence file
and an adjacent file named by appending .envelope.json (for example,
cloudflare-evidence.json.envelope.json).
Missing sidecars fail EXT023; no legacy fallback or automatic restamping exists.
Keep both private files under ignored .infra and preserve exact payload bytes.

A trusted offline producer can call infra_core.service_evidence.capture_service_evidence
with independently reviewed config/profile dictionaries, the original payload bytes,
and commit=the clean reviewed Git HEAD. It returns sidecar bytes only, after checking
the schema-4 payload. Supply the selected provider-free profile from
config/quotas/profiles.toml. Persist the returned bytes beside the unchanged payload.
The helper performs no collection or Git lookup and does not authenticate a producer;
validate the observation sources and reviewed inputs independently. Do not wrap old
observations to claim they were newly collected.

The CLI independently resolves clean HEAD before and after validation. The service-usage
predicate binds role usage to the exact payload SHA256, original collection start/end,
account_id and unit from the reviewed proposal, region=global, and a configuration
digest. Global denotes account/organization-wide coverage, not resource placement.
The digest is SHA256 of UTF-8 JSON of {proposal: config, profile: selected_profile},
with sorted keys, compact separators, ASCII escaping and nonfinite values rejected.
It includes scope_id, every proposed resource, growth budget and all profile fields;
JSON object formatting/key order in the proposal is intentionally immaterial.
Any semantic configuration/profile change or code commit requires freshly reviewed
matching evidence. Evidence is still limited to 15 minutes from collection start;
sidecar and payload clocks must match exactly. Reads are bounded to 10 MiB payload
and 64 KiB sidecar. EVID001-EVID004 and EXT023 omit private source values.

This adapter reuses the Apache-2.0
[in-toto Statement pattern](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
through the existing shared API, without dependencies. It is unsigned consistency,
not source authenticity, billing eligibility or authorization. The pure audit keeps
its schema-4 dictionary interface; both library factories now require the same
payload/sidecar contract (see below). No service deployment entry point is enabled.
Rollback requires matching
code/contracts and weakens CLI transport checks; it never grants deployment authority.

### Organization billing periods (M03-PR11 period slice)

Evidence/report schema 4 retains the billing_period contract introduced in schema 3;
usage_month has no fallback.
For Supabase this is exactly {anchor_at, starts_at, ends_at}, each an offset-aware
ISO timestamp. Record the independently reviewed original organization-creation
anniversary in anchor_at, not the start of the latest clamped cycle. Validate the
actual source period against the organization, including its precise reset time.
The engine normalizes to UTC and preserves the anchor's time and original day:
January 31 becomes February 28/29 then March 31, without shifting the anniversary.
It requires starts_at <= audit time < ends_at and the exact adjacent monthly
anniversaries. At the reset instant only the new cycle is valid. EXT024 rejects a
mismatched cycle or a period on the unmetered DNS subset; closed-field/timestamp
errors retain GOV003/GOV002. No calendar-month fallback exists.

This adapts the organization anniversary and month-end clamping pattern from
[Supabase's billing-cycle guide](https://supabase.com/docs/guides/platform/your-monthly-invoice)
using Python stdlib calendar/datetime and existing contracts. No external code is
copied and no dependency, wrapper or license obligation is added. The guide's paid
invoice explanation does not establish Free eligibility. Independently verify the
Free organization's actual usage reset and UTC boundaries; incompatible resets or
subscription changes require review, not an invented anchor. Distinct MAU totals
must come from the whole cycle, not summed daily counts.

The anchor is an operator attestation inside the hashed payload, not an independently
authenticated fact. Existing envelope bindings detect changed bytes, not a fabricated
anchor. Collect new period-specific readings, review the anchor/source and profile
revision, then create a matching sidecar for the clean reviewed commit. Never convert
old evidence by updating clocks, renaming fields or incrementing schema_version.
Rollback needs compatible code, profile and freshly reviewed evidence together.
Storage history is additionally required below. Deployment remains disabled.

### Collection and usage coverage (M03-PR11 service slice)

Evidence and audit-result schemas are now 4; proposal schema is 2, while component
output contracts remain 1. Evidence requires collection_started_at and
collection_completed_at. Ordered clocks must satisfy original observed_at equals
collection start, start no more than 15 minutes old, and completion no later than
now. Downloading or rewriting a file cannot refresh the original readings.

Each Supabase usage metric is a closed object. Egress, cached egress, storage GB-hours
and MAU use value, covered_from and covered_through. The window starts at billing_period.starts_at,
ends no later than collection completion, and its cutoff
must independently be at most 15 minutes old. A fresh collection with one stale
metric fails EXT022. Partial-cycle/reset/delta totals are rejected. Values must
be known, finite and nonnegative; missing data is never zero.

storage_mb uses value and as_of instead: it is the existing point-in-time capacity
ceiling, with the same 15-minute freshness limit and no monthly reset. The audit
result exposes normalized per-metric clocks in usage_coverage beside forecast.
Growth remains an explicit conservative budget from EACH metric's original cutoff
through billing_period.ends_at, including the gap before collection and unmanaged
usage. The engine does not infer a rate or prove that the operator's budget is sufficient.
Cloudflare usage/growth stay empty objects; its collection clocks still apply.

### Cumulative storage billing (M03-PR11 history slice)

**BREAKING:** proposal schema 2 and evidence/report schema 4 require a fifth Supabase
metric, storage_gb_hours, in both usage and growth. The closed reading has value,
covered_from and covered_through, with the same original cycle start, fresh cutoff,
and collection-completion bound as the other cumulative metrics. Require all projects
in the target organization, including unmanaged consumption. Missing, scalar,
nonfinite, negative, boolean or unknown readings/budgets fail; there is no zero or
capacity-derived fallback. For storage history and its budget, JSON accepts integers
or quoted exact decimal strings (for example "743.875"), not binary float readings;
unquoted fractions fail GOV001 rather than risk losing digits before comparison.
The pure Python boundary also accepts exact Decimal values; bound JSON proposals
must use JSON-compatible integers/strings. Cloudflare usage/growth remain empty objects.

Supabase [storage billing](https://supabase.com/docs/guides/platform/manage-your-usage/storage-size)
uses GB-hours and lists 744 GB-hours for Free. The engine checks cumulative
storage_gb_hours plus its explicit remaining-cycle budget against that allowance.
It uses the published GB-hour bound directly, including short/leap cycles, rather
than multiplying 1 GB by an assumed 744-hour cycle or prorating the quota. The
independent conservative 1000 MB live capacity ceiling stays in place. A fresh
small capacity sample or deletion cannot erase earlier billed usage. No conversion
between that MB sample and historical GB-hours is attempted; obtain source totals
in the explicit GB-hour unit, not an ambiguous dashboard average or daily sum.

Growth is an operator-reviewed upper bound on additional GB-hours from that
metric's original cutoff through billing_period.ends_at, covering reporting lag,
all retained/new objects and unmanaged activity. Zero is acceptable only with a
source-backed no-further-consumption justification; it is never a default. Neither
a live sample nor the engine establishes this future budget's sufficiency. Forecast
arithmetic uses a fixed 28-significant-digit Decimal context and rounds upward, so
tiny excess cannot round down to the quota. EXT021 rejects consumed or projected
overuse; GOV003/GOV001 and EXT022 retain structural/numeric/coverage diagnostics.
A quota breach does not calculate a dollar charge or imply Free overages are paid.

This adapts Supabase's documented cumulative metering using existing Decimal and
coverage contracts. No external code is copied and no new dependency, wrapper or
license obligation is added. The payload remains an unsigned attestation: a matching
hash cannot authenticate the source, completeness, totals or growth assumptions.
[MAU](https://supabase.com/docs/guides/platform/manage-your-usage/monthly-active-users)
continues to require distinct whole-cycle users, not summed daily counts.
Supabase profile revision is now 3 because billing history is mandatory. Existing
limits/review dates and Cloudflare revision 1 are unchanged; the newly reviewed
GB-hour ceiling is 744. Private evidence must bind the new revision and proposal.
Collect new actual history and budgets, then create a matching sidecar against the
clean reviewed commit; schema-1/2/3 evidence and schema-1 proposals have no automatic
conversion. The public history value and budget deliberately remain null/invalid.
Rollback requires compatible code, profiles, proposals and newly reviewed evidence.
No collector, runtime cost monitor or deployment entry point is introduced.

The explicit window versus sample distinction adapts the Apache-2.0
[OpenTelemetry metric data model](https://opentelemetry.io/docs/specs/otel/metrics/data-model/)
using existing stdlib/governance helpers. No telemetry dependency, OTLP interface,
SDK collector or architecture exception is added. Source authenticity, automated
collection and operational quota reactions remain separate prerequisites.

**Migration:** schema-1/2/3 evidence is rejected at the CLI and both
factories before secret lookup or registration. Collect new evidence with actual
source windows/samples; never add current clocks to old scalar values. The public
example remains unverified, stale and unknown. Keep real documents under .infra.
Rollback requires compatible code and evidence; it restores weaker coverage checks
and never establishes eligibility or deployment authority. Schemas cannot be
converted by renaming fields or changing a version number.

For Cloudflare:

- Set `coverage` to `all-zone-dns-records`, `scope_name` to the zone FQDN,
  `usage`/proposal `growth` to `{}`.
- `resources` includes **all** existing zone records, each with `id`, `name`,
  `type`, including unmanaged TXT/MX records and other-service records. Traverse
  every inventory page; an empty list is valid only after an evidenced empty scan.
- Confirm zone/account membership and current Free subscription privately. No
  registrar purchase or paid DNS add-on is modeled. Proposed names cannot already
  exist or repeat; multi-record RRsets need a subsequent design.

For Supabase:

- `account_id` identifies the user whose full Owner/Administrator Free-project
  entitlement was reviewed; `scope_id` identifies the target Free organization.
- Set `coverage` to `all-owned-admin-free-projects-and-target-org-usage`.
  `resources` contains every Free project across those organizations, with `id`,
  `scope_id`, `database_mb`. Include paused/unmanaged projects conservatively.
- `usage` readings include every target organization's project in each metric
  from the table, with the windows/samples defined above. `growth` is a conservative
  budget for all remaining-cycle traffic/storage growth, including unmanaged services. Never replace missing readings with zero.
- Independently review organization subscription, project sizes, absent add-ons,
  branching, replicas, IPv4, custom domains, Auth/Realtime/Functions and other
  unmodeled usage. Record `other_services_reviewed` only after this review.

These are operator attestations, not cryptographically verified live scans.
The engine cannot detect fabricated/incomplete evidence with `complete=true`.
It rejects unsupported shape/fields; it cannot prove that an assertion is true.
Account terms and usage can change after review. Static traffic budgets do not
limit real requests: runtime monitoring, quota reactions, availability review and
fresh protected preview are prerequisites to eventual operation. No zero-billing
guarantee or production readiness is implied by a passing offline audit.

## SDK and secret boundary

**BREAKING library migration:** both service factories now require original
schema-4 evidence bytes, immutable sidecar bytes and a mandatory expected commit.
There is no dictionary fallback, optional binding, or automatic conversion. Only
the pure accounting function infra_core.services.governance.audit keeps its
existing dictionary interface. Use the same producer helper/contract as the CLI
above, preserving exact payload bytes and original clocks.

`register_services(config, evidence, profile, token, passwords, *, envelope, commit)`
is the sole resource composition function. config/profile remain reviewed
configuration dictionaries; evidence/envelope must be bytes. It validates the
complete bound observation and checks secret input structure **before** registering
any provider or component. Pass explicit Pulumi Output[str] values, or use the
configuration-backed wrapper below. One password Output is required per project,
keyed by proposal key; Cloudflare accepts none. The adapter marks tokens/passwords
secret regardless of the caller's existing secret flag and exports identities only.

`register_services_from_config(config, evidence, profile, *, envelope, commit)`
freezes the proposal/profile and validates immutable evidence/envelope bytes before
creating pulumi.Config(unit). It resolves every required key through require_secret()
then delegates the same frozen inputs/bytes/expected commit to composition, which
rechecks freshness and binding immediately before registration. Missing any secret,
failed binding or evidence expiring during lookup registers nothing. Mutating the
caller's proposal/profile during lookup cannot change the frozen resource graph.

For both factories, commit is an independently established clean reviewed checkout
identity supplied by the caller; never copy it from the envelope. The factories
perform no Git lookup and cannot prove that a caller supplied the running code's
actual identity. A future approved program must establish that identity independently
(as the CLI does), review the proposal/profile and bind its stack/backend before
calling. Output injection necessarily happens outside the factory; the Config-backed
path provides the guarantee that lookup follows preflight. Neither path activates
the normal program, selects/initializes a stack, verifies credential ownership, nor
enables preview/deploy. Sidecars remain unsigned, not deployment authority.
Rollback needs compatible code/contracts and weakens pre-registration transport
checks; it never grants authority or upgrades old observations.

| Unit namespace | Required Pulumi config keys |
| --- | --- |
| cloudflare-edge | `token` |
| supabase-database | `token`; `databasePassword-<key>` for every proposed project key |

For example, project key app uses supabase-database:databasePassword-app. No
provider-specific ambient token fallback is added. The Pulumi runtime supplies
Config values (including its supported environment mechanisms); the factory does
not read provider environment variables or accept secrets in proposal JSON.

For a **separately approved future stack**, enter credentials interactively with
`pulumi config set --secret cloudflare-edge:token --stack cloudflare-edge`, or the
corresponding Supabase token/password keys. Omitting the value prompts for input;
do not put secret literals in shell history, command arguments, proposals or logs.
No such stack is initialized by this release. Keep even encrypted stack config
outside tracked source under the repository's existing private-artifact policy.

`require_secret()` marks the Output secret; it does not establish that its input
was encrypted on disk. An operator must use encrypted config entry and verify the
selected stack's passphrase provider. Output injection also preserves its prior
behavior: the adapter explicitly marks injected Outputs secret. Tests exercise
both paths through actual SDK serialization; they do not prove real provider log
redaction, credential validity, state encryption for a deployed service, or IAM.
See [encryption custody and migration](pulumi-backend.md#explicit-encryption-policy-and-custody)
for the schema-v2 policy, recovery and rotation prerequisites.

Providers use fixed HTTPS endpoints; every native child has an explicit provider,
parent and `protect=True`. Protection blocks deletion/replacement until an explicit
reviewed operational change; it does not prevent all in-place modifications. This
PR models new resources only. Existing-state reconciliation, update/replacement,
import, aliases, destructive changes and credentials-to-account verification are
required future operational work, and are not exposed as CLI actions here.

Cloudflare uses `pulumi-cloudflare==6.23.1`. Supabase's official registry entry
requires [a local generated SDK](https://www.pulumi.com/registry/packages/supabase/).
The SDK is committed as a uv workspace member, generated with CLI 3.272.0,
bridge 1.5.0 and Supabase 1.11.0. Its package metadata pins parameterization; see
`sdks/supabase/README.md`. No generation or provider-plugin download runs in PR CI.
Generated Python is excluded from our Ruff/mypy traversal; the actual constructors,
serialized properties, parameterization and secret Outputs are exercised in mocks.
Our adapter/core remain linted and strictly typed. Review generated-code diffs and
upstream licenses whenever refreshing SDKs; never hand-edit generated Python.

Mandatory policy allows only these native resource kinds and fixed provider
endpoints. All other external types and extra properties fail closed. Local policy
checks do not prove billing scope or replace complete pre-registration preflight.

## Verification and next operational gates

```sh
uv sync --locked --all-groups
uv run --locked pytest tests/test_services.py
uv build --all-packages
uv run --locked infra verify
```

Tests use synthetic evidence, real Python SDK constructors and Pulumi mocks with
provider invokes forbidden. They assert exact graph equivalence, explicit provider
and parent, protection and secret propagation. No test logs real tokens or uses a
cloud backend. The existing matrix/shared pre-commit gate includes these tests.

Before activation, separately authorize actual inventory collection and protected
preview; verify account-bound credentials, no existing state collisions, service
eligibility, secret-provider encryption, ownership and rollback, admission/security
for any application data, monitoring and backend/environment controls. Supabase RLS,
schema migrations, backup/restore and application credentials require a subsequent
data-plane design. Workers and other paid/metered products remain forbidden.

## Controlled single-service apply (M05-PR6)

`uv run --locked infra apply --help` describes the explicit adapter. It requires
unit, commit, actor, environment, bundle and journal, and exactly one of --check or
--allow-resource-writes. The composed CLI admits only owner/main workflow_dispatch
with the exact main commit and unit-apply environment. Core-only callers cannot
execute updates. Normal deploy and preview dispatch keep their existing boundaries.

config/service-apply.json ships with both service entries disabled. Activation requires a
separately reviewed tracked change to the selected service entry, the service's existing preview flag and enrolled
operations-policy.json. No flag, key or GitHub setting is enabled by this PR.

The private schema-1 bundle has paths, backend_account_id, cli_archive,
provider_home and output fields. paths must contain operation, approval, operator,
approver, backup_receipt, backup_manifest, environment, plan, encrypted_configuration,
proposal, evidence, envelope, qualification, posture and posture_envelope. Each is
an existing bounded .infra file. The CLI archive and provider_home are explicitly
prepared, checksum-pinned inputs; the output must be new in an existing private
directory. Supply the original encrypted stack configuration bytes and the exact
unchanged CLI checkpoint export used by capture; reformatting changes their hashes.

Execution uses schema-2 operation approvals: the schema-1 fields plus
execution_inputs_sha256. This binds the frozen proposal, service evidence, profile,
qualification, backend posture, encrypted configuration, plan and backend account
scope. Signature roles/type and exact-byte bindings remain unchanged. Schema-1
preflight is still supported by the core API but cannot admit this executor. Callers
must supply a saved plan produced from the same reviewed factories, pinned toolchain
and inputs. No plan-authoring CLI is added; the existing preview command does not
save this artifact. Saved plans constrain known values/operations, not every unknown
provider value. Reapprove any changed plan or input; do not edit signed artifacts.

The durable journal path is fixed to .infra/operations/UNIT.json. Protect and retain
it across runner jobs; never restore an old prepared journal to retry an operation.
Preflight checks signatures, current clean commit, fresh observations and required
policies before the credential callback. It recollects current environment controls,
then uses local serialization and journal compare-and-swap to record admission.
Only then are explicit backend credentials/passphrase loaded into an isolated home
with verified CLI/providers/uv. Service tokens remain encrypted Pulumi config values.

The adapter selects an existing qualified stack, compares its encrypted checkpoint,
runs a fresh mandatory-policy preview, rechecks frozen inputs/current controls/state,
then records running and performs the exact saved-plan update. It accepts only
same/create/update/read operations; deletes/replacements, unknown types, unprotected
children and missing explicit provider/parent bindings are rejected. The owned child
checks runtime identity, signatures, frozen files and admitted/running dry-run mode
before using the existing secret-backed factory. Preview APIs are not widened.

A failure before update launch records failed; a launched update with incomplete,
failed or inconsistent evidence records indeterminate. Never retry or automatically
roll back that operation. Inspect live ownership/checkpoints under a separate
operational instruction. A receipt-write error after known success leaves the
journal succeeded and still requires reconciliation, not replay.

The manual service-apply workflow requires the protected unit-apply environment and
a dedicated service-operations runner group. Administrators must provide durable
journals and frozen encrypted inputs, pinned archives/provider caches, main-only
reviews, independent signing custody, least-privilege backend/provider credentials,
and a read-only OPERATION_OBSERVATION_TOKEN able to inspect environment settings.
SERVICE_APPLY_BUNDLE and SERVICE_APPLY_JOURNAL locate the prepared files. Checkout
clean is disabled to preserve ignored journals; the runner must be dedicated/trusted
and its sources/dependency environment independently controlled. No PR job runs on
that runner. Provider reads/updates and independent writer exclusion still require
live acceptance; tests exercise synthetic transport and a provider-free local engine.

GitHub serializes this workflow per unit; local locking is not distributed fencing.
All external writers/recovery/import workflows must share reviewed exclusion rules.
No raw events, decrypted values or state are uploaded. Normal cleanup deletes only
the owned temporary workspace; force-killed runners require secure cleanup while
preserving the durable journal. No live apply was run as routine verification.

## M06 Cloudflare staged activation preparation

M06-PR7 prepares Cloudflare activation without enabling either service. The previous
single service apply switch covered both Cloudflare and Supabase. Schema 2 now
requires an explicit boolean for each service:

```json
{
  "schema_version": 2,
  "units": {
    "cloudflare-edge": false,
    "supabase-database": false
  }
}
```

**BREAKING configuration migration:** schema-1 service apply files, including
`enabled: true`, are rejected. Migrate the tracked file and deployed checker code
together; do not interpret the legacy global value as both services being approved.
Only the two exact unit names are accepted, and both values must be booleans.
Selecting a disabled or unknown service fails before bundle/credential access.
Parent preflight and the owned program's repeated service admission select the
same unit. OCI apply and resource-import policy schemas remain unchanged.

Enabling `cloudflare-edge` in a later reviewed change will not enable
`supabase-database`. Both still require their own preview gate, signed exact-input
approvals, journal, protected environment and all existing execution checks.
This switch is a necessary gate, not a standalone authorization. This PR adds no
keys, DNS records, account data, live flag values or workflow dispatch.

### Cloudflare activation sequence for a separately authorized operation

1. Independently accept the M06 protected-runner/trust, backend, backup, account
   and writer-exclusion prerequisites for `cloudflare-edge`. Their pending gap
   reports are not acceptance. Confirm the exact existing project-scoped stack,
   Cloudflare account and zone, effective token scope, encrypted configuration,
   retained journals and independent operator/approver/requester identities.
2. Review the intended DNS change and existing unmanaged records using the current
   supported proposal/evidence contracts. Use fresh complete zone evidence and
   the actual Free-plan profile; do not refresh timestamps or change limits to
   pass. The scope of record names, types, contents, TTL and proxy behavior belongs
   in private reviewed configuration, not an invented production example here.
3. In a separately reviewed tracked change, enable only
   `units.cloudflare-edge` in `config/service-apply.json` and the Cloudflare
   preview flag in `config/pulumi.toml`. Keep the Supabase entry and preview flag
   false. Enroll operation trust only after independent identity/custody review;
   no other service or resource gate is implied by this change.
4. At the resulting reviewed main commit, prepare the exact private execution
   bundle, encrypted configuration, original checkpoint, complete backup and
   action-specific signatures. Flag/configuration/commit changes invalidate old
   approvals and evidence bindings: recollect and reapprove rather than patching
   signatures or restamping observations. Use existing admission freshness limits.
5. Produce and independently review the exact saved plan with the existing pinned
   factories/toolchain and mandatory policies. **Harness gap:** the existing
   preview CLI does not save the executor's required plan, and this PR adds no
   plan-authoring CLI. A separately reviewed plan-production procedure/artifact is
   required before proceeding; do not substitute preview JSON or fabricate a plan.
6. Under the protected main workflow context, run the existing admission check:

   ```sh
   uv run --locked infra apply --check --unit cloudflare-edge --commit COMMIT --actor ACTOR --environment cloudflare-edge-apply --bundle .infra/cloudflare-apply.json --journal .infra/operations/cloudflare-edge.json
   ```

   `COMMIT` and `ACTOR` are placeholders for the actual reviewed identities.
   This command is expected to reject the disabled baseline. After separately
   authorized enablement, it still needs enrolled trust, fresh environment controls
   and the exact frozen bundle. It is not a bypass for main/owner dispatch checks.
7. Only after explicit operational authorization, dispatch the existing protected
   service-apply workflow for `cloudflare-edge` and that exact commit. It executes
   shared verification, pre-credential admission, mandatory-policy preview and
   the single saved-plan update using the dedicated runner and durable journal.
   Never select Supabase as part of the Cloudflare stage.
8. Retain the operation receipt, exact plan/approval hashes, journal head and
   private post-state evidence. Independently reconcile the intended DNS records,
   checkpoint and actual externally observed DNS behavior before accepting this
   stage. Successful workflow/journal status alone is not independent service
   health or proof of all unknown provider values. Monitoring activation and the
   later Supabase stage remain separate work.

### Stop conditions and rollback limits

Stop on missing prerequisites, plan-authoring gaps, expired evidence, unexpected
records, deletion/replacement, drift, incomplete provider output or a failed
check. A launched operation with an uncertain result remains `indeterminate`;
retain writer exclusion, journals, backups and original evidence. Do not retry,
reset history, automatically roll back DNS or infer that failure means no effect.
A missing receipt after journal success also requires reconciliation, not replay.

Returning only `units.cloudflare-edge` to false through a reviewed change blocks
new Cloudflare admission; it does not cancel an in-flight operation or undo DNS
records. Reverting this PR requires restoring matching schema-1 code/config with
the global switch disabled; never roll back to an enabled global policy. Any DNS
correction or writer release needs a separate reviewed operational decision.

Focused gates:
`uv run --locked pytest -q tests/test_service_activation.py tests/test_service_apply.py tests/test_oci_apply.py tests/test_import_driver.py`.
The shared gate is `uv run --locked infra verify`. The existing local synthetic
operation gate can additionally exercise service transport/engine behavior without
cloud credentials. No live Cloudflare activation or acceptance was performed by
this engineering PR; production configuration, evidence and authorization remain
pending.

## M06 Supabase staging checks and procedure

M06-PR8 delivers checks and the staged procedure; activation remains pending.
Neither service gate, preview flag, credential enrollment nor production project
is changed. The Supabase stage uses its own schema-2 `supabase-database` apply
entry from M06-PR7; Cloudflare enablement is never Supabase authorization.

### Offline staging inputs

Use a clean committed checkout and independently reviewed account and organization
identities, rather than copying expectations from candidate evidence:

```sh
uv run --locked infra services check-staging --account-id ACCOUNT_ID --scope-id ORGANIZATION_ID --config .infra/supabase.json --evidence .infra/supabase-evidence.json --encrypted-configuration .infra/supabase-stack.json
```

The account/organization values above are placeholders. Configuration is the
existing Supabase proposal schema; evidence and its adjacent `.envelope.json`
sidecar retain the existing usage schema and original clocks. All four private
inputs must be distinct canonical relative `.infra/*.json` files with no symlinks,
each at most 1 MiB. The checker captures tracked foundation, service gates and
quota profiles, then rechecks their bytes, all private inputs and clean Git
identity before returning. It never calls a provider, accesses credentials,
decrypts configuration, writes files or imports the Pulumi runtime.

The existing service audit enforces the exact Supabase provider/unit, reviewed
account and organization, Free eligibility, complete unmanaged project inventory,
profile revision/date, billing-cycle anchor, metric coverage and projected growth.
Storage capacity and cumulative GB-hours remain separate guards. Missing or late
usage is never zero-filled or restamped. This checker introduces no new quotas,
profile dates or provider-terms assumptions.

The encrypted JSON configuration uses exactly `encryptionsalt` and `config`.
The salt and every secure value must have a nonempty `v1:` suffix. `config` must
contain exactly `supabase-database:token` and
`supabase-database:databasePassword-<key>` for every proposed project key. Every
value is a single-field `{"secure": "v1:..."}` object. Missing/extra entries,
plaintext, duplicate fields and wrong namespaces fail. This is the same shared
ciphertext-shape validator used by preview/apply, including Cloudflare and OCI
callers; existing executor diagnostics remain unchanged. No ciphertext is decrypted
or echoed. Matching shape cannot establish valid encryption, token scope, password
strength, different passwords, actual key custody or successful readback.

A successful input check reports `staging_evidence: inputs-consistent` and
`status: pending`, with `activation_authorized`, `execution_authorized` and
`live_controls_verified` false. The CLI exits 1 because operational acceptance is
still pending. `preview_enabled` and `apply_enabled` only describe the currently
tracked Supabase flags; even true values confer no authority. Invalid input fails
with redacted `STAGE001`. Reports include input digests, not account/organization
identities, proposal content, tokens, passwords or ciphertext. This report cannot
replace the original private evidence or signed operation admission.

### Separately authorized Supabase activation sequence

1. Independently accept protected execution/custody, backend readiness, independent
   backup, account readiness and writer exclusion for `supabase-database`. Confirm
   the existing project-scoped stack, actual organization/user visibility and
   organization-wide usage; a successful pending gap report is not acceptance.
2. Review intended project keys, organization, names, region and supported project
   properties using the existing proposal contract. Account-wide Free project
   capacity and the target organization's actual billing cycle must be covered.
   The existing factory uses the reviewed API endpoint and disables legacy API
   keys according to its contract; do not widen it for staging convenience.
3. Prepare the exact encrypted token/password configuration under independent
   custody. Run the offline command above while activation remains disabled.
   Independently verify actual token permissions, ownership, decryptability and
   password handling; never put secret literals in chat, PRs or shell arguments.
4. Separately review the Supabase-only apply entry and preview-flag enablement at
   a new main commit. Leave unrelated service/unit settings as independently
   reviewed; do not inherit Cloudflare approvals. Recollect/reapprove all evidence
   whose commit, configuration or policy binding changed.
5. Prepare the pinned parameterized Supabase provider/runtime with the existing
   verified toolchain process, exact saved plan and action-specific signed
   execution bundle. **Existing harness gap:** preview does not produce the
   executor's saved plan; this PR adds no plan-authoring CLI. Do not proceed
   without a separately reviewed plan-production procedure/artifact. Provider
   acquisition and schema identity checks remain the executor's existing gates.
6. Under the protected main workflow context, perform existing pre-credential
   admission for the exact reviewed commit and bundle:

   ```sh
   uv run --locked infra apply --check --unit supabase-database --commit COMMIT --actor ACTOR --environment supabase-database-apply --bundle .infra/supabase-apply.json --journal .infra/operations/supabase-database.json
   ```

   The disabled baseline intentionally rejects this command. After separately
   authorized enablement, all signatures, freshness, backend, plan, environment
   and journal checks still apply. Only an explicit operational authorization
   permits dispatching the existing protected service-apply workflow for Supabase.
7. Retain its receipt, exact plan/approval bindings, durable journal and private
   post-state evidence. Independently reconcile project identities, organization,
   configuration and actual observed state. Project creation does not establish
   application schema, migrations, database contents, RLS enforcement, backups of
   database data or end-user availability. Those claims require separate scope
   and evidence; Pulumi checkpoint recovery is not database-content recovery.

Stop on quota/coverage uncertainty, plan gaps, unexpected identities/properties,
deletes/replacements or indeterminate results. Retain the freeze and journals;
never retry, reset history or compensate automatically. Disabling the Supabase
entry blocks new admission but does not cancel an in-flight update, delete a
project, restore database data or release writers. Any corrective action requires
a separate reviewed operational decision. No live activation was performed here.

Focused gate:
`uv run --locked pytest -q tests/test_supabase_staging.py tests/test_preview_driver.py tests/test_service_apply.py`.
The full gate is `uv run --locked infra verify`; existing isolated service runtime
tests cover the shared execution validator. No dependency, proposal/evidence
schema migration or activation change is introduced.

## Service preview graph correspondence (M07-PR4)

Preview receipt schema 3 retains `service_graph`: a SHA-256 and resource count for
Cloudflare/Supabase, or null for OCI. OCI uses `oci_graph` as described in
[OCI preview correspondence](oci-components.md#oci-preview-graph-correspondence-m07-pr5).
Service receipts require complete engine pre/output observations for the exact
stack, existing Independent component, explicit provider and each proposed child.
URNs, parent/provider relationships, protection, custom/component kind and all
reviewed nonsecret inputs must match. Unknown or extra resources, duplicate pre
observations, missing observations, replacements and substitutions fail with the
redacted `PREVIEW009` diagnostic. The driver emits no receipt after a mismatch.

The matcher adapts the pinned Pulumi 3.272.0
[engine event format](https://github.com/pulumi/pulumi/blob/v3.272.0/pkg/engine/events.go)
and [wire serializer](https://github.com/pulumi/pulumi/blob/v3.272.0/pkg/backend/display/events.go)
(Apache-2.0); no dependency or copied implementation is added. Provider version,
empty download override and reviewed `__defaults` metadata have explicit handling.
Secret inputs must carry the engine's blinded secret/ciphertext marker. Secret
values and resource outputs are excluded from comparison and never exported.
Provider references must identify the exact reviewed provider URN; known IDs
must agree with observed provider state. IDs may be unknown during preview. Unknown governed input values fail.

The receipt contains only the matched graph's digest/count, preserving the existing
input/event hashes and false authorization fields. It is unsigned consistency
evidence, not proof of source authenticity, account entitlement or live readiness.
Aggregate service preflight and mandatory policy checks remain required. This
slice does not strengthen saved-plan apply admission.

Compatibility: schema-1 and schema-2 receipts are rejected for all units. Regenerate receipts
and downstream approvals with fresh evidence and the reviewed code; never restamp
old receipts. Matcher and receipt source files are included in policy source
bindings. Rollback requires matching contracts and regenerated evidence; no state,
resource identity, provider binding, secret key or activation flag is migrated.
