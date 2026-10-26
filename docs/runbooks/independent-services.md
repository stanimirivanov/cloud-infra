# Independent Cloudflare and Supabase services

This library adds offline service preflight and protected Pulumi components. It
does not activate deployments. `config/pulumi.toml` identities remain disabled;
the normal program, `infra preview --unit NAME` and `infra deploy --unit NAME` still reject provisioning.
There is no Terraform adoption, OCI output dependency, Kubernetes integration,
DNS zone creation, SQL migration or cloud API collector here. Configuration lookup
is explicit through the library factory described below.

## Ownership and map

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
