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
| Supabase egress | Target organization/current month | Consumed plus remaining-month budget at most 5000 MB uncached and 5000 MB cached |
| Supabase file storage | Target organization | Current plus growth at most 1000 MB |
| Supabase monthly active users | Target organization/current month | Consumed plus budget at most 50,000 |

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
current evidence. The checked-in evidence intentionally fails validation.

```sh
uv run --locked infra services audit --config .infra/cloudflare.json --evidence .infra/cloudflare-evidence.json
uv run --locked infra services audit --config .infra/supabase.json --evidence .infra/supabase-evidence.json
```

Output is the exact validated additive proposal, projected counts/usage and
`deployment_authorized: false`. Inputs are JSON; neither command imports a cloud
SDK, discovers credentials, queries a provider nor writes state. No token/password
field is accepted in a proposal. Do not store sensitive record content in it;
proposal output is intended for review and contains record names/addresses.

Evidence must bind schema 1, provider, account/user identity, zone/organization and
profile revision. `verified`, `complete`, `other_services_reviewed` must be true,
and `plan` must be `free`. Record a private review reference in `source`.
Entitlement evidence expires in 30 days, inventory/usage in 15 minutes, published
terms in 90 days. Future timestamps fail. `usage_month` must be current UTC month;
confirm the provider's actual billing period and reconcile it conservatively.

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
- `usage` includes every target organization's project in each metric from the
  table. `growth` is a conservative budget for all remaining-month traffic/storage
  growth, including unmanaged services. Never replace missing readings with zero.
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

`register_services(config, evidence, profile, token, passwords)` remains the
resource composition function with its existing call signature. It deep-copies
inputs, completes preflight and checks secret input structure **before** registering any provider or component. Pass explicit
Pulumi `Output[str]` values, or use the configuration-backed wrapper below. One
password Output is required per project, keyed by proposal `key`; Cloudflare accepts
none. The adapter marks tokens/passwords secret regardless of
the caller's existing secret flag. It never exports passwords or service-role keys.

`register_services_from_config(config, evidence, profile)` freezes and audits the
three input documents before creating `pulumi.Config(unit)` and reading secrets.
It reads all required keys synchronously with `require_secret()` before delegating
to the existing composition path, which rechecks frozen evidence immediately
before registration. A missing token or any project password registers nothing.
This is a library factory; it does not activate the normal program or select/init a
stack, verify credentials-to-account ownership, or enable preview/deploy.

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
