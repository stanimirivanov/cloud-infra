# Account-wide free-tier governance

The governance engine evaluates an entire OCI billing tenancy across the supported
resource families, rather than granting each stack its own free allowance. It is
a preflight foundation, not permission to deploy or a zero-billing certificate.
All resource deployment units and the normal Pulumi entry point remain disabled.
These checks do not modify deployed resources or external state ownership.

## Boundaries and files

```text
config/account.example.toml                 Unverified operator account template
config/quotas/profiles.toml                  Versioned, dated entitlement profiles
packages/infra-core/src/infra_core/
  governance/contracts.py                  Strict document/numeric/time validation
  governance/resources.py                  Closed resource cost classification
  governance/audit.py                      Aggregate final/peak/monthly evaluator
  inventory/oci.py                         Read/list-only paginated SDK adapter
packages/infra-program/src/infra_program/governance.py
                                           Pre-registration gate and policy adapter
policies/PulumiPolicy.yaml                  Mandatory Python Pulumi policy pack
tests/test_governance*.py                   Accounting and actual policy enforcement
tests/test_inventory.py                     Credential-free SDK/coverage tests
.infra/                                    Ignored private account/inventory/proposal files
```

infra-core does not import Pulumi or infra-program. Both the CLI and the
pre-registration gate call the same pure evaluator; the mandatory Pulumi policy
uses the same resource classifier. The policy is a second layer: resource-local
checks cannot establish aggregate account capacity or monthly consumption.

## Entitlement matrix

| Profile | Eligibility | A1 capacity ceiling | Monthly A1 allowances | Boot + block storage |
| --- | --- | --- | --- | --- |
| oci-free | Verified Free Tier tenancy, home region | 2 OCPUs / 12 GB | 1,500 OCPU-hours / 9,000 GB-hours | 200 GB aggregate |
| oci-paid-a1 | Separately verified paid-tenancy A1 allowance | 4 OCPUs / 24 GB | 3,000 OCPU-hours / 18,000 GB-hours | 200 GB aggregate |
| cloudflare-free | Separate offline service preflight; deployment disabled | 200 DNS records/zone | None | See independent services runbook |
| supabase-free | Separate offline service preflight; deployment disabled | 2 Free projects across owned/admin orgs | Org usage + growth | See independent services runbook |
| aws-free / gcp-free | Disabled pending account-specific eligibility and metering | None | None | None |

Sources reviewed on 2026-10-25: [Oracle Always Free resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
and the [OCI price list](https://www.oracle.com/cloud/price-list/). Published terms
are not account eligibility. Source reviews expire after 90 days; operator
entitlement and other-service review expire after 30 days. Re-review sources and
account evidence before changing dates. Do not raise limits just to pass a check.
The storage monthly model conservatively bounds GB-months to 200 as well as
instantaneous capacity; it does not model a cloud invoice or billing rounding.

Repository source retirement does not establish the sizing of deployed resources.
Reconcile live account inventory against the selected entitlement profile before
any adoption or capacity change.

## Collecting evidence

Default verification needs no OCI SDK or credentials. Install the optional
collector only when an authorized operator needs to read the tenancy:

```sh
uv sync --locked --extra inventory-oci
```

Copy config/account.example.toml to .infra/account.toml. Supply the tenancy OCID,
actual home region, reviewed account profile and real verification timestamp.
Bind profile_revision to the published profile's revision; changes to eligibility
or limits require a revision bump and renewed account verification.
The template deliberately fails: verified and other_services_reviewed are false.
Record external reservations under reservations using ocpus, memory_gb and
block_gb; these add capacity, never subtract it. Include separately reserved A1
capacity that is not represented by live instances. A human must reconcile
reservations and all services outside the collector before marking the review.

Use an existing OCI API-key configuration with tenancy-wide read/inspect rights
for the listed APIs. The collector accepts an explicit credential file and profile;
it never writes credentials, provisions resources or mutates state:

```sh
uv run --locked --extra inventory-oci infra governance inventory \
  --account .infra/account.toml --oci-config /private/path/oci-config \
  --oci-profile DEFAULT --usage .infra/usage.json --output .infra/inventory.json
```

Keep account, usage, inventory and proposals under ignored
.infra; never upload them as PR artifacts. Credential file contents and raw SDK
errors are withheld from CLI diagnostics. Failed collection removes any old
destination payload and sidecar so a previous success cannot silently survive a retry.

The adapter enumerates every subscribed READY region and the tenancy root plus
all non-deleted descendant compartments, using list_compartments with subtree
access_level=ANY. It paginates SDK list calls and scans instances (including stopped
instances), boot volumes in every availability domain, block volumes, clusters,
and virtual pools. Terminated instances/volumes and deleted clusters are excluded.
Any permission/API failure, missing coverage, duplicate IDs or discovered virtual
pool prevents a complete snapshot. Objects outside the home region are collected
and rejected by audit; they are never silently filtered away.

The snapshot's complete flag means those enumerated families, not every OCI
product. Backups, Object Storage, load balancers, network egress, public-address
charges, paid images/licenses, databases and other products require independent
operator review. The SDK listing cannot prove monthly usage, account eligibility,
resource ownership, image pricing or the absence of other billable services.
The other_services_reviewed assertion records that external review; it is not an
automated discovery result. This is why a green result never authorizes deployment.

Monthly usage must be obtained separately from authoritative account usage or
billing evidence. The collector does not fabricate zeros or assume a new month
has no consumption. The explicit --usage JSON contract is:

```json
{
  "account_id": "ocid1.tenancy.oc1..REPLACE",
  "provider": "oci",
  "month": "2026-10",
  "observed_at": "2026-10-25T10:00:00+00:00",
  "covered_through": "2026-10-25T09:59:00+00:00",
  "source": "Operator reference to authoritative billing/usage evidence",
  "values": {
    "a1_ocpu_hours": 1200,
    "a1_memory_gb_hours": 7200,
    "block_gb_months": 150
  }
}
```

These are illustrative values, not live account evidence. All three metrics are
required, as of an explicit timezone-aware timestamp no more than 15 minutes old,
for the current UTC month and matching tenancy. If billing telemetry cannot
provide sufficiently fresh complete values, the audit fails; do not invent them.
Omitting --usage allows collection for investigation but cannot pass audit.

### Automated OCI usage observations (M04-PR4)

`infra_core.inventory.oci_usage.collect_usage` uses the existing optional OCI SDK
through `OCIReader.usage_page`: only `request_summarized_usages`, `USAGE_ONLY`,
HOURLY, no filters, grouped by tenancy/SKU/unit. An explicit elapsed hour cutoff
in the current UTC month is required. Queries use contiguous start-inclusive,
end-exclusive windows of at most 36 hours, with 1,000 rows/page and no SDK retries.
Budgets are 64 pages, 10,000 rows and 16 MiB aggregate canonical observations;
each observation is limited to 1 MiB. Failures never return a partial collection.

The closed mapping covers A1 CPU B93297, A1 memory B93298 and block storage
B91961/B91445 using the corresponding dimensional price-list unit strings. No
unit conversion, fuzzy matching or cost-based inference occurs. Other SKU/unit
pairs, duplicate aggregate rows, malformed quantities and intervals fail closed.
Absent metrics remain unknown; only an explicit returned zero becomes zero.
Decimal arithmetic preserves decoded quantities, with bounded precision. SDK
float decoding may already lose wire precision: hashes bind canonical SDK
snapshots, not original HTTP response bytes. All observations remain private.

Sources: [Oracle Usage API semantics](https://docs.oracle.com/en-us/iaas/Content/Billing/Concepts/costanalysisoverview.htm)
and [Oracle SKU price list](https://www.oracle.com/ae/a/ocom/docs/corporate/pricing/oracle-paas-and-iaas-global-price-list.pdf).
The query end and latest row end are not completeness proofs; `covered_through`
always remains None. This result cannot replace the existing manual usage evidence.
Administrator-owned live acceptance must establish actual API unit mappings,
complete account/billing visibility, source precision and a fresh authoritative
coverage watermark. Reporting lag or absent proof blocks acceptance; never
restamp observations or relax the 15-minute gate. SDK buffering/socket waits are
not hard process bounds; later protected orchestration must enforce its deadline.

## OCI inventory sidecars (M03-PR11 CLI slice)

**Breaking transport migration:** collection publishes inventory.json and adjacent
inventory.json.envelope.json under ignored .infra; governance audit requires both.
Preserve exact bytes: reformatting invalidates SHA256. Recollect legacy standalone
JSON with current reviewed code/configuration; never restamp old observations.

The [shared envelope contract](security-evidence.md) adapts the Apache-2.0
[in-toto Statement pattern](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
without dependencies. The oci-inventory predicate binds role inventory to original
collection start/end, configured account_id/home_region, unit=oci-account, clean
HEAD and a full account/profile digest: SHA256 of UTF-8 JSON of
{account: account_config, profile: selected_profile}, using sorted keys, compact
separators, ASCII escaping and rejection of nonfinite values. Reservations,
verification and profile revision/limits bind; TOML formatting does not. Inventory
intentionally does not bind a future proposal; full accounting still audits each plan.

Both CLI operations require stable clean HEAD before/after work. Collection removes
an old pair before SDK access and removes incomplete output on collection, binding
or write failure. Two writes are not an atomic transaction: a crash may leave a
partial pair, which consumers reject. Audit bounds reads to 10 MiB payload/64 KiB
sidecar, checks strict JSON, byte/scope/clock binding and measured coverage, then
runs all existing eligibility/usage/plan rules. Freshness stays 15 minutes from
original collection start; sidecar/payload clocks must match exactly. GOV043 covers
transport/checkout failures, EVID001-EVID004 shared checks, GOV040 sanitized collection.

infra_core.inventory_evidence.capture_inventory preserves schema-2 observations;
usage=null remains investigatory and cannot pass billing audit. Sidecars prove
unsigned consistency, not authenticity, complete IAM visibility or deployment
authority. The [OCI library preflight](oci-components.md#bound-inventory-at-registration-m03-pr11)
now requires the same bytes/sidecar with independent expected commit. Pure accounting
still accepts dictionaries; the [cutover consumer](kubernetes-cutover.md#commit-bound-cutover-evidence)
now validates the same captured pair. Operations stay disabled. Rollback
needs compatible code/contracts and weakens transport checks without granting authority.

## Proposal and accounting contracts

The CLI consumes a normalized full proposal, not Terraform JSON or a raw Pulumi
preview. A future component compiler must generate it for every deployment unit
in the account before any resource registration. Do not hand-label a partial
stack proposal complete and treat it as account proof.

```json
{
  "schema_version": 1,
  "account_id": "ocid1.tenancy.oc1..REPLACE",
  "provider": "oci",
  "complete": true,
  "units": [{
    "name": "oci-oke",
    "changes": [{
      "key": "workers",
      "action": "create",
      "existing_ids": [],
      "resource": {
        "type": "oci:ContainerEngine/nodePool:NodePool",
        "region": "eu-frankfurt-1",
        "props": {
          "nodeShape": "VM.Standard.A1.Flex",
          "nodeShapeConfig": {"ocpus": 1, "memoryInGbs": 6},
          "nodeConfigDetails": {"size": 2},
          "nodeSourceDetails": {"bootVolumeSizeInGbs": "50"}
        }
      }
    }]
  }]
}
```

Each unit name and unit/change key is unique. Actions are create, update, replace
or delete. Create has no existing_ids. Others require distinct live resource IDs
with independently evidenced matching unit ownership, each claimed at most once.
Delete requires resource=null; other actions require explicit type, region and
props. The collector assigns owner=null to every object: tags do not prove
ownership. It marks volumes retained=true. Subtraction is therefore blocked for
collector-only evidence until a later reviewed adoption/ownership mechanism.

Inventory schema_version=2 includes account_id, provider, observed_at, complete,
all_regions, all_compartments, covered_types, resources and usage. covered_types
must enumerate Instance, BootVolume, Volume and Cluster native OCI Pulumi tokens.
Every resource has id, type, region, owner, retained and props. Instance props use
shape and shapeConfig.ocpus/memoryInGbs; volume props use sizeInGbs, vpusPerGb and
isAutoTuneEnabled; cluster props use type. Top-level and change contracts reject
unknown fields, missing fields and malformed types rather than filling defaults.

Accounting rules:

- Start with every observed object, including unmanaged resources and retained
  disks, then add reservations and the aggregate proposal across all units.
- Existing instance footprints include compute only; actual boot records supply
  their storage. Desired instances/pools include their implicit boot storage,
  preventing missing disks without double counting existing boot volumes.
- Final = existing + reserved + desired - independently owned removed/replaced
  capacity. Retained resources cannot be subtracted.
- Peak adds full new/replacement capacity to the baseline, with no credit for
  other deletes. In-place updates add only positive deltas. Node cycling is
  denied until a separate surge/replacement model is reviewed.
- Monthly forecast = consumed + peak held for the remaining month, starting from
  the usage observation time and rounding remaining hours upward. Deletion
  cannot refund already consumed usage. Storage uses the month's actual hours.
- Both final and peak must fit every capacity bound; every monthly forecast
  must fit its allowance. Unknown/nonfinite/negative values, unknown types,
  paid shapes, enhanced clusters and paid/automatic volume performance fail.

Only explicit Basic OKE, A1 Flex, balanced-or-lower standalone volume performance
with auto-tune disabled, and the reviewed network primitives are classified.
Instance boot performance must explicitly be balanced 10 VPUs/GB; boot sizes are
at least 50 GB. NodePool's API has no bootVolumeVpusPerGb input: proposed pools
model boot size but cannot prove future disk performance. Real disk inventory
checks performance, and image/performance review remains a resource-activation
prerequisite. Numeric Pulumi unknowns are denied by preflight; Pulumi may skip
policy callbacks for unknown preview values, so the policy alone is insufficient.

```sh
uv run --locked infra governance audit --account .infra/account.toml \
  --inventory .infra/inventory.json --plan .infra/proposal.json
```

Success returns status=within-modeled-limits, final/peak/monthly values and
deployment_authorized=false. Evidence files and true/complete flags are trusted
operator inputs, not signed attestations. No result is cached as a deployment
token. Recollect/reverify evidence before any future protected operation.

## Verification and activation gates

```sh
uv run --locked infra verify
uv build --all-packages
```

The same pre-commit and Linux CI gate runs lint, formatting, strict mypy,
schema/accounting/negative tests and tracked-artifact checks. CI's explicit
backend_integration step also runs a real Pulumi preview against a temporary file
backend and proves the mandatory policy rejects an unclassified synthetic
ComponentResource. It needs no provider plugins or OCI credentials and never
deploys cloud resources. Local opt-in uses RUN_PULUMI_LOCAL_QUALIFICATION=1 and
the pinned Pulumi CLI, as described in the backend runbook.
The policy integration runner uses PYTHONUNBUFFERED=1 and explicitly decodes CLI
output as UTF-8; future protected policy invocations must preserve those settings
when capturing output.

Future deployment code must call infra_program.governance.preflight with the full
account proposal before its registration callback and attach policies/ as a
mandatory policy pack. Activation additionally requires actual backend
qualification, verified inventory/usage/eligibility, reviewed ownership and image
contracts, handling of currently external services, protected-environment approval
and tests tying the generated proposal to the registered resource graph. Until
then the resource entry point and CLI preview/deploy remain unconditional denials.
Do not weaken these gates to compensate for incomplete evidence.


## Evidence clocks and coverage migration

Recollect inventory to produce schema v2; do not relabel v1 snapshots. In addition
to existing resource/account fields, v2 includes collection_started_at,
collection_completed_at and coverage. observed_at must equal the original start;
start <= completion <= audit time and the entire scan must be under 15 minutes old.
Fresh completion cannot hide an old scan or re-date old records.

coverage contains unique regions/compartments, per-region availability_domains,
and successful queries. Every query records operation, region, compartment,
availability_domain (null unless applicable), and raw result count. Validation
requires exactly the region/compartment discovery calls, AD discovery per region,
instances/volumes/clusters/virtual_pools per scope, and boots per AD/scope. Missing,
extra or duplicate queries, discovery counts inconsistent with declared scope,
nonzero virtual pools, missing root/home scope, invalid counts and counts
smaller than retained resource records fail. Raw counts can include terminated
objects filtered out of final inventory. Completeness booleans alone cannot pass.

Usage now requires covered_through separately from observed_at: the time through
which billing values are complete versus when the report was observed. Both must
be fresh within 15 minutes, in the current UTC month, and coverage cannot follow
observation. Remaining usage is conservatively forecast from covered_through, so
reporting latency cannot erase unmeasured consumption. Re-collect stale usage;
never set covered_through to report-download time without authoritative support.

The scope matrix records what the reader discovered and successfully queried;
it does not prove permission to discover every compartment, that scope stayed
unchanged during a multi-request scan, or that unsigned JSON was not edited.
Effective IAM/discovery coverage and trusted provenance still need independent
review before any future operation. This implementation does not enable deployment,
assert live eligibility, establish operational SLOs or install drift/cost monitors.
