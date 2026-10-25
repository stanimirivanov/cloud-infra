# Account-wide free-tier governance

The governance engine evaluates an entire OCI billing tenancy across the supported
resource families, rather than granting each stack its own free allowance. It is
a preflight foundation, not permission to deploy or a zero-billing certificate.
All resource deployment units and the normal Pulumi entry point remain disabled.
Terraform source, deployed resources and state ownership are unchanged.

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
| cloudflare-free | Disabled pending inventory, usage and classifier implementation | None | None | None |
| supabase-free | Disabled pending organization/project governance | None | None | None |
| aws-free / gcp-free | Disabled pending account-specific eligibility and metering | None | None | None |

Sources reviewed on 2026-10-25: [Oracle Always Free resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
and the [OCI price list](https://www.oracle.com/cloud/price-list/). Published terms
are not account eligibility. Source reviews expire after 90 days; operator
entitlement and other-service review expire after 30 days. Re-review sources and
account evidence before changing dates. Do not raise limits just to pass a check.
The storage monthly model conservatively bounds GB-months to 200 as well as
instantaneous capacity; it does not model a cloud invoice or billing rounding.

The preserved legacy HCL regression ceiling of 4 OCPUs / 24 GiB is independent
of this engine. Its current two 8 GiB workers exceed the free profile's 12 GB
aggregate ceiling. This PR does not resize or adopt them.

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

On PowerShell, run the command on one line (the backslashes above are POSIX shell
line continuations). Keep account, usage, inventory and proposals under ignored
.infra; never upload them as PR artifacts. Credential file contents and raw SDK
errors are withheld from CLI diagnostics. Failed collection removes any old
destination snapshot so a previous success cannot silently survive a retry.

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
        "type": "oci:containerengine/nodePool:NodePool",
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

Inventory schema_version=1 includes account_id, provider, observed_at, complete,
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

The same pre-commit and Windows/Linux CI gate runs lint, formatting, strict mypy,
schema/accounting/negative tests and existing legacy validation. CI's explicit
backend_integration step also runs a real Pulumi preview against a temporary file
backend and proves the mandatory policy rejects an unclassified synthetic
ComponentResource. It needs no provider plugins or OCI credentials and never
deploys cloud resources. Local opt-in uses RUN_PULUMI_LOCAL_QUALIFICATION=1 and
the pinned Pulumi CLI, as described in the backend runbook.
The policy integration runner uses PYTHONUNBUFFERED=1 and explicitly decodes CLI
output as UTF-8; future protected policy invocations must preserve those settings
when capturing output, including on Windows.

Future deployment code must call infra_program.governance.preflight with the full
account proposal before its registration callback and attach policies/ as a
mandatory policy pack. Activation additionally requires actual backend
qualification, verified inventory/usage/eligibility, reviewed ownership and image
contracts, handling of currently external services, protected-environment approval
and tests tying the generated proposal to the registered resource graph. Until
then the resource entry point and CLI preview/deploy remain unconditional denials.
Do not weaken these gates to compensate for incomplete evidence.
