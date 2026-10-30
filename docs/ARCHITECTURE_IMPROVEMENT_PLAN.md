# Architecture and code improvement plan

Proposed 30 October 2026 against the [coverage audit](MULTI_PROVIDER_AUDIT.md).
This is a design backlog, not implemented functionality or activation approval.
The current guardrails already implement much of the requested safety model;
extend them instead of creating a parallel unchecked deployment path.

## 1. Preserve the core boundaries

Keep pure validation/accounting in `infra-core`, Pulumi registration in
`infra-program`, and runtime dependencies in member manifests. Update the single
`uv.lock` through uv. For each provider, distinguish: package availability,
resource classification, component implementation, read-only collection,
credentialed preview qualification, and live acceptance.

Use a closed provider capability registry containing supported resource types,
account scope, profile revision, parser, collector, proposal compiler and component
factory. Unknown providers/resources must fail. Do not generalize every cloud to
“VM size + disk”: request, CU-hour, GB-hour, build-credit and egress meters have
different scopes, periods and units.

## 2. Refactor components without changing ownership

| Proposed change | Source boundary | Acceptance evidence |
| --- | --- | --- |
| Split `Services` into Cloudflare DNS and Supabase project implementations behind `register_services` | [service components](../packages/infra-program/src/infra_program/services/components.py) | Existing factory contract, secret propagation, explicit provider/parent/protect and child names preserved; real SDK mock serialization unchanged |
| Introduce frozen validated proposal/output types at adapter boundaries | [service configuration](../packages/infra-program/src/infra_program/services/configuration.py), [OCI components](../packages/infra-program/src/infra_program/oci/components.py) | No registration before full audit; invalid/unknown values fail before token lookup; stable schema versions and IDs |
| Add optional standalone A1 compute/storage components | New reviewed OCI modules using existing classifier | Explicit ARM image, home region, storage/performance and peak model; full account aggregation; no public ingress by default |
| Add typed endpoint contracts | Existing [network dependency](../packages/infra-program/src/infra_program/oci/dependencies.py) pattern | Account/project/unit binding, committed output digest, no unknown preview IDs, no plaintext passwords/connection strings in public outputs |

Keep current component tokens/names where possible. Renaming components changes
URNs and may propose replacements; prove compatibility with a saved fixture graph
and qualified preview before introducing aliases or migration. `protect=True`
prevents accidental deletion, not billing or all updates. Avoid a generic component
that silently chooses a paid shape when free capacity is unavailable.

## 3. Make free-tier admission complete

Extend [account audit](../packages/infra-core/src/infra_core/governance/audit.py)
and [policy adapter](../packages/infra-program/src/infra_program/governance.py)
with selected-profile context and a graph-level admission check. Resource-local
policy must stay mandatory; account-level validation must run before registration
and again against the approved saved plan before execution. Ordinary Python
`assert` is unsuitable for security/billing checks because optimized Python can
remove it; use the existing explicit `require`/`GovernanceError` pattern.

Proposed algorithm (design pseudocode):

```text
resolve explicit provider + billing scope + dated plan entitlement
reject credits/trials when permanent_free is required
capture complete inventory and original usage coverage watermark
reject unknown, stale, incomplete or unsigned/untrusted required evidence
compile all affected units into one account proposal
calculate existing + retained + reservations + replacement overlap
calculate consumed + conservative usage through period end
check every capacity and usage dimension against selected allowance
compare the reviewed proposal to the engine's saved resource graph
admit only the exact commit/configuration/plan under one fenced writer
```

Use existing envelope/signature contracts according to their trust boundary:
unsigned hashes prove consistency only. Extend schema deliberately for account
plan cohort, shared payer/organization, original billing anchor, units and source
version. Never infer unused allowance from a missing API row or a zero-dollar
invoice covered by promotional credits.

Required negative cases include wrong region, shape, disk class, RAM, unknown
resource/property, profile mismatch, paid add-on, stale/missing meter, account
scope omission, 31-day usage, billing anniversary, cross-stack concurrent change,
retained disk, and replacement that fits final capacity but exceeds peak.
Existing tests already cover many OCI/service cases; extend those tests rather
than duplicating implementation arithmetic in new test helpers.

## 4. Prioritize missing providers by feasible free offerings

| Order | Proposed component family | Required safe defaults and meter coverage |
| --- | --- | --- |
| A | Cloudflare Workers/Pages | Free plan, bounded builds/requests/CPU; reviewed code artifact digest, route ownership, separate encrypted secrets; no paid bindings by default |
| A | Neon PostgreSQL/branches | Free plan, bounded projects/branches, autosuspend, CU-hours + storage + egress; branch lifetime and data deletion reviewed explicitly |
| B | GCP e2-micro | Only three eligible US regions, standard persistent disk, aggregate VM-hours and disk allowance; no external IPv4/NAT/LB or paid image by default; prove usable networking separately |
| B | AWS DynamoDB/Lambda | Explicit eligible account plan; Standard provisioned DynamoDB with bounded aggregate table/index capacity; Lambda bounded memory/duration/invocations and no paid provisioned concurrency; separately classify logs/endpoints/egress |
| B | Render Free web service | Explicit Free service plan, aggregate hours/build/egress, ephemeral filesystem, no disk or expired database dependency |
| B | Vercel/Netlify | Verify Hobby use eligibility or Free credit plan; exact artifact/framework function graph and preview deployment retention; reject paid extensions |
| C | OCI Object Storage / Cloudflare R2 | Storage class, versions, multipart uploads, request/retention/egress meters and state-backup consumption; bucket creation alone is not an enforceable storage cap |
| C | Cloudflare Tunnel | Connector placement and lifecycle, encrypted tunnel credential, restricted routes/access, host usage and connector health |
| Excluded | New-account AWS EC2/S3 permanent-free baseline; Fly.io free Machines | No default module claiming permanent-free eligibility. Optional paid/trial work needs a separate explicitly named policy mode |

For each new binding, review the official Pulumi registry or upstream bridge,
maintainer, license, schema, plugin origin and supported version before adding a
dependency. AWS/GCP native Pulumi packages are candidates; less common PaaS
bindings may require a reviewed Terraform bridge. Do not claim every provider has
an official native Python SDK. Avoid shell provisioners/dynamic providers as a
shortcut around preview, import, secret and lifecycle semantics. Require pinned
plugin provenance, unit serialization tests and opt-in provider qualification.

## 5. State, secrets and orchestration

1. Retain distinct provider/unit stacks and the `oci-network -> oci-oke` dependency.
   Generalize a DAG only when another real dependency is introduced. Validate
   acyclic topology, account-specific credentials and committed outputs; never
   apply every stack concurrently just because their states are separate.
2. Serialize mutations by billing scope as well as by stack. Two independent
   stacks can consume the same free allowance between audit and apply. Use a
   durable external writer fence and atomic reservation protocol; a local lock
   or CI concurrency group alone does not cover outside writers.
3. Review backend separation per environment/account. Existing stack names inside
   one bucket provide namespaces, not security isolation. Scope access using
   actual OCI IAM capabilities; use separate buckets/principals if required.
   Backend redesign must be separately qualified, never silently migrate state.
4. Keep provider credentials separate from backend HMAC keys and audit signing
   keys. Use encrypted `require_secret` inputs, ephemeral operation environments,
   per-stack passphrase custody where qualified, and independent encrypted backups.
   A managed KMS alternative needs explicit availability/cost/custody review.
5. Preserve pure configs outside secret files. Add a reviewed `.env` ignore rule
   only if dotenv support is intentionally introduced; do not imply it exists now.
6. Keep SQL migrations and application deployment as explicit versioned artifacts
   with their own rollback/backup procedures. Infrastructure creation does not
   supply a secure relational schema, working frontend or application connectivity.

## 6. Runtime usage controls and operator acceptance

Commission existing monitoring only after reader IAM, heartbeat, durable ledger,
recipient delivery and stale-data behavior have been demonstrated. Extend it with
per-provider meter snapshots and independent invoice reconciliation. Alerts-only
budgets are notifications, not universal enforcement. Any provider spend-cap
feature needs explicit service coverage and latency qualification.

Suggested operator policy: investigate at 70% of an allowance, block discretionary
growth at 85%, and enact the reviewed load-shedding procedure before 95% or an
earlier forecasted breach. These are proposed operational margins, not provider
limits or new code. The stop procedure must preserve databases/state and account
for billing lag. Never use automatic destructive teardown as a billing guarantee.

Deliver each admitted provider slice with design rationale, profile revision,
collector completeness evidence, negative tests, pinned plugin, protected preview,
recovery plan and guide updates. Run the shared gate and inspect a qualified plan
before activation. Stop if source evidence cannot support an authoritative fresh
usage bound. A documentation or code review cannot guarantee a zero invoice.
