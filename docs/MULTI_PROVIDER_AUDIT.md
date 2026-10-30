# Multi-provider coverage and gap audit

Reviewed: 30 October 2026. Source baseline: `d00427ca5afa4468aaae481aee11d531d8e0d4e4`.
Scope: tracked source, dependency manifests, policy, configuration, workflows and
tests; official public provider terms. No cloud account, invoice, deployed state,
effective IAM permission or live availability was inspected.

## Architectural conclusion

This repository is a guarded Pulumi foundation, not an activated multi-cloud
provisioning platform. It implements OCI network/Basic OKE components and narrow
Cloudflare DNS/Supabase project components. All four units have `enabled=false`
and `preview_enabled=false` in [pulumi.toml](../config/pulumi.toml). Separate apply,
import, recovery and monitoring gates also remain disabled. Engineering closeout
does not mean operational acceptance; see [M06](m06-closeout.md).

The split between pure `infra-core` contracts and `infra-program` Pulumi adapters
is sound. Account-wide evidence checks precede registration; unknown resource
types fail closed. Adding an SDK alone cannot establish free-tier coverage.

See the [improvement plan](ARCHITECTURE_IMPROVEMENT_PLAN.md) for proposed work and
the [operator guide](USER_GUIDE.md) for current supported procedures.

## Implementation coverage

“Implemented” below means source and offline contracts exist, not live activation.

| Provider/service | Repository coverage | Missing integration or boundary |
| --- | --- | --- |
| OCI A1 compute | `pulumi-oci==5.5.0`; A1 classifier, inventory and account accounting; OKE node-pool component | No general-purpose standalone VM component; only reviewed A1, not all free shapes |
| OCI networking/OKE | `Network` and `Oke` ComponentResources; explicit provider; Basic cluster; versioned network StackReference | Activation, live image/version/availability evidence, ownership and cluster acceptance remain pending |
| OCI boot/block storage | Boot sizes in node proposals; standalone volume classifier and inventory; aggregate final/peak/monthly limits | No reusable standalone volume component; backups and retained object history need separate accounting |
| OCI Object Storage | Existing S3-compatible state backend; read-only posture and opt-in synthetic qualification | No application bucket component or complete object/request/egress quota collector; backend use is not managed bucket provisioning |
| GCP | Disabled `gcp-free` placeholder | No SDK dependency, e2-micro component, region/disk policy, project inventory, billing-account aggregation or usage collector |
| AWS | Disabled `aws-free` placeholder | No SDK dependency or EC2/DynamoDB/S3/Lambda components or account-plan/usage adapters. `AWS_*` variables currently authenticate OCI S3 state, not AWS infrastructure |
| Cloudflare DNS | `pulumi-cloudflare==6.23.1`; existing-zone DNS-only A/AAAA/CNAME records; token scoped collector | No zone creation, proxied CDN configuration, registrar management or cross-provider endpoint wiring |
| Cloudflare Workers/Pages | Provider SDK available, no governed resources | Code bundles, builds, routes, secrets, deployment versions and usage accounting absent |
| Cloudflare R2/Tunnel | No governed resources | Bucket class/operation accounting, tunnel token lifecycle, connector rollout and access policy absent |
| Supabase PostgreSQL | Vendored generated `pulumi-supabase==1.11.0`; Nano project in existing Free org; encrypted password/token; project/usage evidence | No SQL schema/migrations, RLS, application credentials distribution or tested production database backup/restore |
| Supabase branches | Generated SDK includes `branch.py` | Intentionally unclassified/rejected by governance; SDK availability does not imply free eligibility |
| Neon | None | Provider binding/provenance, project/branch/role components, CU-hour/storage/egress collection and branch cleanup absent |
| Fly.io | None | No adapter; new-account Machines do not meet permanent free-compute requirements |
| Render | None | No Free web-service adapter, deployment artifact contract, aggregate hours/build/egress accounting; Free Postgres is time limited |
| Vercel | None | No project/deployment/domain/function adapter, Hobby eligibility or usage guard |
| Netlify | None | No site/deployment/function adapter or current credit-plan accounting |

Evidence: [member dependencies](../packages/infra-program/pyproject.toml),
[OCI components](../packages/infra-program/src/infra_program/oci/components.py),
[service components](../packages/infra-program/src/infra_program/services/components.py),
[resource classification](../packages/infra-core/src/infra_core/governance/resources.py),
[profiles](../config/quotas/profiles.toml), and
[service collection contracts](runbooks/independent-services.md).

## Current free-tier eligibility matrix

Terms below were checked on 30 October 2026. Limits are shared at the provider's
billing scope, not duplicated by Pulumi stack. A permanent offer has no fixed
expiry today; providers may change terms. Account evidence must establish actual
eligibility. Follow linked terms again before implementing or operating a module.

| Service | Published allowance or restriction | Strict-free decision |
| --- | --- | --- |
| OCI Always Free A1 | 1,500 OCPU-hours and 9,000 GB-hours/month; 2 OCPUs/12 GB equivalent. Boot + block 200 GB and 5 backups in home region. Free-only Object Storage: 20 GB combined, 50,000 requests/month | Current `oci-free` profile matches compute/block limits. Paid-tenancy price list separately states 3,000/18,000 shared hours; never grant that profile without proof. Object limits differ by account type; manual review required. [Always Free](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm), [paid pricing](https://www.oracle.com/cloud/price-list/) |
| GCP Compute Engine | Eligible non-preemptible e2-micro hours equal one VM-month across us-west1/us-central1/us-east1; 30 GB-month standard persistent disk; 1 GB qualifying outbound transfer | Conditional candidate. All projects sharing billing allowance must be counted; no SSD/balanced-disk substitution. IPv4/NAT/load balancers are separate costs. [Free program](https://docs.cloud.google.com/free/docs/free-cloud-features), [network pricing](https://cloud.google.com/vpc/network-pricing) |
| AWS EC2 | Pre-15 July 2025 accounts had a 12-month offer; newer Free plans are limited to six months or credit exhaustion | Reject t2.micro/t3.micro as permanent free compute. By this review date the old 12-month cohort has expired. [EC2 eligibility](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-free-tier-usage.html), [current FAQ](https://aws.amazon.com/free/free-tier-faqs/) |
| AWS S3 | New-account offer uses temporary credits; historic 5 GB/20,000 GET/2,000 PUT allowances were not permanent | Reject standard S3 workload storage as a permanent free baseline. [S3 pricing](https://aws.amazon.com/s3/pricing/) |
| AWS DynamoDB | Standard table class: 25 GB, 25 provisioned RCU and 25 WCU per Region/payer monthly free scope | Conditional candidate; aggregate tables/indexes, disable capacity growth beyond allowance, do not assume on-demand requests, PITR or backups are free. [Pricing](https://aws.amazon.com/dynamodb/pricing/) |
| AWS Lambda | 1 million requests and 400,000 GB-seconds/month | Conditional candidate; bound duration, memory, concurrency and invocations; separately meter logs, storage, API frontends and transfer. Concurrency alone cannot cap monthly use. [Pricing](https://aws.amazon.com/lambda/pricing/) |
| Cloudflare DNS/Workers/Pages | DNS profile conservatively caps 200 records/zone. Workers Free: 100,000 requests/day, 10 ms CPU/invocation; Pages Free: 500 builds/month | DNS subset implemented; Workers/Pages candidates need independent meters, with Pages Functions charged against applicable Workers limits. [DNS](https://developers.cloudflare.com/dns/manage-dns-records/), [Workers](https://developers.cloudflare.com/workers/platform/limits/), [Pages](https://developers.cloudflare.com/pages/platform/limits/) |
| Cloudflare R2 | Standard class: 10 GB-month, 1 million Class A and 10 million Class B operations/month; Internet egress free | Conditional, metered overages possible; Infrequent Access excluded. [R2 pricing](https://developers.cloudflare.com/r2/pricing/) |
| Cloudflare Tunnel | Free-plan tunnel capability requires separately operated connectors and appropriate access controls | Candidate only after connector hosting/traffic cost and account plan are reviewed. A tunnel is not free compute. [Tunnel documentation](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/) |
| Supabase | Free: two active projects; 500 MB database, 1 GB file storage, 5 GB uncached + 5 GB cached egress, 50,000 MAU; inactive projects pause | Existing subset; independent org/project scope checks retained. Branch billing needs separate approval and is excluded. [Pricing](https://supabase.com/pricing), [branch billing](https://supabase.com/docs/guides/platform/manage-your-usage/branching) |
| Neon | Current Free pricing: 100 projects, 10 included branches/project, 100 CU-hours/project, 1 GB database/project, 5 GB public transfer/project; idle scale-to-zero | Candidate, not installed. Capture dated plan evidence; do not reuse older 0.5 GB/50 CU-hour examples. Account/API semantics must be qualified. [Pricing](https://neon.com/pricing) |
| Fly.io | New organizations use metered Pay As You Go | Exclude from strict permanent-free container target; trials or grandfathered credits do not qualify a new account. [Pricing](https://docs.fly.io/about/pricing) |
| Render | Free web services share 750 hours/workspace/month, idle after 15 minutes, no persistent disk; Free Postgres expires after 30 days | Web services conditional for hobby/testing availability; exclude Free Postgres as permanent storage. Bandwidth/build limits remain separate. [Free services](https://render.com/docs/free) |
| Vercel | Hobby is free for personal, noncommercial use; features pause on exhausted limits | Conditional for eligible use only; validate each delivery/function meter. No production-commercial blanket eligibility. [Hobby](https://vercel.com/docs/plans/hobby) |
| Netlify | Current Free plan has a shared 300-credit monthly limit | Conditional; model deploys, requests, bandwidth and compute in credits; do not assume legacy plans' allowances. [Pricing](https://www.netlify.com/pricing/) |

## Findings and risk disposition

| Priority | Finding and evidence | Consequence / recommendation |
| --- | --- | --- |
| P1 | No credentialed or live operational acceptance in this audit; tracked activation gates remain false | Do not advertise a finished deployable platform. Complete existing ten-gate acceptance before activation; no flag-only shortcut |
| P1 | OCI collector covers instances, volumes, clusters and virtual pools; `other_services_reviewed` is an operator assertion | Object storage/state versions, backups, egress, licenses and other services can incur charges outside automated checks; add inventory/meter coverage incrementally |
| P1 | Mandatory resource policy ceilings are 4 OCPUs/24 GB/200 GB, the largest reviewed profile, while Free account preflight is 2/12/200 | Policy pack alone is insufficient. Preserve account preflight and bind selected profile plus aggregate saved graph to execution; add wrong-profile/bypass tests |
| P1 | OCI Usage API collector deliberately returns unknown `covered_through`; service usage relies partly on supplemental operator observations | Existing 15-minute freshness requirements can prevent live acceptance. Resolve authoritative telemetry completeness; never invent timestamps or weaken checks for availability |
| P1 | One configured backend bucket/prefix and one passphrase policy; units have distinct stack names | Logical state separation exists, but distinct credential/key/bucket blast-radius isolation is not proven. Verify effective IAM, key custody, backup independence and external-state ownership |
| P2 | `Services` multiplexes providers with conditional logic; OCI components use typed outputs, services export generic maps | Refactor provider-specific components behind the existing validated factory; preserve resource URNs and output schema compatibility |
| P2 | OCI OKE depends on committed network outputs; services are independent and there is no generic multi-provider execution DAG | Add explicit endpoint contracts and deployment artifacts before promising seamless DNS/database/frontend integration |
| P2 | No root `.env` ignore pattern or automatic dotenv loading | Use ignored `.infra/operator.env` only if needed; encrypted stack config is preferred. Do not instruct new users to create plaintext root `.env` |
| P2 | Monitoring machinery exists but tracked observation/delivery flags are disabled | A merged workflow is not a running cost/drift alarm. Commission readers, durable state, heartbeat, recipients and failure handling separately |

These findings describe coverage and assurance limits, not demonstrated live
exploits or confirmed bills. Existing negative tests, protected components,
provider pins, source scans and synthetic integration checks are valuable; they
cannot certify provider-side limits, IAM, availability or zero future charges.

## Audit validation

The accompanying change adds documentation only. It changes no resource graph,
dependency, profile, state identity, credential or activation flag. The repository
shared gate checks local documentation links and CLI examples as well as security,
architecture, lint, formatting, types and tests. See the PR verification result for
the actual run; source inspection is not a credentialed preview.
