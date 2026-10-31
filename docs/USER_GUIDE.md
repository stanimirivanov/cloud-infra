# User and Operator Guide

Reviewed 30 October 2026. Applies to the `cloud-infra` uv workspace and its
currently disabled deployment configuration. All relative paths and commands
below start at the repository root, the directory containing `HARNESS.md`.

## 1. What you can operate today

You can install the workspace, run offline verification, prepare proposals,
validate private evidence, and perform explicitly authorized read-only inventory
collection. OCI network/Basic OKE, Cloudflare DNS records and Supabase Free
projects have component libraries. Their tracked preview/apply gates are disabled.
Production stack initialization, import and state recovery are not onboarding
steps. GCP, AWS, Neon, Fly.io, Render, Vercel and Netlify have no deployable modules.

Read the [coverage and current limits](MULTI_PROVIDER_AUDIT.md),
[proposed improvements](ARCHITECTURE_IMPROVEMENT_PLAN.md) and
[M06 acceptance boundary](m06-closeout.md) before planning deployment.

**There is no zero-billing guarantee.** The checks reject known unsafe proposals
within their modeled scope. They cannot prevent external writers, application
traffic, credential misuse, unmodeled products, delayed billing or changed terms.
A zero current invoice can also hide promotional-credit consumption. If an
unconditional zero-charge outcome is required, do not activate a metered paid
account/service without provider-enforced limits covering every billable meter.
Free services can pause or reclaim resources; this guide is an operator procedure,
not a provider availability or durability guarantee.

### Inspect implemented provider capabilities

```sh
uv run --locked infra providers inspect
uv run --locked infra providers inspect --provider oci
uv run --locked infra providers inspect --provider gcp
```

This read-only command emits schema-version-1 JSON with `kind=provider-capabilities`.
It reads validated foundation configuration and closed repository metadata; it
makes no provider calls and writes no files. `sdk_binding` names the declared
Pulumi package, not proof that a plugin is installed or usable. Classification,
collection and component lists describe only the implemented subsets, with
limitations alongside them. Current OCI, Cloudflare and Supabase support is partial.
AWS, GCP, Neon, Fly.io (`flyio`), Render, Vercel and Netlify are reported unsupported.
Unknown provider names fail with `CAP002`; inconsistent metadata fails with `CAP001`.

Each unit exposes its configured preview flag, stack and dependencies.
`foundation_enabled` is false because the foundation loader rejects any other value.
These flags do not summarize separate apply/import/recovery gates or live account
readiness. `execution_authorized`, `activation_authorized`, `live_controls_verified`
and `sdk_installation_checked` remain false, even if a preview flag is configured
true. A successful inspection means the report was generated, not that the selected
provider can deploy. No credentials or backend locator are included in the report.

## 2. Accounts and regional prerequisites

Create only accounts actually needed. Account creation does not authorize a
resource deployment. For every provider, record privately: account/organization
ID, owner, actual plan, creation date, billing cycle/timezone, allowed regions,
payment status, shared billing scope, terms URL/date and alert recipients. Enable
MFA and store recovery codes separately. Never create extra accounts to bypass
free-tier restrictions. Trial credit and a permanent free allowance are different.

### OCI: supported component family

1. Start at [Oracle Cloud Free Tier](https://www.oracle.com/cloud/free/), verify
   your identity and complete the payment verification requested at signup.
   Verification/temporary card holds are not a monthly spending cap.
2. Choose the Home Region carefully before finishing signup; record its exact
   region code. Home Region is not interchangeable with a deployment preference.
   Use that region for free compute/storage. A lack of A1 capacity is a reason to
   wait or reconsider the design, not silently choose a paid shape/other region.
3. Record whether the tenancy is Free-only, trial or paid. Select the matching
   profile only after checking entitlement; do not upgrade merely to make the
   larger `oci-paid-a1` numbers pass. See the audit's linked Oracle terms.
4. Create/review the target compartment and a dedicated API-signing identity.
   Inventory needs visibility across subscribed regions and compartments, not
   just the target compartment. Separately review least-privilege mutation access
   before eventual activation.
5. Store the API private key outside source with mode 0600. Keep an explicit OCI
   SDK INI profile with `tenancy`, `user`, `fingerprint`, `key_file`, `region` and,
   if needed, `pass_phrase`. Use `--oci-config` and `--oci-profile`; the inventory
   command does not require ambient cloud credentials.
6. Review existing backend bucket ownership and IAM separately. Its S3 customer
   secret keys are distinct from API-signing credentials. Do not create a new
   bucket, change the configured namespace or copy another operator's state.

### GCP: prospective integration, not implemented

1. Sign in through [Google Cloud Free](https://cloud.google.com/free), create an
   account/project and follow identity/payment verification. The ongoing Free
   Tier requires a billing account; trial expiry is a separate event.
2. Record the billing account ID and every attached project that consumes its
   shared allowance. Enable Compute Engine only when the reviewed design is ready.
3. For a future e2-micro module, select **us-central1, us-west1 or us-east1** and a
   zone within it. Require standard persistent disk and check aggregate time and
   storage against the audit matrix. European regions do not qualify for this offer.
4. Review connectivity before creating a VM: external IPv4, NAT and load balancers
   can introduce charges independently of the free instance. Use the current
   [network price table](https://cloud.google.com/vpc/network-pricing); an outbound
   tunnel still needs working, accounted-for network access.
5. Prepare a least-privilege federated identity where practical; do not commit a
   service-account JSON key. This repository does not yet consume GCP credentials.

### AWS: prospective service-specific integration

1. Use [AWS Free Tier](https://aws.amazon.com/free/) signup, verify account identity,
   enable root MFA and create a separate operational identity. Record the actual
   account plan shown by Billing, including credit and expiry dates. Signup/payment
   requirements can vary; follow the current flow rather than an old tutorial.
2. Keep the account on the intended plan. The six-month Free plan is not permanent
   free hosting; continuing after expiry must not be treated as an automatic
   zero-cost upgrade. Check the [current FAQ](https://aws.amazon.com/free/free-tier-faqs/).
3. Reject EC2 micro instances and ordinary S3 storage as the permanent-free
   platform baseline. Evaluate only individually eligible services such as the
   DynamoDB/Lambda candidates in the audit, including their ancillary products.
4. Pick and record a supported region and payer scope. Create billing alerts
   before workloads. Prefer short-lived role credentials over root/access keys.
   There is no AWS deployment or usage collector in this repository today.

### Cloudflare: DNS supported; other services prospective

1. Create a [Cloudflare account](https://dash.cloudflare.com/sign-up), verify email,
   enable MFA and choose the Free plan for the intended zone. Registering/buying a
   domain is a separate cost; free DNS does not include domain registration.
2. Add your existing domain through the dashboard and follow its authoritative
   nameserver instructions at the registrar. Coordinate the DNS cutover with the
   owner and verify existing mail/verification records. The code manages records
   in an existing active zone; it does not perform this onboarding step.
3. Record account ID, zone ID and domain. Create a zone-scoped read token with
   Zone Read/DNS Read for collection. A future approved DNS mutation needs its
   separately reviewed write permissions. Avoid the global API key.
4. Workers and Pages use separate limits from DNS. R2 activation asks for an R2
   subscription/payment setup; inspect its confirmation screen and overage terms
   before enabling it. [R2 onboarding](https://developers.cloudflare.com/r2/get-started/).
5. For a future Tunnel, choose the intended Zero Trust plan, review access rules
   and plan a connector host. Do not equate a tunnel with a managed web server.

### Supabase: supported project component

1. Create a [Supabase account](https://supabase.com/dashboard), secure it with MFA
   and create/select a Free organization. Review memberships across all Free
   organizations where you are owner/admin; the project cap is shared.
2. Record user ID, organization slug, actual billing-cycle anchor and desired
   project region. Choose near your application subject to data-location needs;
   there is no GCP-style three-US-region rule for this module.
3. Prepare a management API token and a unique strong database password in the
   password manager. The management token is not an anon/publishable application
   key, and a database password is not a service-role API key.
4. Do not create the same project manually if Pulumi will later own creation.
   Existing resources need a separately authorized adoption path. Keep new
   proposals Nano/Free and disable paid add-ons/branching.
5. Plan schema migrations, RLS, backups and application connectivity separately;
   project creation supplies none of those guarantees. Review inactivity behavior
   in [Supabase pricing](https://supabase.com/pricing).

### Neon, Render, Vercel, Netlify and Fly.io: prospective only

| Provider | Onboarding sequence | Decision before preparing any deployment |
| --- | --- | --- |
| [Neon](https://neon.com/pricing) | Sign up, select Free, secure login, record org/project and region; use a restricted API key and store database connection credentials separately | Free signup does not require a card; check current CU-hours, branch count, storage and transfer before creating branch environments |
| [Render](https://render.com/docs/free) | Sign up, connect only the needed Git repository, choose a workspace/region and explicitly select Free for a web service | Confirm the current verification/payment prompt and reject paid disk/instance upgrades; Free Postgres is not permanent storage; build/bandwidth usage is separate |
| [Vercel](https://vercel.com/docs/plans/hobby) | Sign up, choose Hobby, connect the intended Git repository, inspect detected build/function configuration | Confirm personal noncommercial eligibility; reject a paid team/add-on requirement; static deployment can still include generated serverless routes |
| [Netlify](https://www.netlify.com/pricing/) | Sign up, choose Free, connect the intended repository, review build/publish directory and generated functions | Verify current credit plan rather than legacy allowances; review over-limit behavior and avoid enabling paid upgrades/recharge |
| [Fly.io](https://docs.fly.io/about/pricing) | Review current pricing before creating an organization or entering payment details | No new-account permanent-free Machines target; skip deployment under this project's strict-free requirement |

For no-card Free plans, use the Free signup path and stop to review any unexpected
paid subscription prompt. A saved payment method neither proves nor disproves
free eligibility. Do not disable payment verification or assume a missing card
prevents resource suspension/data loss. UI names and eligibility can change.

## 3. Install the workspace and run the task runner

The actual task runner is the `infra` console command, installed by `infra-program`.
There is no required Make/Task/Poetry wrapper. The workspace has `infra-core`,
`infra-program` and the vendored Supabase SDK, with one root lockfile.

Use Linux x64 and the pinned toolchain. Root Python requirement is 3.12.x;
`.python-version` pins 3.12.14. uv is 0.12.5 and Pulumi is 3.272.0. The reviewed
installer also supplies the security/workflow tools. From a trusted checkout:

```sh
python3 .github/scripts/install-tools.py
export PATH="$PWD/.infra/tools/uv:$PWD/.infra/tools/pulumi:$PATH"
uv sync --locked --all-groups
uv run --locked pre-commit install
uv run --locked infra --help
uv run --locked infra backend inspect
uv run --locked infra verify
```

Installation downloads verified tools/dependencies and needs network access.
Verification itself needs no cloud credentials. A missing binary/checksum failure
is a setup failure; do not skip a check or substitute an unreviewed version.
The gate checks secrets, tracked artifacts, architecture, documentation commands
and links, workflows, lint, formatting, types and tests. Some real-engine/provider
integration gates require explicit opt-in; a normal pass is not a live preview.

Read [HARNESS.md](../HARNESS.md) and the
[trusted-toolchain runbook](runbooks/trusted-toolchain.md) for pin updates and CI.
Do not edit the generated SDK or install packages dynamically during a deployment.

## 4. File and configuration manifest

Create a private working directory with restrictive permissions:

```sh
umask 077
mkdir -p .infra
chmod 700 .infra
cp -n config/account.example.toml .infra/account.toml
cp -n config/oci.example.toml .infra/oci.toml
cp -n config/cloudflare.example.json .infra/cloudflare.json
cp -n config/supabase.example.json .infra/supabase.json
```

Only copy the examples needed for your provider. They deliberately fail until
real configuration/evidence is supplied. Never mark `verified=true` or change a
timestamp simply to make a validation pass.

| File | Contents and ownership |
| --- | --- |
| `config/pulumi.toml` | Reviewed project/backend identity, passphrase policy, four disabled stack identities and dependencies; not a credential file |
| `config/quotas/profiles.toml` | Dated published terms/profile revisions; enabled classification does not enable execution |
| `.infra/account.toml` | OCI tenancy, home region, selected profile/revision, real verification and external reservations |
| `.infra/oci.toml` | Foundation region/compartment, approved admin CIDRs, AD/service network evidence, node sizes, Kubernetes version and ARM image review |
| `.infra/cloudflare.json` | Existing account/zone IDs, DNS resource keys/props; no token fields |
| `.infra/supabase.json` | User/org IDs, project region/name/key and per-meter remaining-cycle growth budgets; no password/token fields |
| `.infra/usage.json` | Authoritative OCI current-month totals, original observation and completeness watermark; see the governance runbook for schema |
| `.infra/inventory.json` and `.envelope.json` suffix | Collected OCI inventory and adjacent exact-byte binding sidecar |
| `.infra/cloudflare-evidence.json`, `.infra/supabase-evidence.json` and sidecars | Complete provider-specific evidence; preserve bytes and collection clocks |
| `packages/infra-program/Pulumi.<stack>.yaml` | Conventional encrypted stack config location beside `Pulumi.yaml`, only once an approved stack exists; ignored by Git |
| Outside checkout: OCI INI and signing key | Explicit credential file/profile; key mode 0600, containing directories 0700 |

Sidecar naming is literal: `.infra/inventory.json.envelope.json`, not
`.infra/inventory.envelope.json`. Protected operations stage reviewed encrypted
configuration into isolated temporary workspaces; they do not implicitly select
a production stack from your current directory.

There is **no automatic `.env` loading**, and root `.env` is not currently ignored.
Prefer a password-manager/environment injection mechanism. If an operator needs
a local shell file, use ignored `.infra/operator.env`, mode 0600, and explicitly
load only that trusted file in the relevant short-lived shell. This remains
plaintext secret storage, unlike Pulumi encrypted config. Never commit it or
paste its contents into an issue/log. Do not use `set -x` around credentials.

### Required secret and environment contracts

Offline verification/proposal/audit commands need no tokens. Read-only collection,
protected preview and eventual mutation have different credential requirements.

| Name | Required where / source |
| --- | --- |
| `PULUMI_CONFIG_PASSPHRASE` | Protected state operations; random secret at least 20 characters, held separately from encrypted state/config backups |
| `OCI_S3_ACCESS_KEY`, `OCI_S3_SECRET_KEY` | GitHub environment secrets for OCI state access; workflows map these to `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Runtime S3-compatible backend credentials, currently OCI customer secret keys; not AWS workload credentials |
| `AWS_SESSION_TOKEN` | Optional runtime session token if the reviewed backend credential mechanism uses one; not required for ordinary OCI HMAC keys |
| `OCI_BACKEND_AUDIT_CREDENTIALS` | Protected read-only backend audit secret JSON: `tenancy`, `user`, `fingerprint`, `key_content`; optional `pass_phrase` |
| `BACKEND_POSTURE_ACCOUNT_ID` | Independently reviewed GitHub environment variable identifying backend tenancy; not inferred from a credential blob |
| `OCI_RESOURCE_PREVIEW_CREDENTIALS` | OCI preview secret JSON: `tenancy`, `user`, `fingerprint`, `key_content`; separate resource reader principal |
| `OCI_USER_OCID`, `OCI_FINGERPRINT`, `OCI_PRIVATE_KEY_PATH` | OCI execution environment; previews derive them from explicit reader config. Apply/import workflow uses the first two environment secrets and a runner-local path variable for the third |
| `SERVICE_API_TOKEN` | Unit-specific GitHub preview environment secret; mapped to `CLOUDFLARE_API_TOKEN` or `SUPABASE_API_TOKEN` |
| `CLOUDFLARE_API_TOKEN`, `SUPABASE_API_TOKEN` | Read-only service observation handoff. Mutation credentials in encrypted Pulumi config are a separate contract |
| `SERVICE_PREVIEW_INPUTS`, `OCI_PREVIEW_INPUTS` | Protected JSON bundles containing reviewed config/evidence/qualification and encrypted configuration; use the exact handoff schema in the preview workflow/script |
| `cloudflare-edge:token` | Pulumi encrypted config key for the Cloudflare component provider |
| `supabase-database:token` | Pulumi encrypted config key for the Supabase management provider |
| `supabase-database:databasePassword-<resource-key>` | One encrypted password for each proposed Supabase resource; example key `database` requires `databasePassword-database` |

The factory calls `pulumi.Config(unit).require_secret(...)` after evidence checks.
Exporting a token environment variable does not substitute for its encrypted
stack config key. Conversely the observation workflow still requires its explicit
reader token even if a provider token is encrypted in a stack file.

Additional contracts only for separately commissioned operations:

| Workflow | Additional secrets/variables |
| --- | --- |
| Apply/import | `OPERATION_OBSERVATION_TOKEN` maps to `GH_TOKEN`; `SERVICE_APPLY_BUNDLE/JOURNAL`, `OCI_APPLY_BUNDLE/JOURNAL` or `RESOURCE_IMPORT_BUNDLE/JOURNAL` point to prepared private evidence. Slash here abbreviates two variables, e.g. `SERVICE_APPLY_BUNDLE` and `SERVICE_APPLY_JOURNAL` |
| Recovery | `RECOVERY_S3_ACCESS_KEY`, `RECOVERY_S3_SECRET_KEY`, `RECOVERY_PASSPHRASE`, `RECOVERY_BACKUP_PASSWORD`; OCI recovery reader has `OCI_RECOVERY_USER_OCID`, `OCI_RECOVERY_FINGERPRINT`, `OCI_RECOVERY_PRIVATE_KEY_PATH`; `STATE_RECOVERY_BUNDLE`, `STATE_RECOVERY_JOURNAL` |
| Recovery rehearsal | `RECOVERY_BACKUP_PASSWORD` maps to `BACKUP_PASSWORD`; `RECOVERY_PASSPHRASE`, `RECOVERY_RECEIPT`; variables `RECOVERY_POLICY`, `RECOVERY_REPOSITORY` |
| Monitoring | `MONITORING_ENABLED`, `MONITOR_INDEX`, `MONITOR_DELIVERY_ENABLED`; separate `MONITOR_DELIVERY_TOKEN` for issue delivery, plus observation/backend credentials for selected unit |

Use each workflow's exact schema and protected environment. Do not populate all
these secrets in a generic developer shell. See
[backend](runbooks/pulumi-backend.md), [services](runbooks/independent-services.md),
[recovery](runbooks/state-recovery.md) and [monitoring](runbooks/scheduled-monitoring.md).

For missing providers there are **no supported config keys here**. A future design
must define GCP federated/ADC credentials, AWS role credentials, Neon/Render API
tokens, Vercel/Netlify deployment tokens, R2 keys or tunnel tokens explicitly.
Setting familiar vendor environment names today will not enable their modules.

### Encrypted config entry after approved stack initialization

Production initialization is currently blocked. Once separately implemented and
authorized, use the exact reviewed backend/project/stack and explicit passphrase
secrets provider. These are interactive config commands for an **already approved
existing stack**, not a way to activate this checkout:

```sh
cd packages/infra-program
pulumi config set --stack cloudflare-edge --secret cloudflare-edge:token
pulumi config set --stack supabase-database --secret supabase-database:token
pulumi config set --stack supabase-database --secret supabase-database:databasePassword-database
```

Omitting the value prompts for it instead of placing it in shell history. Use
only the command appropriate to the selected unit. Confirm the YAML contains
encrypted `secure:` entries and the expected secrets-provider metadata; never
copy plaintext into YAML or use `--show-secrets` for routine inspection. Back up
encrypted config and checkpoint together. Passphrase rotation requires controlled
re-encryption and recovery rehearsal, not just changing an environment variable.

## 5. Initialization, preview and apply workflow

### Current safe workflow

1. Install and verify as above. Inspect backend configuration without logging in
   to a default Pulumi Cloud backend. The existing OCI bucket/prefix is reserved;
   do not reuse externally owned state or initialize a same-named production stack.
2. Prepare only the needed private configs. OCI requires real image/AD/version and
   network evidence; the public example is not runnable provisioning input.
3. Render the offline OCI proposal after replacing `ACCOUNT_ID` with the reviewed
   tenancy. This command makes no provider calls:

```sh
uv run --locked infra oci proposal --config .infra/oci.toml --account-id ACCOUNT_ID > .infra/proposal.json
```

4. This produces the normalized governance proposal for creating both OCI units.
   Inspect it against [free-tier governance](runbooks/free-tier-governance.md).
   Existing resources require independently reviewed ownership/change mappings;
   the generated create-only proposal is not an adoption or update plan. Do not
   feed a raw Pulumi engine preview to `--plan`. Review all affected units and
   existing ownership before claiming completeness.
5. Collect current evidence and audit it using section 6. Evidence binds the clean
   reviewed Git commit/configuration. Uncommitted work or a subsequent config/commit
   change invalidates that binding; recollect rather than editing sidecars.

The following commands are useful **expected denials** under tracked configuration:

```sh
uv run --locked infra preview --unit oci-network
uv run --locked infra deploy --unit oci-network
```

Likewise, direct `pulumi preview` or `pulumi up` in `packages/infra-program` is not
the supported deployment path: the normal program has no approved context and
fails. Do not bypass the dispatcher by replacing `__main__.py`, enabling flags,
removing policy or manually invoking component constructors.

### Isolated backend initialization test

An operator may explicitly opt into a **local synthetic** qualification:

```sh
uv run --locked infra backend qualify --local-test --allow-backend-writes
```

It initializes disposable local state with synthetic data and exercises encryption,
locking and recovery. It creates no provider resource and does not qualify OCI.
Real remote qualification requires the protected workflow, dedicated credentials,
fresh posture evidence and explicit authorization described in the backend runbook.

### Eventual approved production workflow

The intended engine sequence is initialize/select the explicit stack with
`--secrets-provider passphrase`, generate a policy-checked saved plan using
`pulumi preview`, then apply exactly that approved plan using `pulumi up`.
Here those engine actions must be supplied by the protected orchestration with
bound evidence, not a standalone copy-paste shell recipe. Production stack
initialization itself remains an activation prerequisite.

Before any execution, an operator and reviewer must resolve the ten readiness
gates: trust/runner enrollment, backend posture, independent backup/recovery,
account entitlement, writer exclusion, unit-specific readiness, ownership,
monitoring and the remaining acceptance items in
[operational readiness](runbooks/operational-readiness.md). Use the exact staged
procedure for the selected unit; a successful preview never grants apply authority.

The saved operation must bind commit, config, checkpoint and plan digests to the
unit/account, approvals and journal predecessor. Inspect creates, updates,
replacements and deletes; forecast replacement overlap and retained storage.
Recollect stale evidence. Execute through the protected unit apply workflow only
after separately authorized activation; stop on unknown outcome and reconcile
journal/state before retrying. Do not run auto-approve or a second writer.

### Stack execution order

| Unit | Prerequisite | Operational order |
| --- | --- | --- |
| `oci-network` | Qualified backend/account/ownership | First OCI resource stack |
| `oci-oke` | Validated committed `oci-network` output contract and matching digest | After network commit; preview outputs/unknown IDs cannot substitute |
| `cloudflare-edge` | Existing zone and its own evidence/credentials | Independent of OCI in current code; no automatic endpoint linkage |
| `supabase-database` | Existing Free org, user-wide project count and org usage | Independent of OCI/Cloudflare; no automatic SQL/app wiring |

Separate states do not mean separate free allowances. Serialize shared-account
changes. Eventual teardown reverses real dependencies, requires backups and an
explicit destructive operation review; `pulumi destroy` is not a billing check.
Do not remove protection or delete state to make a replacement fit.

## 6. Verify usage and remaining allowance

### Read-only OCI collection and offline checks

Run from a clean reviewed checkout with an authorized reader and authoritative
current-month usage file. Optional SDK setup:

```sh
uv sync --locked --all-groups --extra inventory-oci
uv run --locked --extra inventory-oci infra governance inventory \
  --account .infra/account.toml --oci-config /private/path/oci-config \
  --oci-profile DEFAULT --usage .infra/usage.json --output .infra/inventory.json
uv run --locked infra governance audit \
  --account .infra/account.toml --inventory .infra/inventory.json \
  --plan .infra/proposal.json
```

Replace the private credential path. Prepare `.infra/proposal.json` as the complete
normalized proposal, not a partial stack. Inventory scans all subscribed READY
regions/compartments and counts stopped/retained resources. It does not discover
every billable OCI product. Independently inspect backups, Object Storage including
state history, network egress, public addresses, paid images, load balancers and
other services in Cost Analysis before attesting `other_services_reviewed`.

Check account/profile identity, inventory capacity, replacement peak and each
monthly meter. Published profile review expires after 90 days, entitlement after
30 days and inventory/usage after 15 minutes. The usage watermark is the time
through which the provider proves totals complete, not the download time. The
OCI Usage API collector currently leaves this watermark unknown; its success
does not produce admissible complete usage. Stop if authoritative fresh evidence
cannot be obtained. Never manufacture zero totals, restamp or reduce scope.

### Cloudflare and Supabase

```sh
uv run --locked infra services audit \
  --config .infra/cloudflare.json --evidence .infra/cloudflare-evidence.json
uv run --locked infra services audit \
  --config .infra/supabase.json --evidence .infra/supabase-evidence.json
```

These read local files; they do not query provider APIs. Each evidence file needs
its adjacent `.envelope.json` sidecar. Existing read-only collection library APIs
are `infra_core.inventory.cloudflare.collect_zone` and
`infra_core.inventory.supabase.collect_management`; capture/join helpers live in
`infra_core.service_evidence`. Their exact inputs and required operator supplements
are in [independent services](runbooks/independent-services.md). Cloudflare has an
explicit [collection command](runbooks/independent-services.md#cloudflare-collection-command-m07-pr6)
using an independent review and private token file; Supabase collection remains a
library API. Do not write a fake supplement from example values.

Cloudflare checks every existing DNS record, including unmanaged records outside
the supported creation types. Supabase requires all relevant Free projects,
database sizes, original organization billing anniversary, per-metric coverage
and reviewed growth through cycle end. Current storage capacity cannot substitute
for cumulative GB-hours; daily MAU sums cannot substitute for distinct cycle MAU.
Read the dashboard's organization usage and project database metrics independently.

### Optional Python validation driver via uv

This example composes the existing validators; it does **not** collect usage,
authenticate evidence, authorize execution or validate unimplemented providers.
Save it as `.infra/check_usage.py`. It prints only per-check status; inspect a
failed validator privately rather than uploading its raw output.

```python
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
checks = {
    "oci": ["governance", "audit", "--account", ".infra/account.toml",
            "--inventory", ".infra/inventory.json", "--plan", ".infra/proposal.json"],
    "cloudflare": ["services", "audit", "--config", ".infra/cloudflare.json",
                   "--evidence", ".infra/cloudflare-evidence.json"],
    "supabase": ["services", "audit", "--config", ".infra/supabase.json",
                 "--evidence", ".infra/supabase-evidence.json"],
}
selected = sys.argv[1:]
if not selected or any(name not in checks for name in selected):
    raise SystemExit("Select one or more: oci cloudflare supabase")
failed = False
for name in selected:
    try:
        result = subprocess.run(
            [str(root / ".venv/bin/infra"), *checks[name]],
            cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=120, check=False,
        )
        ok = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        ok = False
    print(f"{name}: {'evidence checks passed' if ok else 'BLOCKED'}")
    failed = failed or not ok
raise SystemExit(1 if failed else 0)
```

```sh
uv run --locked python .infra/check_usage.py oci cloudflare supabase
```

Select only configured providers; missing files fail instead of counting as zero.
Run after fresh collection, before each proposed change and during operator
reviews. A script run before month end cannot guarantee there will be no subsequent
usage. Do not schedule it against snapshots that will inevitably be stale.

### Manual verification for prospective providers

| Provider | Inspect before any future integration is accepted |
| --- | --- |
| GCP | Billing Reports by SKU across all linked projects; eligible VM hours/regions, standard disk GB-months, snapshots, IPv4/NAT and egress; quota screens are capacity ceilings, not free entitlement |
| AWS | Billing Free Tier and account-plan/credit expiry, Bills by service/region, DynamoDB provisioned capacities including indexes/storage, Lambda requests and GB-seconds, logs/API/transfer; separate credits from recurring discounts |
| Workers/Pages/R2 | Account Workers daily request/CPU usage, Pages build count, Functions use and R2 Standard storage/Class A/Class B operations; DNS record count alone is irrelevant to those meters |
| Neon | Project CU-hours, every branch's storage, transfer, autosuspend and current Free plan |
| Render | Workspace hours, bandwidth, pipeline usage, service plan, disk attachments and database expiry |
| Vercel | Hobby eligibility, delivery, function compute/invocations, image/build limits and paid integrations |
| Netlify | Team plan and credits used by production deploys, compute, requests and bandwidth; legacy plans require their own terms |
| Fly.io | All machines, stopped-machine storage, volumes/snapshots/IPs and invoiced usage; no permanent-free admission |

Use the [audit's official pricing links](MULTI_PROVIDER_AUDIT.md) to compare actual
usage. Unsupported providers do not receive an automated pass from this repository.

## 7. Billing alarms and review schedule

Set alerts before activation. A small currency budget is an alarm threshold,
not permission to spend that amount and not proof of zero cost. Where the console
requires a positive budget, use the smallest useful threshold accepted by the
provider and review any nonzero charge. Check gross usage as well as net cost.

### OCI

1. Open Billing & Cost Management, Budgets; create a monthly budget with scope
   covering the intended tenancy/compartments and all relevant services.
2. Open the budget's Budget Alert Rules and create actual-spend and forecast-spend
   rules with explicit operator/reviewer recipients. Prefer an early absolute
   amount and a forecast threshold; do not rely solely on a late 100% email.
3. Verify saved scope, recipients and actual delivery through the available
   provider test or a separately reviewed notification test. Record the result.
   Forecast alerts need usage history; they are not instantaneous prevention.
   [Oracle alert procedure](https://docs.oracle.com/en-us/iaas/Content/Billing/Tasks/create-alert-rule.htm).

### GCP

1. Open Billing, select the correct billing account, then Budgets & alerts.
2. Create an alerts-only budget spanning all relevant projects/services; set
   actual and forecast thresholds and named recipients. Review credit treatment
   so trial credits cannot conceal underlying consumption.
3. Confirm notification delivery and compare SKU usage separately. Google now
   also documents spend-cap budgets for supported services; validate their exact
   coverage before relying on one. Do not assume a spend cap covers Compute,
   networking or every linked project merely because the UI offers it.
   [Budgets](https://docs.cloud.google.com/billing/docs/how-to/budgets),
   [spend-cap coverage](https://docs.cloud.google.com/billing/docs/how-to/budgets-spend-caps).

### AWS

1. Open Billing and Cost Management, Budgets; use the zero-spend template where
   offered, or a small custom monthly cost budget. Confirm payer/account scope.
2. Add actual and forecast notifications, verify recipients and enable available
   Free Tier usage notifications. Inspect credit expiry separately.
3. Test/confirm delivery without generating billable workloads. If creating a
   CloudWatch estimated-charge alarm, separately verify its region, metric and
   alarm pricing; it is not required by this repository. Budget actions also need
   separate IAM/impact review and are not a universal hard spending cap.
   [AWS budget procedure](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-create.html).

### Other providers and cadence

Enable available usage notifications in each account and confirm their recipients.
Where no alert exists, assign an operator review rather than claiming automated
coverage. Keep Free-plan limits/auto-upgrade behavior under review; an organization
plan upgrade can change billing even if resource size does not change.

| When | Operator action |
| --- | --- |
| Before every change | Fresh entitlement/inventory/usage, complete proposal, replacement peak, backup and exact plan review |
| Daily while active | Inspect alarms and usage growth, unexpected resources, monitor heartbeat and billing lag; investigate any nonzero cost |
| Weekly | Reconcile external/manual resources, retained storage and tokens; check inactive/paused services and backup restore readiness |
| 7 days and 48 hours before each reset | Forecast through the actual billing-cycle end; include application traffic, builds and retained storage; reserve a conservative margin |
| After billing data settles | Compare the closed-period invoice/SKUs with captured usage; investigate credit dependence and unexplained charges |
| On terms/plan change, at least every 90 days | Re-review official terms and profiles; account entitlement must separately stay within its 30-day window |

OCI usage uses UTC calendar months; Supabase validation uses the actual org
anniversary, not necessarily the first of the month. Workers requests reset daily
at UTC boundaries. Always record provider timestamps in the evidence's required
timezone-aware format, even if operators work in another local timezone.

Suggested internal thresholds are 70% investigate, 85% freeze discretionary growth,
95% execute the pre-reviewed load-shedding plan, or earlier if forecasts require.
These are recommendations, not existing code limits. Runtime throttling must
cover requests/uploads/build triggers as well as provisioning. Stopping a VM
does not remove retained storage costs. Preserve data before destructive cleanup.

The repository's monitor workflow is not commissioned: tracked observation and
delivery remain disabled. Follow [scheduled monitoring](runbooks/scheduled-monitoring.md)
to establish runner, durable state, heartbeat and delivery evidence. Do not claim
alerts are active just because YAML is present or a local audit passed.

## 8. Maintenance, failures and recovery

| Symptom | Response |
| --- | --- |
| Preview/deploy denied | Expected baseline; inspect readiness and activation status, not credentials first |
| Dirty checkout / envelope mismatch | Finish review/commit, then capture fresh evidence bound to that commit/config; never edit hashes |
| Stale or missing usage watermark | Recollect authoritative usage; unknown remains blocked even if a provider API returned successfully |
| Capacity exceeded during replacement | Account for overlap/retained resources; redesign or obtain a separately reviewed maintenance plan, never erase inventory |
| A1 out of host capacity | Retry later or review availability; never auto-fallback to paid shape/region |
| Secret decryption fails | Verify stack/backend and custody; preserve ciphertext/old key, do not initialize replacement state or overwrite passphrase |
| Indeterminate update / lost acknowledgement | Freeze writers, inspect journal and remote state with authorized tooling; no automatic retry |
| Unexpected charge / forecast breach | Stop discretionary changes, identify service/SKU/region and affected credentials, apply reviewed traffic controls, retain evidence and contact provider support if needed |

Rotate provider tokens separately from database passwords and Pulumi encryption
keys. Check every consumer, update encrypted configuration through an approved
operation, verify the new credential and revoke the old one. Review GitHub branch
and environment protections independently of workflow source.

Back up encrypted checkpoints and stack configuration as a pair to an independent
location, with separate key custody and measured restore tests. Pulumi state is
not a database backup: separately test data export/restore and application
recovery. Recovery tools and protection changes need explicit operational
authorization; use [state recovery](runbooks/state-recovery.md) and
[backend recovery](runbooks/pulumi-backend.md).

When retiring a service, review dependencies, exports and retained resources,
then perform only the authorized cleanup. Keep active state out of lifecycle
expiry rules, reconcile remaining volumes/objects/versions and continue invoice
checks until the provider's reporting period settles. Removing a stack file or
repository code never proves cloud resources were removed.
