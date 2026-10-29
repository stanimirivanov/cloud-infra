# Kubernetes resource governance and cutover preparation

This stage adds offline checks and review artifacts. It does not connect to a
cluster, read kubeconfig, install Calico/controllers, provision infrastructure,
enable a deployment identity or change either state system. The normal Pulumi
program and CLI preview/deploy remain unconditional denials. A consistent evidence
bundle is not cutover authorization.

## Map and supported scope

```text
config/kubernetes.example.toml                Incomplete cluster/namespace budget template
config/cutover.example.json                   Incomplete private evidence index
packages/infra-core/src/infra_core/
  kubernetes/config.py                       Typed envelopes, strict TOML and integer units
  kubernetes/resources.py                    Admission controls and closed desired-object schema
  kubernetes/audit.py                        Cluster allocation/current usage/rollout sensors
  cutover.py                                Read/hash evidence + read Git metadata only
packages/infra-program/src/infra_program/governance.py
                                             Same resource rules in mandatory Pulumi policy
tests/test_kubernetes.py, test_cutover.py      Synthetic positive and negative evidence
```

The reviewed workload subset is stateless Linux/ARM apps/v1 Deployment plus
internal ClusterIP Service. Each container must have explicit positive CPU,
memory and ephemeral-storage requests and limits, with requests <= limits.
CPU uses integral cores or millicores; memory/storage use integral Mi/Gi. Unknown,
negative, zero, fractional, nonfinite and unsupported quantity forms fail rather
than being rounded or treated as zero. Every workload pins an image digest,
selects Linux ARM nodes, disables service-account token mounting and uses
non-root RuntimeDefault seccomp, read-only root filesystem, no privilege
escalation and dropped ALL capabilities. Digest syntax does not prove ARM image
compatibility; verify the actual registry manifest before activation.

Host namespaces, volumes, init/ephemeral containers, runtime classes, pod-level
resources, resize fields, unreviewed overrides and unknown object fields fail.
Their scheduling/security behavior needs an explicit model before support.
PVC/PV/StorageClass, StatefulSet, DaemonSet, Job/CronJob, autoscalers, RBAC, CRDs,
Ingress/Gateway, Helm/YAML wrappers and unknown kinds are denied. Lists are only
accepted as the top-level audited JSON bundle; nested wrapper objects are rejected.
Services must be explicit ClusterIP with one bounded TCP port and a selector; no
annotations, external IPs, ExternalName, NodePort or LoadBalancer configuration.

The Pulumi callback uses the actual core token group, for example
kubernetes:core/v1:Service, translating it to the v1 manifest API. Resource-local
callbacks cannot prove complete cluster capacity or control ordering. Kubernetes
provider registration remains denied until a later reviewed activation path.
There is no new Kubernetes SDK dependency or deployment component in this PR.
The adapter materializes the policy SDK's nested mapping/sequence proxies and
converts exactly representable finite whole protobuf doubles to integers. Unknown
values keep the SDK's unknown-value behavior; pure JSON/TOML validation stays
strict. As with the OCI rules, callbacks skipped for unknown preview values cannot
replace complete preflight and live admission checks.

## Namespace admission baseline

Each configured application namespace gets exactly four objects:

| Object | Contract |
| --- | --- |
| Namespace | Restricted Pod Security enforce/audit/warn labels pinned to the reviewed cluster minor |
| ResourceQuota | Equal aggregate request/limit ceilings for CPU/memory/ephemeral storage; bounded pods, services and deployments; zero PVC/storage/LB/NodePort and unreviewed controller quotas |
| LimitRange | Equal default requests/limits and explicit container min/max inside the namespace envelope |
| NetworkPolicy | Select all pods; deny all ingress and egress |

System/default namespaces are excluded. The full audit requires canonical controls
matching the configured envelopes; missing/changed/duplicate controls or objects
in another namespace fail. No control is applied by rendering or checking it.

Default deny is a quarantine baseline: application DNS and all external egress are
blocked. Scoped DNS/application exceptions require separate design and policy
tests; do not add a wildcard exception as a deployment workaround. NetworkPolicy
objects alone do not implement isolation. Oracle documents installing a compatible
policy engine alongside OCI VCN-native CNI; selecting/installing one, accounting
for its resource use and proving enforcement are explicit operational gates.
This stage does not claim complete Pod Security Standards/OpenAPI validation.
Review all policies selecting a pod: a default-deny object does not cancel a
separate allow rule. Evidence must demonstrate isolation, not just controller presence.
Server admission, image/runtime compatibility and scheduling placement must be
tested separately, including failures for forbidden objects. Cluster administrators
or clients bypassing the governed path are outside these static checks.

Sources: [Kubernetes quota object limits](https://kubernetes.io/docs/tasks/administer-cluster/quota-api-object/),
[CPU/memory quotas](https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/quota-memory-cpu-namespace/),
[Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/),
[sidecar/effective resource accounting](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/)
and [Oracle network policy enforcement](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengsettingupcalico.htm).

## Configuration, evidence and accounting

Copy config/kubernetes.example.toml to private .infra/kubernetes.toml. Supply real
OCI account/cluster IDs, region and policy_version=v1.MINOR from the reviewed
cluster version. Budget namespace limits and additional platform/growth headroom
in integer cpu_m, memory_mi, ephemeral_mi and pods. Namespace service/deployment
counts are also explicit positive integers. Example identities/version remain
empty so the template cannot accidentally pass as evidence.

Prepare a normalized cluster JSON snapshot with the following exact fields:

```json
{
  "schema_version": 1,
  "account_id": "ocid1.tenancy.oc1..REPLACE",
  "cluster_id": "ocid1.cluster.oc1.eu-frankfurt-1.REPLACE",
  "region": "eu-frankfurt-1",
  "policy_version": "v1.REPLACE",
  "node_ids": ["ocid1.instance.oc1..REPLACE"],
  "observed_at": "REPLACE_WITH_CURRENT_UTC_ISO_TIMESTAMP",
  "complete": false,
  "source": "Reference to authoritative read-only cluster and quota observations",
  "network_policy_enforced": false,
  "allocatable": {"cpu_m": 0, "memory_mi": 0, "ephemeral_mi": 0, "pods": 0},
  "unmanaged_used": {"cpu_m": 0, "memory_mi": 0, "ephemeral_mi": 0, "pods": 0},
  "namespaces": {
    "applications": {"cpu_m": 0, "memory_mi": 0, "ephemeral_mi": 0, "pods": 0, "services": 0, "deployments": 0}
  }
}
```

This intentionally failing shape example is not usage data. No collector or zeros
are fabricated. An operator must normalize complete authoritative observations:

- allocatable is the measured aggregate for the reported Ready, schedulable ARM
  nodes, after kubelet/system reservations. node_ids are unique OCI instance IDs
  from the nodes' actual provider IDs, not inferred from display names.
- unmanaged_used includes current system, network-policy engine, add-on and other
  namespace consumption; configured reserved is additional headroom, not the same
  usage repeated. Account for scheduling/runtime overhead and injected containers.
- Each managed namespace has all six counters, including zero only when actually
  observed. CPU/memory/storage usage conservatively uses the higher of effective
  requests and limits/current allocated values. Include sidecars, effective init
  requests, overhead, terminating/non-terminal pods and object counts. Existing
  unsupported workloads require review rather than omission.
- Evidence must match the account/cluster/region/minor and be no more than 15
  minutes old, with verified policy-engine enforcement. Missing permission,
  partial coverage or unavailable metrics cannot become a passing snapshot.

Accounting reserves the sum of every namespace envelope plus unmanaged usage and
extra headroom inside measured allocatable. Within each namespace, current usage
is added to all proposed Deployment replica+integer-surge peaks and services.
Multiple containers/deployments/namespaces cannot spend the same capacity twice.
Recreate has zero new surge; existing usage still counts. RollingUpdate requires
integral bounded maxSurge/maxUnavailable and retains one revision. Percentages
and unknown values fail. Existing deployments are not subtracted by name, so this
create-only preparation model can conservatively reject updates. Namespace quotas
also cap admission of non-terminal/terminating pods; a rollout may pause/fail
rather than exceed its envelope. Aggregate arithmetic does not prove per-node fit,
availability, eviction behavior, actual limits enforcement or zero billing.

```sh
uv run --locked infra kubernetes render --config .infra/kubernetes.toml > .infra/kubernetes-resources.json
uv run --locked infra kubernetes audit --config .infra/kubernetes.toml \
  --inventory .infra/cluster-inventory.json --resources .infra/kubernetes-resources.json
```

The JSON List may include reviewed desired
Deployment/Service objects in addition to the canonical controls. Keep manifests
and all live evidence private. Passing returns within-kubernetes-envelope with
deployment_authorized=false. Workloads, admission objects and network controllers
are never applied by these commands.

## Commit-bound cutover evidence

Copy config/cutover.example.json to .infra/cutover.json. Its fields intentionally
fail until real reviewed evidence is supplied. The checker requires an exact clean
Git commit (tracked and untracked changes fail), current backend configuration
digest, identity scope and a capture timestamp within 15 minutes. Each distinct
artifact must be JSON/TOML inside this checkout's .infra, at most 10 MiB (the
inventory and review sidecars are capped at 64 KiB), with the SHA-256 of its exact bytes.
Escapes, changed/missing/duplicated artifacts fail.
Each artifact is read once with a bounded read and parsed from the same hashed
bytes. The checkout is checked again at completion. If a private file changes
after capture, the result describes the captured snapshot; a subsequent check
against the old index fails. Revalidate evidence before any future operation.

**Breaking schema migration:** the bundle is now schema 5 with twenty-two mandatory
roles. inventory_envelope references the original OCI collector sidecar, normally
.infra/inventory.json.envelope.json; inventory references the corresponding original
payload. Both paths/digests are pinned explicitly and must use distinct files.
Schema-1/2/3/4 bundles and missing sidecars fail closed; recollect current observations
and review a new index rather than restamping old data or merely changing a version.
The public example deliberately retains empty identities, clocks and digests.

The checker passes both bounded hashed snapshots to the existing
[OCI evidence adapter](free-tier-governance.md#oci-inventory-sidecars-m03-pr11-cli-slice).
Expected commit comes from clean Git HEAD, account/home region from the reviewed
account configuration, unit is oci-account, and the digest covers the full account
and selected current quota profile. Never take expected scope from the sidecar.
Original collection clocks must match exactly and remain fresh within 15 minutes;
strict JSON and measured coverage checks precede the full accounting audit.
Recomputing the index hash cannot bypass inner byte/scope/clock binding, and a
bound inventory with missing usage still fails billing checks. Neither file is
reopened: changes after capture affect the next check, not the snapshot under review.
CUT001/CUT002 cover bundle schema/path/size/digest failures; EVID001-EVID004 and
GOV diagnostics cover inner binding and inventory/account validation.

The shared unsigned transport reuses the existing in-toto-style contract without
an additional transport dependency; the signature layer below uses PyCA cryptography.
Backend receipt, Kubernetes and operator report payload schemas below are unchanged.
Service billing history is modeled separately. Configured-key authentication is
required below; independent enrollment/custody and protected-commit provenance
remain pending. Administrative snapshot/policy binding is mandatory below. Rollback requires compatible
code/contracts and weakens inventory/review transport
checks; it never grants authority or upgrades historical evidence.

The existing OCI backend receipt must pass its configuration/version/freshness
checks; local receipts cannot do so. OCI account audit is recomputed with current reviewed profiles and full
inventory/usage. adoption-account-proposal.json must contain exactly the OCI
network and OKE units with empty changes: this check has no permission to create,
resize, replace or delete anything. It is not the create-only OCI render output.
The target cluster must exist in the inventory. Kubernetes node IDs must map to
the observed OCI instances; reported CPU/memory allocatable cannot exceed those
instances. Memory comparison conservatively interprets OCI GB as decimal bytes;
units/allocatable interpretation must be reviewed, not loosened to pass a check.
Disk attachment/allocatable relationships still require live operator verification.
OCI config, Kubernetes config and both inventories must agree on identity/version.

### Exact review-input bindings (M03-PR12 consistency slice)

Schema 5 retains ownership_envelope, preview_envelope, health_envelope
and rollback_envelope, each a distinct private JSON file with an explicit index hash.
The public example supplies names only; identities, clocks and hashes stay empty.
Each cutover-review envelope binds seventeen named subjects: all fourteen
artifact roles (including the OCI inventory envelope and all four report payloads),
plus quota_profiles, reviewer_policy and administrative_policy, the exact bytes of
tracked config/quotas/profiles.toml, config/cutover-reviewers.toml and
config/administration.json. The administration role contains the original private
schema-5 main/environment/execution/PR/review observation snapshot. The four review
envelopes and four DSSE signature artifacts are excluded from subjects
to avoid cycles. Finalize the reports and their actual reviewed inputs before
creating these sidecars. Changing any subject, even formatting or an unrelated quota
profile, invalidates all four reviews; merely rehashing the outer index is insufficient.

Use infra_core.cutover_evidence.capture_review(role, subjects, scope=..., now=...)
to return sidecar bytes over the closed SUBJECTS mapping of immutable bytes. Build
scope with review_scope from independently reviewed account_id, region, cluster_id,
clean commit and configuration_sha256=the current FoundationConfig.digest. Unit is
cutover-ROLE, preventing cross-role replay. The scope configuration digest is SHA256
of UTF-8 JSON {backend_sha256: foundation_digest, cluster_id: cluster_id}, sorted keys,
compact separators, ASCII escaping and nonfinite values forbidden. Expected values
at consumption come from clean Git, validated account/Kubernetes inputs and current
foundation configuration, never from a sidecar. Library helpers perform no Git lookup,
file access, source collection or domain audit; consumption retains all semantic checks.

Both envelope clocks must exactly equal that report's original observed_at string.
This is a normalized review instant, not a claim about source collection duration.
The 15-minute report limit and 24-hour rollback limit still apply. Downloading,
rewriting or wrapping a report cannot refresh its observation. A longer rollback TTL
does not permit substituting newer input bytes; review the actual new set again.
Reports must be strict JSON objects without duplicate keys or nonfinite constants.
CUT008 covers report parsing/clock equality; EVID001-EVID004 cover envelope bindings.
All seventeen subjects share the existing 16 MiB aggregate limit, including the tracked
profile/policy snapshots; subjects remain bounded at 10 MiB, reviewer policy and
review envelopes at 64 KiB, administrative snapshot/policy at 1 MiB each, and
DSSE signature files at 96 KiB. The shared envelope count bound is exactly 17;
18 subjects fail, and consumer role sets remain closed.
Profiles, payloads and sidecars are captured before validation and never reopened.

This adapts the existing Apache-2.0
[in-toto Statement subject-set pattern](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
through a small top-level adapter, with no new dependency or external code copying.
Names and roles are significant here. Bare sidecars remain unsigned consistency;
schema 5 additionally authenticates them against configured reviewer keys below.
Neither mechanism proves source truth, causal provenance or administrative approval.
No result grants operational authority.
**Migration:** obtain actual current reviews and matching sidecars, then build a fresh
schema-5 index with all four signature artifacts. Do not restamp old reports or just
update version numbers. Rollback
requires compatible checker/contracts and reviewed evidence together, never activation.

### Configured reviewer-key authentication (M03-PR12 signature slice)

**BREAKING:** schema 5 also requires ownership_signature, preview_signature,
health_signature and rollback_signature. Each private JSON file is a DSSE envelope
with payloadType=application/vnd.in-toto+json, payload=Base64 of the exact corresponding
review-envelope bytes, and exactly one signatures entry containing sig (Base64 of a
64-byte Ed25519 signature) and optional keyid. Standard/URL-safe Base64 is accepted.
The signature covers DSSE v1 PAE, not raw JSON or its digest: ASCII DSSEv1, space,
byte length of type, space, type, space, byte length of payload, space, payload.
See infra_core.review_signatures.preauth for the fixed-type encoding. No signing CLI,
private-key ingestion or signing secrets in CI are introduced; sign externally using
independently approved key custody. The checker verifies the captured bytes before
interpreting the review and never reparses a DSSE payload to obtain different bytes.

config/cutover-reviewers.toml is a closed schema-1 policy with enabled and reviewers.
It ships disabled with an empty list. An enabled policy needs 1-16 entries with exactly
principal, public_key (Base64 of 32 raw Ed25519 bytes), and unique nonempty roles drawn
from ownership, preview, health, rollback. Principal is a stable 1-128-character label
starting with a letter/digit and using letters/digits and _ . : @ / - thereafter;
duplicate public keys are rejected, including
aliases under different principals. Different keys for the same principal permit
explicit rotation. No key is trusted from a signature, payload, environment or URL.
For the requested role, only enrolled keys with that role are tried; reviewed_by must
match the principal of the key whose signature actually verifies. keyid is optional,
unauthenticated and never selects identity or authority. Unknown keys, forged or
replayed bytes, wrong type, disabled/ambiguous policies and mismatched principals fail
CUT009/CUT010 without printing key material or untrusted values.

Any policy/key/role change invalidates prior review bindings. Finalize the seventeen
actual subjects, capture all role envelopes, obtain external DSSE signatures, and
build a new index with hashes for every distinct file. Removing a key revokes it for
checks against the current policy. The current clean Git checkout is the trust root:
this proves possession of a repository-enrolled key, not human/legal identity, MFA,
key custody or that the checkout came from protected main. Independent enrollment,
protected-branch provenance and administrative evidence remain required. Both
operational authorization flags stay false, including after successful verification.
The [administrative sensor](github-administration.md) checks classic main
settings separately; schema 5 now requires that snapshot as a signed subject,
without treating it as GitHub attestation or approval.

The verifier adapts the Apache-2.0 [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
and JSON shape, with the single-signature/Ed25519 profile explicitly restricted here.
It uses [PyCA Ed25519 verification](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ed25519/)
via cryptography==50.0.2 (dual Apache-2.0/BSD), already locked for optional OCI but now
a direct base-runtime dependency; native wheels add about 4-5 MB plus existing locked
CFFI dependencies to a minimal environment. No unrelated packages are upgraded and
no external DSSE implementation, signing framework or network trust client is added.
The fitness sensor permits only the public-key verification primitive and its two
exceptions in infra_core.review_signatures; pure domains retain their import rules.

### Administrative observation consumption (M03-PR12)

The mandatory administration artifact pins a distinct private JSON file, normally
.infra/administration.json. Its original schema-5 bytes and the tracked
config/administration.json bytes join every role's signed subject set. Recollect
with the [administrative sensor](github-administration.md) at the actual clean main
commit; finalize subjects, review envelopes, external signatures and a schema-5
index together. Missing, stale, unsafe, wrong-commit or wrong-policy observations
fail even with fresh valid review signatures. Rehashing only the index cannot
rebind any review to different administrative bytes.

After authenticating all four reviews, cutover passes the already captured snapshot,
administrative policy and reviewer policy bytes to
infra_core.administration.validate_snapshot with the independent clean commit and
review clock. The validator performs no Git, file access, source collection or gh
calls. Both policy hashes, main/environment rules and successful required-check
execution from the pinned main workflow are required. CUT011
covers unavailable administrative policy; ADMIN diagnostics retain their meanings.
Signing these bytes authenticates the configured key holders' review, not the
GitHub server, source truth, human independence or protected-commit history.
Independent reviewer-key enrollment/custody, environment administrator bypass and
protected-commit provenance remain mandatory; both authorization flags stay false.

The ownership/preview/health/rollback reports share these exact header fields:
commit, account_id, cluster_id, region, observed_at, source and reviewed_by.
source is a private reference; reviewed_by must match the enrolled key principal,
not an approval token. Ownership,
preview and health expire in 15 minutes; rollback review expires after 24 hours.

| Report | Additional required fields and rules |
| --- | --- |
| ownership | complete=true, writers_frozen=true, active_operations=0, entries covering every generated OCI graph key exactly once |
| preview | complete=true, graph_sha256, operations exactly matching ownership order; network entries precede OKE |
| health | checks containing exactly nodes-ready, api-authenticated, dns, pod-isolation, quota-admission, arm-image, network-contract |
| rollback | checks containing exactly encrypted-backups, passphrase-recovery, single-owner-rollback, maintenance-window, operator-review |

Every ownership entry has logical_key, id, unit, pulumi_name, pulumi_parent,
provider_region, owner, terraform_address and operation. Names/parents/region/unit
must match the generated OCI graph. IDs and Terraform addresses are unique.
operation=import requires owner=terraform and one distinct source address;
operation=same requires owner=pulumi and terraform_address=null. Ambiguous/dual
ownership, unapproved operations, missing graph entries or a different cluster ID
fail. An entry does not transfer ownership. In particular, importing a resource
does not remove its Terraform ownership; the exclusive-writer transition still
needs an explicitly authorized, rehearsed procedure.

preview.operations is the ordered projection of each entry to logical_key, id,
unit and operation. graph_sha256 is SHA-256 of the current pure OCI proposal JSON
serialized with sorted keys and compact separators, bound to the account ID.
These reports are normalized operator reviews of actual read-only observations;
the checker does not parse raw provider preview/state output. DSSE authenticates
the enrolled key holder only. A real preview containing create/update/delete/replace cannot be
relabelled import/same to pass. Current redesigned networking may require new
resources or disruptive changes and therefore cannot satisfy this unchanged/import
subset until separate reviewed operations address those differences.

```sh
uv run --locked infra cutover check --evidence .infra/cutover.json
```

Success means evidence-consistent, with deployment_authorized=false and
cutover_authorized=false. Hashes and complete/verified flags remain operator inputs;
DSSE verification authenticates only the enrolled key holder, not the source truth
or enrollment process. No result is an authorization token, proof of GitHub
environment protection, live API validation or complete ownership provenance.
Never upload raw state, kubeconfig, secrets or these private reports to public CI.

## Operational sequence and remaining gates

1. Review the OCI adoption mapping and all immutable/security/sizing differences.
   Implement and test separate-stack orchestration and verified NetworkOutputs
   source bindings first; the current combined library must not be aimed at one
   reserved stack. Confirm required main checks and protected-environment reviewers
   administratively. Obtain a separate explicit instruction for operational work.
2. Freeze every external-state/Pulumi/recovery writer, including external automation;
   verify idle locks without deleting them. Capture encrypted backups and encrypted
   stack configuration/passphrase recovery material in controlled storage. Rehearse
   single-owner recovery with synthetic isolated state before a maintenance window.
3. Recollect live inventories, monthly usage, supported versions/images, API/IAM
   access and preview evidence. Verify provider IDs/units and graph bindings.
   Stop for uncovered costs, unsupported fields, changes/replacements or uncertain
   ownership. A missing current prerequisite stays blocked; do not waive it.
4. Under the separately approved procedure, transfer network ownership first,
   verify its versioned contract/source stack, then OKE. Keep resource protection.
   Use operation-specific import/removal steps with one writable owner at every
   checkpoint. Do not bulk import, force state, infer aliases or restore a stale
   external state after Pulumi has modified resources. This repository currently
   provides no executor for those steps.
5. Review and separately authorize any network-policy engine/admission baseline
   installation. Budget it, test API server dry-run and real forbidden-object
   admission in an isolated namespace, and demonstrate network isolation. Verify
   platform DNS health; denied application DNS under quarantine is expected.
   General workload egress and application availability need explicit additional
   policies and probes; this stage deploys no application.
6. Recheck protected ownership, node/API/CNI/DNS health, admission rejections,
   provider billing and drift. If any checkpoint fails, halt writers and follow
   the reviewed single-owner rollback route. Rollback is an authorized operation,
   not automatic restoration of both engines. Record final owner and lock status.

See [OCI adoption boundaries](oci-components.md), [backend recovery](pulumi-backend.md)
and [account governance](free-tier-governance.md). These instructions prepare a
reviewable operation; no cutover, controller installation or approval is performed
by this PR.

## Verification

uv run --locked infra verify and uv build --all-packages use no cluster credentials.
The normal CI/hook tests exercise strict schemas, quantities, surge/current usage,
aggregate capacity, billable/privileged resource denials, evidence tampering,
ownership and deployment freezes. CI's opt-in tests exercise the real Analyzer
RPC host with complete controls, workload and OCI node-pool inputs, accepting
valid inputs and rejecting LoadBalancer at mandatory enforcement. A separate local
CLI preview proves enforcement of the pack on an unreviewed component. No provider
plugin or Kubernetes connection is used. These are policy/consistency tests, not
live admission, scheduling, image or operational readiness tests.

## Ownership preparation checkpoints (M05-PR8)

`uv run --locked infra ownership prepare --evidence .infra/ownership/index.json`
checks one OCI unit before import review. It reads private files and prints a
redacted checklist; it never writes a receipt, changes a journal, edits source
state, imports resources, releases a writer or authorizes ownership transfer.
The existing cutover evidence check and its always-false authorization result are
unchanged. Operational flags and reviewer enrollment remain disabled.

The public [ownership example](../../config/ownership.example.json) is deliberately
incomplete and unusable. Prepare a private schema-1 index with source, target_stack,
entries and artifacts. All artifact references have exactly path and sha256;
paths must be distinct regular files under this checkout's ignored .infra, without
symlink ancestors. Each file/index is bounded to 1 MiB; all artifacts together are
bounded to 4 MiB. The checker rereads every artifact and the index after validation.
No state payloads, IDs, addresses, credentials or backend locators appear in output
or diagnostics. Source state can contain secrets; supply it only through reviewed
private runner custody, never a tracked file or workflow artifact.

### Input contract and review subject

| Artifact | Required contents |
| --- | --- |
| request | Existing schema-1 operation request: import, one of oci-network/oci-oke, exact clean commit, encrypted target-configuration digest, current target-checkpoint digest, expiry and predecessor |
| configuration | Captured OCI configuration JSON with foundation and image objects using the same schema as the OCI apply adapter; existing graph/security/image checks apply |
| encrypted_configuration | Existing OCI encrypted stack configuration encoding: encryptionsalt beginning v1: and an empty config object |
| source_checkpoint | Current Terraform state-v4 JSON with matching lineage/serial and known managed instance IDs; only read locally |
| target_checkpoint | Existing Pulumi encrypted CLI checkpoint export, version 3, with the exact reserved stack root and no pending operations |
| journal | Current fixed .infra/operations/UNIT.json, latest entry prepared for this exact request |
| freeze | Fresh externally reviewed writer-freeze observation over the canonical preparation binding |

Source identity contains engine=terraform, backend_sha256, workspace, lineage and
serial. backend_sha256 is the separately reviewed source-backend locator digest;
workspace/lineage/serial identify the captured source scope. Lineage must be a
canonical UUID, and serial must match the captured state. The checker cannot infer
workspace/backend identity or effective writer exclusion from a state file; those
remain explicit reviewer attestations. It checks metadata consistency, not the
truth of an administrator's claim.

Entries use the existing cutover ownership fields: logical_key, id, unit,
pulumi_name, pulumi_parent, provider_region, owner, terraform_address, operation.
They must cover exactly the selected unit's existing graph. Names/parents/region
must match the reviewed OCI configuration. Imports require owner=terraform, one
distinct managed source address of the matching OCI resource type/ID and no target
ownership of that ID. Same entries require owner=pulumi, terraform_address=null,
and a matching protected target resource with the actual configured provider and
component parent. Source and target cannot both record ownership of a same entry.
Mixed units, duplicate IDs/addresses/keys, unknown owners, extra target resources,
unprotected/dangling target bindings and partial mappings are rejected.

The source reader supports managed state-v4 resources with attributes.id,
optional module addresses and integer/string index_key values. Data resources are
not ownership. Tainted/deposed instances, flat legacy attributes, other state
versions and unknown IDs are rejected. This is a narrow independent reader of the
[Terraform state-v4 representation](https://github.com/hashicorp/terraform/blob/main/internal/states/statefile/version4.go),
not a Terraform state editor or full state validator. It adds no dependency and
copies no upstream code. Keep source-engine/version/provider compatibility review
separate from passing this metadata check. Remote state retrieval/decryption is
outside this command.

The pure ownership.preparation_binding helper constructs the canonical review
subject from the index, request and captured artifact bytes, plus the independently
expected foundation digest and prepared journal head. Its payload includes the
request digest, source identity, target stack, complete ordered mapping,
configuration/foundation digests, source/target checkpoint digests and journal head.
The encrypted configuration is bound through the request. Do not treat computing a
binding as a successful preparation or permission to execute.

The freeze document has exactly schema_version=1, phase=writers-frozen,
binding_sha256, complete=true, other_writers_reviewed=true, active_operations=0,
frozen_at, checkpointed_at, observed_at, expires_at, reviewed_by and writers. Its
writers array contains exactly the source Terraform identity digest and target
Pulumi stack-identity digest, each with frozen=true and active_operations=0. Compute
those identity digests with operations.digest(source) and
operations.digest(target_stack), respectively. Unknown, duplicate or missing
writers fail closed. All clocks require explicit UTC: prepared journal time <=
frozen_at <= checkpointed_at <= observed_at <= now < expires_at <= request expiry.
The complete freeze interval must be no older than 15 minutes. This is the existing
cutover freshness convention, not an asserted operational SLO.

### Preparation sequence and next transitions

1. Review source-backend/workspace identity and exclusive-writer custody. Prepare
   an immutable import request and its prepared per-unit journal using the existing
   operation contract; recording prepared never grants execution authority.
2. Freeze both known writers and review all other automation/administrative writers.
   Capture source and target checkpoints after the freeze. Record source ownership
   honestly: an import does not itself remove Terraform ownership.
3. Construct the exact unit mapping and review the canonical binding. Record the
   externally observed freeze, active-operation count, reviewer and clocks. The
   command independently checks source records, target identities and collisions.
4. Run ownership prepare against the exact clean checkout. A passing result has
   phase=checkpointed, hashes/counts and next_transition=import-review, or
   post-import-equivalence-review if every entry is already same. Execution,
   ownership transfer and writer release authorization are all false. Re-running
   preparation is diagnostic, not replayable operational approval.
5. Retain private artifacts under the reviewed custody procedure. M05-PR9 supplies
   separately admitted import execution; M05-PR10 handles post-import equivalence,
   source release and handoff. Advancing the journal or changing any input requires
   new preparation evidence. This command rejects admitted/running/terminal journals
   rather than resetting them. It never automatically compensates or retries.

Network preparation does not prepare OKE. Use separate requests/checkpoints and
network-before-OKE operational sequencing. If an ownership conflict or uncertain
operation exists, preserve both recorded owners and the freeze for reconciliation;
do not remove a state record to make this check pass. Cryptographic operational
approval, backup/recovery readiness, live identity/security checks and actual
external source release are later independent gates, not established by this
read-only checklist.
