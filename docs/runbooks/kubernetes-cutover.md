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

Use single lines on PowerShell. The JSON List may include reviewed desired
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
inventory sidecar is capped at 64 KiB), with the SHA-256 of its exact bytes.
Escapes, changed/missing/duplicated artifacts fail.
Each artifact is read once with a bounded read and parsed from the same hashed
bytes. The checkout is checked again at completion. If a private file changes
after capture, the result describes the captured snapshot; a subsequent check
against the old index fails. Revalidate evidence before any future operation.

**Breaking schema migration:** the bundle is now schema 2 with thirteen mandatory
roles. inventory_envelope references the original OCI collector sidecar, normally
.infra/inventory.json.envelope.json; inventory references the corresponding original
payload. Both paths/digests are pinned explicitly and must use distinct files.
Schema-1 bundles and missing sidecars fail closed; recollect current observations
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

This slice reuses the existing unsigned in-toto-style contract, without dependencies.
Backend receipt, Kubernetes and operator report schemas below are unchanged. Complete
billing/history modeling and full M03-PR12 provenance/administrative binding remain
pending. Rollback requires compatible code/contracts and weakens inventory transport
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

The ownership/preview/health/rollback reports share these exact header fields:
commit, account_id, cluster_id, region, observed_at, source and reviewed_by.
source/reviewed_by are references, not credentials or approval tokens. Ownership,
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
the checker does not parse raw provider preview/state output or authenticate the
reviewer. A real preview containing create/update/delete/replace cannot be
relabelled import/same to pass. Current redesigned networking may require new
resources or disruptive changes and therefore cannot satisfy this unchanged/import
subset until separate reviewed operations address those differences.

```sh
uv run --locked infra cutover check --evidence .infra/cutover.json
```

Success means evidence-consistent, with deployment_authorized=false and
cutover_authorized=false. Hashes and complete/verified flags are unsigned operator
inputs; someone can recompute them. They detect inconsistency with the reviewed
inputs, not hostile forgery. No result is an authorization token, proof of GitHub
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
