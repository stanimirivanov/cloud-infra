# OCI networking and OKE components

This protected component library and pure proposal renderer do not provision,
adopt, resize or move existing resources. Standalone Pulumi execution, CLI
preview/deploy and all configured deployment identities remain disabled.
Existing external resource/state ownership remains authoritative; source retirement
does not transfer it. Cutover requires a separate explicit operational request.

## Source map and contracts

```text
config/oci.example.toml                         Incomplete operator template
packages/infra-core/src/infra_core/oci/
  config.py                                    Immutable reviewed inputs + strict TOML loader
  graph.py                                     Complete ordered OCI graph and proposal
  security.py                                  Shared resource security sensors
packages/infra-program/src/infra_program/oci/
  components.py                                Native Network/Oke components + governed factory
tests/test_oci.py                               Negative contracts and native SDK graph equivalence
```

The graph contains two logical units, oci-network and oci-oke, consistent with the
reserved stack identities. register_foundation validates inputs and security,
then runs the account-wide capacity/peak/monthly evaluator over the entire graph
before creating the provider or components. It registers native pulumi-oci
resources from those same property dictionaries, resolving typed references to
Pulumi Outputs. A closed constructor table prevents extra resource types. No
OCI lookups, image selection or Kubernetes operations occur in the program.

Every native resource has an explicit provider, parent and protect=True. The
provider pins the reviewed region and tenancy. The guarded Network/Oke
constructors are implementation details; use the governed factories. SDK mock tests
compare every actual resource type, input and reference to the normalized
proposal and enforce provider/protection/import/alias options. Invalid inputs,
missing inventory or failed cost checks are tested with all Pulumi registration
constructors forbidden. The SDK's actual case-sensitive tokens are
oci:Core/... and oci:ContainerEngine/...; old lowercase examples were corrected
because they did not match the native SDK.

NetworkOutputs schema version 1 includes account_id, region, compartment_id,
VCN/API/worker/pod CIDRs, and the VCN, three subnet and three NSG IDs. OKE checks
the schema, account, region, compartment and CIDRs. It consumes network IDs;
networking never depends on OKE. OKE outputs only cluster ID, pool ID and region.
There are no credentials or kubeconfig outputs.

The existing register_foundation factory still composes both logical units for
library consumers; do not point that combined graph at a reserved single-unit stack.
The independent network preview path below registers only oci-network. OKE
StackReference wiring and committed-output validation are described below.

## Independent network preview (M04-PR10)

`network_graph(cfg)` validates the existing FoundationConfig and builds only the
network subset. `register_network(cfg, account, profile, inventory, *, envelope, commit)`
freezes inputs, validates resource security and audits a proposal containing only
oci-network before registering its protected provider/component/resources. All
existing account-wide inventory, usage coverage, entitlement and capacity checks
remain mandatory; existing compute/storage still count even though the network
graph proposes no compute/storage. The optional proposal `units` argument rejects
any resource omitted from the declared units. The combined factory is unchanged.

**BEHAVIOR-ADJACENT:** an explicit `NetworkPreviewContext` can reach this factory
only through SDK dry-run/identity/flag/contract admission. No environment/file loader,
standalone execution or CLI path activates it. Network configuration deliberately
retains full conservative FoundationConfig validation, including image/version,
placement and capacity requirements; this slice introduces no separate config schema.

The stack exports exactly `network` (the existing version-1 account/region/
compartment/CIDR/seven-ID object) and `network_stack_identity` (the explicit full
`organization/free-infrastructure/oci-network` identity). These values contain no
credentials or kubeconfig. Preview IDs may be unknown; preview outputs are not
committed dependency evidence. PR11 must validate actual committed outputs and
source identity before admitting OKE. No source stack is created or selected here.

No import, alias, backend namespace upgrade, state move or adoption is performed.
Existing owners remain authoritative. Reverting this slice restores network preview
denial without affecting resources/state. Tracked preview flags, deployment and
cutover remain disabled; protected driver/workflow activation is still later work.

Focused tests: `uv run --locked pytest tests/test_oci_network.py tests/test_oci.py tests/test_preview_program.py -q`.

## Independent OKE dependency (M04-PR11)

**BEHAVIOR-ADJACENT:** explicit `OkePreviewContext` admission requires SDK dry-run,
the oci-oke identity, its enabled preview flag and the reviewed contract. The only
dependency is `organization/free-infrastructure/oci-network`. `register_oke` runs
the existing full account-wide inventory/usage preflight, then uses the SDK
StackReference read (explicit resource ID), with no stack creation or selection.
The mandatory policy permits only this fully scoped reference and closed SDK
reference fields; it cannot independently prove the engine's read semantics.

The source must export exactly `network` and `network_stack_identity` from PR10.
All output metadata must be known and non-secret, with no secret output names.
The schema-1 object must match expected source/account/region/compartment/CIDRs and
contain seven distinct typed OCIDs. Missing, secret, unknown, malformed or mismatched
outputs fail with OCI041 before any managed resource/provider/component registration.
Adapter errors omit output values and raw diagnostics; SDK/engine logging must also
be isolated by the later constrained driver. Metadata consistency cannot
prove live ownership, authenticity or that referenced resources still exist; trusted
backend custody and administrator-owned live acceptance remain separate requirements.

The exact OKE-only graph binds those IDs while retaining the internal cluster-to-pool
reference. Preflight runs again before managed registration, including freshness,
capacity and monthly budgets. No network resource is recreated. The protected OKE
component depends on the read reference; children retain explicit parent/provider.
The sole stack export `oke` contains schema 1, region, cluster ID and node-pool ID.
It contains no kubeconfig or credentials. Existing combined/network APIs and exports
are preserved; no state, alias, import or backend namespace migration occurs.

Reverting this slice restores OKE preview denial. Tracked preview flags, standalone
program/CLI execution, deployment and cutover stay disabled. The constrained driver
and protected orchestration remain later M04 tasks.

Focused tests: `uv run --locked pytest tests/test_oci_dependency.py tests/test_oci.py tests/test_oci_network.py tests/test_preview_program.py -q`.

## Bound inventory at registration (M03-PR11)

**Breaking library migration:** use
`register_foundation(cfg, account, profile, inventory, *, envelope, commit)`.
Inventory and envelope must be original immutable bytes from the
[OCI collection handoff](free-tier-governance.md#oci-inventory-sidecars-m03-pr11-cli-slice).
account/profile remain reviewed dictionaries; cfg remains FoundationConfig.
Standalone dictionaries, missing binding arguments and mismatched/stale evidence
fail before any provider/component/resource registration. Preserve schema-2 bytes
and original clocks; recollect legacy observations rather than restamping them.

The factory freezes reviewed inputs, builds/validates its own ordered graph and
passes its complete normalized proposal through the common preflight gate. That
gate freezes account/profile/proposal, validates exact-byte/config/scope/clock binding
and measured coverage, then runs full eligibility/capacity/monthly accounting before
invoking the private registration closure. The closure consumes its owned frozen
configuration and graph, so mutation of caller dictionaries during audit cannot
change the emitted tenancy, topology or properties. Network/OKE output schema 1,
resource kinds, SDK serialization and protection/provider rules are unchanged.

The lower-level adapter is
`preflight(account, profile, inventory, plan, register, *, envelope, commit)`.
Its inventory/envelope also require bytes; plan remains a dictionary. It invokes
the callback once after successful validation, but callbacks are trusted Python:
it cannot prove that arbitrary callback code registers the audited plan. Use the
sole OCI composer for that graph contract; this gate is not a sandbox or permit.

Both APIs require an independently established expected clean commit. They do not
discover Git or authenticate sources; never copy expected commit from the sidecar.
A future approved executor must bind its running checkout, reviewed configuration,
stack/backend and real proposal. Sidecars remain unsigned consistency evidence.
Pure accounting retains dictionaries; cutover now requires a pinned inventory
sidecar through its schema-2 review bundle.
Rollback requires compatible code/contracts and weakens transport checks; no version
of this library grants deployment, import or state-transfer authority.

## Topology and security boundaries

| Layer | Component contract | Enforced boundary |
| --- | --- | --- |
| VCN | Explicit RFC1918 CIDR; disjoint regional API/worker/pod subnets | Same default CIDRs, strict overlap/capacity validation |
| Routing | Internet gateway for API/workers; All Services gateway for OCI; pods route only through service gateway | No NAT or load balancer; private pods have no general internet route |
| Subnet firewall | Explicit empty security list on every subnet, with NSGs providing rules | VCN default SSH/egress rules are not implicitly attached |
| API | Public endpoint with explicit administrator IPv4 CIDRs, /24 or narrower, TCP/6443 | No unrestricted public API rule |
| Workers | Public subnet, internal worker/pod communication, control-plane TCP/10250, ICMP fragmentation | No public SSH, NodePorts or unrestricted worker ingress |
| Pods | Private subnet, pod NSG, internal/API/OCI-services communication | Explicit pod security boundary |
| OKE | BASIC_CLUSTER and OCI_VCN_IP_NATIVE at cluster and pool | No enhanced features or paid virtual pools |
| Compute | A1 only; default 2 x 1 OCPU / 6 GB; explicit 50 GB boot disks | Free profile fits 2 OCPU / 12 GB; account-wide preflight may impose less |
| Images/versions | Exact reviewed ARM OKE image, matching region/version; explicit supported version/ADs | No latest-version lookup or x86 fallback |

API permits worker/pod TCP/6443 and 12250; worker/pod NSGs permit the required
internal traffic and control-plane access. Worker internet egress is HTTP/HTTPS
and ICMP 3,4; metadata/DNS is restricted to 169.254.169.254. OCI service traffic
uses the explicit regional All Services identifier/label. Stateful return traffic
is implicit. Public ICMP 3,4 for workers is the narrowly scoped path-MTU rule,
not general public ingress. Administrator CIDRs are explicit reviewed inputs;
choosing an API source does not grant OCI IAM or Kubernetes RBAC privileges.

Sources: [Oracle OKE network rules](https://docs.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengnetworkconfig.htm),
[VCN-native cluster configuration](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengcreatingclusterusingoke_topic-Using_the_Console_to_create_a_Custom_Cluster_with_Explicitly_Defined_Settings.htm),
[Basic clusters](https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengcreatingbasicclusters.htm)
and [Oracle service-gateway pricing](https://www.oracle.com/cloud/networking/virtual-cloud-network/faq/).
The service gateway has no standing charge. Egress, public IP eligibility,
images/licenses, storage and other services still need account-specific review;
the components do not establish a zero-cost invoice.

## Reviewed inputs and offline proposal

Copy config/oci.example.toml privately to .infra/oci.toml. Its empty identifiers,
version, administrator list and evidence intentionally fail. Supply:

1. The actual compartment, account home region, regional All Services OCID/CIDR
   label and explicit availability domains obtained through authorized read-only
   OCI queries. Confirm these refer to the same region/compartment scope.
2. An exact Kubernetes vX.Y.Z present in both current cluster and node-pool
   options. supported_versions is an operator-reviewed intersection, not a live
   query result generated by this library.
3. An OKE ARM/aarch64 image OCID reviewed against the chosen Kubernetes version,
   A1 shape and region, with timestamp and source reference. The review expires
   after 30 days, including the co-reviewed version/placement/service inputs.
   Architecture metadata is operator evidence, not proof inferred from an OCID.
   No fallback image or arbitrary version is ever selected by the program.
4. Reviewed administrator CIDRs, node/CPU/RAM/boot sizes and pod limits. The
   component ceiling of 4 OCPU / 24 GB / 200 GB is only the maximum supported
   envelope; verified account-wide profiles and live usage can impose less.

NodePool's API has no boot-performance setting. Explicit size, standard image
review and encryption-in-transit are enforced; actual volume performance and
retention must be rechecked from inventory at activation. Scaling, node cycling
and image upgrades need a reviewed overlap model; no cycling settings are emitted.

```sh
uv sync --locked --all-groups
uv run --locked infra oci proposal --config .infra/oci.toml \
  --account-id ocid1.tenancy.oc1..REPLACE > .infra/oci-proposal.json
uv run --locked infra governance audit --account .infra/account.toml \
  --inventory .infra/inventory.json --plan .infra/oci-proposal.json
```

Inputs and proposals stay private under ignored .infra. The proposal uses create actions
and symbolic resource references; it is not a Pulumi deployment plan or adoption
manifest. Existing resources remain fully counted, so a parallel full-size cluster
may correctly fail capacity checks. Do not subtract them or mark them owned just
to obtain a passing audit. See the [governance runbook](free-tier-governance.md).

## Adoption review before any cutover

Prepare a private table with external source address/ID, live OCI properties, proposed
Pulumi unit/type/name/parent/provider, intended operation and independently
verified owner. Start with this mapping; it is guidance, not executable imports:

| External source ownership | Proposed logical unit / keys | Required decision |
| --- | --- | --- |
| oci_core_vcn.oke_vcn | oci-network / vcn | Match CIDRs/DNS/compartment; replacement is a stop condition |
| oci_core_internet_gateway.ig, oci_core_route_table.rt | internet, public-routes | Review service-route addition and subnet attachments |
| k8s_endpoint_subnet, node_subnet, pod_subnet | api-subnet, worker-subnet, pod-subnet | Pod privacy, routes and security-list changes may be disruptive |
| api_endpoint_nsg, node_nsg | api-nsg, worker-nsg | Map individual rule OCIDs; explicitly retire unsafe rules |
| No existing managed equivalent | services, pod-routes, empty-security, pod-nsg and new scoped rules | New resources, separately reviewed |
| oci_containerengine_cluster.oke_cluster | oci-oke / cluster | Compare immutable endpoint/CNI/VCN fields before adoption |
| oci_containerengine_node_pool.oke_node_pool | oci-oke / workers | Review pinned image/version, 8→6 GB sizing, placement and boot disks |
| OKE-created instances and boot volumes | Observed account inventory, not separate child resources in this graph | Track ownership and retention without double ownership/import |

Component parents change Pulumi URNs. Aliases do not transfer external state ownership.
Never run two state engines as writers for the same object, bulk-import with
guessed IDs, or import OKE-managed instances/disks as independently owned resources.
Keep protect=True; removing protection is an explicit operation-specific review.
The library emits no import IDs or aliases and removes nothing from external state.

Stop before ownership transfer if a preview proposes unapproved replacement,
destruction, wrong region/account, default security-list exposure, unsupported
images/versions, uncovered billing or capacity excess. Require qualified OCI state
backend evidence, current complete account inventory/usage, reviewed graph-to-live
diff, protected-environment approval and a backup/recovery rehearsal. Sequence
network ownership first, validate its versioned exports, then OKE; independently
review any networking or worker changes against workload availability. Snapshot
both state systems without plaintext secret exports, and document a single-owner
rollback route. Actual import/remove-state/refresh/apply commands belong in the
separately approved cutover procedure, never this development harness.

## Verification and limits

Run uv run --locked infra verify and uv build --all-packages. Focused iteration
uses uv run --locked pytest tests/test_oci.py. Existing hooks/CI run these sensors
without credentials or provider downloads for the mock graph. The pinned
pulumi-oci 5.5.0 SDK constructor/wire checks are real; OCI API/provider-plugin
integration is not exercised. Mypy checks our source strictly, while traversal of
the very large generated SDK is skipped; native constructor/serialization tests
cover that boundary.

Private pods cannot reach arbitrary external APIs with this routing model.
General pod internet egress, load balancers, volumes created by workloads,
capacity availability, IAM policies and Kubernetes governance need later reviewed
work. No cloud preview, deployment, import, account verification or ownership
transfer was performed by these tests. A green mock harness is not operational
readiness or authorization to enable a stack.

## Controlled OCI apply (M05-PR7)

OCI apply is a separate disabled capability, using the same signed admission,
backup binding, isolated runtime, policy/event checks and durable outcomes as
[service apply](independent-services.md#controlled-single-service-apply-m05-pr6).
config/oci-apply.json, preview flags and operation policy must all be reviewed and
enabled before use; this change enables none of them. Existing preview APIs remain
dry-run-only. Graph factories, security rules and versioned outputs are unchanged.
No new resource kinds, imports, replacements, deletes or implicit stack creation
are supported. An existing stack with the exact reserved identity is mandatory.

### Inputs and signatures

Use the service bundle schema (schema_version, paths, backend_account_id,
cli_archive, provider_home, output). All paths are private files below ignored
.infra; output must be new. Each file is bounded to 1 MiB, the combined frozen set
to 4 MiB. Use the normal service input names plus account. For OCI, proposal is
JSON with foundation and image objects matching the existing OCI TOML schema;
account is the captured account object as JSON. Evidence/envelope are the original
immutable inventory bytes and sidecar. Encrypted configuration uses the existing
JSON stack configuration encoding with encryptionsalt and an empty config object.
There are no cloud keys in that configuration.

OKE additionally requires dependency_outputs, network_receipt and network_journal.
Dependency outputs must contain only network_stack_identity and the existing
schema-1 network object, with known non-secret IDs/CIDRs in the reviewed account,
region and compartment. network_journal is an exact snapshot of the current fixed
.infra/operations/oci-network.json; its latest entry must be a succeeded network
apply matching the receipt operation UUID and journal head. The receipt binds the
canonical network output digest and exact encrypted checkpoint digest produced
after network success. Any later prepared/failed/indeterminate network operation
invalidates that prerequisite until independently reconciled and successfully
replaced. This is intentional even if its previous outputs happen to be unchanged.

Both units use a schema-2 execution approval. The execution-input binding retains
the outer service/backend_account_id encoding used by the shared driver. Its inner
OCI profile is canonical JSON containing adapter=oci-apply-v1, hashes of all frozen
non-approval inputs (including dependency files), profile hash and foundation
configuration digest. Review the actual bytes; never derive expectations from an
unverified approval. A saved plan from the same factories and pinned runtime remains
an operator-supplied artifact. Plan authoring is not automated here. Plans must
contain the exact existing graph, protected resources and explicit native provider
bindings. Pinned Pulumi omits read-only StackReferences from saved plans and records
their built-in pulumi provider instead; only that exact default provider is allowed
without protection. Mandatory policy allows only its default name with empty
configuration; it is engine infrastructure with no billable cloud resources.
The owned OKE factory checks the fixed actual StackReference.

### Sequence and custody

1. Review effective external writer exclusion, protected environments and separate
   credential custody. Provision a trusted dedicated service-operations runner with
   durable .infra storage. Restrict that runner group to reviewed manual workflows.
   No PR jobs may run there or receive operational credentials.
2. Prepare and separately approve the network operation for the exact main commit.
   Its journal is .infra/operations/oci-network.json, environment oci-network-apply.
   Dispatch the Protected OCI apply workflow for oci-network. The workflow runs
   shared verification and a credential-free cloud preflight using only the
   read-only GitHub operation-observation token.
3. Only an admitted update receives separately supplied S3 backend credentials,
   passphrase and OCI_USER_OCID/OCI_FINGERPRINT/OCI_PRIVATE_KEY_PATH. The key path must
   refer to private runner material under .infra. The driver copies it into its
   disposable workspace with mode 0600 and checks the owned copy before execution.
   Ambient credential discovery and plugin downloads remain disabled.
4. After network succeeds, capture its current committed outputs and retain its
   sanitized receipt and journal snapshot. Prepare a new OKE request, backup and
   independently signed approval binding those exact dependency bytes. Its journal
   is .infra/operations/oci-oke.json, environment oci-oke-apply. A network approval
   cannot authorize OKE, and network success does not establish OKE success.
5. Dispatch OKE separately. Before preview, before update and after update the
   driver re-exports the fixed network checkpoint, compares its digest/outputs to
   the approved dependency, and rejects any mismatch. The child also checks the
   actual StackReference's known/non-secret values against the expected digest
   before registering OCI resources. It never applies network to repair OKE input.

Set OCI_APPLY_BUNDLE and OCI_APPLY_JOURNAL as protected per-environment variables.
The manual workflow requires owner/main/exact SHA, keeps cloud credentials out of
preflight, and preserves ignored journals during checkout. Both units share one
workflow concurrency group and .infra/operations/oci-dependency.apply.lock for local
serialization. Local locks and GitHub concurrency cannot fence external writers;
exclusive IAM/process custody is an activation prerequisite. No workflow was
dispatched and no cloud resources were touched during implementation verification.

### Outcomes and recovery

The network receipt adds checkpoint_sha256 and dependency_outputs_sha256 to the
existing success receipt. These contain no resource values or credentials. Read
outputs from the committed backend, not from preview or synthesized IDs. An invalid
post-update output/export makes the result indeterminate; it never emits a success
receipt. The network and OKE journals remain independent: OKE failure does not
rewrite network success. Preserve both on partial completion. No automatic retry,
compensating deletion, rollback or writer release occurs. Receipt persistence
failure after a succeeded journal requires reconciliation, not a new apply.

Code rollback stops future admission and does not undo cloud changes. Keep live
activation, external writer exclusion and actual OCI/provider acceptance separate
from the credential-free synthetic/local verification evidence.

The shared runtime currently enforces a 300-second total command deadline. Long OCI
provisioning may exceed it and must remain indeterminate pending reconciliation;
review execution deadlines before live activation. Do not retry a timed-out update.


## OCI preview graph correspondence (M07-PR5)

Receipt schema 3 requires complete engine pre/output observations for the existing
network or OKE graph compiled from the captured configuration. The shared matcher
checks exact stack/component/resource identities, parents, protection, explicit
provider/region/tenancy, pinned provider version, and all governed inputs. It
compares A1 shape, node count, memory and boot storage against the reviewed graph
and selected profile capacity. Existing account-wide preflight and mandatory
policies remain required; per-resource comparison cannot establish free billing.

OCI `oci_graph` contains only graph SHA-256/count, selected-profile SHA-256 and,
for OKE, the committed network-output SHA-256 (`service_graph` is null). Matching
also checks the exact read-only network StackReference, built-in provider,
stack identity and observed committed outputs. The pinned engine emits the external
read with no protection bit and its built-in provider with no parent; these exact
forms are qualified locally. All managed OCI resources still require protection.
No raw account values or outputs
are retained in the receipt. Compiler, config, dependency and resource classifier
sources join the policy binding. No provider dependency is added: the matcher
adapts the same Apache-2.0 pinned Pulumi engine event pattern as the service matcher.

Intra-stack symbolic references must equal concrete IDs observed for their expected
resource. The engine event format does not prove per-property dependencies; unknown
IDs/placeholders cannot establish correspondence and cause a redacted `PREVIEW010`
failure with no receipt. In particular, first-create previews with unresolved IDs
cannot produce a successful receipt. Wrong/extra/missing resources, changed refs,
profile/account mismatches and substituted dependency outputs also fail closed.

Regenerate schema-1/2 receipts and downstream approvals with fresh evidence and
reviewed code; never restamp an old receipt. Rollback requires compatible code and
regenerated evidence. No resource/state migration, activation, standalone VM,
replacement handling or saved-plan apply admission is introduced. Receipts remain
unsigned consistency observations with both authorization fields false.

Focused verification:
`uv run --locked pytest -q tests/test_preview_results.py tests/test_preview_driver.py tests/test_ownership_handoff.py`.
The existing opt-in local CLI qualification in `tests/test_service_apply_runtime.py`
checks built-in provider and read events without an OCI plugin or cloud credentials.
