# OCI networking and OKE components

This protected component library and pure proposal renderer do not provision,
adopt, resize or move existing resources. The root Pulumi program, CLI
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
constructors are implementation details; use register_foundation. SDK mock tests
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

The current factory composes both logical units in an offline test program.
It is not a multi-stack deployment orchestrator. Separate state deployment and
StackReference wiring must be introduced and reviewed at cutover, with exported
network contracts bound to their actual source stack/account and governance
proposal. Do not point one combined program at either reserved stack identity.

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
Pure accounting and cutover still accept dictionaries pending explicit migration.
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

Use a single line on PowerShell instead of POSIX backslash continuations. Inputs
and proposals stay private under ignored .infra. The proposal uses create actions
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
