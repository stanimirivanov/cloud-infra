# OCI components

Use register_foundation for combined library composition, register_network for
independent networking and register_oke for independent OKE. Each builds
the pure infra-core OCI graph, validates resource security and audits the complete
account proposal before registering a provider or any component. Require original
immutable inventory/envelope bytes and an independently supplied expected commit;
never derive expectations from the sidecar or accept a dictionary fallback. Freeze
reviewed inputs and delegate through infra_program.governance.preflight before
executing the private graph registration closure. Library calls do not discover
Git: the future approved caller must establish clean reviewed checkout identity.
Constructor
permits prevent accidental direct registration; Python modules are not a security
sandbox. Normal program/CLI operations and configured deployment units stay disabled.

The native SDK emitter must consume that exact graph, with no new defaults,
lookups, invoke calls, imports, aliases, dynamic providers or unreviewed resource
types. Keep the constructor table closed. Every native resource uses an explicit
OCI provider, parent and protect=True. Network cannot reference cluster resources.
Versioned network outputs contain identities/CIDRs only, never secrets or kubeconfig.
Admitted previews export only their unit's identity interface. register_oke alone
may read the exact organization/free-infrastructure/oci-network StackReference
after initial preflight. Reject secret/unknown/missing/mismatched committed outputs,
then repeat preflight on the bound OKE graph before any OCI provider/component or
managed registration. Do not synthesize IDs or widen the policy reference exception.

Pure planning, image/version/placement validation and governance belong in
infra-core/oci. Pulumi objects belong here. Any is confined to heterogeneous
SDK property translation; keep public configuration and output contracts typed.
Generated SDK modules are excluded from mypy traversal for bounded verification;
actual SDK constructors and every serialized input/reference are checked by mocks.

Run the focused OCI tests after graph/policy changes and the complete harness
before delivery. Preserve the deployment freeze and follow the OCI components
runbook for adoption prerequisites. Never run a credentialed preview, import,
apply or destroy as routine verification.
