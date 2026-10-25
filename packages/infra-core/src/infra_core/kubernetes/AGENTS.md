# Kubernetes governance

Keep this package pure and offline. It accepts desired JSON manifests and explicit
normalized cluster evidence; never read kubeconfig, invoke kubectl, import cluster
clients or install controllers. The normal deployment program remains disabled.

The supported object/workload schema is closed. New controllers, init/ephemeral
containers, runtime classes, volumes, ingress/egress exceptions, Helm/YAML wrappers,
RBAC or external services require a design, accounting model and negative tests.
Never ignore unknown objects or treat unknown quantities/usage as zero. Retain
namespace-wide zero quotas for cloud-billing resources and unsupported controllers.

Resource-local Pulumi checks supplement full cluster preflight. Budget namespace
limits against measured allocatable minus unmanaged/system usage and additional
headroom; add current managed usage and desired rollout peaks without deletion
credit. Keep admission/isolation objects exactly aligned with configuration.
Do not claim that static schemas or default-deny objects prove live admission,
CNI enforcement, image architecture, scheduling fit or billing safety.

Cutover preparation in infra_core.cutover may read/hash private evidence and Git
metadata only. It must never execute state transitions or return authorization.
See docs/runbooks/kubernetes-cutover.md before changing evidence contracts.
