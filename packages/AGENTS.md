# Python workspace boundaries

The root pyproject.toml and uv.lock own the shared Python environment. Keep all
runtime dependencies in member manifests, development tools in the root dev group,
and tool configuration in the root manifest. Run commands with uv run --locked.
Do not create member lockfiles, install dependencies dynamically or edit sys.path.

infra-core owns CLI, pure configuration and verification. It must not depend on
infra-program or Pulumi. infra-program may depend on infra-core and the Pulumi SDK;
standalone program resource operations and deployment units remain disabled.
The in-process preview_program adapter accepts explicit reviewed service/network context
only with the SDK dry-run flag and matching project/stack/organization. It is not
an authorization boundary against arbitrary Python callers. The library preview_driver
checks clean head, contracts, frozen inputs and the owned runtime. infra-program
owns the infra console composition: core accepts an explicit preview callback,
without importing program/Pulumi. CLI collection requires explicit private inputs,
backend evidence and an enabled tracked preview contract. Manual service/OCI
workflows provide pre-credential admission; external approvals, IAM and custody
remain administrator prerequisites. Never add environment-based
admission or a non-preview branch to this adapter.
The OCI component library may register only after its complete preflight gate;
credential-free tests use Pulumi mocks. Backend qualification
may write only synthetic state in an invocation-specific namespace or a temporary
local backend. Never mix qualification with imports or resource deployment.

Use typed functions and small explicit data contracts. Any is limited to parsed
heterogeneous TOML/JSON and SDK responses at explicit validation boundaries.
Python 3.12 is the supported runtime; .python-version pins the patch for local
and CI use.

Run subprocess argument arrays with explicit cwd and bounded timeouts. Propagate
failures; replace potentially secret-bearing raw diagnostics with safe errors.
Normal verification checks Python and tracked artifacts without provider/state
operations. Only opt-in isolated qualification exercises synthetic checkpoint
operations; it must never target resource stacks.

Policy changes need negative tests and stable actionable rule IDs. governance/
owns pure account capacity, replacement peak and monthly usage rules; inventory/
owns optional read-only provider adapters. Never import an SDK in the pure engine
or infer ownership from tags. Missing inventory/usage is a failure, not zero.
Only infra_core.review_signatures may import the three reviewed cryptography
verification symbols; signing APIs and crypto imports in pure domains remain forbidden.
infra-program may wrap the pure rules as mandatory policies, but resource-local
policy checks never replace account-wide pre-registration checks. See
docs/runbooks/free-tier-governance.md before changing accounting contracts.

kubernetes/ owns a closed offline manifest subset, namespace envelopes and
cluster usage/rollout checks. No Kubernetes client, kubeconfig access, controller
installation or provider activation is part of this stage. cutover.py may read
private evidence/Git metadata only and must always return authorization=false.

services/ owns independent Cloudflare DNS and Supabase project proposal preflight.
The infra-program/services adapter may register only after this complete audit;
normal deployment remains disabled. sdks/supabase is a pinned generated workspace
dependency. Do not introduce runtime generation, API calls or state coupling.
