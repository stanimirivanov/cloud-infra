# Python workspace boundaries

The root pyproject.toml and uv.lock own the shared Python environment. Keep all
runtime dependencies in member manifests, development tools in the root dev group,
and tool configuration in the root manifest. Run commands with uv run --locked.
Do not create member lockfiles, install dependencies dynamically or edit sys.path.

infra-core owns CLI, pure configuration and verification. It must not depend on
infra-program or Pulumi. infra-program may depend on infra-core and the Pulumi SDK;
normal program/CLI resource operations and deployment units remain disabled.
The OCI component library may register only after its complete preflight gate;
credential-free tests use Pulumi mocks. Backend qualification
may write only synthetic state in an invocation-specific namespace or a temporary
local backend. Never mix qualification with imports or resource deployment.

Use typed functions and small explicit data contracts. Any is limited to parsed
heterogeneous HCL/TOML/JSON and SDK responses at explicit validation boundaries.
Python 3.12 is the supported runtime; .python-version pins the patch for local
and CI use.

Run subprocess argument arrays with check=True, explicit cwd and bounded timeouts.
Propagate errors. Render legacy Terragrunt with synthetic inputs in a temporary
copy; materialize only approved generated filenames. Disable backend access and
use the readonly provider lock. Legacy validation never plans/applies, runs hooks
or mutates deployed state. Only opt-in isolated qualification exercises synthetic
checkpoint operations; it must never target resource stacks.

Policy changes need negative tests and stable actionable rule IDs. governance/
owns pure account capacity, replacement peak and monthly usage rules; inventory/
owns optional read-only provider adapters. Never import an SDK in the pure engine
or infer ownership from tags. Missing inventory/usage is a failure, not zero.
infra-program may wrap the pure rules as mandatory policies, but resource-local
policy checks never replace account-wide pre-registration checks. See
docs/runbooks/free-tier-governance.md before changing accounting contracts.
