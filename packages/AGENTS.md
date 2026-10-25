# Python workspace boundaries

The root pyproject.toml and uv.lock own the shared Python environment. Keep all
runtime dependencies in member manifests, development tools in the root dev group,
and tool configuration in the root manifest. Run commands with uv run --locked.
Do not create member lockfiles, install dependencies dynamically or edit sys.path.

infra-core owns CLI, pure configuration and verification. It must not depend on
infra-program or Pulumi. infra-program may depend on infra-core and the Pulumi SDK;
provider resources, backends and deployment units are deferred to later PRs.
Keep the program entry point disabled until those reviewed controls exist.

Use typed functions and small explicit data contracts. Any is limited to parsed
heterogeneous HCL at the legacy policy boundary. Python 3.12 is the supported
runtime; .python-version pins the patch for local and CI use.

Run subprocess argument arrays with check=True, explicit cwd and bounded timeouts.
Propagate errors. Render legacy Terragrunt with synthetic inputs in a temporary
copy; materialize only approved generated filenames. Disable backend access and
use the readonly provider lock. Never plan/apply, run hooks or mutate state here.

Policy changes need negative tests and stable actionable rule IDs. This packaging
migration preserves the legacy architecture and cost policy; account-aware quotas
are a later change, not an implied result of passing the current harness.
