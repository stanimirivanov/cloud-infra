# Free-tier infrastructure

Pulumi Python components and governance for OCI networking and OKE, Cloudflare
DNS, and Supabase Free projects.

Resource deployment is disabled. The project currently supports offline proposal
validation, cost and security policies, and isolated backend qualification.
Account eligibility and measured usage must be verified before deployment.
Start with the [User and Operator Guide](docs/USER_GUIDE.md) for account setup,
secrets, supported workflows and usage checks. The
[multi-provider audit](docs/MULTI_PROVIDER_AUDIT.md) records current coverage and
free-tier terms; the [architecture plan](docs/ARCHITECTURE_IMPROVEMENT_PLAN.md)
proposes extensions without enabling deployment.
The [M04 closeout](docs/m04-closeout.md) separates implemented preview engineering
from administrator-owned live acceptance; all tracked preview flags remain false.
The [M05 closeout](docs/m05-closeout.md) reconciles protected operations, monitoring
and recovery capabilities with failure rehearsals and a separate live acceptance
checklist; its final implementation merged in PR #156.
The [M06 closeout](docs/m06-closeout.md) maps the delivered readiness checks and staged
procedures to those ten acceptance gates. Operational acceptance and activation
remain pending; M06-PR13 engineering closeout requires its own CI and merge.

## Development

Use Git and Python 3.11+ from the repository root in a POSIX shell on Linux x64:

```shell
python3 .github/scripts/install-tools.py
export PATH="$PWD/.infra/tools/uv:$PWD/.infra/tools/pulumi:$PATH"
uv sync --locked --all-groups
uv run --locked infra verify
```

The shared gate checks secrets, private artifacts, architecture, documentation,
formatting, lint, typing and tests without cloud credentials. CI runs it on Linux.

See [HARNESS.md](HARNESS.md) for the architecture, commands, and operational
boundaries.
