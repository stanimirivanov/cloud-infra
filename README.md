# Free-tier infrastructure

Pulumi Python components and governance for OCI networking and OKE, Cloudflare
DNS, and Supabase Free projects.

Resource deployment is disabled. The project currently supports offline proposal
validation, cost and security policies, and isolated backend qualification.
Account eligibility and measured usage must be verified before deployment.
The [M04 closeout](docs/m04-closeout.md) separates implemented preview engineering
from administrator-owned live acceptance; all tracked preview flags remain false.

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
