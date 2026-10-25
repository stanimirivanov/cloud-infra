# Free-tier infrastructure

Pulumi Python components and governance for OCI networking and OKE, Cloudflare
DNS, and Supabase Free projects.

Resource deployment is disabled. The project currently supports offline proposal
validation, cost and security policies, and isolated backend qualification.
Account eligibility and measured usage must be verified before deployment.

## Development

From the repository root in PowerShell 7 on Linux/Windows x64:

```shell
./.github/scripts/install-tools.ps1
uv sync --locked --all-groups
uv run --locked infra verify
```

The shared gate checks secrets, private artifacts, architecture, documentation,
formatting, lint, typing and tests without cloud credentials. CI runs it on Linux
and Windows.

See [HARNESS.md](HARNESS.md) for the architecture, commands, and operational
boundaries.
