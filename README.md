# Free-tier infrastructure

Pulumi Python components and governance for OCI networking and OKE, Cloudflare
DNS, and Supabase Free projects.

Resource deployment is disabled. The project currently supports offline proposal
validation, cost and security policies, and isolated backend qualification.
Account eligibility and measured usage must be verified before deployment.

## Development

Install uv **0.12.5**, then run from the repository root:

```sh
uv sync --locked --all-groups
uv run --locked infra verify
```

The shared gate checks private artifacts, formatting, lint, strict typing, and
tests without cloud credentials. CI runs it on Linux and Windows.

See [HARNESS.md](HARNESS.md) for the architecture, commands, and operational
boundaries.
