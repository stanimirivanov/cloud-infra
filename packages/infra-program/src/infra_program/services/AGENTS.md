# External-service SDK boundary

register_services is the sole resource composition path. The configuration-backed
register_services_from_config wrapper audits frozen inputs before Config lookup,
requires every token/password via require_secret(), then delegates to that path.
Both factories require immutable evidence/envelope bytes and an independently
reviewed expected commit. Validate exact-byte/scope/config/profile/clock binding
before Config lookup or registration; revalidate frozen inputs after secret lookup.
No dictionary fallback, implicit commit from evidence or automatic conversion.
Factories do not discover Git: a future approved caller must supply clean reviewed
checkout identity independently, as the CLI does. Pure accounting stays dictionary-based.
Audit before registering any provider/component/resource; use only that graph.
Every child has an explicit provider, parent and protect=True. Endpoints are
fixed, tokens/passwords are Pulumi secret Outputs, outputs contain identities only.
Do not expose default providers, invokes, API clients, dynamic providers or new
resource kinds. Pure cost/structure rules belong in infra-core/services.

Keep stack identities and normal program/CLI operations disabled. Mocks must
exercise the real generated Supabase SDK parameterization and Cloudflare SDK
serialization. No cloud credentials, state imports, network calls or data-plane
SQL are part of this library's verification.
