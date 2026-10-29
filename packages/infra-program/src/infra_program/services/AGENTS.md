# External-service SDK boundary

register_services is the sole resource composition path. The configuration-backed
register_services_from_config wrapper audits frozen inputs before Config lookup,
requires every token/password via require_secret(), then delegates to that path.
Both factories require immutable evidence/envelope bytes and an independently
reviewed expected commit. Validate exact-byte/scope/config/profile/clock binding
before Config lookup or registration; revalidate frozen inputs after secret lookup.
No dictionary fallback, implicit commit from evidence or automatic conversion.
Factories do not discover Git: an approved caller must supply clean reviewed
checkout identity independently, as the CLI does. Pure accounting stays dictionary-based.
Audit before registering any provider/component/resource; use only that graph.
Every child has an explicit provider, parent and protect=True. Endpoints are
fixed, tokens/passwords are Pulumi secret Outputs, outputs contain identities only.
Do not expose default providers, invokes, API clients, dynamic providers or new
resource kinds. Pure cost/structure rules belong in infra-core/services.

preview_program may dispatch these factories only after explicit context/contract,
runtime identity and SDK dry-run validation. Standalone program and CLI operations
remain disabled; tracked preview flags stay false. Mocks must
exercise the real generated Supabase SDK parameterization and Cloudflare SDK
serialization. No cloud credentials, state imports, network calls or data-plane
SQL are part of this library's verification.

The separate service_apply owned entry point may call the same factories for an
explicitly admitted preview/update lifecycle. It must validate frozen execution
bindings, live journal head and runtime identity before secret lookup. This does
not widen preview_program admission or authorize direct factory callers.
