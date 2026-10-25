# External-service SDK boundary

register_services is the sole composition entry point. Audit a frozen pure
proposal before registering any provider/component/resource; use only that graph.
Every child has an explicit provider, parent and protect=True. Endpoints are
fixed, tokens/passwords are Pulumi secret Outputs, outputs contain identities only.
Do not expose default providers, invokes, API clients, dynamic providers or new
resource kinds. Pure cost/structure rules belong in infra-core/services.

Keep stack identities and normal program/CLI operations disabled. Mocks must
exercise the real generated Supabase SDK parameterization and Cloudflare SDK
serialization. No cloud credentials, state imports, network calls or data-plane
SQL are part of this library's verification.
