# Foundation configuration boundaries

pulumi.toml contains identifiers and disabled identities, never credentials.
The namespace is isolated from the existing Terraform key. Qualification uses only
new UUID child prefixes; never reuse one for resource stacks. All deployment units
must remain disabled until governance and adoption code is reviewed. Backend/CLI
changes invalidate qualification evidence and require another explicit test.
