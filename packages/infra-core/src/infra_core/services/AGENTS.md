# Independent services

Keep Cloudflare DNS and Supabase database identities separate from OCI and from
each other. Only additive proposals are modeled; updates, adoption, deletion and
replacement need a new ownership/peak model. Evidence must cover unmanaged usage.
Supabase project capacity spans all Free organizations owned/administered by the
user; usage quotas apply to the target organization, database size per project.
Do not treat a paid organization or spend cap as Free eligibility.

Use closed fields and stable EXT diagnostics. Pure validation lives here; provider
SDKs and secret inputs belong in infra-program/services. No live inventory calls,
runtime package generation or deployment activation. See the services runbook.
