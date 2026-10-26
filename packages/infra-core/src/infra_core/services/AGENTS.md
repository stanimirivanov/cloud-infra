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

Proposal schema 2 and evidence/report schema 4 require original collection clocks
and independent per-metric coverage. Cumulative values cover the actual organization anniversary cycle from
its start. Preserve the original anchor across month-end clamping; Cloudflare
requires a null billing period. Do not infer source authenticity from consistency.
storage_mb is a fresh capacity sample. storage_gb_hours is mandatory cumulative
cycle history with a separate remaining-cycle budget and published 744 GB-hour
ceiling. Require integer/quoted decimal GB-hours at JSON boundaries, never floats.
Never derive it from the live size or scale that allowance to cycle length.
Require both capacity and billing guards. Never restamp readings or treat provider
lag/missing values as zero. Contract migrations must remain explicit; this pure
domain cannot import the generic evidence adapter.
