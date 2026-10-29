# Cost, capacity, and evidence-age observations (M05-PR12)

The offline findings command consumes captured OCI inventory/account or
Cloudflare/Supabase service evidence. It compares measured capacity and current
usage against the existing reviewed profile, and original evidence clocks against
an explicit monitoring policy. It makes no provider calls, writes no journal or
incident state, and grants no resource or remediation authority.

```sh
uv run --locked infra monitoring findings --evidence .infra/monitoring/index.json
```

Copy `config/monitoring.example.json` into private storage. The example is disabled
and has unset thresholds; it deliberately cannot produce a usable report. Supply
reviewed private values rather than changing profile limits or observation dates
until a report passes. Enabling a private findings policy enables offline evaluation
only; it cannot enable deployment or provider access. Scheduling, deduplication,
notification delivery and missing-run detection belong to M05-PR14.

## Inputs and policy

The private JSON index has exactly these fields:

```json
{
  "schema_version": 1,
  "scope": {
    "unit": "oci-network",
    "account_id": "replace-with-reviewed-account",
    "scope_id": "replace-with-home-region",
    "profile": "oci-free"
  },
  "policy": ".infra/monitoring/policy.json",
  "evidence": ".infra/monitoring/inventory.json",
  "account": ".infra/account.toml"
}
```

All index/evidence/policy paths must resolve to JSON below this checkout's `.infra`.
The optional account path must resolve to TOML below `.infra`. Symlinks cannot escape
that boundary. Inputs and the tracked profile file are each bounded to 1 MiB.
Private paths, identities, source descriptions, raw properties and resource IDs are
never included in output. Keep captures and output under private custody; even
aggregate findings expose operational information.

Supported scopes:

| Unit | Evidence | Account input | Scope / profile |
| --- | --- | --- | --- |
| oci-network / oci-oke | Existing schema-2 OCI inventory including usage | Existing verified account TOML | Home region; explicitly selected oci-free or oci-paid-a1 |
| cloudflare-edge | Existing schema-4 service evidence | null | Zone ID; cloudflare-free |
| supabase-database | Existing schema-4 service evidence | null | Organization ID; supabase-free |

Use the existing [OCI evidence collection](free-tier-governance.md#collecting-evidence)
and [independent services procedures](independent-services.md). This evaluator
consumes captures; it adds no collector, automatic credential discovery or telemetry
service. The independently supplied scope must match the evidence and selected
profile/revision. Eligibility, source review, completeness and other-service review
must be explicitly recorded. A digest proves byte consistency, not authenticity,
complete billing discovery or effective IAM.

Monitoring policy schema 1 contains exactly:

- `enabled`: true for a deliberately configured private evaluation.
- `warning_utilization_percent` and `critical_utilization_percent`: exact integers
  or decimal strings with `0 < warning < critical <= 100`.
- `warning_age_percent`: exact integer/string strictly between 0 and 100.
- `max_age_seconds`: positive integer limits named `observation`, `billing_lag`,
  `profile`, `entitlement`. Maximum accepted values are respectively 900 seconds,
  900 seconds, 90 days and 30 days, preserving existing governance age ceilings.

There are no implicit thresholds or operational targets. Values, percentages and
comparisons use bounded exact decimal arithmetic, independent of caller precision;
floats, booleans, negative, nonfinite, oversized or unrecognized values fail policy
validation or become unknown measurements. Limits always come from
`config/quotas/profiles.toml`, with existing fixed service bounds retained. No
profile date, allowance or eligibility is changed by evaluation.

## Findings and interpretation

Each finding has a stable identity comprising unit, scope digest and metric, plus
status, a fixed reason code and applicable aggregate value/limit/headroom or age.
The report records `evaluated_at`, the original collection clocks and billing
watermarks/windows. Re-evaluation never refreshes a capture or advances its coverage.
The CLI also binds exact index, policy, evidence, account (when present) and tracked
profile bytes by SHA-256. It returns both authorization fields as false.

- **normal**: a complete, scoped measurement is below the warning threshold.
- **warning**: utilization is at least the warning percentage, or age has reached
  the warning percentage of its maximum.
- **critical**: utilization reaches the critical percentage, a reviewed bound is
  exhausted/exceeded, or age reaches its maximum. Exhaustion includes equality;
  negative headroom records overage rather than clamping it to zero.
- **unknown**: required measurement, entitlement, scope, coverage or clock cannot be
  established. Missing usage never means zero. An expired age can be critical while
  the dependent measurement is unknown. Exactly-at-maximum evidence remains within
  the existing inclusive freshness gate; older evidence cannot establish health.

Report status prioritizes unknown, critical, warning, then normal. Every finding is
retained, so a known critical result remains visible alongside unrelated unknowns.
`complete` is false whenever any finding is unknown. Valid normal/warning/critical
reports exit zero; unknown reports exit one while preserving JSON on stdout. Invalid
policy/index/I/O returns a redacted `FND001` diagnostic. No report is promised when
inputs cannot be opened or policy cannot be validated.

OCI capacity includes live instances and separately recorded boot/block volumes,
retained/unmanaged resources and explicit reservations across the captured tenancy.
It reuses the complete query/scope validator and resource footprint classifier;
there is no credit for future deletions or inference from ownership tags. Network
and OKE observations of one tenancy share its allowance: never sum their reports
as if each stack had its own free quota. Monthly findings compare consumed values
to reviewed allowances only; they add no remaining-month forecast or billing model.
A current collection timestamp cannot make a lagging billing cutoff current. Each
missing monthly metric becomes unknown; unrelated valid readings remain visible.

Cloudflare counts all zone records, including existing TXT/SRV/wildcard records,
and has no invented billing meter. Supabase counts all owned/admin Free projects,
including other organizations and paused projects, and reports the maximum observed
per-project database size against the existing 500 MB bound. Its usage reads the
current target organization's exact anniversary cycle through the existing billing
and per-metric coverage validators. Storage MB is an as-of gauge; cumulative metrics
must start at the current cycle boundary. Late, missing or partial metric coverage
cannot be replaced with collection completion or a new month label.

A fresh healthy capture returns normal with the same finding identities after an
incident condition clears. This module stores no recovery history or delivery state;
PR14 must compare persisted observations and handle absent reports/missing runs.
The operation-request/journal protocol is unchanged; offline findings do not require
an execution request or append monitor journal transitions.

## Verification and limits

```sh
uv run --locked pytest -q tests/test_operational_findings.py tests/test_governance.py tests/test_services.py
uv run --locked infra verify
```

Tests cover all four units, numeric/age boundaries, partial billing, independent
watermarks, clock skew, billing anniversaries, retained/reserved capacity, scope
mismatches, secret-safe CLI output and recovery to normal. No cloud credentials,
provider SDK, network access or state writes are used. Existing collectors and
admission audits remain unchanged. Captured observations still depend on external
source authenticity, actual account-wide coverage and billing delay; findings are
bounded monitoring evidence, not an invoice or a certificate of zero future cost.
Reverting this feature removes the offline interface without a state migration.
