# Foundation configuration boundaries

pulumi.toml contains identifiers and disabled identities, never credentials.
The namespace is isolated from the existing Terraform key. Qualification uses only
new UUID child prefixes; never reuse one for resource stacks. All deployment units
must remain disabled until governance and adoption code is reviewed. Backend/CLI
changes invalidate qualification evidence and require another explicit test.

quotas/profiles.toml separates published, dated terms from actual verified account
eligibility. Disabled providers must stay disabled until their inventory, usage
and cost classification are implemented. Refresh reviews from primary sources;
never increase a bound or advance a review date just to pass an audit. Private
account/inventory/usage documents belong under ignored .infra, never config/.
account.example.toml must remain unverified and unusable as deployment evidence.
Increment profile revision whenever eligibility or limits change; account evidence
must bind to that revision and be verified again, never silently inherit new limits.
