# Foundation configuration boundaries

pulumi.toml contains identifiers and disabled identities, never credentials.
The namespace must remain isolated from externally owned state keys.
Qualification uses only
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

oci.example.toml stays incomplete. Actual administrator CIDRs, image/version/AD
and regional service evidence belong in ignored .infra. Do not introduce lookup
fallbacks, paid routing or expand ingress to make a cluster appear ready. See
docs/runbooks/oci-components.md before changing these contracts.

kubernetes.example.toml and cutover.example.json are deliberately incomplete.
Keep real cluster usage, ownership maps, review reports and hashed evidence under
ignored .infra. Never advance dates, assert network-policy enforcement, or grant
cutover authority simply to satisfy static checks. See the Kubernetes cutover runbook.
Schema-4 cutover indexes require all four role-bound review sidecars and DSSE
signatures over the actual reviewed input snapshot. cutover-reviewers.toml ships
disabled with no enrolled keys. Public keys/principal/role enrollment needs independent
review; never add private keys or treat valid signatures as operational approval.

administration.json pins public GitHub repository/check-app identities and the
qualification environment name. Schema-2 observations require both main and
environment controls; old main-only snapshots must be recollected. Administrative observations stay private under .infra;
passing the read-only sensor cannot enable deployment or enroll reviewer keys.

Service examples contain no tokens/passwords. service-evidence.example.json must
remain unverified, incomplete and stale. Service profile enablement permits offline
classification only; all pulumi.toml deployment identities remain disabled. Keep
private scope/usage evidence under .infra and use the independent services runbook.
