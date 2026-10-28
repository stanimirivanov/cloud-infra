# Automation boundaries

PR validation is credential-free and runs the complete shared gate on Linux and
Windows for every PR without path filters or actor exclusions. Do not use
pull_request_target to execute PR code. The manual Pulumi foundation workflow
depends on shared verification, requires main and owner checks, and uses the
dedicated protected environment. OCI signing credentials belong only to its
read-only audit step; S3 credentials and passphrase belong only to isolated
qualification. The manual service-preview workflow uses per-service protected
environments, a matching explicit main dispatch SHA and a credential-free enabled
contract check before its secret-bearing CLI handoff. Signing material is ephemeral;
only the sanitized CLI receipt may be uploaded. Tracked flags stay false. Never
broaden service admission to OCI implicitly: the OCI workflow uses explicit --oci
mode, separate per-unit environments and distinct backend/resource signing inputs.
OKE must supply captured committed network outputs; never bootstrap/apply network
state to make a preview pass. Both modes retain the same credential-free gate,
sanitized receipt and owned cleanup requirements. Never
expose operational credentials to PR validation. Configuration of required
reviewers/main-only environment branches is an administrator prerequisite.

Pin external Actions to reviewed full SHAs in config/toolchain.json. Install tools
only through .github/scripts/install-tools.ps1; native providers use
.github/scripts/install-providers.ps1 and pinned archive-member verification.
Neither installer executes provider code. Verify hashes before extraction.
Opt-in Supabase integration may run verified schema metadata RPCs with credentials
removed and external proxy traffic denied; never configure or mutate cloud resources.
Keep complete checkout history and mandatory redacted secret scans; no blanket
baselines, inline suppression or scanner-output uploads. See the trusted-toolchain
runbook for updates and incident handling.

Pin tool versions, set explicit minimum token permissions and disable checkout
credential persistence in verification. Changes to action pins require review.
Branch protection and environment approvals are repository settings; do not
claim YAML alone enforces them. Never print secrets or upload state as test data.
