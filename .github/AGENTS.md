# Automation boundaries

PR validation is credential-free and runs the complete shared gate on Linux and
Windows for every PR without path filters or actor exclusions. Do not use
pull_request_target to execute PR code. The manual Pulumi foundation workflow
depends on shared verification, requires main and owner checks, and uses the
dedicated protected environment. Secrets belong only to isolated qualification,
never PR validation or disabled resource preview/deploy. Configuration of required
reviewers/main-only environment branches is an administrator prerequisite.

Pin external Actions to reviewed full SHAs in config/toolchain.json. Install tools
only through .github/scripts/install-tools.ps1; verify hashes before extraction.
Keep complete checkout history and mandatory redacted secret scans; no blanket
baselines, inline suppression or scanner-output uploads. See the trusted-toolchain
runbook for updates and incident handling.

Pin tool versions, set explicit minimum token permissions and disable checkout
credential persistence in verification. Changes to action pins require review.
Branch protection and environment approvals are repository settings; do not
claim YAML alone enforces them. Never print secrets or upload state as test data.
