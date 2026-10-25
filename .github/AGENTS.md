# Automation boundaries

PR validation is credential-free, read-only and runs for every PR without path
filters or actor exclusions. Do not use pull_request_target to execute PR code.
Deployment must depend on the shared verification workflow. Keep existing
owner/environment controls; no deployment actions belong in verification.
Pin tool versions, set explicit minimum token permissions and disable checkout
credential persistence in verification. Changes to action pins require review.
Branch protection and environment approvals are repository settings; do not
claim YAML alone enforces them. Never print secrets or upload state as test data.
