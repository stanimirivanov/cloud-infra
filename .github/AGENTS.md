# Automation boundaries

PR validation is credential-free, read-only and runs for every PR without path
filters or actor exclusions. Do not use pull_request_target to execute PR code.
The legacy Terraform cloud writer/recovery are frozen. The manual Pulumi foundation
workflow depends on shared verification, requires main and owner checks, and uses
the dedicated protected environment. Secrets belong only to isolated qualification,
never PR validation or disabled resource preview/deploy. Configuration of required
reviewers/main-only environment branches is an administrator prerequisite.
Pin tool versions, set explicit minimum token permissions and disable checkout
credential persistence in verification. Changes to action pins require review.
Branch protection and environment approvals are repository settings; do not
claim YAML alone enforces them. Never print secrets or upload state as test data.
