# Automation boundaries

PR validation is credential-free and runs the complete shared gate on Linux
for every PR without path filters or actor exclusions. Do not use
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
only through .github/scripts/install-tools.py; native providers use
.github/scripts/install-providers.py and pinned archive-member verification.
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

Manual recovery-rehearsal runs only on the dedicated protected recovery runner,
after main/owner and shared verification checks. Separately supplied backup and
Pulumi recovery credentials belong only to its rehearsal step. Restore writes must
remain in fresh disposable local state, never the mounted source or production
backend. Keep runner isolation, source transport and credential custody explicit;
no PR job may receive recovery credentials or run on that recovery runner.

Manual OCI apply follows the service apply custody boundary and uses one shared
OCI dependency concurrency group, plus the durable local dependency lock, to
serialize network/OKE. Both require separate unit environments/approvals and a
dedicated service-operations runner. OCI key paths refer only to reviewed private
runner material under .infra; cloud secrets are absent from preflight. Preserve the
journal during checkout and never run this workflow from PR validation.

Manual resource-import uses separate unit-import environments and its own disabled
contract, while sharing OCI apply concurrency and durable local locks. Keep cloud
credentials out of import preflight and all PR jobs. Only the admitted import step
receives the reviewed OCI/backend credentials. No generated code, raw checkpoint,
source state or private engine stream may be uploaded.

Scheduled monitoring is a separate default-disabled main entry point. Preserve
fresh action-specific drift approval; never forge workflow_dispatch context or mint
signatures to make a cron run pass. Only the admitted drift step receives provider
credentials. Cost/health collection and the hosted watchdog stay credential-free
apart from scoped GitHub read access; notification tokens belong to delivery steps.
Keep the local incident outbox, host enrollment, explicit initialization and original
heartbeat watermark intact. Missing state/steps are unknown, never a fresh baseline.

Manual state-recovery uses separate unit-recovery environments and the protected
recovery runner after main/owner/exact-SHA shared verification. Preserve signed
credential-free preflight, shared OCI/service operation concurrency and durable local
locks/journals. Only the explicit admitted step receives backend writer and recovery
credentials; keep provider Read credentials separate inside the driver. Never upload
state, automatically retry imports or release writers from this workflow.
