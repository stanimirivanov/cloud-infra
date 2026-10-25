# Pulumi backend qualification and recovery

## Current release boundary

Resource provisioning, imports, production stack initialization, ownership transfer
and automatic state recovery are disabled. `infra preview --unit NAME`
and `infra deploy --unit NAME` are intentional readiness failures. Qualification
receipts never authorize resource deployment. The normal Pulumi program still fails
before declaring resources; its Pulumi.yaml establishes only the Python entry point.

`config/pulumi.toml` owns the CLI pin, backend identity, short evidence TTL and disabled
unit/stack identities. The CLI pin must match the SDK in uv.lock. The existing OCI
bucket is reused only under `pulumi/`; externally owned state objects are untouched.
Every qualification uses a fresh `pulumi/qualification/<UUID>` prefix
and a `qualification-<UUID>` stack in project `backend-qualification`.

The tool performs real checkpoint operations only in that generated namespace. It
creates no bucket, IAM policy, provider resource, compute instance or database.
Never use qualification tooling against an adopted resource stack.

## Local and protected checks

From the checkout, with the configured Pulumi CLI on PATH:

```sh
uv sync --locked --all-groups
uv run --locked infra backend inspect
uv run --locked infra backend qualify --local-test --allow-backend-writes
```

Local qualification uses disposable filesystem storage and generated synthetic
credentials. Its receipt has `kind=local` and is rejected as OCI evidence. It proves
CLI/runtime/encryption/locking behavior, not OCI compatibility. Default verification
runs unit tests without backend writes; CI explicitly opts into the isolated local
integration test on Windows and Linux. pip is a locked development dependency because
the Pulumi Python host uses `pip list` for package discovery; dependencies are still
installed by uv. No deployment-time pip install is performed.

For a real OCI test, an authorized operator selects `qualify` in the **Pulumi
foundation** manual workflow on main. The workflow serializes foundation operations,
runs verification first, checks out the dispatch commit, and executes behind the
`pulumi-backend-qualification` environment. It exposes only S3 HMAC credentials and
the passphrase to the qualification step; there are no OCI provider/API credentials.
PRs cannot trigger that workflow. Preview/deploy dispatches intentionally fail.
No real OCI qualification has been performed merely by merging this implementation.

Before enabling qualification, an administrator must:

1. Create the environment with required reviewers, prevent self-review where available,
   and restrict deployment branches to protected main. Reviewers approve the actual
   workflow commit; the in-workflow main/owner checks are additional controls, not a
   substitute for environment branch protection.
2. Store `OCI_S3_ACCESS_KEY`, `OCI_S3_SECRET_KEY`, and a randomly generated
   `PULUMI_CONFIG_PASSPHRASE` of at least 20 characters as environment secrets.
   These are existing S3-compatible HMAC credentials, not an OCI API signing key.
3. Restrict the credential's object-storage permissions to the intended bucket and
   namespace to the extent OCI IAM permits. Do not assume S3 ARN/prefix IAM syntax
   maps directly to OCI. If isolation cannot be enforced, use a separately approved
   dedicated bucket and update configuration before testing.
4. Confirm available object-storage allowance and retention settings before writes.
   Configuration does not prove billing eligibility or remaining account storage.
   Qualification checkpoints are capped at 1 MiB by the tool, but that check occurs
   after the initial checkpoint write and does not cap bucket history/total usage.
5. Review bucket lifecycle rules for qualification history. Stack removal does not
   promise deletion of backend metadata/history. Clean only expired qualification
   prefixes after verifying no update is active. Never apply an expiry rule to active
   stack/checkpoint data. Production state retention needs a separate reviewed policy.

Repository environment and branch settings are administrative prerequisites; this PR
provides the workflow and runbook, not proof those settings have been applied.

An authorized local OCI qualification alternatively requires the three environment
variables above, followed by:

```sh
uv run --locked infra backend qualify --allow-backend-writes
uv run --locked infra backend check-receipt
```

Do not put credentials/passphrases on command lines. The tool clears ambient
Pulumi and cloud credential overrides, uses a temporary PULUMI_HOME, supplies only reviewed
HMAC credentials, disables EC2 metadata credentials, and uses HTTPS/path-style access
with the configured region. Empty or missing secrets fail before CLI startup.

## Qualification evidence

A successful run checks encrypted stack config and checkpoint storage, rejects
unexpected provider/cloud resources, holds a real update open and verifies another
writer is rejected by a backend lock, restores an encrypted exported checkpoint,
and verifies its synthetic secret decrypts correctly. The runner captures raw CLI
output, including the synthetic plaintext readback, without printing it. Failures
report a phase and exit code rather than potentially secret-bearing diagnostics.

Cleanup removes only the invocation-specific stack, without force or lock cancellation.
A cleanup failure fails qualification. Backend metadata/history can remain. The run UUID
is printed so operators can inspect an orphan namespace after failure. A failed retry
removes stale local evidence; a request without the write flag preserves it.

Only the sanitized `.infra/qualification.json` receipt is saved/uploaded (one-day
artifact retention). It records the run UUID, configuration digest, tool version,
time, check names and `deployment_authorized=false`. No raw output, checkpoint,
stack configuration, passphrase or credential is uploaded. It expires within the
configured maximum 24 hours and configuration changes invalidate it.

The receipt is unsigned diagnostic evidence, not a tamper-proof attestation or an
access token. Later deployment activation must bind trusted workflow provenance,
reviewed commit, fresh governance/inventory results and backend evidence. Local
receipts cannot satisfy OCI evidence checks, and even a valid OCI receipt cannot
unlock preview/deploy in this release. Encrypted state can still expose resource
metadata; encryption of secret values is not encryption of every checkpoint byte.

## Recovery procedure (operator-run; never automatic)

For future adopted stacks, freeze all writers first and confirm the exact backend,
project and stack. Record active operations and investigate locks before any action.
Never delete a lock merely because a runner appears idle.

Keep reviewed backups of BOTH the encrypted checkpoint export and encrypted stack
configuration, plus a separately controlled backup of the passphrase. Store backups
outside public CI artifacts. Loss of the passphrase can make secrets unrecoverable.

Rehearse recovery using an isolated backend/project/stack and synthetic data first.
The qualification tool exercises checkpoint import and secret readback for its own
stack; it is not a complete disaster-recovery rehearsal for adopted cloud resources.
Validate backend permissions, locking and identity before any actual restoration.

An explicitly authorized recovery must restore the intended encrypted configuration
and checkpoint using the matching secret provider, then inspect a preview for
unintended replacement/deletion. Do not point two writable backends at the same
resources. Do not restore an old external-state snapshot after Pulumi has modified
resources without reconciling actual cloud state and resource ownership.

If cleanup/qualification fails, inspect only the printed generated namespace. Do
not use force removal, cancel other writers, push production state, recreate a stack
with a conflicting identity or silently switch to Pulumi Cloud/local storage.

## Sources

- [Pulumi DIY backend configuration and permissions](https://www.pulumi.com/docs/iac/operations/stack-management/using-a-diy-backend/)
- [Pulumi passphrase and home environment variables](https://www.pulumi.com/docs/iac/cli/environment-variables/)
