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

## Explicit encryption policy and custody

Foundation schema 2 requires `secrets_provider = "passphrase"`. Other providers,
implicit defaults and schema 1 fail closed; no KMS/Vault service is provisioned.
Both synthetic initial and recovery stack initialization use this reviewed policy.
Backend bucket/prefix/region and disabled units stay unchanged. The current
qualification receipt version is described below.

**Migration:** the new policy is included in the configuration digest. Old
qualification receipts and backend-posture documents therefore fail binding even
if their timestamps/check lists remain current. Collect new posture and explicitly
requalify; never edit digests or restamp old evidence. No stack re-encryption or
production migration is performed by updating this file. Existing future stacks
must separately prove their actual encryption provider; declaring policy is not
proof of external stack settings. Reverting schema/policy also requires compatible
code and fresh evidence; never reuse a receipt merely because a digest reappears.

A designated operator owns passphrase custody and a second reviewer owns recovery
acceptance before activation. Use a cryptographically random passphrase stored in
a controlled password manager; the qualification workflow retains its minimum
20-character check. Keep an access-controlled recovery copy separate from encrypted
checkpoint and stack-config backups, with named recovery holders and tested access.
No actual holders or production custody arrangements are attested by this PR.

Expose the passphrase only to the protected operation that needs decryption;
never save it in public config, command arguments, source or CI artifacts. Protected
workflow environment injection is the current handoff, not an encryption service.
Local qualification generates a disposable random passphrase. Encrypted checkpoints
still expose nonsecret metadata, and a leaked passphrase plus ciphertext can reveal
secrets. `require_secret()`/secret Outputs cannot repair plaintext source files.

Passphrase rotation is a separate operational change: freeze writers, preserve
reviewed encrypted backups and old-key recovery access, re-encrypt config and state
with the approved provider, rehearse restore and verify previews before retiring
old custody. Never silently replace an environment passphrase for an existing stack.
Provider-token revocation and database-password rotation are distinct operations:
review their consumers/impact, update encrypted config, verify approved operations,
then revoke old credentials. This factory performs none of these live changes.
Independent recovery qualification uses synthetic data and is not production DR.

The [Pulumi secrets model](https://www.pulumi.com/docs/iac/concepts/secrets/)
and [interactive encrypted config entry](https://www.pulumi.com/docs/iac/cli/commands/pulumi_config_set/)
are adapted using the already locked Apache-2.0 Pulumi SDK; no new dependency or
managed service is added. Managed encryption and authenticated production key
lifecycle remain separate architecture/operations decisions.

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
the passphrase and fresh BACKEND_POSTURE_JSON evidence to the qualification step;
there are no OCI provider/API credentials in the workflow.
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
3. Collect and review bucket posture using the read-only commands below. Store the
   resulting JSON as environment secret `BACKEND_POSTURE_JSON` immediately before
   qualification. It must be under one hour old at preflight. This is a manual
   evidence handoff, not a signed collector attestation; protect who may update it.
   Stale/missing/unsafe evidence fails before any remote checkpoint operation.
4. Restrict the credential's object-storage permissions to the intended bucket and
   namespace to the extent OCI IAM permits. Do not assume S3 ARN/prefix IAM syntax
   maps directly to OCI. If isolation cannot be enforced, use a separately approved
   dedicated bucket and update configuration before testing.
5. Confirm available object-storage allowance and retention settings before writes.
   Configuration does not prove billing eligibility or remaining account storage.
   Qualification checkpoints are capped at 1 MiB by the tool, but that check occurs
   after the initial checkpoint write and does not cap bucket history/total usage.
6. Review bucket lifecycle rules for qualification history. Stack removal does not
   promise deletion of backend metadata/history. Clean only expired qualification
   prefixes after verifying no update is active. Never apply an expiry rule to active
   stack/checkpoint data. Production state retention needs a separate reviewed policy.

Repository environment and branch settings are administrative prerequisites; this PR
provides the workflow and runbook, not proof those settings have been applied.

## Read-only backend posture

The optional OCI reader uses only get_namespace, get_bucket and fully paginated
list_retention_rules/list_preauthenticated_requests. It never reads state objects
or changes bucket/IAM policy. With separate read-only API credentials:

```sh
uv run --locked --extra inventory-oci infra backend collect-posture --account-id OCID --oci-config .infra/oci-config --output .infra/backend-posture.json
uv run --locked infra backend check-posture --evidence .infra/backend-posture.json
```

The schema-v1 posture document binds to the unchanged foundation configuration,
bucket, namespace and region and records collection start/completion. Both clocks
must be ordered and within one hour. Checks require NoPublicAccess, Enabled
versioning, Standard storage, explicit writable status, zero retention rules/PARs
and no lifecycle-policy ETag. Unknown values fail; policies need separate reviewed
support rather than a boolean override. Versioning is checked, never enabled;
retained history still needs allowance/budget review. A failed collection removes
stale output and exposes only safe errors. The reader cannot prove least-privilege
IAM, audit-log configuration, retention durability or account eligibility.

The protected workflow writes its private evidence secret to the ignored default
path and validates it before remote qualification. Operator-collected JSON can be
forged; trusted collection/signing and fresh posture on every future protected
preview remain activation prerequisites, not guarantees of this offline validator.

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
writer is rejected by a backend lock, then removes only its own synthetic stack
and reconstructs it from the encrypted checkpoint/configuration in a fresh workspace
and PULUMI_HOME. Fresh-session secret readback must match. The separately retained
passphrase is supplied explicitly. The restoring CLI uses a new home/current
working directory and an explicit backup set on the same temporary filesystem.
Before correct-key readback, another fresh workspace/home copies only the
project/program and encrypted stack config, logs in to the same isolated backend,
and receives a separately generated, deliberately different passphrase. It runs
only config get and checkpoint output reads of the synthetic sentinel. Neither a
new stack nor an update/import is attempted with that key. Each read must exit
with a recognized error exit (1 or 255) and the pinned CLI's incorrect-passphrase
diagnostic on stderr, without returning the plaintext sentinel. Success, unrelated errors, timeouts, unavailable
CLI and signal termination all fail qualification. Raw output is withheld.
Correct-key readback after these rejections must still match the original sentinel.
The wrong-key value is passed only through the subprocess environment, never CLI
arguments, logs or the receipt. No automatic fallback to a working key is allowed.

This does not exercise off-host backup retrieval, independent credential recovery
or loss of the entire machine. The runner captures raw CLI
output, including the synthetic plaintext readback, without printing it. Failures
report a phase and exit code rather than potentially secret-bearing diagnostics.

Cleanup removes only the invocation-specific stack, without force or lock cancellation.
A cleanup failure fails qualification. Backend metadata/history can remain. The run UUID
is printed so operators can inspect an orphan namespace after failure. A failed retry
removes stale local evidence; a request without the write flag preserves it.

Only the sanitized `.infra/qualification.json` receipt is saved/uploaded (one-day
artifact retention). It records the run UUID, configuration digest, tool version,
time, check names, encrypted checkpoint SHA-256/byte size, backup age and measured
restore seconds, plus `deployment_authorized=false`. Timings use a high-resolution
performance clock: backup age spans export through simulated loss; restore spans
fresh login/init/import, both wrong-key rejection probes and final correct-key
readback, excluding loss simulation and cleanup. Schema-v3 timings include this
additional negative acceptance work and are not directly comparable to v2 timings.
These observations are not an agreed production RTO/RPO or a data-recovery guarantee.
Schema-v1/v2 receipts are rejected. Receipt schema 3 requires the exact
wrong-passphrase-rejected check in addition to the existing five checks; that check
means both config and checkpoint rejection completed. Run a new qualification to
obtain v3; never edit versions, timestamps or check names to upgrade old evidence.
No raw output, checkpoint, stack configuration, passphrase or credential is uploaded. It expires within the
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
The qualification tool now rehearses synthetic stack loss and independent-session
restore; it is not a complete disaster-recovery rehearsal for adopted cloud resources.
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

Posture field semantics follow [Oracle bucket metadata](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/object_storage/models/oci.object_storage.models.Bucket.html)
and [read/list Object Storage APIs](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/object_storage/client/oci.object_storage.ObjectStorageClient.html).

Wrong-key detection follows the [pinned Pulumi passphrase manager](https://github.com/pulumi/pulumi/blob/v3.272.0/pkg/secrets/passphrase/manager.go):
ErrIncorrectPassphrase and its locked-decrypter error identify cryptographic
rejection. CLI upgrades must review this classifier and rerun the real local
backend_integration test. An unsupported diagnostic fails closed, not as proof of
rejection. This adapts the existing Apache-2.0 Pulumi CLI contract without adding a
dependency. The opt-in local integration (also run in CI) exercises both incorrect
and matching keys; ordinary offline mocks cannot prove that a real cipher rejected
an incorrect key. Same-host synthetic acceptance does not verify off-host backups,
independent human custody, live principal access, credential rotation or production DR.
