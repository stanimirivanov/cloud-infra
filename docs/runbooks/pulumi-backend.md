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

Foundation schema 3 requires `secrets_provider = "passphrase"`. Other providers,
implicit defaults and schemas 1/2 fail closed; no KMS/Vault service is provisioned.
Both synthetic initial and recovery stack initialization use this reviewed policy.
Backend bucket/prefix/region and disabled units stay unchanged. The current
qualification receipt version is described below.

**Migration:** project identity, preview flags and dependencies are now included
in the configuration digest alongside the encryption policy. Old
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
integration test on Linux. pip is a locked development dependency because
the Pulumi Python host uses `pip list` for package discovery; dependencies are still
installed by uv. No deployment-time pip install is performed.

For a real OCI test, an authorized operator selects `qualify` in the **Pulumi
foundation** manual workflow on main. The workflow serializes foundation operations,
runs verification first, checks out the dispatch commit, and executes behind the
`pulumi-backend-qualification` environment. Its read-only audit step receives
separate OCI signing credentials and collects fresh posture before qualification.
Only the later qualification step receives S3 HMAC credentials and the passphrase.
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
3. Configure the read-only audit signing secret and independently reviewed tenancy
   variable as described below. Qualification now collects its own fresh posture
   pair in the same job; manual BACKEND_POSTURE_JSON/BACKEND_POSTURE_ENVELOPE_JSON
   secrets are unused. Missing/unsafe collection fails before remote checkpoint writes.
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

## Protected audit and credential contract

Select audit in the manual Pulumi foundation workflow for metadata-only checks;
select qualify to collect and validate the same evidence before isolated writes.
The default inspect and disabled preview/deploy operations receive no signing key.
The shared credential-free workflow must pass first, and both jobs require main
and the repository owner. Checkout uses the exact dispatch commit. No workflow is
run or repository/environment setting changed by merging this code.

In the protected environment, independently set BACKEND_POSTURE_ACCOUNT_ID in
GitHub environment vars to the reviewed tenancy. Store OCI_BACKEND_AUDIT_CREDENTIALS
as an environment secret containing a JSON object with required string fields
tenancy, user, fingerprint and key_content (the complete PEM signing key); optional
pass_phrase supports an encrypted key. No key-file paths, extra SDK settings,
empty values, duplicate JSON keys or multiline INI fields are accepted. The whole
JSON is limited to 64 KiB; key_content alone may be multiline. Tenancy must equal
the independent expected account before any SDK call. Region comes from reviewed
foundation config. Keep the JSON out of source, commands and public examples.

Administrators must assign a separate principal with only the namespace/bucket
metadata and retention-rule/PAR list permissions required by the existing reader,
scoped to the intended bucket/account as OCI permits. It must have no object-data
read/write or IAM mutation permission. Review actual IAM policy and denied writes
independently; successful metadata reads cannot establish least privilege. Never
reuse the S3 writer key as an audit signing key. Required reviewers, protected-main
branch restrictions and no self-review remain external administrative prerequisites.

The adapter uses the existing locked inventory-oci extra, writes a temporary key
and explicit SDK config outside the checkout (0700 directory/0600 files on the
hosted Linux runner), and removes them before returning. SDK/CLI output is withheld;
AUDIT001 reports failure without credentials or private payload values. Failed
attempts remove stale pairs/reports. The always-run cleanup removes private posture
and sidecar files after their same-job consumer. Forced runner termination cannot
guarantee finally/cleanup execution; use the specified ephemeral hosted runner.

Only .infra/backend-audit.json is uploaded for one day: closed status, original
collection clocks, commit/configuration identity, payload/envelope SHA256 and
explicit deployment_authorized=false. The qualification receipt is separate;
raw posture, sidecars, credentials and state are never artifacts. A successful
audit summary is retained even if later qualification fails. GitHub run history
provides execution context for independent review; the JSON is unsigned and is
neither a source attestation nor deployment/cutover authority. No freshness renewal,
IAM proof or activation occurs. M03-PR12 must consume reviewed provenance separately.

This adapts [GitHub environment protection](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/control-deployments)
and [Oracle's explicit SDK config](https://docs.oracle.com/en-us/iaas/tools/python/latest/configuration.html)
using stdlib glue and the existing OCI extra (Oracle UPL/Apache-2.0 license options);
no new dependency or signing service. Legacy manual posture secrets can be retired
after this workflow is adopted. Rollback needs the old workflow and a freshly
collected exact-byte pair restored to those secrets; the sanitized artifact cannot
reconstruct private evidence. Local CLI collection and receipt schema 3 are unchanged.

## Read-only backend posture

The optional OCI reader uses only get_namespace, get_bucket and fully paginated
list_retention_rules/list_preauthenticated_requests. It never reads state objects
or changes bucket/IAM policy. With separate read-only API credentials:

```sh
uv run --locked --extra inventory-oci infra backend collect-posture --account-id OCID --oci-config .infra/oci-config --output .infra/backend-posture.json
uv run --locked infra backend check-posture --account-id OCID --evidence .infra/backend-posture.json
```

Collection requires a clean Git checkout and emits .infra/backend-posture.json
plus .infra/backend-posture.json.envelope.json. Offline checks and remote
qualification require both; --account-id supplies the independently reviewed
expected tenancy. The consumer gets the commit from its own clean checkout,
region/configuration from config/pulumi.toml and fixed unit backend. It never
adopts scope expectations from the supplied envelope. The producer records the
same original collection clocks in payload and envelope; a changed checkout
during collection fails publication. Reads are bounded before parsing; duplicate
payload keys and malformed JSON fail with sanitized diagnostics. The shared
[unsigned envelope contract](security-evidence.md) binds the exact payload bytes;
reformatting JSON or changing line endings fails validation.

**Migration:** standalone legacy posture JSON is rejected. Collect a fresh pair
from the reviewed commit and set the independent expected tenancy, then explicitly
requalify. The protected workflow now performs collection in its own job. Do not wrap old payloads,
restamp observations or edit a sidecar to pass. Local disposable qualification is
unchanged; receipt schema remains 3. Backend source changes still require renewed
qualification. Reverting this change restores the older weaker handoff and needs
compatible workflow code; do not retain newly collected evidence as activation
proof after a revert.

The schema-v1 posture document binds to the unchanged foundation configuration,
bucket, namespace and region and records collection start/completion. Both clocks
must be ordered and within one hour. Checks require NoPublicAccess, Enabled
versioning, Standard storage, explicit writable status, zero retention rules/PARs
and no lifecycle-policy ETag. Unknown values fail; policies need separate reviewed
support rather than a boolean override. Versioning is checked, never enabled;
retained history still needs allowance/budget review. A failed collection removes
both stale outputs and exposes only safe errors. Partial file publication is
removed on handled I/O failures; an interrupted/mixed pair fails consumer binding.
The reader cannot prove least-privilege IAM, audit-log configuration, retention durability or account eligibility.

The protected workflow uses its freshly collected pair within the same job;
local operators preserve exact bytes when using the CLI. Operator-collected JSON
and its unsigned sidecar can be forged together. Controlled workflow execution is
additional review context, not cryptographic source authentication. Trusted signing
and fresh posture on every future protected preview remain activation prerequisites.

An authorized local OCI qualification alternatively requires the three environment
variables above, followed by:

```sh
uv run --locked infra backend qualify --account-id OCID --allow-backend-writes
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

## Local encrypted-pair capture (M05-PR3)

`uv run --locked infra backup capture --help` describes the explicit backup-write
command. It accepts a schema-1 operation request, --checkpoint and --config paths
under ignored .infra, an absolute --repository outside this checkout, its exact
--repository-id, a private --password-file (mode 0600), and --exported-at with an
explicit timezone. --allow-backup-write is required. The destination must already
be initialized; capture never initializes, restores, prunes or deletes snapshots.
Only local/mounted repositories are supported; production storage is unconfigured.

Supply a frozen encrypted checkpoint export without --show-secrets, and the matching
stack configuration in JSON-formatted YAML (a valid Pulumi YAML subset). Standard
YAML syntax and plaintext config entries are deliberately rejected rather than
introducing another runtime parser. Every config entry must be a secure v1 value;
passphrase salt must match the checkpoint. Plaintext Pulumi secret wrappers are
rejected. Unmarked sensitive values cannot be detected; ciphertext validity and
recoverability require the later recovery rehearsal. The operation's configuration
hash binds this exact stack-config file, and its checkpoint hash binds the export.
The source export clock is supplied by the operator, must be within one hour and is
not refreshed by packing. This command does not export live state, freeze writers,
authenticate provenance or establish that the supplied pair is current production state.

The verified restic 0.19.1 executable backs up exactly checkpoint.json,
stack-config.json and manifest.json. The manifest binds stack/unit/commit, request
hash, file hashes, source/capture clocks and destination repository identity.
A successful complete snapshot produces a local receipt with the snapshot ID and
manifest hash. Exit 3 (partial snapshot), malformed summary, wrong repository,
timeout or persistence error is never reported as success. The UUID capture directory
is reserved and retained on uncertainty: reconcile snapshots before retrying with
a separately reviewed request. Credentials and raw tool diagnostics are never
included in receipts. No cloud credentials or ambient restic configuration are inherited.

The restic binary is BSD-2-Clause licensed; its official v0.19.1 archive digest was
checked against GitHub release metadata, and its decompressed executable hash is
pinned in config/toolchain.json. No Python dependency is added. The opt-in existing
operation_integration gate initializes only a disposable test repository and restores
the captured synthetic files for hash comparison. This is not off-host recovery,
a production retention policy or proof of independent storage/key custody. Those
remain separately reviewed work. A mounted directory may share the production
failure domain despite being outside the checkout. Keep the restic password and
Pulumi passphrase under separate custody; neither is part of the backup set.

## Isolated restore rehearsal (M05-PR4)

`uv run --locked infra backup rehearse --help` describes the opt-in local-write
command. Supply --policy, --receipt, --repository, --password-file,
--passphrase-file and a new --output path under .infra. --allow-local-writes is
required. Password/passphrase files must be distinct, private (0600) files.
Use config/recovery.example.json as an incomplete template: both numeric objectives
must be explicitly supplied. No production RPO/RTO is implied by test values.

New captures use manifest schema 2, adding source_host_id: SHA-256 of the source
machine ID. Rehearsal compares the current host fingerprint, never its raw ID.
Schema-1 backups remain stored but must be recaptured for this gate; do not edit or
restamp their old manifests. require_independent_host=true rejects same-host
rehearsals. False is for explicitly limited local tests, reported as same-host.
Different machine IDs are host evidence, not hardware/custody attestation; containers,
cloned images and dishonest hosts limit this sensor.

The receipt pins repository/snapshot/manifest identity. Rehearsal retrieves only the
three expected bounded files using restic --no-lock, checks their hashes and stack identity, and creates
new temporary backend, project and isolated Pulumi HOME directories. It imports
only into that disposable local backend; no program, preview, resource provider,
production stack or source writer is run. Independent wrong-key HOMEs must yield
the pinned CLI's recognized incorrect-passphrase error for configuration and
checkpoint reads before matching-key reads succeed. Raw decrypted data is discarded.
The sanitized report binds the policy digest, snapshot and manifest, source export
age and monotonic retrieval/readback duration. Exceeded objectives produce
objectives_met=false and CLI exit 1. Other failures produce no successful report.
Timings exclude runner provisioning and credential retrieval; they do not establish
end-to-end production disaster-recovery guarantees. Workspaces are removed after
normal failure/success; force-killed runners require secure disposal.

The manual recovery-rehearsal workflow requires main, repository owner, shared
verification and the protected recovery-rehearsal environment. Administrators must
provide an isolated, disposable self-hosted Linux runner in the recovery runner group, separately mount
the existing local repository, configure RECOVERY_REPOSITORY and RECOVERY_POLICY
(with independence required), and separately supply RECOVERY_RECEIPT,
RECOVERY_BACKUP_PASSWORD and RECOVERY_PASSPHRASE. No production destination or
credentials are configured by this PR. Review secret-size limits before handoff.
Credential files and the report are ephemeral; only sanitized CLI output is logged.
PR validation never receives these credentials. The existing operation_integration
gate exercises real encrypted capture/readback locally with same-host limits.

Keep snapshot retention/pruning frozen during the lock-free read. Runner-group
availability and repository access must be verified administratively before dispatch;
this workflow does not create runner infrastructure or establish external protections.

M05-PR10 strengthens newly generated isolated-rehearsal reports to schema 2. They
add the measured started/completed clocks, unit/stack/backup-operation ID,
checkpoint/configuration digests and source/recovery host hashes. Existing wrong-key,
readback, independence and RPO/RTO measurements remain unchanged. The separate
[owner handoff gate](kubernetes-cutover.md#signed-owner-handoff-m05-pr10) requires
these scope bindings and rejects old unscoped reports; it never restores production
state. No recovery credentials or raw machine identifiers are added to reports.

## M06 backend readiness checks

M06-PR3 combines the existing remote qualification receipt and bucket posture
checks with an explicit observation of the four existing project-scoped stacks.
It is an offline gap report, not stack bootstrap, credential admission or backend
acceptance. No deployment flag, bucket policy, namespace or stack is changed.

From a clean committed checkout, use an independently reviewed expected tenancy:

```sh
uv run --locked infra backend check-readiness --account-id OCID
uv run --locked infra backend check-readiness --account-id OCID --evidence .infra/backend-readiness.json
```

Without an index, every evidence component reports `pending`. The optional closed
schema-1 index has exactly these fields; each path may instead be null:

```json
{
  "schema_version": 1,
  "qualification": ".infra/qualification.json",
  "posture": ".infra/backend-posture.json",
  "stacks": ".infra/backend-stacks.json"
}
```

`posture` requires its existing `.envelope.json` sidecar. Every artifact must be
a distinct canonical relative `.infra/*.json` path without symlinks. Captures are
limited to 1 MiB per file. Duplicate fields, path aliases (including the sidecar),
unknown index fields and malformed evidence fail with redacted `BREADY001`.
Captured bytes and the clean checkout identity are rechecked before returning.
Account identifiers and raw observations are not included in the report.

The qualification component calls the existing schema-3 receipt validator:
remote `oci-s3` kind, current configuration digest and CLI version, all encryption,
locking and independent-recovery checks, measured recovery metrics and the
configured TTL are required. A local test receipt cannot establish remote
readiness. Qualification receipts bind configuration, not a commit or signing
identity; their provenance still needs independent review. This PR adds an optional
clock argument to the validator so the combined check uses one captured clock;
existing callers retain the same wall-clock behavior.

The posture component calls the existing payload/envelope validator against the
independently supplied account, current clean commit and loaded configuration.
Its original collection clocks must remain within one hour. Private/versioned,
Standard, writable storage with no PARs, retention rules or lifecycle policy is
still required by the existing contract. A separately reviewed retention design
must respect this contract or explicitly change it; do not claim acceptance by
adding an unchecked retention boolean.

### Existing-stack observation contract

The stack file is an **unsigned operator observation**, not a live Pulumi listing
or evidence that this checker decrypted production state. Its closed schema is:

- `schema_version`: integer 1.
- `account_id`: the independently expected tenancy.
- `commit`: current reviewed clean checkout commit.
- `configuration_sha256`: the foundation configuration digest reported by
  `uv run --locked infra backend inspect`.
- `backend`: the exact configured backend URL, also reported by that command.
- `collection_started_at` and `collection_completed_at`: original timezone-aware
  ISO timestamps, ordered and no more than one hour old.
- `stacks`: exactly four records, one per configured unit. Each record contains
  only `unit`, `stack_identity`, `exists`, `secrets_provider`, `pending_operations`.

For each of `oci-network`, `oci-oke`, `cloudflare-edge`, and `supabase-database`,
`stack_identity` must be `organization/free-infrastructure/` followed by the unit
name, `exists` must be true, `secrets_provider` must be `passphrase`, and
`pending_operations` must be integer zero. Missing stacks, ambiguous or duplicate
identities, other projects/backends, unknown encryption and pending operations
block consistency. Never substitute a qualification stack or initialize a missing
production stack merely to fill this record.

The backend custodian must inspect the exact existing stacks using separately
reviewed read-only access and preserve the original observation context privately.
No stack-observation collector is added here. Do not place checkpoints, encrypted
configuration, passphrases or raw account evidence in the repository or PR. A
consistent assertion is labeled `operator-observations-consistent`; no semantic
claim about actual ciphertext, effective IAM or live resource ownership follows.

### Acceptance boundary and remaining review

The report always has `status: pending`, `backend_ready: false`,
`execution_authorized: false`, `activation_authorized: false` and
`live_controls_verified: false`. The CLI exits 1 for pending or invalid input.
Missing evidence is pending; supplied stale, unsafe or mismatched evidence is an
error. Consistent qualification/posture are labeled `observed-controls-consistent`.
The report cannot serve as a successful readiness acceptance record by itself.
Independent review must bind the original evidence and clocks, not restamp this
summary or equate a synthetic qualification with production-stack recovery.

Before live acceptance, the backend/key custodian and independent reviewer must
review the effective S3 identity and least privilege, exact backend namespace and
exclusion of external state, all four existing stack identities, passphrase/key
custody, independently available recovery access, retained version history and
storage budget. Write tests, qualification workflow dispatch and stack creation
remain separate explicitly authorized operational actions. No such live action
was performed by this engineering PR; missing live evidence remains pending.

Focused verification uses
`uv run --locked pytest -q tests/test_backend_readiness.py tests/test_backend.py tests/test_backend_envelopes.py tests/test_operations_evidence.py`.
The shared gate remains `uv run --locked infra verify`. This adds no dependency or
receipt/posture schema migration; reverting the checker removes only the new
reporting interface and cannot undo an operational action.
