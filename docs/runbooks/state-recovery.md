# Authorized state recovery (M05-PR15)

`infra state-recovery --help` restores one approved encrypted checkpoint/configuration
pair to an **existing** Pulumi-owned unit. Supported units are `oci-network`,
`oci-oke`, `cloudflare-edge` and `supabase-database`. This is checkpoint recovery,
not resource rollback or application-data recovery. It never creates a stack,
forces an import, applies resources, retries an import or releases writers.

`config/state-recovery.json` ships disabled. Operation policy, reviewer enrollment,
preview contracts, backend qualification and environment protections remain separate
activation requirements. Enabling this contract or dispatching the workflow requires
an operational review; merging this implementation performs neither action.

## Scope and custody

Use a dedicated protected recovery runner with independent access to the selected
pre-initialized **local restic repository**. Production backup transport and credential
custody require separate review. The repository must be outside this checkout and
contain the exact selected three-file snapshot. The recovery host must differ from
the backup source host and must have successfully rehearsed that same snapshot.

Maintain an external idle freeze throughout admission, import and independent
operator reconciliation. Freeze both OCI units for either OCI recovery. GitHub
concurrency and the shared local dependency/apply locks protect cooperating clients;
they cannot freeze another host or revoke external credentials. Preserve durable
`.infra/operations/<unit>.json` journals and coordinate every runner against the same
journal/locks. The signed freeze observation attests this operational work; it does
not discover IAM state or stop writers itself.

Only the state-import subprocess receives S3 writer credentials. Isolated observers
receive the old pair's passphrase and reviewed read-only provider credentials, never
S3 credentials. Review provider credentials embedded in historical encrypted state:
preview flags alone cannot constrain provider Read behavior or make old credentials
read-only. OCI review binds the supplied user/fingerprint identity. Provider archives,
CLI and uv are pinned and verified; the disposable programs run with offline package
resolution. Raw checkpoint/configuration, engine diagnostics and decrypted values
must stay private and must never be uploaded as workflow artifacts.

## Admission inputs

Reuse the schema-2 two-role admission and prepared-journal protocol in
[controlled service apply](independent-services.md#controlled-single-service-apply-m05-pr6).
The operation is `recovery`, protected environment is `<unit>-recovery`, and both
roles sign the exact recovery execution profile. A current successful `apply`
journal entry establishes service ownership; OCI requires a successful `import`
entry plus the authenticated earlier owner-handoff evidence below.

The private bundle has exactly these keys:

- `schema_version`: 1; `paths`: the closed map below.
- `backend_account_id`, `cli_archive`, `provider_home`: existing reviewed backend
  and pinned runtime inputs used by other operation drivers.
- `repository`: absolute path to the existing local restic repository.
- `configuration_destination`: `.infra/recovery/configs/<unit>/<operation_id>.json`.
- `output`: a new private receipt path under `.infra`.

Create private destination parent directories beforehand. Destinations must not
exist; publication uses exclusive creation, mode 0600 and file/directory fsync.
Every `paths` value is an existing bounded private file under `.infra`. Common keys:

`evidence`, `envelope`, `proposal`, `encrypted_configuration`, `qualification`, `operation`,
`approval`, `operator`, `approver`, `backup_receipt`, `backup_manifest`, `environment`,
`posture`, `posture_envelope`, `plan`, `current_checkpoint`, `restore_checkpoint`,
`restore_configuration`, `restore_manifest`, `restore_receipt`, `restore_policy`,
`rehearsal`, `freeze`, `credential_review`.

Confirm this map against the driver's `names(unit)` contract when preparing inputs.
OCI additionally needs `account`, `peer_checkpoint`, `owner_decision`, `owner_approval`,
`owner_operator`, `owner_approver`, `owner_subject`, `owner_checkpoint`; OKE also needs
`dependency_outputs`, equal to the current network root outputs.

`backup_manifest`/`backup_receipt` describe the **current safety backup**. The recovery
request binds its current checkpoint and configuration hashes. `restore_*` identify
the selected historical pair and its independently verified snapshot. Repository ID,
manifest, checkpoint and configuration bytes must all match the actual restic
snapshot. A filesystem copy or unsigned snapshot label is insufficient.

`restore_policy` uses the existing rehearsal schema: version 1, positive finite
`max_backup_age_seconds` and `restore_objective_seconds` (at most 300), and
`require_independent_host: true`. The schema-2 `rehearsal` must identify this host,
snapshot, policy and pair, pass both objectives and prove key acceptance/rejection.
The operation's own total timed interval includes retrieval, key checks, import and
both reconciliation passes. Exceeding it after launch leaves an indeterminate result.

`credential_review` is schema 1 with `unit`, restored `checkpoint_sha256` and
`configuration_sha256`, `read_only_scopes_reviewed: true`,
`historical_provider_credentials_reviewed: true`, `provider_identity_sha256`
(OCI user/fingerprint canonical digest; null for services), `reviewed_at`, `expires_at`.
Its observation is at most 15 minutes old and expires no later than the request.

The canonical `plan` is generated by `infra_core.recovery_contracts.plan`: version 1,
operation `state-recovery`, `subject_sha256`, immutable configuration destination,
`resource_operations: false`, `writer_release: false`. The subject hashes the operation,
current checkpoint/configuration, restored checkpoint/configuration/manifest/receipt,
proposal and credential review. `freeze` binds that subject and contains schema 1,
`frozen_at`, `observed_at`, `expires_at`, and a `writers` map for exactly the affected
unit (both OCI units). Each entry is `owner: pulumi`, `source_active: false`,
`target_active: false`, `active_operations: 0`. The safety export must follow the
freeze; the observation follows that export and is at most 15 minutes old.

OCI `owner_subject` is the original handoff artifact-name/hash map. Its digest must
match `owner_approval.evidence_sha256`, with original two-role DSSE signatures
verified using the current operations-policy trust. `owner_checkpoint` must match
that subject and the restored resource identities. The original decision receipt,
approval hash and handoff ID must agree. This authenticates historical provenance;
it does not rerun the expired handoff decision or grant fresh writer authority.
Current recovery signers bind this entire provenance and the fresh freeze. A changed
policy/foundation or unavailable historical reviewer key requires a separately
reviewed trust migration; there is no bypass.

## Protected execution and outcomes

The manual `.github/workflows/state-recovery.yml` requires main, repository owner,
exact dispatch SHA, shared verification and the separate unit recovery environment.
Its credential-free preflight calls `--check`; only the later admitted step receives
`RECOVERY_S3_ACCESS_KEY`, `RECOVERY_S3_SECRET_KEY`, `RECOVERY_PASSPHRASE` and
`RECOVERY_BACKUP_PASSWORD`. OCI also requires read-only recovery user/fingerprint
secrets and the private runner key path variable. `OPERATION_OBSERVATION_TOKEN`
checks current GitHub environment protection; repository settings and IAM must be
reviewed independently. Bundle/journal variables name the prepared private files.

The CLI requires explicit workflow context and exactly one of `--check` or
`--allow-state-writes`, together with `--unit`, `--commit`, `--actor`, `--environment`,
`--bundle`, `--journal`. Core-only callers have no recovery callback by default.
Check mode never acquires credentials or changes journals/state.

Before launch, the driver verifies exact current and restored resource identities,
parents/providers/protection and managed input/output properties. Network outputs
must remain equal; OKE uses only the frozen network output projection locally.
Missing stacks/resources, pending operations, corrupt checkpoints, changed managed
properties and re-encrypted managed-property ciphertext are conservatively rejected.
This slice is not a general bootstrap disaster-recovery mechanism.

The selected pair is imported into a disposable backend, its salt-bound synthetic
canary must reject a wrong key and accept the reviewed key, all local secrets must
decrypt, and refresh plus mandatory-policy preview must report only same/read.
The current source and OCI peer must still exactly match before the single import.
Recovered configuration is published to the immutable destination, then the imported
source is exported encrypted and checked again in another disposable backend.
Locally decrypted deployment hashes must match before/after (excluding only engine
manifest metadata); Pulumi may legitimately re-encrypt ciphertext during import.
Plaintext exists only in the isolated subprocess response and is never recorded.
The source/peer are checked again after reconciliation.

Admitted attempts end `failed` before import, `indeterminate` once import may have
started, or `succeeded` after all checks. Failure diagnostics are withheld. A receipt
records hashes, timings, journal head and configuration publication status. Neither
success nor failure grants writer release or resource-operation authority. Keep the
freeze, inspect the durable journal and actual backend privately, and obtain a
separate operational review before activating the recovered configuration and writers.
An interrupted import or config-publication failure must never trigger automatic
compensation or replay. Process termination may leave a `running` journal without
a receipt; treat that as indeterminate. Reverting this code does not undo a recovery.

## Verification

Focused credential-free checks:
`uv run --locked pytest -q tests/test_recovery_driver.py tests/test_recovery_rehearsal.py`.
The shared gate is `uv run --locked infra verify`.
Opt-in disposable engine checks use `RUN_OPERATION_INTEGRATION=1 uv run --locked pytest -q -m operation_integration`.
They exercise synthetic local checkpoints/restic only, including encrypted import,
wrong keys, empty configuration/output rehearsal, missing target refusal, signed
admission failures, pre/post drift, changed inputs and interrupted writes. No live
cloud operation or workflow dispatch is part of these checks.
