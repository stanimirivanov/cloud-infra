# Isolated drift observation (M05-PR11)

The drift observer (`infra drift --help`) observes one existing unit: `oci-network`, `oci-oke`,
`cloudflare-edge` or `supabase-database`. It compares live refresh-preview results
and the reviewed desired program against an encrypted captured checkpoint.
It never accepts refresh results into authoritative state or remediates resources.

`config/drift.json` ships disabled. Preview identities, operation policy and reviewer
keys also remain disabled/unset. Activation needs an independently reviewed main
commit, provider Read behavior and effective read-only IAM, including credentials
retained inside historical encrypted provider state. A preview flag alone cannot
constrain a provider implementation. There is no drift workflow, schedule or
notification service in this slice; protected orchestration follows in M05-PR14.
Do not expose credentials to an untrusted checkout or a general-purpose runner.

## Admission and private inputs

Use the same private bundle, schema-2 two-role signatures, backup receipt/manifest,
backend qualification/posture and prepared journal protocol described in
[controlled service apply](independent-services.md#controlled-single-service-apply-m05-pr6).
The operation is **monitor**, the environment is `<unit>-monitor`, and the fixed
journal is `.infra/operations/<unit>.json`. Both signers must be distinct from the
requester. Monitor currently retains the existing backup requirement; it grants
no backup restoration or resource-write permission. A prepared request cannot be
replayed after admission. OCI observes under the shared network/OKE local lock;
services share the per-unit apply lock. External writer exclusion remains necessary.

A bundle has exactly `schema_version` (1), `paths`, `backend_account_id`,
`cli_archive`, `provider_home`, and `output`. All file references are private paths
under `.infra`. `output` must be a new file with an existing private parent.
Each input is at most 1 MiB, total at most 6 MiB. Paths contain:

- `operation`, `approval`, `operator`, `approver`, `backup_receipt`, `backup_manifest`,
  `environment`: existing monitor-specific operation admission artifacts.
- `proposal`, `evidence`, `envelope`, `encrypted_configuration`, `qualification`,
  `posture`, `posture_envelope`: existing unit preview inputs. OCI also needs `account`.
- `checkpoint`: exact encrypted CLI stack-export bytes, complete existing protected
  graph with pinned provider scope, passphrase encryption and no pending operations.
  OCI provider authentication must come from the explicit reviewed identity rather
  than embedded alternate authentication fields. Service provider tokens must be
  encrypted in checkpoint inputs/outputs and use the fixed official endpoint.
- `plan`: canonical `infra_core.drift_results.plan(unit)` bytes, describing
  `isolated-drift`, `preview-only-run-program`, `policy-preview`, remediation false.
  Bind their SHA-256 as the operation approval's plan digest; this is an observation
  protocol descriptor, never a saved update plan.
- `credential_review`: schema 1, `unit`, `checkpoint_sha256`,
  `configuration_sha256`, `read_only_scopes_reviewed: true`,
  `historical_provider_credentials_reviewed: true`, `provider_identity_sha256`,
  `reviewed_at`, `expires_at`. Review must be current within fifteen minutes and
  expire no later than the request. OCI identity digest is the canonical
  `operations.digest` of `OCI_USER_OCID` and `OCI_FINGERPRINT`; service identity
  is null because the encrypted provider/configuration bytes bind its tokens.
  This signed attestation records external review, not discovered IAM authority.
- OKE additionally needs `dependency_outputs` and `network_checkpoint`: matching
  real committed network root outputs, identity, region, account, CIDRs and IDs.
  The isolated backend receives only that verified root metadata; no network
  providers/resources are imported or refreshed as part of the OKE observation.

Execution approval binds adapter `isolated-drift-v1`, SHA-256 of every non-approval
input (including plan, checkpoint and credential review), foundation digest,
profile digest and backend account ID. The exact schema-2 binding is assembled by
`infra_program.drift._admit` before the existing signature verifier runs. Freeze
these bytes before external signing; changing any input requires fresh approvals.
The `--check` path verifies admission and re-queries GitHub environment controls
without credentials, journal changes or tool execution.

The explicit command shapes are:

```sh
uv run --locked infra drift --check --unit oci-network --commit <reviewed-main-sha> --actor <owner> --environment oci-network-monitor --bundle .infra/drift/bundle.json --journal .infra/operations/oci-network.json
uv run --locked infra drift --allow-local-writes --unit oci-network --commit <reviewed-main-sha> --actor <owner> --environment oci-network-monitor --bundle .infra/drift/bundle.json --journal .infra/operations/oci-network.json
```

The CLI requires protected manual main execution context: `GITHUB_EVENT_NAME`
workflow_dispatch, `GITHUB_REF` refs/heads/main, exact `GITHUB_SHA`, and
`GITHUB_ACTOR` matching both `--actor` and `GITHUB_REPOSITORY_OWNER`. These caller
assertions do not provision GitHub protection. Independently provision/review the
named environment and dedicated runner before operational use. The library accepts
an explicit trusted caller and lazy credential callback; it is not an authorization
boundary against arbitrary same-user Python code.

After signed admission and journal CAS, credentials are acquired explicitly:
AWS access key/secret (optional session token), a passphrase of at least 20
characters, and for OCI user/fingerprint/private key path under `.infra`.
The source-export process receives backend credentials and no OCI identity.
The local observer receives provider credentials and no AWS variables, using a
separate owned filesystem backend. Service tokens/passwords stay in encrypted
reviewed inputs. No credentials are discovered from ambient CLI profiles.

## Observation and outcomes

The source adapter exposes encrypted stack export only. Export must match the
captured source before observation, and source is re-exported afterward, including
failure paths. For OKE both network and OKE checkpoints must match. A temporary
local backend receives the encrypted checkpoint through local stack init/import.
Its closed commands then run:

1. `refresh --preview-only --run-program` using the existing dry-run-only factory.
2. `preview --refresh=false` with the mandatory repository policy pack.

Pulumi refresh does not accept a local policy pack, so its complete raw preview
events are validated separately before the mandatory-policy comparison. Both
stages compare against the original copied checkpoint; neither persists refreshed
state. The local checkpoint hash must match its post-import baseline afterward.
Tool/provider hashes, frozen inputs, owned files, admission expiry and journal
head are rechecked between stages. Refresh/compare have a shared 240-second budget,
with a 300-second overall budget reserving time for the final source export.
Raw process diagnostics are discarded. Bounded events yield only counts/digests;
resource properties, IDs and secrets are not copied into the report.

- **clean**: both stages completed, mandatory policy passed, only same/read counts,
  unchanged source and local checkpoint.
- **drifted**: both completed with create/update/delete/replacement or other change
  counts. Observation succeeded; this does not authorize remediation.
- **unknown**: failed/unavailable provider, incomplete/invalid events, policy or
  protected-delete preview failure, timeout, changed inputs/checkpoints, expired
  admission or inability to prove source preservation. Never interpret this as clean.

The new mode-0600 report binds operation/commit/checkpoint/configuration, input and
approval digests, observation interval, aggregate stage results, source/local
preservation and terminal journal head. Both authorization fields remain false.
Clean/drifted finish the journal as succeeded. Unknown is failed or indeterminate
when preservation is uncertain after running. Unknown exits nonzero after writing
its report; setup failures before admission may leave no report. Interrupted
persistence requires inspecting journal and report together; never replay a monitor
request automatically. Drifted is a successful observation and exits zero; an
incident/notification decision belongs to M05-PR14. Revert this PR to remove the
interface, or independently review gate deactivation; no migration is required.

## Verification and activation limits

```sh
uv run --locked pytest -q tests/test_drift_results.py tests/test_drift.py tests/test_drift_runtime.py
RUN_OPERATION_INTEGRATION=1 uv run --locked pytest -q -m operation_integration
uv run --locked infra verify
```

Offline tests cover all four graph scopes, monitor-specific signatures, credential
separation, error/unknown handling and source rechecks. The existing opt-in gate
uses synthetic RPC provider-deletion/error/timeout events and the real pinned
engine with disposable, provider-free encrypted state. It proves local refresh
and desired-config comparison leave source/local state unchanged. It does not
prove native OCI/Cloudflare/Supabase Read RPC behavior, live deletion observation,
read-only IAM, production backend isolation or hostile concurrent writer exclusion.
Those remain separately authorized credentialed acceptance prerequisites; no
production provider or state operations run as routine verification.
