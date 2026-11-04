# M07 engineering closeout and live prerequisites

M07 adds provider capability reporting, tighter preview and apply bindings, and
operator collection commands for the supported service units. PR1–PR9 are merged
through [PR #202](https://github.com/stanimirivanov/cloud-infra/pull/202) at
`624a9a1027b9c75d4590687dc1dfbbf7d2d0cac7`. PR10 tracks the guide and this
acceptance record under [issue #203](https://github.com/stanimirivanov/cloud-infra/issues/203).
Its engineering acceptance is pending its required checks and merge.

The tracked foundation flags are false for all four units. The per-unit service
apply, OCI apply, and OCI import switches are also false. Live acceptance is
pending for every unit. The operator sequence and input manifest are in the
[User and Operator Guide](USER_GUIDE.md).

## Repository acceptance evidence

Test names refer to the [repository test suite](../tests/).

| Slice | Merged PR | Evidence and acceptance boundary |
| --- | --- | --- |
| PR1 | [#186](https://github.com/stanimirivanov/cloud-infra/pull/186) | `test_provider_capabilities.py` covers the closed capability catalog, configured units, unsupported providers, and reporting authority flags. |
| PR2 | [#188](https://github.com/stanimirivanov/cloud-infra/pull/188) | `test_services.py` covers provider composition and SDK registration with the existing protected service contracts. |
| PR3 | [#190](https://github.com/stanimirivanov/cloud-infra/pull/190) | `test_governance_policy.py` covers policy configuration and the selected OCI profile limits. |
| PR4 | [#192](https://github.com/stanimirivanov/cloud-infra/pull/192) | `test_preview_results.py` and `test_preview_driver.py` cover exact Cloudflare and Supabase graph matching and rejection of substitutions. |
| PR5 | [#194](https://github.com/stanimirivanov/cloud-infra/pull/194) | The receipt and driver tests also cover OCI identities, capacity, reference resolution, and OKE committed dependency binding. |
| PR6 | [#196](https://github.com/stanimirivanov/cloud-infra/pull/196) | `test_service_collection.py` and `test_cloudflare_collection.py` cover scoped read-only collection, redaction, original clocks, and private evidence publication. |
| PR7 | [#198](https://github.com/stanimirivanov/cloud-infra/pull/198) | `test_service_collection.py` and `test_supabase_collection.py` cover complete membership reconciliation and preservation of operator billing and database readings. |
| PR8 | [#200](https://github.com/stanimirivanov/cloud-infra/pull/200) | `test_operational_findings.py`, `test_account_readiness.py`, and `test_provider_capabilities.py` cover collection boundaries and missing, stale, or unknown meters. |
| PR9 | [#202](https://github.com/stanimirivanov/cloud-infra/pull/202) | `test_execution_evidence.py`, `test_service_apply.py`, and `test_oci_apply.py` cover missing or stale receipts, substitutions, cross-unit replay, and exact saved-plan and encrypted-configuration bindings. |

The PR9 verification record reports 517 focused tests, 4,190 passes and 83 skips
in the shared gate, 12 SDK preview transport tests, and 61 isolated operation
tests. Ten targeted import integration tests passed after the import fixture
correction. These results come from offline tests, synthetic responses, and
isolated backends. See the [PR9 verification record](https://github.com/stanimirivanov/cloud-infra/pull/202).

## Compatibility and retained limits

- Preview receipt validation requires schema 3. Protected apply additionally
  requires its execution binding and the exact `paths.preview_result` bytes
  in the signed execution inputs. Recollect against the reviewed commit and
  obtain new approvals. Use the private `plan_sink` callback on the protected
  Python preview driver for the saved plan and graph receipt from one invocation.
  The existing CLI emits diagnostic receipts. See the
  [apply input contract](runbooks/independent-services.md#controlled-single-service-apply-m05-pr6).
- OCI graph matching requires concrete IDs for intra-stack references. A
  first-create preview with unresolved references fails receipt validation.
  OKE also requires the exact committed network output dependency. Treat
  either gap as a stop in the affected unit's staging procedure. See the
  [OCI graph contract](runbooks/oci-components.md#oci-preview-graph-correspondence-m07-pr5).
- OCI usage collection records observation time while the authoritative
  completeness cutoff requires independent evidence. The reports classify
  out-of-scope costs separately. Cloudflare entitlement and Supabase billing
  windows and database sizes require operator review or readings. See the
  [cost findings contract](runbooks/operational-findings.md).

## Live acceptance evidence still required

Apply the existing ten-gate acceptance process to the exact unit, account, and
reviewed commit. The roles below identify who must supply each pending record.
See the [M06 gate-by-gate disposition](m06-closeout.md#ten-gate-operational-disposition).

| Responsible role | Pending evidence |
| --- | --- |
| Repository administrator and runner custodian | Verify main and environment protections, required reviews and checks, bypass restrictions, distinct signer roles, and actual runner and credential custody. |
| Backend and backup custodians | Qualify remote state and encryption for the exact existing stack. Verify least-privilege access, retention, a current checkpoint/configuration backup, independent storage and key custody, and an off-host restore rehearsal. |
| Provider account owner | Confirm live entitlement and full credential visibility, inventory, other services and retained usage. Supply authoritative billing coverage and reviewed thresholds, including OCI's original cutoff, Cloudflare's exact zone scope, and Supabase's complete membership and independently measured usage. |
| Source and target state owners | Verify external writer exclusion and durable journal custody. Resolve prior indeterminate operations. For adoption, establish exact ownership mappings, native import equivalence and independently evidenced source release. |
| Unit operator and independent approver | Review a fresh credentialed graph and saved plan for the selected existing stack, verify exact checkpoint and config bytes, and obtain separate activation and action approval. For OKE, confirm successful network state and matching committed outputs. Reconcile the post-operation checkpoint and journal after any authorized execution. |
| Kubernetes and operations owners | Verify OKE admission, network isolation and ARM readiness where applicable. Exercise live drift and health observation, durable monitoring and delivery, and the independently approved recovery procedure before accepting ongoing operation. |

Retain those records in the protected evidence store and enroll the required
reviewers before seeking activation. If a required observation is missing,
stale, or unprovable, leave that unit pending and route it to its evidence owner.
