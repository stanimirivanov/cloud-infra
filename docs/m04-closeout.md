# M04 engineering closeout

M04 is Independent stacks and protected previews. This is the finite closeout
against the [fixed plan](m04-plan.md), including the owner-approved PR13a/PR13b
split. Engineering completion is conditional on **PR17's CI passing and merge**.
The owner may then close the GitHub milestone separately. No further M04 runtime
feature PRs, cross-milestone prerequisites or stubs are planned.

The implementation baseline is [PR #114](https://github.com/stanimirivanov/oci-oke-terraform/pull/114),
merged as 3bc28485f952045c2a8cb80ba062543a7cbf6e68; the owner reported its checks
passed. This PR needs its own Linux CI results. Live acceptance is separate
and remains blocked. Every tracked preview flag is false; deployment and cutover
authorization remain false. Neither this record nor successful tests authorize
operations, change GitHub settings or transfer resource/state ownership.

## Fixed-scope reconciliation

PR numbers below are GitHub PRs, not original plan IDs or issue numbers. All tasks
are implemented within their stated repository/synthetic boundaries; the final
row is accepted only after this closeout's CI and merge.

| Plan task | Implementation | Repository evidence / boundary |
| --- | --- | --- |
| PR1: explicit identities/contracts | #82 | Four closed stack identities, foundation schema 3, one-way network dependency; test_preview_contracts.py |
| PR2: OCI graph extraction | #84 | Behavior-preserving private graph/builders and native SDK serialization; test_oci.py |
| PR3: bounded observation transport | #86 | Fixed-host TLS, retry/response limits and observation digests; test_provider_evidence.py |
| PR4: OCI usage | #88 | Bounded queries, exact classification, unknown coverage retained; test_oci_usage.py |
| PR5: Cloudflare collection | #90 | Full zone/DNS membership plus independent entitlement review; test_cloudflare_collection.py |
| PR6: Supabase collection | #92 | Management identity/plan collection reconciled with original usage/DB supplements; test_supabase_collection.py |
| PR7: native executable verification | #94 | Pinned archive/member/executable checks; test_provider_tools.py |
| PR8: downstream cache verification | #96 | Supabase bridge cache and parameterization verification; test_supabase_provider_cache.py |
| PR9: program admission/services | #98 | Explicit context, SDK dry-run/identity gates, preflight before secrets/resources; test_preview_program.py |
| PR10: network stack | #100 | Independent protected network factory and versioned identity exports; test_oci_network.py |
| PR11: OKE dependency | #102 | Exact committed StackReference and scope validation before registration; test_oci_dependency.py |
| PR12: result contract | #104 | Raw-event policy/completion checks, exact bindings and sanitized receipts; test_preview_results.py |
| PR13a: runtime/transport | #106 | Verified CLI companions, closed SDK command adapter and bounded raw RPC capture; test_preview_runtime.py |
| PR13b: executor/bootstrap | #108 | Existing-stack selection, frozen inputs, ciphertext, runtime/source/version rechecks and actual dependency digest; test_preview_driver.py |
| PR14: CLI orchestration | #110 | Fresh collection/backend posture and qualification gates, exclusive private receipt; test_preview_orchestration.py |
| PR15: protected services | #112 | Main/owner/exact commit, separate environments, pre-secret gate and private handoff; test_service_preview_workflow.py |
| PR16: protected OCI | #114 | Explicit OCI mode, separate signers, original usage/dependency inputs and isolated cleanup; test_oci_preview_workflow.py |
| PR17: integration/closeout | Issue #115, this PR | Actual pinned SDK/process/loopback RPC to receipt, timeout regression and finite reconciliation; test_preview_integration.py |

Test names refer to the [tests directory](../tests/); implementation contracts
and public interfaces are detailed in the corresponding [plan records](m04-plan.md).
There are no uncovered repository items in this fixed map. Administrator controls
and credentialed acceptance below are explicitly outside engineering completion.

## What integration establishes

The new CI-only gate joins the actual pinned Automation SDK LocalWorkspace/Stack,
closed Command, real subprocess lifecycle, loopback gRPC server/client, bounded
raw Wire and PR12 receipt validation. It covers all four stack identities, private
diagnostic suppression, exact event-byte framing and policy signals. Invalid or
missing policy/completion signals, update summaries, error diagnostics, malformed
or oversized streams and a hung worker cannot produce a successful receipt.

Only the executable launch is redirected to a synthetic Python CLI worker.
Archive pins are synthetic inside a fixture root; this is not verification of a
release artifact. Existing release-asset tests cover real pinned archives. The
worker does not run the Pulumi engine, child resource program, provider plugins,
backend selection or cloud APIs. Other suites separately cover semantic preflight,
SDK resource serialization, bootstrap parsing, collectors and protected handoff
using mocks/spies. These are complementary boundaries, not one credentialed run.
The synthetic policy event is a test input, not proof that a live policy pack ran.

PR17 adds a bounded direct-process-handle kill/wait fallback when process-group
cleanup fails; regression tests cover denied and ineffective tree kills. OS permissions still
govern descendant cleanup. No isolation claim extends to a hostile host or an
arbitrary privileged Python caller. Receipts remain unsigned consistency evidence.

## Administrator-owned live acceptance

These are activation prerequisites, not additional M04 code PRs:

1. Establish required checks/review/bypass controls and independently verify all
   four main-only preview environments, reviewers and credential custody. The
   current administration sensor covers qualification settings, not these four
   environment configurations or historical review provenance.
2. Verify effective least-privilege provider, collection and backend credentials,
   encryption custody, backend posture, retention and recovery suitability.
   Repository tests cannot prove deployed IAM or production recovery SLOs.
3. Supply fresh independent account eligibility and complete inventory/usage
   coverage, preserving original clocks and billing watermarks. Successful OCI
   queries do not supply billing coverage; missing/late metrics remain blocked.
   Keep provider entitlement and Supabase operator supplements independently reviewed.
4. Verify existing project-scoped stacks and backend namespace compatibility,
   with compatible non-secret committed network outputs for OKE. A network preview
   does not commit outputs. Missing stacks/outputs are blockers, not permission to
   initialize, import or apply them during verification.
5. Obtain explicit live-preview authorization and a separately reviewed tracked
   flag change, regenerate configuration-bound qualification/evidence, satisfy
   protected approvals and run credentialed acceptance for each intended unit.
   GitHub's secret-size limit applies; oversized bundles stay blocked pending a
   separately reviewed transport. Passing engineering CI never flips these gates.

Source verification is current code only; effective external controls and source
authenticity are not established by a matching digest, workflow YAML or clean HEAD.
See [PR15/16 contracts](m04-plan.md#pr15-protected-service-preview-workflow) for
the precise environment names, secrets and private handoff limitations.

## Repository closeout gate and subsequent scope

The existing CI matrix must pass the shared `uv run --locked infra verify`, builds,
local backend/policy-host qualification, native/downstream asset checks and the
new `preview_integration` gate. It sets RUN_SYNTHETIC_PREVIEW_INTEGRATION=1 and runs
`uv run --locked pytest -q -m preview_integration` on Linux. This heavy
subprocess gate is opt-in locally; the normal suite mechanically checks its CI wiring.

After this PR's CI and merge, the only M04 closeout action is owner-managed
milestone closure; live acceptance remains separately tracked. M05 retains apply,
imports/adoption, ownership transfer, monitoring and production recovery. Any new
runtime requirement needs its own reviewed scope rather than reopening M04 by
default. This PR dispatches nothing and changes no state or activation flag.
