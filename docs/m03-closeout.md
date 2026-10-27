# M03 engineering closeout

Decision date: 27 October 2026. M03 is Security and evidence hardening.
Repository engineering is complete against the scope reconciled below.
Operational activation remains blocked. This record becomes the final closeout
after its documentation-only PR passes the existing CI gates and is merged.
The repository owner may then close the GitHub milestone separately.

## Scope and evidence basis

The user approved one final documentation-only PR after reconciling the retained
twelve-task plan. No further M03 runtime feature PRs are planned.
The original prose plan was not found as a standalone versioned document;
the auditable basis is the [retained task map](../HARNESS.md), accepted implementation
issue criteria, source/tests and the retirement amendment in the
[dated harness audit](harness-audit.md). This record preserves that limitation.

Implementation baseline: [PR #78](https://github.com/stanimirivanov/oci-oke-terraform/pull/78),
merged as c3b622c5de050d41bfc04fc41b2ca6c4ea3ac598. Its Linux and Windows Harness
jobs succeeded in [run 40454100602](https://github.com/stanimirivanov/oci-oke-terraform/actions/runs/40454100602).
Those results establish the recorded development checks, not live administrative
or cloud readiness. The closeout PR must obtain its own CI results.

M03 delivers bounded development controls and offline evidence validation:

- Trusted tool installation, immutable Actions, secret scanning and fitness checks.
- Explicit secret ingestion/encryption policy and synthetic recovery acceptance.
- Backend, usage and inventory coverage with exact-byte evidence bindings.
- Configured-key cutover review authentication and administrative observations.
- Disabled resource operations and explicit limits on what each result proves.

## Original-task reconciliation

The first column contains original plan IDs. The evidence column contains actual
GitHub PR numbers; these differ from the issue numbers in HARNESS.md.

| Original task | Disposition and supported scope | GitHub PR evidence |
| --- | --- | --- |
| M03-PR1: trusted CI chain | Complete: SHA pins, verified installers and workflow syntax sensor | #32, #36 |
| M03-PR2: secret scanning | Complete: current, staged and reachable-history scans | #32 |
| M03-PR3-PR5: legacy ingress/capacity/images | All three superseded by implementation retirement; live adoption checks remain required | #28 |
| M03-PR6: shared envelopes | Complete: strict pure envelope APIs and intended consumer migrations | #38, #44, #50, #52, #54, #56, #58, #64, #72 |
| M03-PR7: secret contracts | Complete: explicit passphrase policy, config-backed secret ingestion and custody guidance | #40 |
| M03-PR8: independent recovery | Complete within same-host synthetic scope: fresh workspace/HOME, readback and wrong-key rejection | #34, #40, #42 |
| M03-PR9: backend posture | Complete: read-only observations and independently scoped exact-byte bindings | #34, #44 |
| M03-PR10: protected backend audit | Repository workflow complete; actual administration/IAM remain activation prerequisites | #46 |
| M03-PR11: usage coverage | Offline contracts complete: scope, per-metric coverage, billing periods and storage history | #34, #48, #50, #52, #54, #56, #58, #60, #62 |
| M03-PR12: cutover evidence | Repository validators complete: bound inventory/reviews, DSSE verification and administrative/PR observations | #58, #64, #66, #68, #70, #72, #74, #76, #78 |

Retirement and the architecture/documentation fitness sensor were approved
prerequisites implemented in #28 and #30. Trusted-chain and measured-evidence
harness improvements in #32/#34 also satisfy the corresponding M03 tasks;
they are shared evidence, not additional unfinished milestones.

Superseded tasks are recorded as superseded, never as successful cloud changes.
Retirement removed repository execution paths without deleting cloud resources,
external state or externally owned resource addresses. Recreating those paths
to complete the old tasks is outside the approved closeout.

## Completed consumer boundaries

The [shared evidence runbook](runbooks/security-evidence.md) describes the pure
consistency API and consumer obligations. Intended migrations are complete:

| Consumer | Accepted boundary |
| --- | --- |
| Backend posture and remote qualification precondition | Original posture payload plus backend-posture sidecar, independent tenancy/configuration and clean commit |
| Service CLI and both service factories | Original usage payload plus service-usage sidecar before secret lookup or registration |
| OCI collection/audit and library preflight/registration | Original inventory plus oci-inventory sidecar and independent configuration/commit |
| Offline cutover inventory | The same captured inventory/sidecar pair, followed by domain validation |
| Ownership, preview, health and rollback reviews | Exact captured subjects, four role envelopes and four configured-key DSSE signatures |
| Administrative cutover input | Captured snapshot and policy bytes inside every signed review; rootless semantic revalidation |

Internal pure accounting APIs intentionally retain dictionary inputs. They are
not transport admission boundaries and do not discover Git or authenticate origin.
Synthetic backend qualification receipts retain their schema-3 validator.
The reserved backend-recovery envelope kind does not imply that receipts have
been migrated or signed. Neither case is an outstanding M03 migration task.

No general promise to wrap or authenticate every future evidence format is made.
New consumers or provenance mechanisms require a separately approved scope.
Existing bounded formats and validators remain in force until such a change.

## Contract and authority boundary

This documentation closeout changes no accepted schema, runtime behavior,
dependency, workflow or configuration. Current boundaries remain:

- Foundation configuration schema 2 has explicit passphrase-only encryption policy.
- Backend qualification receipts use schema 3 and measure synthetic recovery only.
- Administrative snapshots use schema 5 with public administrative policy schema 3.
- Cutover indexes use schema 5 with 17 subjects and 22 distinct private artifacts.
- The reviewer policy is schema 1, disabled and empty by default.
- Every configured deployment unit stays disabled; resource entry points deny operations.
- Deployment and cutover authorization remain false even when evidence is consistent.

The public [foundation configuration](../config/pulumi.toml) and
[reviewer policy](../config/cutover-reviewers.toml) remain unchanged.
Examples remain incomplete. No real key enrollment, production secret migration,
resource preview/deployment, ownership transfer or state recovery is authorized.
Existing opt-in backend qualification remains limited to synthetic isolated namespaces.

Hashes bind bytes, scope and clocks. Configured-key signatures authenticate
possession of an enrolled key for a role. Neither establishes provider source truth,
human independence, effective IAM or historical enforcement. Administrative snapshots
remain unsigned, same-client and non-atomic. Current settings cannot retroactively
prove which settings protected a historical merge.

## Administrator-owned activation prerequisites

These are separate operational obligations, not additional M03 framework features.
They have not been live-verified by this closeout. Owner roles below must be assigned
to actual accountable people before activation; no identity or custody is inferred.
Missing or inaccessible evidence keeps activation blocked.

| Owner role | Required evidence before activation | Closeout status |
| --- | --- | --- |
| GitHub administrator | Effective required checks, administrator enforcement, environment reviewers, main-only selection and administrator-bypass posture | Unverified live |
| Repository/security owner | Actual reviewer identity and effective permissions, independent review, last-push independence and protected history for the chosen commit | Unverified live |
| Security/key custodians | Approved principals, public-key fingerprints/roles, separate custody, recovery access and revocation arrangements | No real reviewer keys enrolled |
| Cloud/backend administrator | Effective least-privilege IAM, bucket privacy/retention, protected credential scope and passphrase custody | Unverified live |
| Infrastructure/account owner | Current eligibility, complete inventory/usage visibility, live network/capacity/image checks and exclusive external ownership | Unverified live |
| Operational approver | Accepted private evidence, approved execution scope, rollback responsibility and explicit operational instruction | No activation approval |

Use the existing [administrative](runbooks/github-administration.md),
[backend](runbooks/pulumi-backend.md) and [cutover](runbooks/kubernetes-cutover.md)
runbooks to identify evidence and its limits. A successful sensor is only one input
to acceptance. In particular, a missing administrator-bypass field is not proof
that bypass is disabled; a non-author User ID is not proof of independent custody.

For each obligation, the owner must retain the actual observation time, exact
commit/configuration scope, evidence location and independent acceptance decision.
Private evidence, secrets and state stay outside the public repository and CI artifacts.
This record contains no acceptance signatures and does not substitute for those records.
Never restamp old observations or fabricate a historical approval to satisfy a checker.

Actual reviewer enrollment may later need an administrator-owned policy-only PR
using independently approved public keys. That is a separately authorized activation
change; this closeout does not enable the policy or introduce a signing workflow.
Changing GitHub settings or enrolling a key alone cannot unlock the disabled executor.

## Later engineering boundaries

The following belong to separately approved M04/M05 planning:

- Separate-stack orchestration, protected resource previews, mandatory policy
  attachment and explicit adoption/cutover execution.
- Trusted live evidence collection/source authentication and continuous cost,
  drift and availability monitoring with operator responses.
- Production/off-host resource and data recovery objectives and rehearsals.

Additional GitHub provenance automation, broader review-history pagination and
large-inventory performance budgets are possible follow-ups, not automatic M03
requirements. No thresholds, dependencies or new collectors are selected here.
An actual correctness defect remains a defect to triage; an acknowledged proof
limit does not by itself authorize another implementation slice.

## Finite closeout acceptance

1. Merge this single documentation-only closeout PR after its existing Linux and
   Windows Harness checks succeed. Do not change runtime files, policies, enabled
   flags, dependencies or workflows as part of closeout.
2. Retain the closeout merge commit and its CI links as engineering verification.
   The existing [Harness workflow](../.github/workflows/verify.yml) runs package
   build, the complete shared gate and opt-in disposable-local backend integration
   on both platforms without cloud credentials.
3. The repository owner may close the M03 milestone with this exact disposition:
   **Engineering complete; deployment and cutover disabled; activation prerequisites outstanding.**
4. Carry the owner-assigned activation checklist into subsequent operational
   planning. No new M03 runtime feature PRs are planned or implied by closing the milestone.

For this documentation-only change, the user requested that full verification run
in CI because the local host is busy. Lightweight local checks are recorded in
the PR; no unexecuted local check is claimed. Existing commands remain
`uv run --locked pytest tests/test_fitness.py -q`, `git diff --check` and
`uv run --locked infra verify`. The full shared gate is delegated to CI for this PR.

Earlier local aggregate runs hit the existing 300-second limit; split runs completed
the unfinished tests. That limitation remains disclosed, and no timeout, assertion
or gate is weakened for closeout. Earlier green CI does not replace this PR's results.
PR delivery does not itself merge the PR or close the GitHub milestone.
