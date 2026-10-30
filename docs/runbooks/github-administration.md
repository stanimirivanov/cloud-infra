# GitHub administrative observations

M03-PR12 adds a read-only sensor for classic main, qualification environment protection, harness execution, merged-PR linkage and final-head review observations. It does not change
repository settings, enroll reviewer keys or grant operational authority. Normal infra verify exercises
synthetic responses only; it never needs a GitHub token or calls GitHub.

## Collect and check

Use a clean committed checkout at the current main HEAD, an installed trusted
GitHub CLI and separately configured read-only authentication. GitHub documents
Administration (read) permission for branch protection and Actions (read) for
environment/run metadata, Checks (read) for check runs and Pull requests (read) for PR metadata. Never give PR verification
these credentials. The adapter
uses eleven explicit GET requests for the current two required checks to github.com with API version 2022-11-28, a
30-second timeout per request, and suppressed raw stdout/stderr on failure. It
does not enumerate secret values, change settings or follow caller-provided URLs.

```sh
uv run --locked infra security collect-administration --output .infra/administration.json
uv run --locked infra security check-administration --evidence .infra/administration.json
```

Choose a new ignored .infra JSON output path for each collection; existing files
are never overwritten. Missing tools, denied/404 endpoints, ruleset-only protection
and unsafe settings fail without writing a successful snapshot. A 404 is absent
or inaccessible, never proof that protection is unnecessary. Correct settings
through a separate administrator-owned process; never weaken policy to get PASS.

**BREAKING:** private snapshots now require schema 5; public policy remains schema 3.
Older snapshots fail closed. Use the current reviewed policy
and recollect main, environment, execution, PR and review observations; do not relabel old evidence.
Rollback needs the matching checker/policy/snapshot contracts together.

The closed schema-5 index contains commit, policy_sha256 (exact SHA-256 of both
config/administration.json and config/cutover-reviewers.toml), started_at,
completed_at and responses. Responses contain repository, branch, protection,
environment, branches, checks, workflow_runs, pull_requests, pull_request and reviews
objects from their corresponding REST endpoints. The whole document and each
parsed response are limited to 1 MiB; duplicate JSON
fields fail. Collection must finish within five minutes; all observations expire
15 minutes after collection started. Any policy byte change or different/dirty
checkout invalidates the snapshot. Recollect; do not restamp it.

## Supported controls

The public [administrative policy](../../config/administration.json) pins the
repository numeric ID and name, both required check context/app pairs and the
qualification environment name and verification workflow numeric ID/path. These IDs
were observed from GitHub, not inferred from check names. A test
keeps both contexts aligned with the verification workflow matrix and the
environment name aligned with the foundation workflow. The pinned workflow ID
was observed from GitHub; recreating the workflow requires explicit policy review.

- Repository default branch and observed protected branch must both be main,
  whose current HEAD equals this checkout. This deliberately does not support
  historical commits or feature-branch attestations.
- Classic protection must enforce administrators, prohibit force pushes/deletions,
  and require up-to-date Linux harness checks from the pinned GitHub App.
  Context-only/any-app checks, missing or ambiguous matches fail.
- At least one PR approval, stale approval dismissal and last-push approval are
  required, with no explicit user/team/app PR bypass allowances.
- The configured environment needs a matching name/repository URL and positive
  numeric ID, exactly one required-reviewers rule with self-review prevention,
  and 1-6 distinct User/Team numeric reviewer identities. This checks structure,
  not independent identity approval or membership. Additional restrictive rules
  such as wait timers may coexist.
- Its deployment selection must use custom branch policies with exactly one
  entry selecting branch main. Tags, wildcards, protected-branches-only mode,
  missing branch/tag type and incomplete/multiple policy lists fail. The collector
  requests per_page=100&page=1; both total_count and page length must be one, so
  additional pages cannot be ignored as a successful complete result.

## Required-check execution observations

The checks mapping contains one REST page per exact required context. Collection
queries that commit's check runs with an encoded check_name, filter=latest,
per_page=100&page=1. Every page must have total_count=1 and one record matching the
context, pinned App ID and expected HEAD, completed with conclusion=success. Missing,
ambiguous, pending, skipped, neutral or failed records fail ADMIN005. Check IDs must
be distinct and all must share one positive check-suite ID.

Only then does collection request actions/runs filtered by that numeric suite ID;
it never follows URLs from responses. Exactly one completed successful push/main
run must match the pinned workflow ID/path, suite, commit and source/head repository
IDs. Original workflow/check clocks must be ordered within the run and not later
than observation completion. They are never restamped. A completed run may be older
than the 15-minute observation window while HEAD remains unchanged; this measures
commit-bound execution, not a new periodic CI freshness policy. No workflow is
triggered, rerun, cancelled or polled. Missing/denied data fails without writing
successful evidence. Normal verification exercises synthetic responses only.

The schema-5 cutover subject set stays at 17 subjects/22 private artifacts. Recollect
schema-5 observations and regenerate all reviews/signatures after snapshot migration;
old environment-only snapshots cannot be upgraded by new outer hashes/signatures.

## Merged-PR observations

After execution validates, collection requests commits/{full_sha}/pulls with
per_page=100&page=1. The REST array is stored as pull_requests.items. Exactly one
record is supported: zero, multiple or malformed records fail ADMIN006, and a
one-record first page cannot hide a later page. An ambiguous association requires
operator investigation, never picking the first match or weakening the checker.
Its positive numeric PR ID/number, closed state, merge_commit_sha and base
repository ID/name/main must match the independently expected checkout/policy.

Only then does the collector GET pulls/{number}, using the validated integer,
never a response URL. Canonical details must match that PR ID/number and head SHA,
repeat the merge/base binding, and report merged=true. Head SHA must be a full
40/64-character lowercase hash. Author and merger must have positive numeric IDs
and User/Bot types. These fields describe actors; they do not approve their identities.
Original created/merged/closed timestamps must be ordered, not future, and the
merge must precede the observed main workflow creation. Squash/merge/rebase results
are accepted only when GitHub reports that exact introducing merge SHA; ambiguous
or unsupported histories fail closed. No merge method is inferred from messages.

These canonical PR/head inputs bind the review observations below. They cannot
establish last-push approval or prove that current branch protections were
enforced at merge time. Missing/denied PR
metadata writes no successful snapshot. Fresh outer cutover signatures cannot
upgrade invalid or legacy inner observations; subject/artifact counts stay 17/22.

## Final-head review observations

After canonical PR validation, GET pulls/{number}/reviews?per_page=100&page=1
collects submitted review metadata into reviews.items. Only 1-99 records are
supported: a full 100-record first page could hide later decisions and fails
ADMIN007. Larger histories need a separately reviewed pagination implementation;
never truncate, filter or discard adverse records to make evidence pass.

Every record needs a distinct positive review ID, positive User/Bot actor ID,
canonical pull_request_url, full commit_id and known submitted state. PENDING,
unknown states, missing clocks and malformed records fail closed. Original
submitted_at clocks must be chronological, at/after PR creation and no later
than observation completion. Same-user decision timestamps must increase;
indistinguishable decision order is unsupported. Comments do not replace a
verdict. The latest APPROVED/CHANGES_REQUESTED/DISMISSED decision per numeric
user supersedes earlier decisions. Any unresolved change request blocks;
a dismissed latest decision cannot count as approval.

The observed classic protection approval count must be met by distinct User IDs
different from the PR author, with OWNER/MEMBER/COLLABORATOR association, APPROVED
on the exact final PR head before or at merge. Stale-head, bot, self, unassociated
and post-merge approvals do not count. A newer approval can resolve that user's
older change request; two approvals from one user still count once. Other users'
change requests cannot be erased by collecting sufficient approvals elsewhere.

This measures numeric non-author identity and observed association only. It does
not prove effective write permission, independent human identity, last-push actor
or approval after that push, signing-key custody, historical enforcement, or
independently authenticated API data. Recollect schema-5 observations and regenerate
all four cutover review envelopes/signatures. Public policy remains schema 3;
cutover bundle remains schema 5 with 17 subjects and 22 private artifacts. Deployment
and cutover authorization remain false, including after valid review observations.

## Proof limits and remaining gates

Success returns observed-controls-consistent and both authorization flags false.
This is an unsigned, same-client, non-atomic snapshot. Offline validation cannot
authenticate edited responses or clocks. Collection observes successful execution
and merged-PR/review records, not independently authenticated execution, last-push independence or historical protection
enforcement or that settings remained unchanged between requests. GitHub CLI and local checkout integrity are trusted.
The documented environment GET contract does not guarantee administrator bypass
is exposed; independent verification remains required even on success. An explicit
can_admins_bypass value, if present, must be false; missing is not proof of false.
No result proves
team membership, independent
human identity, key custody, effective IAM or secret visibility. More restrictive
rulesets may coexist; ruleset-only equivalence is not implemented.

The [schema-5 cutover consumer](kubernetes-cutover.md#administrative-observation-consumption-m03-pr12)
now binds these original bytes and the administrative policy into all four signed
reviews. It calls infra_core.administration.validate_snapshot with captured immutable
payload/policy/reviewer_policy bytes, an independent expected commit and clock;
that API performs no I/O. The CLI wrapper still enforces clean Git before/after.
The [M03 closeout](../m03-closeout.md) records this repository implementation as
complete. Actual reviewer identity/permissions, independent key enrollment/custody,
administrator-bypass acceptance and protected-commit/last-push evidence remain
administrator-owned activation prerequisites. No further M03 collector feature is
implied by these proof limits. Future provenance automation needs separate approval.
Deployment and cutover stay disabled. Keep the raw snapshot private; do not upload
it to public CI or treat it as an approval token.

The adapter follows the official [branch protection](https://docs.github.com/en/rest/branches/branch-protection?apiVersion=2022-11-28)
and [environment](https://docs.github.com/en/rest/deployments/environments?apiVersion=2022-11-28)
and [branch policy](https://docs.github.com/en/rest/deployments/branch-policies?apiVersion=2022-11-28)
and [check runs](https://docs.github.com/en/rest/checks/runs?apiVersion=2022-11-28)
and [workflow runs](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2022-11-28),
[commit-associated pull requests](https://docs.github.com/en/rest/commits/commits#list-pull-requests-associated-with-a-commit)
[pull request details](https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request)
and [PR reviews](https://docs.github.com/en/rest/pulls/reviews#list-reviews-for-a-pull-request)
REST contracts through stdlib plus the existing gh executable. This adapts the API
pattern without copying an implementation or adding a Python dependency.

## M06 repository trust and runner enrollment checks

M06-PR2 delivers checks with enrollment **pending**, as requested by the owner.
The verified repository is `stanimirivanov/cloud-infra`, numeric ID `1323328453`;
verification workflow ID `395674516` and check App ID `15368` are unchanged.
The old repository name in the administrative policy is corrected. This is
**BEHAVIOR-ADJACENT**: previously bound administrative snapshots and signatures
must be recollected against the new policy bytes, never rewritten or restamped.

From a clean committed checkout, inspect the enrollment gaps without a token,
network calls, file writes or operational credentials:

```sh
uv run --locked infra security check-enrollment
uv run --locked infra security check-enrollment --evidence .infra/enrollment.json
```

The optional private index has this closed schema (an empty index is valid):

```json
{"schema_version": 1, "administration": null, "environments": {}}
```

Replace `administration` with a canonical relative `.infra/*.json` path to the
schema-5 output of `infra security collect-administration`. Add environment-name
keys mapped to distinct private JSON paths in `environments`. Those files use the
existing schema-1 `infra_core.administration.collect_operation_environment` API
and its validator; collection is an explicit read-only administrator action with
separately configured GitHub authentication. The enrollment checker itself never
collects anything. There is no automatic runner-custody collector in this PR.
Keep raw evidence private and do not upload it to public CI.

Administrative evidence must pass the existing complete checks for current main,
required check/App identities, successful verification, merged PR and final-head
reviews. Each supplied environment observation must bind the same repository and
current clean commit, expire after 15 minutes, require non-self reviewers, explicitly
disable administrator bypass and select only branch main. Missing observations
are `pending`; supplied invalid evidence fails with redacted `ENROLL001`, rather
than being silently treated as absent. Symlinks, duplicate JSON fields, reused
artifact paths, unknown environments and paths outside `.infra` are rejected.
The checker rechecks checkout identity and captured file bytes before returning.

Coverage includes backend qualification, all four previews, all four apply,
monitor and recovery environments, both OCI imports, `oci-handoff`,
`recovery-rehearsal` and `monitor-watchdog`. Service import policy slots are
reserved and unsupported; they are not enrollment requirements. Regression tests
compare this inventory and runner groups with the actual workflow declarations.

Operation trust remains disabled with no enrolled reviewers or invented age
limits. When enabled through a later independently reviewed change, the checker
reuses the admission policy validator and requires distinct operator/approver
principals with distinct keys and complete role coverage. This is configuration
consistency only. Requester/operator/approver independence still belongs to each
signed operation's admission; this report cannot replace it. Cutover reviewer
policy bytes remain bound through the existing administrative snapshot contract;
independent cutover identity enrollment is also still required.

Every report has `status: pending`, `enrollment_complete: false`,
`execution_authorized: false`, `activation_authorized: false` and
`live_controls_verified: false`. The CLI exits 1 for a pending report as well as
invalid input, so it cannot become a green activation gate. Valid observations
are labeled `observed-controls-consistent`, not enrolled. The report is unsigned
and is not an M06 readiness acceptance record; future independent acceptance must
bind the original observations and their clocks, not promote this gap summary.

### Independent enrollment review still required

An administrator and independent reviewer must record public principal/key
identities, actual permissions, role separation and private-key custody outside
Git. GitHub reviewer IDs and signing principals are not assumed to identify the
same human. Review team membership, last-push independence, administrator bypass,
secret visibility and the effective repository/workflow restrictions separately.
Never send private keys or credentials in issues, PRs or chat.

For `service-operations`, verify only this repository's reviewed main workflows
can reach the runner, no untrusted PR jobs or workspaces share it, operation
journals and the monitoring outbox survive restart, and collection, drift and
delivery credentials remain separate. For `recovery`, verify the same access
restriction plus host isolation, independent backup access, durable recovery
journals and separation of read-only observers from state writers. Record host
custodian, runner/group identities, storage ownership and recovery procedures in
private reviewed evidence. A runner label or workflow group declaration alone
does not prove isolation or custody. Do not automatically initialize lost journals.

The read-only GitHub inspection during this PR found only the legacy
`oci-infrastructure` environment, with no protection rules or deployment branch
policy. Required operational environments were absent. This is a historical gap
observation, not current acceptance evidence; recollect after administrator-owned
configuration and independent review. No environment, runner, key, secret, policy
enablement or production resource is created by this PR.

Focused regression gate:
`uv run --locked pytest -q tests/test_enrollment.py tests/test_administration.py tests/test_operation_admission.py`.
Run the complete `uv run --locked infra verify` gate before delivery.
