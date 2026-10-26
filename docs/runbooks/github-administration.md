# GitHub administrative observations

M03-PR12 adds a read-only sensor for classic main and qualification environment protection. It does not change
repository settings, enroll reviewer keys or grant operational authority. Normal infra verify exercises
synthetic responses only; it never needs a GitHub token or calls GitHub.

## Collect and check

Use a clean committed checkout at the current main HEAD, an installed trusted
GitHub CLI and separately configured read-only authentication. GitHub documents
Administration (read) permission for branch protection and Actions (read) for
environment metadata/branch policies. Never give PR verification
these credentials. The adapter
uses five explicit GET requests to github.com with API version 2022-11-28, a
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

**BREAKING:** both the public policy and private snapshot now require schema 2.
Main-only schema-1 policies/snapshots fail closed. Use the current reviewed policy
and recollect both main and environment observations; do not relabel old evidence.
Rollback needs the matching checker/policy/snapshot contracts together.

The closed schema-2 index contains commit, policy_sha256 (exact SHA-256 of both
config/administration.json and config/cutover-reviewers.toml), started_at,
completed_at and responses. Responses contain repository, branch, protection,
environment and branches
objects from their corresponding REST endpoints. The whole document and each
parsed response are limited to 1 MiB; duplicate JSON
fields fail. Collection must finish within five minutes; all observations expire
15 minutes after collection started. Any policy byte change or different/dirty
checkout invalidates the snapshot. Recollect; do not restamp it.

## Supported controls

The public [administrative policy](../../config/administration.json) pins the
repository numeric ID and name, both required check context/app pairs and the
qualification environment name. These IDs
were observed from GitHub, not inferred from check names. A test
keeps both contexts aligned with the verification workflow matrix and the
environment name aligned with the foundation workflow.

- Repository default branch and observed protected branch must both be main,
  whose current HEAD equals this checkout. This deliberately does not support
  historical commits or feature-branch attestations.
- Classic protection must enforce administrators, prohibit force pushes/deletions,
  and require up-to-date Linux/Windows harness checks from the pinned GitHub App.
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

## Proof limits and remaining gates

Success returns observed-controls-consistent and both authorization flags false.
This is an unsigned, same-client, non-atomic snapshot. Offline validation cannot
authenticate edited responses or clocks; collection does not prove historical
check success, PR review, protected-main provenance or that settings remained
unchanged between requests. GitHub CLI and local checkout integrity are trusted.
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
Independent reviewer-key enrollment/custody and protected-commit evidence remain
separate M03 work.
Deployment and cutover stay disabled. Keep the raw snapshot private; do not upload
it to public CI or treat it as an approval token.

The adapter follows the official [branch protection](https://docs.github.com/en/rest/branches/branch-protection?apiVersion=2022-11-28)
and [environment](https://docs.github.com/en/rest/deployments/environments?apiVersion=2022-11-28)
and [branch policy](https://docs.github.com/en/rest/deployments/branch-policies?apiVersion=2022-11-28)
REST contracts through stdlib plus the existing gh executable. This adapts the API
pattern without copying an implementation or adding a Python dependency.
