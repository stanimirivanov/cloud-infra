# GitHub administrative observations

M03-PR12 adds a read-only sensor for classic main protection. It does not change
repository settings, enroll reviewer keys or grant operational authority. Normal infra verify exercises
synthetic responses only; it never needs a GitHub token or calls GitHub.

## Collect and check

Use a clean committed checkout at the current main HEAD, an installed trusted
GitHub CLI and separately configured read-only authentication. GitHub documents
Administration (read) permission for branch protection. Never give PR verification
these credentials. The adapter
uses three explicit GET requests to github.com with API version 2022-11-28, a
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

The closed schema-1 index contains commit, policy_sha256 (exact SHA-256 of both
config/administration.json and config/cutover-reviewers.toml), started_at,
completed_at and responses. Responses contain repository, branch and protection
objects from their corresponding REST endpoints. The whole document and each
parsed response are limited to 1 MiB; duplicate JSON
fields fail. Collection must finish within five minutes; all observations expire
15 minutes after collection started. Any policy byte change or different/dirty
checkout invalidates the snapshot. Recollect; do not restamp it.

## Supported controls

The public [administrative policy](../../config/administration.json) pins the
repository numeric ID and name and both required check context/app pairs. These IDs
were observed from GitHub, not inferred from check names. A test
keeps both contexts aligned with the verification workflow matrix.

- Repository default branch and observed protected branch must both be main,
  whose current HEAD equals this checkout. This deliberately does not support
  historical commits or feature-branch attestations.
- Classic protection must enforce administrators, prohibit force pushes/deletions,
  and require up-to-date Linux/Windows harness checks from the pinned GitHub App.
  Context-only/any-app checks, missing or ambiguous matches fail.
- At least one PR approval, stale approval dismissal and last-push approval are
  required, with no explicit user/team/app PR bypass allowances.

## Proof limits and remaining gates

Success returns observed-controls-consistent and both authorization flags false.
This is an unsigned, same-client, non-atomic snapshot. Offline validation cannot
authenticate edited responses or clocks; collection does not prove historical
check success, PR review, protected-main provenance or that settings remained
unchanged between requests. GitHub CLI and local checkout integrity are trusted.
Environment approval, branch restrictions and administrator bypass are not
measured in this slice and remain required before operations. No result proves
team membership, independent
human identity, key custody, effective IAM or secret visibility. More restrictive
rulesets may coexist; ruleset-only equivalence is not implemented.

Environment observations, cutover bundle consumption, independently reviewed
reviewer-key enrollment/custody and protected-commit evidence remain separate M03 work.
Deployment and cutover stay disabled. Keep the raw snapshot private; do not upload
it to public CI or treat it as an approval token.

The adapter follows the official [branch protection](https://docs.github.com/en/rest/branches/branch-protection?apiVersion=2022-11-28)
REST contract through stdlib plus the existing gh executable. This adapts the API
pattern without copying an implementation or adding a Python dependency.
