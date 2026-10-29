# Agent entry point

This is a Pulumi Python uv workspace for multi-provider free-tier infrastructure.
Resource deployment and state ownership transfers remain disabled. Backend
qualification is opt-in and isolated; see docs/runbooks/pulumi-backend.md.
Read [HARNESS.md](HARNESS.md) for the map and commands, then only the instructions
and source in the directory you change. Do not ingest all docs.

## Plan -> Execute -> Verify

1. Plan: check `git status --short`, identify ownership, acceptance criteria and
   the smallest change. Preserve existing work. On a clean tree, switch to `main`
   and `git pull --ff-only`. Use `gh issue create` with requirements, scope and
   acceptance criteria; branch as `feature/issue-N` or `fix/issue-N`.
2. Execute: follow the nearest scoped AGENTS.md; keep topology changes explicit.
   Never move deployed state to make validation pass.
3. Verify: run `uv run --locked infra verify`. Read diagnostics, fix their cause and
   rerun affected checks. Never suppress a failure or claim an unexecuted check.
   For infrastructure changes, an authorized credentialed preview is additional
   evidence; offline checks cannot prove availability, security or billing.
4. Review the diff; stage only issue files. Commit `[#N] summary`, push, and use
   `gh pr create` with title `[#N] title`, `Closes #N`, summary, verification and
   limitations. Return the PR URL and stop. Do not merge or poll CI.

Deliver one coherent PR per requested task. Choose boundaries by the behavior,
contracts and acceptance criteria being delivered, not a line-count or PR-size
limit. Keep the complete change reviewable, include its tests, and exclude unrelated
refactors. Do not split a requested task into multiple or stacked PRs solely for size.

For explicitly requested PR revisions, reuse its branch and issue, inspect only
relevant feedback, verify, commit, push and comment with the resolution. Stop.

## Non-negotiable boundaries

- Deployed-state apply/destroy/import/recovery are never routine verification.
  Only documented opt-in qualification may exercise synthetic checkpoint
  operations in new isolated namespaces. Infrastructure mutations and ownership
  transfers require an explicit operational request.
- Never commit credentials, state, plan files, private account evidence or caches.
- Keep cloud credentials out of PR verification and untrusted workflow code.
- Do not bypass checks or broaden a policy exception to get a green result.
- A new resource type, state unit, provider, public ingress or paid service needs
  an explicit design rationale, policy change and regression test in the issue/PR.
