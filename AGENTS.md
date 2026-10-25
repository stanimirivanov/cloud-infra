# Agent entry point

This repository provisions OCI networking and an OKE Basic cluster using Terraform
and Terragrunt. Read [HARNESS.md](HARNESS.md) for the map and commands, then only
the instructions and source in the directory you change. Do not ingest all docs.

## Plan → Execute → Verify

1. Plan: check `git status --short`, identify ownership, acceptance criteria and
   the smallest change. Preserve existing work. On a clean tree, switch to `main`
   and `git pull --ff-only`. Use `gh issue create` with requirements, scope and
   acceptance criteria; branch as `feature/issue-N` or `fix/issue-N`.
2. Execute: follow the nearest scoped AGENTS.md; keep topology changes explicit.
   Never edit generated Terraform or move state to make validation pass.
3. Verify: run `python scripts/verify.py`. Read diagnostics, fix their cause and
   rerun affected checks. Never suppress a failure or claim an unexecuted check.
   For infrastructure changes, an authorized credentialed plan is additional
   evidence; static checks cannot prove availability, security or billing.
4. Review the diff; stage only issue files. Commit `[#N] summary`, push, and use
   `gh pr create` with title `[#N] title`, `Closes #N`, summary, verification and
   limitations. Return the PR URL and stop. Do not merge or poll CI.

For explicitly requested PR revisions, reuse its branch and issue, inspect only
relevant feedback, verify, commit, push and comment with the resolution. Stop.

## Non-negotiable boundaries

- Do not run apply, destroy, import, state push/move or recovery as verification.
  Infrastructure mutations require an explicit provisioning request.
- Never commit credentials, tfvars values, state, plan files or generated caches.
- Keep cloud credentials out of PR verification and untrusted workflow code.
- Do not bypass checks or broaden a policy exception to get a green result.
- A new resource type, state unit, provider, public ingress or paid service needs
  an explicit design rationale, policy change and regression test in the issue/PR.
