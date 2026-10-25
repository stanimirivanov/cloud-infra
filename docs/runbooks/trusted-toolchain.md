# Trusted toolchain and secret detection

## Bootstrap and trust roots

Use PowerShell 7 and Git on Linux/Windows x64. In a PowerShell session, run
`./.github/scripts/install-tools.ps1`, then the locked commands in
[HARNESS.md](../../HARNESS.md). The installer downloads fixed uv, Pulumi,
Gitleaks and actionlint releases into ignored .infra/tools, verifies the committed
archive SHA-256
before extraction, and adds their binary directories to this session's PATH and
GITHUB_PATH in CI. It never executes downloaded installer scripts. Fresh extraction
directories avoid stale install contents. Gitleaks and actionlint use stable binary locations
whose SHA-256 hashes are rechecked by every infra verify invocation; PATH substitutes are
not accepted. Verification does not install anything or access cloud APIs.

[config/toolchain.json](../../config/toolchain.json) is the reviewable trust root.
The release asset URLs and digests were read through the official GitHub release
APIs on 25 October 2026: [uv 0.12.5](https://github.com/astral-sh/uv/releases/tag/0.12.5),
[Pulumi 3.272.0](https://github.com/pulumi/pulumi/releases/tag/v3.272.0),
[Gitleaks 8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1), and
[actionlint 1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12).
The downloaded Linux and Windows scanner and workflow-linter archives matched
those digests; extracted scanner/linter binaries supplied the additional binary hashes. SHA-256 protects against
replacement relative to these reviewed values; it does not prove publisher
integrity, code safety, or a cryptographically independent release identity.

Checkout and upload-artifact retain their existing v4 major lines, resolved to
full commit SHAs through the official repositories' Git ref APIs on the same date.
The gate checks every workflow/action YAML uses reference against the reviewed
catalogue. Local reusable workflows must exist. Hosted runner images, PowerShell,
Git and the platform TLS store remain bootstrap trust dependencies. Python is
selected by .python-version through pinned uv; Python distributions and locked
Python dependencies remain upstream supply-chain dependencies, not independently
attested by this repository. No cache is restored by the workflows.

Gitleaks CLI is MIT-licensed and adds a standalone development binary, not a Python
runtime dependency. Its default rule set is extended without custom exclusions.
The Gitleaks Action is not used.

## Coverage and failure handling

The shared gate copies tracked and nonignored new working files to a temporary
snapshot, scans staged additions separately, and scans all locally reachable Git
refs including merge-parent diffs. Ignored private .infra/state/cache files are
not scanned or uploaded. Symlink/out-of-checkout working inputs fail closed.
Shallow clones fail; CI uses fetch-depth: 0. Reachability is local: unfetched fork
refs, unreachable objects and remote-only history are not a coverage claim.

The pinned scanner uses explicit configuration, ignores inline allow comments,
and receives an empty ignore file; GITLEAKS configuration environment overrides
are removed. There is no baseline. All scanner output is captured and suppressed,
reports use full redaction in temporary storage and are deleted afterwards. A
failure identifies the scan stage without exposing source snippets or raw errors.
No scan report is uploaded. Missing/tampered tools, scanner errors and timeouts
fail verification. This pattern detector cannot prove absence of all secret types,
encoded/binary secrets or credentials in ignored private files.

To investigate a failure, run the installed scanner privately with --redact=100
and the explicit repository configuration; keep any report under ignored .infra.
A removed credential remains in history. Confirm whether a finding is real; rotate
or revoke real credentials before planning a separately authorized history repair.
Do not add blanket path/SDK/history exclusions, inline suppressions or baselines
just to make the gate pass. Any narrowly justified policy change needs review and
a negative regression test preserving the original detection requirement.

## Updates and external enforcement

For a tool update, review the official release/tag, retrieve its asset digest and
compare the actual archive hash, then update both supported platforms in the
manifest and existing version contracts. Recompute scanner/linter binary hashes only
after archive verification. Review the full Action commit and its release context;
update YAML and the catalogue together. Run checksum-tampering, planted-secret and
workflow mutation tests, then the complete gate. There are no floating downloads.

Read-only inspection for issue #31 returned "Branch not protected" for classic
main protection, an empty effective-main-rules list, and 404 for the named
qualification environment (absent or inaccessible). An administrator must establish
required Harness matrix checks, review/anti-bypass rules, and qualification
reviewers/main-only branches before treating these as protected execution paths.
The PR does not change these settings. Cloud IAM, bucket controls and hosted-runner
isolation were not audited here. Resource operations remain disabled.

## Workflow syntax sensor

`uv run --locked infra security workflows` runs the same actionlint check required
by infra verify. It checks every .yml/.yaml file directly in .github/workflows,
including reusable workflows, using the catalogue-verified binary under
.infra/tools/actionlint. It never executes workflow steps or installs tools.
A missing/tampered binary, empty workflow inventory, syntax/expression error,
launch failure or 60-second per-file timeout fails with WORKFLOW001. Diagnostics
include only the file and validated numeric locations/rule kinds (up to ten);
source snippets, error messages and stderr are suppressed. Inspect source at the
reported location privately; do not publish raw tool output with private values.

[actionlint's documented integrations](https://github.com/rhysd/actionlint/blob/v1.7.12/docs/usage.md)
are explicitly disabled with -shellcheck= and -pyflakes=; those unpinned tools
must not be discovered through PATH. An explicit empty configuration prevents a
repository-local ignore rule from weakening this gate. MIT-licensed actionlint
adds one development executable per platform and no Python runtime dependency.
Existing pytest contracts continue to enforce reviewed Action pins and repository
credential/permission/trigger boundaries in the full gate. The focused workflow
CLI checks syntax/expressions only; it does not replace those safety contracts,
validate composite action metadata, prove shell behavior, inspect GitHub settings,
or authenticate upstream releases independently of the reviewed digest catalogue.
