# Independent workflow audit: codex/audit-2

Snapshot: `main` at `c2070cf8b4e7b0ade76cb000a5805009754eec55`. Audit date: 2026-10-14 (Vancouver). Findings are grouped by root cause, not counted once per occurrence. Workflow findings: **0 High, 5 Medium, 3 Low**. No production files changed.

## Inputs and limits

Read AGENTS.md, docs/modules.md, docs/notices.md, docs/specs/network-egress-privacy.md, all 12 files in `.github/workflows/`, and tools/release_gate.py. Requested `docs/release-process.md`, `docs/install.md`, `docs/specs/windows-release-signing-policy.md`, and `docs/plans/e4-audit-and-qa-plan.md` are absent at this snapshot. The available signing policy is `docs/specs/program-e/WIN-release-signing-policy.md`; also consulted windows-acceptance-and-milestone-builds.md and BUNDLE-integration-plan.md. Missing documents are a scope limitation, not invented policy. This audit does not inherit another Codex batch.

Static proof and hermetic reproduction only: no Actions run, target execution, secret access, live tool download, or release publication. Repository/org permission defaults, branch protections and cache contents were not queried. Proposed fixes below are deliberately not implemented.

## Findings

### CODEX-1 — Medium: every remote action uses a mutable tag

Evidence: `.github/workflows/qa-windows.yml:21,22,184` uses checkout@v4, setup-python@v5 and softprops/action-gh-release@v2; `.github/workflows/pages.yml:44` uses deploy-pages@v4. All remote `uses:` references across the 12 workflows are version tags, not 40-hex commits. The release/deploy actions execute with write permissions. This proves missing immutable references, not an upstream compromise.

Fix: pin each remote action to a reviewed full commit SHA, retaining the version as a comment; automate reviewed pin updates. Regression: `test_remote_actions_are_immutable`, strict xfail CODEX-1.

### CODEX-2 — Low: three jobs lack explicit execution budgets

Evidence: `.github/workflows/pages.yml:36-44` deploy; `.github/workflows/qa-windows.yml:57-78` linux-package; `.github/workflows/qa-windows.yml:132-194` release have no job-level timeout-minutes. Step timeouts in other jobs do not cover these jobs. A hung action/build can therefore occupy the platform's default budget; this is not an infinite hang claim.

Fix: add explicit job budgets (e.g. 15, 45, 15 minutes respectively), with bounded download/subprocess timeouts where practical. Regression: `test_every_job_has_timeout`, strict xfail CODEX-2.

### CODEX-3 — Medium: Pages build inherits deployment and OIDC privileges

Evidence: `.github/workflows/pages.yml:10-13,18-35` grants pages:write and id-token:write at workflow level; build has no override and runs pip-installed tools and repository scripts. These privileges are needed by deploy, not ordinary build/test code.

Fix: workflow contents:read; build contents:read only; deploy pages:write and id-token:write at job level. Regression: `test_pages_build_has_read_only_permissions`, strict xfail CODEX-3.

### CODEX-4 — Low: nightly fuzz token permissions depend on external defaults

Evidence: `.github/workflows/nightly-fuzz.yml:1-33` has neither workflow nor job permissions. Its checkout/install/fuzz code therefore has no repository-local least-privilege declaration. Actual excess token rights are unverified and depend on repository/organisation defaults.

Fix: declare contents:read (all unspecified scopes then denied). Regression: `test_workflows_declare_permissions`, strict xfail CODEX-4.

### CODEX-5 — Medium: build-time package downloads lack artifact hash locks

Evidence: `.github/workflows/qa-windows.yml:27,66`, backend-bundle.yml:203,236,353, pages.yml:27 and pip installs in all live-tool workflows have no --require-hashes/hash-locked dependency closure. Even sigstore==3.6.2 is a version pin, not a wheel digest. --only-binary prevents sdists, not substitution or drift in transitive wheels. setup-python '3.12' and setup-java '21'/'25' also select moving runtime patch releases without a repository-pinned artifact digest.

Fix: resolve platform-specific complete wheel locks with hashes, install them before installing the local project with --no-deps; freeze build/runtime versions and record verified digests. Keep apt host packages explicitly outside the reproducibility claim or use a pinned runner image. Regression: `test_pip_downloads_require_hashes`, strict xfail CODEX-5 (only the pip portion is checked).

Distinction: direct Ghidra and rizin curl/Invoke-WebRequest downloads are SHA-256-checked before extraction. Ghidriff git sources have a full commit pin. backend-bundle's pin-report job computes candidate hashes intentionally, without installing those candidates; it is not falsely counted as a production unverified-download path.

### CODEX-6 — Medium: restored extracted tools bypass pin verification

Evidence: `.github/workflows/corpus-tier-r.yml:83-100,108-128` caches extracted rizin and Ghidra trees. A cache hit skips archive download/hash verification; neither restored tree is checked against an immutable per-file manifest before use. A digest in the cache key authenticates the key string, not the restored file bytes. This proves a missing integrity boundary, not that fork caches can overwrite main caches or that poisoning occurred.

Fix: cache original archives and verify pinned SHA-256 on every restore before extracting, or verify a pinned per-file manifest before executing an extracted tree. Other caches (backend/BinDiff/intel) delegate validation to provisioning tools; do not infer the same bypass without reviewing those tools. Regression: `test_corpus_cache_does_not_skip_verification`, strict xfail CODEX-6.

### CODEX-7 — Medium: argument parsing errors bypass release event restrictions

Evidence: `tools/release_gate.py:221-237` catches parser errors and returns publish=true before ref_decision can reject a non-push event. Calling main with `--event pull_request --ref refs/pull/1/merge` but no required --head reproduces publish=true. This contradicts the module's "any event but push ... never publishes" invariant. The current workflow supplies all arguments and excludes PRs from release-gate, so this is **not** a current PR publishing exploit.

Fix: parse/validate event and ref first; fail closed for invalid arguments and disallowed events. If the documented availability-oriented fail-open policy is retained, apply it only to valid main/tag pushes after eligibility is established. Regression: `test_gate_parse_error_cannot_publish_for_pr`, strict xfail CODEX-7; uses fake output streams, no git/API calls.

### CODEX-8 — Low: skip-checks trailers are counted as built milestones

Evidence: `tools/release_gate.py:35,65-73` recognises only five bracket markers. `skips_ci('subject\n\n\nskip-checks: true\n')` returns false, and counted_merges includes such a non-head commit. GitHub documents both `skip-checks:true` and `skip-checks: true` trailers as skipping push/PR workflows: https://docs.github.com/en/actions/how-tos/manage-workflow-runs/skip-workflow-runs (retrieved 2026-10-14). This makes the release cadence count a commit without its own CI run.

Fix: recognise valid terminal trailers, preserve the head exception only when a run actually exists, and sanitize squash messages before merge. Bracket markers in copied PR bodies can skip the push build entirely; release_gate cannot repair a run that was never started. The release marker anywhere in the head body also forces a prerelease by design, so require explicit release intent rather than copying issue text into squash messages. Regression: `test_skip_check_trailers_are_recognised`, strict xfail CODEX-8 (both spellings). None of this audit's commit messages contains a skip or release marker.

## Reviewed areas without a proven defect

- Injection: dispatch strings are passed through environment variables and quoted arguments (backend version/platform validation, NVD CVE word array, fuzz numeric validation). Direct run expressions inspected are controlled matrix constants, runner fields, or validated plan outputs. No untrusted issue/PR title/body or dispatch string was proven to enter a run script as shell source.
- PR publishing: qa-windows release-gate is push-only; release depends on it and does not use always(); a PR has no successful publish gate. pages has no PR trigger; backend-bundle has dispatch/call/tag triggers and an explicit publish input plus acceptance gates. Upload-artifact evidence steps are not release publication. New callable-workflow callers would require their own audit.
- Secrets: GH_TOKEN appears only in the read-only release-gate and the dedicated backend publication job; no literal secret or token-printing step was found. Persisted checkout credentials in ordinary read-only jobs increase exposure surface but do not prove leakage. Mutable actions remain CODEX-1.
- Platform differences: Windows uses PowerShell/cmd for hashing and compiling; Linux uses sha256sum/MinGW or gcc; both analyse owned fixtures without executing target binaries. live-unified uses Java 21 while live-backend/corpus use 25; no compatibility failure was reproduced. Windows BinDiff/intel legs are explicitly advisory, so a green job is not a Windows acceptance pass. Linux full smoke coverage is reported in package 2.
- Microsoft-derived corpus prohibition is explicit in corpus-tier-r; fixture DLL/PDB compilation is from owned C sources, not Microsoft binaries/PDBs. This is not an artifact-level compliance attestation.

## Reproduction and regression disposition

All eight CODEX-1 through CODEX-8 checks are strict expected failures at the audited snapshot. A repair produces XPASS(strict) until the corresponding mark is removed. Passing controls also check event gating and prohibit risky event/input expressions directly in run blocks.

```bash
python -m pytest tests/test_codex_pkg_*.py -q
ruff check tests/test_codex_pkg_*.py
python -m pytest tests/test_codex_pkg_workflows.py -rx -q
```

Tests use source reads, AST and pure release-gate helpers only; no network, credentials, git subprocesses, Actions or target binary execution. New test files are added in the third commit.
