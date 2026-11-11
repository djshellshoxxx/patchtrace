# PatchTrace — Claude Code autonomous alpha build handoff (2026-10-13)

**Snapshot, not a truth source.** Re-read current GitHub state before work. Base observed: `main` at `0a4bc09bb0f658a8b39a799e489b0239620504f0`. Repo: `djshellshoxxx/patchtrace`. Active draft PR [#19](https://github.com/djshellshoxxx/patchtrace/pull/19), `feature/alpha-file-overview-20261013`, last inspected head `476016590be5cd1315613759af18ff61c7c27851`. Other contributors may be editing `ui.py`, the file overview, and documentation. Prefer a new non-overlapping branch; rebase/merge only after checking ownership and passing tests.

## Verified existing work

- PySide6 desktop, SQLite project storage, static PE AMD64 ingestion, offline sample, native supervised Ghidriff, headless CLI, enrichment, acquisition, N-way and optional secondary-engine adapters; see `docs/modules.md`.
- Python >=3.12; `pyproject.toml` pins PySide6 6.12.0, Pydantic 2.13.5, PyInstaller 6.22.3 in dev extra. Windows onedir ZIP and Linux tarball workflows are in `.github/workflows/qa-windows.yml`; native Ghidriff Windows matrix in `live-backend.yml`.
- `docs/qa.md` records historical beta.90 packaging and native Windows fixture acceptance. These do NOT prove the latest commit passes or that clean Windows manual GUI testing was done.
- PR #15 already addressed cross-function Next/Previous diff navigation and some tooltips; do not reimplement that without examining current code.
- PR #19 implements a **preliminary** `src/patchtrace/preflight.py` snapshot-only metadata table, GUI `File overview` action and tests. It does not yet parse PE headers/signatures or implement full SPEC-26 D.

## Observed blockers and CI interpretation

**B1 — confirmed release publishing failure:** [workflow run 38492874312](https://github.com/djshellshoxxx/patchtrace/actions/runs/38492874312) at `64fda061`: Ubuntu QA, Windows QA, Linux package and smoke passed; `release` failed with GitHub 403 `Resource not accessible by integration` while creating `v0.1.0-beta.100`. The workflow sets `permissions: contents: write` for its release job; this is likely a token/integration/repo-policy restriction and cannot be assumed solvable by editing Python code. Confirm effective GitHub Actions permissions and event context; advise maintainer on settings/credential changes if needed. Preserve Windows ZIP as an Actions artifact and report build green versus release publication failed distinctly. Do not suppress/relabel failed publishing as success or put secrets in code. Avoid excessive release attempts.

**B2 — historical, may be resolved on newer commits:** [PR #19 workflow run 38494944366](https://github.com/djshellshoxxx/patchtrace/actions/runs/38494944366) failed on Linux and Windows at `21ccb19d` because `tests/test_preflight_overview.py` could not import `patchtrace.preflight` during a test-first intermediate commit. Later inspected PR head `47601659` **does contain** `src/patchtrace/preflight.py`; newer runs 38495105376 / 38495105378 were still queued at inspection. Check latest SHA+run before treating that old red as an active bug.

**B3 — real acceptance gaps:** official relocatable offline Ghidra/Ghidriff/JDK bundle not built/tested disconnected; clean interactive Windows GUI, signature/authenticode, complete PE inspection, raw Hex/Binary/Base64 views, exhaustive informative tooltips, some Phase 3 UI and live external engines remain incomplete. Do not confuse these with minimum alpha build blockers.

**B4 — stale docs:** `tasks/todo.md` and `docs/specs/completeness-audit.md` contain older '[planned]' statuses already superseded by merged Phase 2/3 work. Reconcile from code and CI, not guesses, after functional changes.

## Execution sequence — autonomous until useful alpha artifact

### Step 0: reality check and ownership (fast)

1. Inspect `git status -sb`, `git log -8 --oneline`, `gh pr list --state open`, current PR #19 diff/commits and `gh run list --limit 15`; check which branch is actually being modified by another worker.
2. Read `AGENTS.md`, `docs/modules.md`, `docs/specs/gui-preflight-inspection.md`, `docs/specs/ui.md`, `docs/specs/verification.md`, `tasks/todo.md` and relevant tests. Do not load the full repository into model context.
3. Record exact state and CI errors in a concise working note at `tasks/claude-progress.md` (or PR conversation). Make no duplicate branch for already active work.
4. Create or update a small `Alpha implementation matrix` with SPEC-26 parts A/B/C/D/E: implemented, partial, missing, blocked, tests required. Identify smallest coherent user-visible alpha slice.

### Step 1: build gates before feature expansion (P0)

1. Check latest PR #19 Linux and Windows pytest, Ruff, Windows freeze and native Ghidriff matrix. For a real failure: extract failing job and its specific traceback, reproduce with a focused test, fix root cause, add regression, rerun focused then broader suite.
2. Confirm packaging entrypoint from `src/patchtrace/__main__.py` and `tools/build_windows.py`, collected PySide6 plugins, expected `dist/PatchTrace-0.1.0-windows-x64.zip` and SHA-256, no PyInstaller cross-compile from Linux, Qt offscreen `--self-test`, and CLI import without Qt for headless commands.
3. Treat release 403 as a separately tracked repository-permissions problem, NOT a Python build failure. Document exact corrective permissions/action needed; preserve accessible Actions ZIP even without Release creation.
4. Merge PR #19 only if CI gates pass and branch ownership permits. If active worker continues, leave it alone and base parallel work on stable interfaces; integrate afterwards.
5. Before substantial refactoring, ensure `QT_QPA_PLATFORM=offscreen python -m pytest -q` and `python -m ruff check src tests tools` baseline. Use `python -m pip install -e '.[dev]'`. Log real outcomes.

### Step 2: ship a valuable large modular SPEC-26 slice (P0 after gates)

Prefer three bounded streams, with an integration owner. Avoid simultaneous edits of `src/patchtrace/ui.py`.

**Stream A: Pure PE inspection and comparison** (capable coding model). Specify and implement `pe_overview/` with `models.py`, `reader.py`, `headers.py`, `sections.py`, `metadata.py`, `entropy.py`, `compare.py`, plus an optional **Windows-only** `signature.py` adapter. Enforce byte/count/time limits, explicit source/provenance, fail-closed parse statuses, immutable owned file identity and SHA verification. Separate PE header presence, checksum and Authenticode trust. Implement useful first slice: machine/subsystem, timestamp (untrusted), entrypoint RVA, image base, sections/imports/exports summary, overlay and bounded entropy. Add unit/fuzz fixtures for corrupt/short/hostile input, invalid offsets, high entropy, Unicode paths, cancellation, signature unknown. Windows Authenticode trust requires native Windows acceptance; do not simulate as passed. Update `docs/modules.md` and spec/contracts before new public interfaces.

**Stream B: Scoped byte representations** (capable coding model; only after agreeing Stream A's byte-access interface). Independent pure providers for bounded Hex/Binary/Base64 conversion and explicit whole-file or verified function-file-range selection. Do not base64 encode decompiler text. Fail clearly for function ranges without validated RVA-to-file mapping; never fabricate raw bytes. Add safe paged reads, offset/length caps and SHA identity; Qt adapter consumes providers and performs off-thread reads via existing job patterns. Tests: binary null/high-bit, Base64 padding, section gaps/overlap, overflow, huge files, cancellation, hash mismatch, clipping.

**Stream C: Tooltip/completeness registry** (low-cost model for inventory/docs and fixtures; capable model for Qt integration). Inventory all functional actions/widgets except New/Open. Declare semantic IDs and WHAT/WHY/SOURCE/availability tooltip templates; plain/safe rich text only. Add accessibility descriptions and Qt tests for dialogs, disabled controls, dynamic widgets, no missing tooltips. Do not change analysis data or overwrite active GUI edits; use a stand-alone registry/module + tests before one integration commit.

**Optional Stream D: CI/QA owner** (low-cost for log classification, capable coding model for changes). Triage current job logs, verify build path, test packaging, propose permissions repair without weakening gates; investigate remaining Phase 3 UI gaps only after alpha-critical streams pass.

Integration owner (capable model) alone edits shared `ui.py` and final `docs/qa.md`; merges streams incrementally after review. Require pinned public interfaces, no SQLite/schema migrations unless essential; pure backend modules have no Qt dependency. Do not pretend unavailable input ranges/signatures are supported.

### Step 3: end-to-end alpha acceptance

Run focused unit/module tests first, then `QT_QPA_PLATFORM=offscreen python -m pytest -q` and `python -m ruff check src tests tools`. Verify Windows Actions `qa (windows-latest)` actual exe build and ZIP artifact, Linux tests and native Ghidriff fixture. Manually verify on real Windows when available: launch portable ZIP on a clean profile, open Sample, New project, File overview before expensive analysis, run/import analysis, move between diff hunks/functions, Hex/Binary/Base64 offsets and evidence scope, settings, export, cancel/close, tooltips, high-DPI/resizing. Do not mark unrun checks passed; record exactly in `docs/qa.md` and `tasks/todo.md`.

Alpha can have incomplete specs if explicitly labelled. Produce a Windows standalone **alpha** test artifact for GUI/feature evaluation, not a falsely 'production ready' package. Native Ghidra remains optional for sample and imported data. Do not block alpha on fully relocatable offline backend bundle, real AI credentials, external engine acceptance, or release-writing permissions if Actions ZIP is successfully available; keep those as explicit open gates.

## Agent / token budget discipline

- Cheapest *capable* model for grep/inventory, focused simple fixtures, release-log triage and docs. Mid-tier for tested module implementation, Qt, packaging, merge resolution. High-tier only for independently evidenced subtle PE/Authenticode or ownership/security challenges, difficult design conflicts or repeated failed approaches. Choose from actually available current models; no hard-coded model ID.
- Delegation only for separable file ownership. Give each agent exact paths, dependencies, acceptance/tests and output budget. Do not start competing copies of the same work. Primary agent coordinates source-of-truth contracts and does shared integration.
- Require agents to respond with changed files, tests actually run and results, unresolved blockers, branch/commit and proposed merge; no lengthy narration. Maintain brief branch notes so parallel workers do not repeat investigation.
- Use `rg`, targeted lines and failed tests instead of dumping all source/logs. Do not repeatedly run the 5-way Ghidra native matrix when a small pure-model test suffices. Prefer existing project fixtures, test tools and mature permissively licensed packages after notice review; use reputable primary docs and peer-reviewed/textbook material for new algorithms if required. No YouTube/blog-based research.
- Red/green/refactor: write a failing regression for confirmed bugs; fix the minimal cause; rerun focused tests; run whole suite before merge. Smaller PRs (ideally one coherent feature) are cheaper to review and safer than a giant forever branch.
- Merge passing PRs promptly. Inspect unmerged branches by merge-base/diff before reuse; never merge obsolete conflicting drafts wholesale or reset/force-push someone else's work. Do not break current project DB or report formats.
- Never execute inspected binaries or trust model-generated commands; never leak local paths/session credentials or start network downloads silently.

## Final report contract

Return one compact status report: current main/PR SHA; exact issue/CI blockers **with links**; implemented modules/GUI controls; files changed; tests and Windows build/run numbers; downloadable alpha artifact URL if produced; accepted/incomplete/unverified checklist; PRs opened/merged; next 3 priority slices. If a task cannot be completed because of permissions, mark it blocked with required maintainer action instead of repeatedly spending tokens retrying.

The user has authorized autonomous modular implementation and merge **after passing checks**. Do not stop to ask about routine decisions. Stop only for credentials, external repo settings, destructive operations, unapproved external transmission or a genuine product-scope choice that cannot be reasonably inferred.

## Continuation pointer (2026-10-16)

For the current merge-first PR state, verified #77 merge, current-head CI blockers for #64/#76/#78/#61, stacked #80 dependency and overlapping #79/#82 label proposals, read [chatgpt-merge-first-handoff-20261016.md](chatgpt-merge-first-handoff-20261016.md) before resuming. Both documents are time-stamped snapshots: GitHub branch tips and current CI supersede them.
