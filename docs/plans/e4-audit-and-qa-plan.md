# E-4 / E-6 audit and QA method

Status: method, 2026-10-14. Consistent with `docs/plans/program-e-execution-plan.md` section 6.4 (audit and migration readiness) and `docs/specs/program-e/E6-test-performance-beta-plan.md`, whose sections 2-7 hold the full matrices, budgets and scenarios. This file is the per-feature procedure and does not restate them. Standing rules: `AGENTS.md`, `docs/plans/worker-brief.md` section 2.

## 1. Who and when
One Sonnet auditor per feature, never the builder of that feature, starts when the feature's last slice is merged (features that are 100 percent built first). Haiku may run the grep checks. The auditor is token-frugal: it reads the feature's package and tests, not the repository. Automated evidence and owner-only evidence are reported in separate tables; an owner-only row is never counted done by a bot.

## 2. Per-feature checklist
Each cell needs evidence (a file path plus a test name) or the word `absent`.
1. Merged to `main`; Linux and Windows CI green on the audited SHA.
2. Spec status line and `docs/modules.md`, `tasks/todo.md`, `docs/qa.md` rows present.
3. Persisted contracts additive only; schemas regenerated and drift test clean (`python tools/generate_schemas.py`, then `git diff --exit-code docs/schemas`); an older project or record still opens.
4. Product invariants (worker brief section 2): no target execution; no silent network (consent per operation); no fabricated evidence; no uncalibrated number shown as confidence; engines and channels never averaged; conflicts kept; unknown is not a negative vote; shared-origin evidence counted once; explicit older/newer orientation; provenance on everything; untrusted text bounded and escaped; one main window; pure models separate from Qt.
5. Strict JSON for untrusted input (duplicate keys and NaN rejected); every parser has one hostile-input test.
6. Tooltips and accessible names for every interactive widget (`tests/test_tooltips.py`); sane keyboard order.
7. Frozen-smoke import: the feature package imports inside the frozen build (`tools/frozen_smoke.py`) and each new CLI verb answers `--help`.
8. Performance budget met or recorded (section 6).
9. No open High or Medium finding.

## 3. Bug-hunt recipe
1. Read the package, its tests and its spec section; list the inputs that cross a trust boundary (files, JSON, advisory or tool text, paths, child-process output, network).
2. Hunt by theme, one pass each: correctness against the spec tables; hostile input (oversized, truncated, wrong schema, control characters, bidi, markup); Windows paths (spaces, Unicode, 260 characters, reserved names, CRLF); cancellation and timeouts for every child and network call; SQLite thread ownership and locks; orientation swap and stale-cache mix-ups; resource use (memory, rows, recursion depth); product invariants.
3. **Repro rule**: a finding exists only with a repro: a failing test, or a command with exact output, runnable offline and hermetic. Without one it is a note labelled `suspicion`; it is not a finding and does not block.
4. Record each finding in `docs/audits/<date>-<feature>.md`: id, severity, repro, expected versus actual, file and line, status.

## 4. Severity scale
- **High** (E6 P0/P1): data loss or corruption; a product-invariant break (target execution, silent upload, fabricated evidence, uncalibrated number shown as confidence, averaged engines); crash on launch; a wrong result shown as right. Blocks the build and migration readiness.
- **Medium** (P2): wrong or missing explanation; hostile input causing a hang or unbounded resource use; a Windows-only failure with a workaround. Blocks migration readiness.
- **Low** (P3): cosmetic, wording, minor inefficiency. Recorded; does not block.

## 5. Fix rule
Red test first, then the fix, then focused tests and `ruff check` on touched files. The auditor fixes small defects itself (about 50 lines or fewer, inside the feature's own files) and routes the rest to the feature owner with the repro. A shared file (execution plan section 4) is never edited by the auditor: the change goes to its owner as an ask. A test is never skipped or loosened to get green; an unfixable failure is recorded in `docs/qa.md` with the exact command and output. Each fix gets a `docs/qa.md` line with the commit.

## 6. Performance and accessibility checks
- Performance: budgets and method are in E6 plan section 5 (offscreen Qt, best of 3, host and versions stated, `data()` call ceilings). Every new table or tree is a lazy `QAbstractItemModel` measured at 100,000 rows (first paint 250 ms, reset 250 ms, sort 500 ms, filter 150 ms; CI ceiling about 3x). Remedies in order: virtualize, move to a worker with progress and cancel, cap with a visible "truncated, showing N of M", and only last change the budget with an owner-approved note. The 500 ms enrichment cache-hit objective is a known miss and stays visible.
- Accessibility: accessible name, description and role on each interactive widget; full keyboard operation; no meaning carried by colour alone. High contrast, DPI and screen-reader behaviour are owner-only checks (E6 plan O1-O3); the offscreen accessibility tree is not a screen-reader run.

## 7. Gates
- Linux: `QT_QPA_PLATFORM=offscreen python -m pytest -q` twice with identical counts; `ruff check src tests tools`; GUI subset 20 times without abort; `python -X dev -W error::ResourceWarning` teardown check; schema drift clean.
- Windows (`qa-windows.yml`): same suite plus frozen smoke. Checklist: CRLF on pinned or generated files; `PYTEST_CURRENT_TEST` under 32767 characters (short explicit parametrize ids); coarse monotonic clock (use `>=`); YAML plain scalars never contain `: `; installs with `--only-binary=:all:`; hermetic tests; grandchild processes gone within 5 s.
- Frozen build: E6 plan section 6, rows W1-W9. A failed row blocks the prerelease. A missing token permission is reported as blocked, never as a successful release.
- Blocked external acceptance (E6 plan section 7, O1-O12) is reported separately in every status message.

## 8. Migration-readiness table
Maintained at `docs/plans/migration-readiness.md`, one row per feature. Columns: feature | slices merged | CI green (Linux, Windows) | audit (link, date) | open High/Medium | tests | docs rows | tooltips and accessible names | frozen-smoke import | schema drift | perf | status. Status values: `building`, `audit`, `fixing`, `ready`, `blocked-external`. `ready` needs every column satisfied and zero open High or Medium findings; Low findings may remain listed.
