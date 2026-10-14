# Multi-engine evidence panel plan (C6), ordered

Date 2026-10-14. Inputs: `docs/specs/multi-engine-evidence-panel.md` (SPEC-28, "S"), `docs/research/phase-c/multi-engine-evidence-ui.md` (research "R", items cited as R#n). Triage: `evidence-panel-troubleshooting.md` ("T"). Labels: [M] measured 2026-10-14 (PySide6 6.12.0, offscreen, Linux); [D] primary doc/source; [H] hypothesis to confirm. PR slices C6-0..C6-4 of S section 12 stay; this plan orders the risky work, sets decision points, measurable gates and fallbacks. Policy: AGENTS.md; spec first, red/green, pure code separate from Qt, no `ui.py` growth beyond the seam, one integration owner.

## 0. Spec edits first (C6-0, docs only, before any code)

Apply R section 9: (1) replace proxy sort/filter with model-owned design, keep proxy only as fallback D-A; (2) threads unparented plus registry; (3) status-label accessible-name rule, 1.4.11 3:1, hide vertical header; (4) row height via `defaultSectionSize`; (5) perf budgets of section 3 below replace S 9.1; (6) drop "accepted in Ghidra" (F6), add diff-ratio labelling and quote Ghidra non-comparability sentence in S 11; (7) tooltip escaping test. Also apply R F1-F5, F7, F8 (algorithm name, "match type", drop "of 83", selection restore, rz-diff mode, unknown sort). Gate: spec diff reviewed; `docs/modules.md` rows added. Why first: S 9.1 targets are impossible with its own 5.1 design [M] and S 5.3.6 guarantees an abort on close [M].

## 1. Ordered steps

| # | Step (slice) | Decision point | Acceptance (measurable) | Fallback if it fails |
|---|---|---|---|---|
| S1 | **Perf spike with synthetic 10k/100k models, no product code** (before C6-2) | D-A: model-owned order/filter vs filter-only proxy. D-B: >100k rows: cap (E8) vs chunked `fetchMore` | Section 3 table green on Linux CI and one Windows run; script lives in `tests/test_evidence_perf.py` | D-A fallback: filter-only `QSortFilterProxyModel` (17 ms @10k, 655 ms @100k [M]) + model-owned sort; cap display at 20k rows with E8 prompt and "narrow filter" instead of 100k |
| S2 | Pure view-model + service (C6-1) | D-C: `assess_reports` quadratic? Pre-index refactor only if 10k build > 1.5 s | `build_view_model` 10k x 3 engines <= 1.5 s (5x CI bound 7.5 s); all S 10.1 tests; `test_evidence_view_has_no_qt`; row index dict per engine (no `next()` scans) | Behaviour-preserving pre-index of `assess_reports` guarded by `test_secondary_evidence.py`; flag to `secondary/*` owner |
| S3 | Qt adapter: model, delegate, detail, states E0-E8 (C6-2) | D-D: sort via `QAbstractItemModel.sort` override (header click) vs custom header slot | `EvidenceTableModel` has no `lessThan`; data() call ceilings (section 3); selection survives sort/filter/reset (test); no `QSortFilterProxyModel` import unless D-A fallback taken | Header `sectionClicked` slot calling `set_order()` directly |
| S4 | Threads: load thread + generation + registry (C6-2/3) | D-E: lifetime policy | Teardown matrix (section 5) green: close while loading, close while running engine, project switch, GC of started thread; zero SIGABRT in 50x repeated run (`pytest --count` or loop) | Keep thread alive in registry and detach UI (never delete); worst case skip `wait` and leave daemon-like finish, never `terminate()` |
| S5 | Text safety + tooltips + accessibility (C6-2/4) | D-F: status announcement mechanism | Hostile-string suite (T section 7 list) green; every tooltip fact also in detail pane; accessible-enumeration test: all interactive widgets named, every Cell text contains unit word, status label name changes; contrast function test >= 4.5 text, >= 3.0 border/focus on palette constants | If status events unreliable: put status in the dock title and detail header too; record Windows UIA/NVDA as open gate for C8 |
| S6 | Engines tab and runs (C6-3, needs C1) | D-G: probe on worker vs on demand | `publish_secondary` called on GUI thread (test); one engine failing keeps others; cancel marks cancelled | Import-only (BinDiff) and rz-diff run behind a flag |
| S7 | Polish, DPI, QA doc (C6-4) | D-H: high-DPI check automated vs manual | Row height grows with font (test at 10/14/18 pt); manual 125/150/200% pass recorded in `docs/qa.md` as open C8 gate | Document as blocked external acceptance, not automated evidence |

## 2. Decision details

- **D-A (S1).** Default: model-owned. Reason [M]: proxy sort 10k = 1.56 s built-in / 2.30 s Python `lessThan`, 100k = 20-30 s; a sorted proxy also re-sorts on every source reset even with `setDynamicSortFilter(False)` (2.2 s @10k) [M, R#n2-3]. Model-owned: sort 4-10 ms @10k, 32-40 ms @100k; filter+reset 9 / 24 ms. Choose proxy only if S3 needs Qt-provided mapping for something the model cannot do (it cannot be needed for current spec).
- **D-B.** Spec cap 100k (E8). If a real project exceeds ~150k matches: `canFetchMore/fetchMore` in 5k chunks (view triggers it at scrollbar end [D Q3]) with total count shown in the summary strip; sorting requires full list so sort button disabled until loaded.
- **D-D.** `setSortingEnabled(True)` calls `model.sort(col, order)` [M]. Implement `sort()`: save selected `match_id`, `layoutAboutToBeChanged`, reorder `view`, `changePersistentIndexList`, `layoutChanged`; reselect by id as belt and braces. Initial default order (contested first) is set by `set_order(None)`, not by the header.
- **D-E.** No parent; registry `_LIVE_THREADS`; `finished -> _release -> deleteLater` (pattern in `ui_series.py`); `shutdown()` = cancel all, `wait()`; signals only to `@Slot` methods on GUI QObjects (R#n13).
- **D-F.** Leave `evidence_status` accessible name empty so `QLabel.setText` fires NameChanged itself (R#n18); also mirror the state into the dock window title. WCAG 4.1.3 verification is manual.

## 3. Budgets (gates). Ceilings are 5x the [M] value for wall time (CI slack) and exact for call counts

| Metric | 10k rows | 100k rows | How measured |
|---|---|---|---|
| `data()` calls, first paint / scroll / select | <= 7 x visible_cells x 1.2 (measured 560 for 80 cells) | same (independent of N) | counting subclass on model; `QT_QPA_PLATFORM=offscreen`, 900x500 view |
| `data()` calls per sort or filter | 0 beyond visible repaint (<= 1 repaint) | same | same |
| Reset (`set_view_model`) incl. `processEvents` | <= 50 ms (M 7-10) | <= 150 ms (M 13-26) | `perf_counter` |
| Sort change | <= 50 ms (M 4-10) | <= 200 ms (M 32-40) | `model.sort()` + `processEvents` |
| Filter / search change | <= 50 ms (M 9) | <= 150 ms (M 24) | includes view rebuild; debounce 150 ms in UI |
| Search key scan | <= 20 ms [H] | <= 200 ms [H] | measured in S1 to confirm |
| View-model build (worker) | <= 1.5 s (S 9.1; CI bound 7.5 s) | <= 15 s [H] | off GUI thread |
| GUI-thread stall while loading | no single GUI-thread callback > 100 ms | same | slot timing wrapper in test |
| Frame budget on scroll | 16 ms/frame: data() cost per frame <= visible_cells x 7 x 10 us ~ 6 ms [M] | same | derived from call ceiling x 10 us |
| `ResizeToContents` | forbidden (40k calls, 370 ms regardless of N [M]) | forbidden | grep test on `ui_evidence.py` |
| Memory (10k rows) | <= 64 MiB (S 9.2) | <= 400 MiB [H] | `tracemalloc` peak |
| Forbidden APIs in `ui_evidence.py` | `lessThan`, `resizeColumnsToContents`, `resizeRowsToContents`, `setHtml`, `setMarkdown`, `QToolTip` with unescaped text | | static grep test |

## 4. Test strategy

1. **Pure** (S 10.1) fast, no Qt. Hypothesis for `filter_rows` vs naive filter; table-driven formatters; banned-string scan.
2. **Perf gates** (`tests/test_evidence_perf.py`, marker `perf`, runs on CI nightly and on demand, call-count assertions run in the default gate because they are deterministic).
3. **Offscreen Qt** (S 10.2). Build the panel standalone (`qtbot.addWidget`) for speed; one test through `MainWindow`. Use `waitSignal` around the *start* call (`raising=True`), `waitUntil` for state; fakes gated by `threading.Event` (no sleeps). Exceptions in `data()`/paint fail tests (pytest-qt capture, PySide >= 6.5.2) [D P1].
4. **Teardown matrix** (mandatory, S4): (a) close dock/window while load thread running; (b) project switch mid-load (generation drop); (c) shutdown during engine run; (d) panel deleted, thread keeps registry reference; (e) started thread with no Python reference + `gc.collect()` must not abort; (f) repeat each 20x in one process. Autouse fixture: after every test, join all registry threads (`wait(5000)`), fail if any still running, then `sendPostedEvents(None, DeferredDelete)`.
5. **Accessibility enumeration**: walk `QAccessible.queryAccessibleInterface(table).child(i)`; assert names, cell text with units, header names; independent of `isActive()` [M].
6. **Hostile text**: see T section 7; includes `Qt.mightBeRichText` oracle on every tooltip string returned by the model.
7. **Manual / external (reported separately)**: Windows glyph fonts, 125/150/200% DPI clipping, NVDA/Narrator on the table and status label, contrast with real palette, frozen EXE smoke (C8).

## 5. Risks (ranked)

| Risk | Likelihood / impact | Mitigation |
|---|---|---|
| Abort on close from running QThread (parented or GC'd) | High / crash | D-E, teardown matrix, grep test for `QThread(` with a parent argument |
| Proxy sort adopted from spec anyway | High / unusable UI at 10k | S1 gate before S3; forbidden-API grep test |
| Rich text from tool strings (tooltips default AutoText) | Medium / security | escape-all tooltip policy, mightBeRichText oracle test |
| Selection/detail flicker after sort/filter/reset | Medium / UX | reselect by `match_id`, test |
| Stale rows after orientation swap or reanalysis | Medium / wrong evidence shown | `project_changed()` on swap (increments revision, `architecture.md`), generation + stale banner tests |
| Accessible status not announced | Medium / a11y | D-F, manual gate |
| `ui.py` merge conflicts | Medium | seam <= 60 lines, rebase before each slice, check open PRs touching `ui.py` |
| C1/C5 shape differs | Medium | adapter `EngineOutcomeView`, duplicate-safe loader |
| Perf numbers differ on Windows | Low-Med | run S1 script once on the Windows runner; ceilings use 5x slack |

## 6. Fallback ladder (when a gate fails)

1. Perf gate fails by < 2x: reduce per-cell roles, precompute strings, drop delegate custom paint for Match cell (use plain two-line text).
2. Fails by > 2x at 10k: fall back to D-A proxy-filter + model-owned sort and cap at 20k with E8.
3. Thread teardown still flaky: no `wait` on GUI thread for the load thread (it is pure and cancellable); keep registry reference to completion; engine runs refuse app close until finished or user confirms.
4. Accessibility enumeration impossible for a control: expose the same information as plain text in the detail pane and record the gap in `docs/qa.md`.
5. Always: do not ship E3 table without the footer rule and banned-string test; if the table cannot be made responsive, ship the Engines tab and summary strip only.

## 7. Done definition

Spec edits merged; S1 numbers recorded in `docs/qa.md`; C6-1..C6-4 merged each with full Linux/Windows CI; teardown matrix repeated 20x green; open gates listed separately (Windows DPI/UIA/glyph pass, frozen smoke, D1-D5 product decisions).
