# Multi-engine evidence UI: prior art, Qt facts, and corrections to SPEC-28 (C6)

Re-validated 2026-10-14 (second pass; first pass was snippet-based). Baseline: `docs/specs/multi-engine-evidence-panel.md` (SPEC-28). Companions: `docs/plans/hard-problems/evidence-panel-plan.md`, `evidence-panel-troubleshooting.md`.
Labels: **V** validated against a primary source read in full this pass; **C** corrected; **U** unverifiable here (source unreachable; do not rely); **M** measured here (PySide6 6.12.0 = pinned version, offscreen, Linux, CPython; bench scripts were scratch, numbers reproduced by the perf gate in the plan). Qt facts are from `qt/qtbase` branch `dev` (docs live as qdoc comments in the .cpp files); behaviour was re-checked on 6.12.0 where it matters. `dev` is newer than 6.12 (e.g. 6.13 deprecates `invalidateFilter`); the pinned API is what counts.

## 1. Sources (primary only; short keys used below)

| Key | Source (raw GitHub unless noted) | Use |
|---|---|---|
| Q1 | qtbase `src/corelib/itemmodels/qsortfilterproxymodel.cpp` | proxy sort/filter semantics |
| Q2 | qtbase `.../qabstractitemmodel.cpp` | reset, layoutChanged, fetchMore |
| Q3 | qtbase `src/widgets/itemviews/qabstractitemview.cpp`, `qtableview.cpp`, `qheaderview.cpp` | fetchMore trigger, tooltip routing, resize cost |
| Q4 | qtbase `src/corelib/thread/qthread.cpp`, `kernel/qobject.cpp`, `global/qnamespace.qdoc` | QThread lifetime, queued connections |
| Q5 | qtbase `src/widgets/accessible/itemviews.cpp`, `qaccessiblewidgetfactory.cpp`, `src/gui/accessible/qaccessible.cpp`, `widgets/qlabel.cpp`, `kernel/qtooltip.cpp` | accessibility, rich-text tooltips |
| P1 | pytest-qt `docs/signals.rst`, `docs/virtual_methods.rst`, `docs/troubleshooting.rst`, `src/pytestqt/{qtbot,plugin}.py` | test patterns |
| W1 | w3c/wcag `understanding/20/use-of-color.html` (1.4.1), `20/contrast-minimum.html` (1.4.3), `21/non-text-contrast.html` (1.4.11), `21/status-messages.html` (4.1.3) | non-colour status |
| G1 | NationalSecurityAgency/ghidra `Ghidra/Features/VersionTracking/src/main/help/.../{Version_Tracking_Intro,providers/VT_Matches_Table,providers/VT_Related_Associations_Table}.html` | VT behaviour |
| G2 | clearbluejar/ghidriff `ghidriff/ghidra_diff_engine.py` | what ghidriff really emits |
| D1 | joxeankoret/diaphora `README.md` | match presentation |
| T1 | qt-creator `src/plugins/coreplugin/ioutputpane.h` | panel/widget separation precedent |
| C1 | Correll and Gleicher, TVCG 20(12) 2014 (carried over from pass 1, abstract only; not re-fetched) | summary-encoding risk |
| C2 | Chow 1970 reject option (bibliographic, carried over) | abstain state |
| X | In-repo: `ui_series.py` `_LIVE_THREADS`, `ui.py::_stop_inspection`, `tests/test_ui.py` `window` fixture | local thread pattern |

U (unreachable, not cited as support): doc.qt.io, ghidradocs.com, zynamics BinDiff manual, PLOS/arXiv uncertainty-visualisation papers (proxy-blocked, HTTP 000). Anything below about BinDiff confidence semantics stays U.

## 2. Validation of Qt claims (note and spec)

| # | Claim | Status | Evidence / correction |
|---|---|---|---|
| 1 | `invalidateFilter()` repeatedly may be slower than `reset()`; reset loses selection | **V** validated 2026-10-14 | Q1 class doc: "using beginResetModel()/endResetModel() may be more efficient ... losing selection information, and will cause the proxy model to be repopulated". Pinned 6.12 has `beginFilterChange()/endFilterChange()`; `invalidateFilter` deprecated from 6.13 [Q1]. Use begin/end pair when a proxy is kept. |
| 2 | `setDynamicSortFilter(False)` protects from re-sorting costs (spec 5.1) | **C** validated 2026-10-14 | Q1 doc only says it stops dynamic updates on source *changes*. **M**: a proxy with an active sort column still re-sorts on source `modelReset` (10k rows: 2.2 s, 255k data() calls) even with dynamic=False; `dataChanged` is then free (0 calls). Call `sort(-1)` before reset or avoid proxy sort. |
| 3 | Proxy sort at 10k "<=150 ms" (spec 9.1) | **C** validated 2026-10-14 | **M**: `QSortFilterProxyModel.sort()` is `std::stable_sort` with `lessThan` -> `data(sortRole)` per compare [Q1 sort_source_rows]. 10k rows: 1.56 s built-in, 2.30 s with Python `lessThan` (155k data() calls, ~10 us each); 100k: 19.9 s / 29.9 s (1.9M calls). Spec target is unreachable with a proxy. |
| 4 | Python `filterAcceptsRow` slow at 10k (note pitfall 2) | **C** validated 2026-10-14 | **M**: 10k rows 17-30 ms (precomputed set), 100k 655-763 ms, 0 extra data() calls. Fine at 10k, too slow at 100k (frame budget). Filter inside the model instead. |
| 5 | Model-owned order+filter via `layoutChanged`/reset | **V** validated 2026-10-14 (new) | **M**: sort 10k 4-10 ms, 100k 32-40 ms; filter by rebuilding an index list + reset 10k 9 ms, 100k 24 ms. Python `sorted(key=...)` is stable. View calls `QAbstractItemModel.sort(col, order)` when `setSortingEnabled(True)` (M, 6.12). |
| 6 | data() call storms (2010 PyQt list) | **U/C** validated 2026-10-14 | Old, unreproducible. **M** replacement: first paint, scroll to end and select are each 560 calls at both 10k and 100k = 80 cells x 7 roles (Display, Decoration, Font, TextAlignment, Background, Foreground, CheckState); cost is proportional to visible cells, not rows. Ceiling: `7 x visible_cells + 20%`. Return early (`None`) for unused roles. |
| 7 | `ResizeToContents` is cheap enough | **C** validated 2026-10-14 | Bounded by `resizeContentsPrecision` (default 1000) [Q3 qheaderview.cpp]. **M**: 40,560 data() calls and ~370 ms per reset regardless of 10k or 100k. Prefer spec 1.7 fixed widths from `fontMetrics`; if ResizeToContents is ever used, `setResizeContentsPrecision(<=50)`. Header doc: `Fixed` sections use `defaultSectionSize`. |
| 8 | `canFetchMore/fetchMore` not needed | **V** validated 2026-10-14 | Q2: defaults do nothing/false. Q3: view calls `fetchMore` when the scrollbar reaches maximum and via a 0 ms timer. Rows are in memory so unnecessary; it is the fallback for progressive loading above 100k rows (plan S1 D-B). |
| 9 | Row height from delegate sizeHint (spec 1.7) | **C** validated 2026-10-14 | **M**: `QTableView` does not call `sizeHint` per row unless rows are resized to contents (0 calls at 100k). Set `verticalHeader().setDefaultSectionSize(max(2*lineSpacing+6, 28))` and `Fixed` mode; hide the vertical header (also exposes RowHeader accessibles, item 17). |
| 10 | Layout/reset selection restore (F5) | **V** validated 2026-10-14 | Q1/Q2: reset drops selection. With `layoutChanged` use `changePersistentIndexList` or reselect by `match_id`; reselect in all cases. |
| 11 | Queued connections / thread rules | **V** validated 2026-10-14 | Q4 `qnamespace.qdoc`: AutoConnection picks Queued if receiver lives in another thread than the emitter, "determined when the signal is emitted". Q4 `qthread.cpp`: a `QThread` object lives in the *creating* thread; slots of a QThread subclass run there; `run()` is the other thread. `qobject.cpp` dtor calls `removePostedEvents(this)`, so queued events to a destroyed receiver are dropped (no crash), but queued *slot-less lambdas* are not covered (item 13). |
| 12 | Destroying a running QThread (spec 5.3.6 "threads parented to the panel") | **C** validated 2026-10-14 | Q4 `~QThread`: `qFatal("QThread: Destroyed while thread is still running")` unless created via `QThread::create` (since 6.3). **M** (exit 134 SIGABRT, not SIGSEGV): parent widget deleted with running thread, or Python GC of an unreferenced started thread. Parent-owned threads therefore guarantee the crash on window close; use no parent plus a module registry like X (`_LIVE_THREADS`), join in `closeEvent`. |
| 13 | Lambda slots are queued automatically | **U/M** validated 2026-10-14 | **M** on PySide6 6.12: lambda/partial connected to a `QThread` subclass signal ran on the GUI thread; but PyQt differs and this was not checked for worker QObjects moved to threads. Rule: connect to `@Slot` methods of GUI-thread QObjects only. |
| 14 | `deleteLater` in tests | **M** validated 2026-10-14 | `processEvents()` does not run DeferredDelete at loop level 0; `QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)` does (test teardown helper, plan T-helpers). |
| 15 | Tooltips from model text | **C** validated 2026-10-14 | Q3: `QEvent::ToolTip` -> `delegate->helpEvent`; tooltip widget is `QTipLabel` (a QLabel, default AutoText, Q5 qlabel.cpp). **M**: `Qt.mightBeRichText` is True for `<b>x</b>`, `&lt;`, `<img src=x>`, `x<br>y`; False for `a < b`, `{0}`. So raw ToolTipRole text renders as HTML; spec 7.3 escaping is required, not optional. QLabel default is AutoText (qlabel.cpp:1361). Use `PlainText` for labels; escape tooltips with `html.escape` before wrapping. |
| 16 | `QPlainTextEdit` plain, `setPlainText` safe | **V** validated 2026-10-14 | Accessible role EditableText (M). Never `toHtml`/`setHtml`. |
| 17 | Accessible name of cells | **V/C** validated 2026-10-14 | Q5 itemviews.cpp:1354: cell Name = `AccessibleTextRole` else `DisplayRole`; Description = `AccessibleDescriptionRole`. Headers likewise via `headerData`. **M**: table exposes Pane, ColumnHeader x2, RowHeader per row (with `headerData` spoken text), Cell. `QAccessible.isActive()` is False offscreen but `queryAccessibleInterface` works. PySide6 6.12 returns `QAccessibleWidget` without `tableInterface()`; enumerate with `childCount()/child(i)`. Spec 10.2 test works if written that way. |
| 18 | `evidence_status` NameChanged event (spec 1.8) | **C** validated 2026-10-14 | Q5 qlabel.cpp:286: `setText` emits `NameChanged` itself *only if `accessibleName()` is empty*. Spec fixes the accessible name to "Engine evidence status", which suppresses updates and makes the manual event convey nothing. Fix: leave the name empty (name = text) or set `setAccessibleName(text)` then fire the event. Qt has no ARIA live region; WCAG 4.1.3 [W1] requires a programmatic status mechanism, so real announcement stays a manual Windows (UIA/NVDA) gate. U. |
| 19 | Dock accessibility | **V** validated 2026-10-14 (M) | `QDockWidget` role Window; set `accessibleName` on dock, tabs, table, detail. |

## 3. WCAG (W1, validated 2026-10-14)

- **1.4.1 Use of Color**: colour must not be the only visual means of conveying information (Understanding doc, intent text read). Spec 0.7 (text + glyph) satisfies it. V.
- **1.4.3 Contrast (Minimum)**: 4.5:1 for normal text, 3:1 large text (thresholds quoted in the Understanding doc). Spec's 4.5:1 badge text rule stands. V.
- **1.4.11 Non-text Contrast**: 3:1 for UI component boundaries/focus indicators needed to identify state. The spec's 1 px badge border and 2 px focus ring need 3:1 against adjacent colours; add to the manual DPI/contrast gate. V (new requirement).
- **4.1.3 Status Messages (AA, WCAG 2.1+)**: status changes must be programmatically determinable without focus. Desktop analogue is a name/value change event; see item 18. V (requirement) / U (Qt behaviour on UIA).
- Offscreen Qt cannot test contrast or announcements; automated: names, roles, glyph-in-text, contrast ratio computed from palette constants (pure function test).

## 4. Ghidra Version Tracking and ghidriff (G1/G2, validated 2026-10-14)

- G1 Matches table: "Score ... indicates how similar two match items are, not necessarily that they are THE correct match. Scores should NOT be compared between different correlator algorithms." Confidence: "no intrinsic meaning other than higher numbers are better for the same correlator algorithm ... should NOT be compared between different correlator algorithms." **C**: the note paraphrased this weakly; this is Ghidra's own non-comparability statement and should be quoted in the footer rationale and spec section 11.
- G1 Intro: accepting a match **blocks** other associations sharing the same source or destination (one-to-one). Statuses are Available, Accepted, Rejected, Blocked. Related Matches table lists all matches for the function under the cursor, from correlators or manual. V; supports the "alternatives for selected row" design.
- **C (F6 is moot)**: ghidriff does not produce VT sessions, acceptance, or status. G2: `ghidra_diff_engine.py` says "Inspired by ... VTMatchInfo.java"; its output per match has `match_types` (correlator/pass names such as `StructuralGraphHash`, `BSIM`, `Decomp Match`) and difflib ratios (`ratio`, `i_ratio`, `m_ratio`, `b_ratio`) computed with `SequenceMatcher` over decompiled text. Therefore: drop the "accepted in Ghidra" attribute (F6); the ratios measure *difference of already-paired functions*, not match confidence, so if shown they need the label "text diff ratio" and must not sit under a match-quality header. SPEC-28 states "Ghidriff exposes no numeric score": correct for matching, incomplete for diff ratios. `FunctionMatch.quality` is a PatchTrace string, not a ghidriff field (grep of G2 finds no `quality`): its provenance must be documented before the header says "quality" (F3 holds).
- D1 Diaphora: README mentions "similarity ratio" and screenshots titled "best matches"/"partial matches": engines may tier a single score. Idea only (AGPL); tiering within one engine is not a cross-engine verdict.
- BinDiff confidence semantics: **U** (manual unreachable). Keep F1: show the algorithm name and similarity; show confidence only as upstream text. Ghidra's wording is the closest verified analogue for "per-algorithm, non-comparable".

## 5. Performance patterns for 10k-100k rows (Qt + Python) [M unless noted]

1. Cost is `data()` calls x ~10 us. Avoid sort/filter paths that call `data()` per compare (proxy `lessThan`). Cache per-column sort keys at load as plain Python lists of ints; order = `sorted(range_or_filtered, key=keys.__getitem__)`.
2. One model, owned order: model holds `rows` (immutable) and `view: list[int]`. Sort via `QAbstractItemModel.sort()` override; filter rebuilds `view` and does one reset. Apply sort to the filtered list from *default order* each time so ties are deterministic.
3. `data()` hot path: one `if role == DisplayRole` with a precomputed string, early `return None` for the other six roles; dispatch tables by column instead of branching on engine names; no formatting, no regex, no object creation in `data()`. Lazy `ToolTipRole`/`AccessibleTextRole` formatting only on request.
4. Batch signals: one `beginResetModel/endResetModel` (7-12 ms at 10k-100k) or one `layoutAboutToBeChanged/layoutChanged` per user action; never per-row `dataChanged` loops; coalesce typing with a 150 ms single-shot timer.
5. Fixed row height and widths (item 7, 9). No `resizeColumnsToContents`/`resizeRowsToContents` on large models.
6. Build the immutable view-model off the GUI thread; hand over one object; GUI work is pointer swap + reset. Slots/dataclass objects with `__slots__`; avoid pydantic validation inside the row path (build once, trust).
7. Detail text is generated on selection only (spec 9.2 stays).
8. Progressive fallback above ~150k rows: `canFetchMore/fetchMore` appending 5k-row chunks (Q2/Q3), or an explicit narrowing prompt (E8).

## 6. Showing uncertainty and disagreement

- Show the **set** of engine outputs, not a summary (C1: summary encodings change decisions). No consensus glyph, no count-of-engines-agreeing as a score.
- Keep three absent-states distinct and non-red: `no record` (engine ran, no pairing), `n/c` (not comparable), `not run`/`failed` (no data). Never sort them as a score; sort by name/address (F8).
- Disagreement is a first-class row state surfaced first (spec default order), with the alternatives list as drill-down on the selected row only (G1 Related Matches precedent), and a visible reason line.
- Say what a number is, in the cell and header (`sim`, `byte sim`, `text diff ratio`), and quote the engine's own non-comparability rule (G1) once, in the footer.
- Abstain (`Unknown`) stays explicit (C2); never infer a threshold from the uncalibrated triage index.
- Non-colour channels: text + glyph + shape + position (contested first). Test the *words*, not the colours.

## 7. Dock panels and worker/controller structure

- T1 Qt Creator separates the pane *object* (`IOutputPane`: lifetime, `outputWidget(parent)` factory, `visibilityChanged`, `clearContents`) from the widget. Same shape as spec 5: `EvidenceController` (no widgets besides seam) builds `EvidencePanel` lazily; panel exposes signals/setters only.
- Qt `QThread` doc (Q4): two valid patterns, worker-object with `moveToThread` or subclass with `run()`. Repo uses subclass + `threading.Event` cancel (X); keep it: a pure function in `run()`, one result signal, results as immutable objects, generation token checked in the GUI slot.
- Ownership: thread has **no parent**, registry set holds it until `finished`, `finished -> deleteLater` (X pattern verified in `ui_series.py`). `closeEvent` sets cancel, `wait(timeout)`, never `terminate()`.
- Dock persistence: `setObjectName` on dock and main window is required for `saveState`; store geometry in QSettings with try/except (spec 1.1).

## 8. Testing patterns (offscreen, pytest-qt 4.5, validated 2026-10-14 via P1 and M)

- `with qtbot.waitSignal(sig, timeout=N) as b:` must wrap the *start* call; `raising=True` by default raises `qtbot.TimeoutError` (P1 signals.rst). Use `check_params_cb` for generation filtering; `qtbot.waitUntil(lambda: ...)` for state predicates (repo idiom X). Avoid `qtbot.wait(ms)` and `time.sleep`; gate fakes with `threading.Event` (repo does).
- Exceptions inside virtual methods (`data`, `paint`, `lessThan`) are captured and fail the test on PySide6 >= 6.5.2 (P1 virtual_methods.rst); a test that provokes one must opt out with `@pytest.mark.qt_no_exception_capture`.
- pytest-qt closes only widgets registered via `qtbot.addWidget` (`w.close(); w.deleteLater()` in `_close_widgets`, qtbot.py); it **does not join QThreads**. A fixture must cancel + `wait()` every worker *before* the widget is closed (the repo `window` fixture pattern). An autouse fixture should assert the live-thread registry is empty after each test and call `sendPostedEvents(None, DeferredDelete)` (item 14).
- Crash triage: SIGABRT with "QThread: Destroyed while thread is still running" (items 12). pytest's built-in faulthandler prints the Python stacks; `PYTHONFAULTHANDLER=1` in CI (pytest-qt troubleshooting recommends it). A missing display aborts Qt immediately; use `QT_QPA_PLATFORM=offscreen`.
- Deterministic perf tests: count `data()` calls with a counting subclass and assert call ceilings (stable across machines) plus generous (5x) wall-clock bounds; measure `layoutChanged`/reset by `time.perf_counter` around `processEvents`.
- Accessibility enumeration: use `QAccessible.queryAccessibleInterface(widget)` and walk `child(i)`; assert `text(QAccessible.Name)`; does not need `isActive()`.

## 9. Corrections the spec needs (summary; details in the plan step S0)

1. 5.1/9.1: replace `EvidenceFilterProxy` sort path with model-owned sort/filter (items 2-5); keep a proxy only if the plan's D-A fallback is chosen.
2. 5.3.6: threads are NOT parented to the panel; registry + join (item 12).
3. 1.8: status label accessible-name rule (item 18); add 1.4.11 3:1 requirement; hide vertical header or give row-header names.
4. 1.7: row height via `defaultSectionSize`, not per-row sizeHint (item 9).
5. 9.1: sort <= 150 ms and filter <= 100 ms hold only for the model-owned design; add data()-call ceiling.
6. 11/F6: remove "accepted in Ghidra"; add ghidriff diff-ratio labelling rule; quote Ghidra's non-comparability sentence.
7. 7.3: tooltip escaping is a requirement (item 15), with a test using `Qt.mightBeRichText`.
