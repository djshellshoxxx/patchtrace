# SPEC-28: Multi-engine evidence panel (Phase C, step C6)

Status: developer-ready design, 2026-10-14; implemented in C6 with the deviations recorded in section 15; Phase D track G adds the BinDiff + BinExport setup and run flow inside the Engines tab (section 16, built 2026-10-14) (measured research `docs/research/phase-c/multi-engine-evidence-ui.md`, plan `docs/plans/hard-problems/evidence-panel-plan.md`). Implements plan item C6 of `docs/plans/phase-c-multi-engine-plan.md`. Relates to SPEC-04 (desktop), SPEC-10/11 (secondary engines), SPEC-26 A (tooltips), SPEC-27 (fusion, calibration). Contract changes: none to persisted data; one additive read helper (section 4.4). Read-only over stored reconciliation; engine runs go through the C1 scheduler.

## 0. Non-negotiable presentation rules

1. Native scores are shown per engine, in the engine's own units, in separate columns. They are NEVER summed, averaged, ranked against each other, colour-scaled on a shared axis, or merged into one number. No "overall", "combined" or "consensus" figure exists.
2. No probability, percentage-of-confidence or "likelihood" wording anywhere. The SPEC-27 `evidence_index` (0..83, placeholder constants) is NOT shown by default and never as a percent. Default UI shows only the four verdict badges (3.3); the `high/moderate/low` tier is not displayed (strength words like "strong/weak" are forbidden). The index is shown only inside the detail pane as `Triage index 55 (uncalibrated, ordering aid only)` (no denominator: '55 of 83' reads like a percentage; research flag F2) behind a "Show triage index" checkbox, default OFF, remembered per user. Decision D1 below.
3. No vulnerability claims: the panel concerns whether two functions are the same function across builds, never whether a fix, bug, exploit or security impact exists. Banned strings (enforced by a test over every user-visible string produced by the view-model): `probab`, `likelihood`, `confidence %`, `vulnerab`, `exploit`, `safe`, `secure`, `fixed`, `verified`, `proven`, `certain`, `%` adjacent to a score label.
4. Missing is not negative: `absent` and `not-comparable` render as "no record" / "not comparable", never as red, never as a "No" vote.
5. Contested wins: any disagreement yields `contested` regardless of how many engines agree.
6. Every string that originates in a tool output, a file, a function name, a stderr tail or a path is untrusted: rendered as plain text only (see 7.4).
7. Colour is never the only carrier: every badge has a text label and a distinct glyph/shape.

## 1. UX specification

### 1.1 Placement
A `QDockWidget` titled "Engine evidence" (object name `evidence_dock`), default area Bottom, tabified with the existing diagnostics area is NOT used; it docks to the right of the workspace splitter as a floating-capable dock, `AllDockWidgetFeatures`, hidden by default until a project is open. Toggled by `View > Engine evidence` (checkable action `evidence_action`, shortcut `Ctrl+Shift+E`) and a toolbar-less status-bar button is not added. Dock minimum size 520x260 logical px; when floated it may be resized freely; dock geometry persists in `QSettings` key `evidence/geometry` (bytes, validated; ignore on failure). The dock never steals focus when shown by a data update.

Inside the dock, a `QTabWidget` (`evidence_tabs`) with two tabs:
- Tab "Evidence" (default): toolbar row, summary strip, match table, detail pane (vertical `QSplitter`).
- Tab "Engines": per-engine run status, launch/cancel (section 6).

### 1.2 Wireframe: Evidence tab (state READY, 3 engines, typical widths 900 px)

```
+- Engine evidence ----------------------------------------------------------[float][x]-+
| [Evidence] [Engines]                                                                  |
| Filter: [ all v ] verdict   [ search name/address...      ]  [x] Hide agreed  [Copy]  |
| Engines: Ghidriff (baseline) | BinDiff 8.0 (imported) | rz-diff 0.9.1 (run 14:02)     |
| Summary: 5,214 matches - 4,801 agree - 37 contested - 212 single-engine - 164 unknown |
| ------------------------------------------------------------------------------------ |
| Match / function     | Verdict            | Ghidriff        | BinDiff         | rz-diff |
|                      |                    | match type      | sim / algorithm | byte sim|
| ---------------------+--------------------+-----------------+-----------------+--------
| ParseHeader          | [=] Agree          | Exact           | sim 0.97 algo name hash | byte sim 0.88 |
| 0x1400A1F00>0x1400A2010                  |                 |                 |         |
| ValidateBuf          | [!] Contested      | Instruction     | pairs elsewhere | no rec. |
| 0x140011000>0x140011300 (2 alternatives)  |                 |                 |         |
| InitTable            | [1] Single engine  | Exact           | no record       | n/c     |
| FooThunk             | [?] Unknown        | n/c             | n/c             | n/c     |
| ------------------------------------------------------------------------------------ |
| Detail: ValidateBuf   (read-only, selectable)                                         |
|  Verdict: Contested - at least one engine pairs an endpoint differently. Review       |
|           identities manually. This is about function pairing only.                  |
|  Alternatives (engine pairs this endpoint with a different counterpart):              |
|    BinDiff: older 0x140011000 -> newer 0x140011B40  sim 0.82  conf 0.64  algo "..."   |
|    Ghidriff (baseline): older 0x140011000 -> newer 0x140011300                        |
|  Limitations: - BinDiff similarity/confidence are BinDiff heuristics...               |
|  Provenance: BinDiff 8 | file sha256 ab12.. | older 11.. newer 22.. | imported ...    |
|  [Copy provenance]  [Go to match in navigator]                                        |
| "Scores are engine-native and not comparable. Not calibrated. Not a vulnerability     |
|  assessment." (always visible footer)                                                 |
+---------------------------------------------------------------------------------------+
```

Column rules:
- Fixed columns: 0 Match (function name, addresses on second line via delegate, elided middle), 1 Verdict, then one column per ENGINE_COLUMNS entry in this fixed order: Ghidriff, BinDiff, rz-diff. A two-line header: engine name, then unit caption (`match type (raw)`, `similarity / algorithm`, `byte similarity (raw bytes)`; the rz-diff caption names its mode so byte and function similarity never share a column, flag F7).
- Engine columns not present for the project (engine never imported/run) are shown but each cell reads "not run" (muted); they are never hidden so the layout is stable and "absence" stays visible. `Hide columns` is not offered in v1.
- Cell text per engine (see 3.2): Ghidriff: `<match_types joined ", ">` (raw upstream strings, no numbers invented; flag F3). PatchTrace's `FunctionMatch.quality` label is not a ghidriff field: when numeric it carries ghidriff's difflib text diff ratio over decompiled code of the already paired functions, so it is shown raw in the details with the label "text diff ratio ... not a match score", never under a match-quality header. BinDiff: `sim 0.97  algo <algorithm>` using the stored `similarity_text` and algorithm name (upstream text preserved, not recomputed from milli); BinDiff's confidence is algorithm-dependent and not documented as a probability, so it appears only in tooltip/details as `confidence value <upstream text> (milli N; algorithm-dependent, not a probability)` with flags (flag F1). rz-diff: `byte sim 0.88` from `similarity_text`; tooltip repeats "raw-byte Levenshtein, not semantic". Units are always in the header AND in the cell prefix (`sim`, `algo`, `byte sim`) so a screenshot of one cell is self-describing.
- Disagreeing engines' cells read "pairs elsewhere" plus the alternative's address pair in the tooltip/detail, not in the cell (keeps the column scannable).
- Sorting: clicking a score column sorts by that ONE engine's native integer milli (rows without a value last, stable tie-break by match id). The sort indicator states the engine. Default sort: verdict priority (contested, unknown, single-engine, agree) then Ghidriff order, so contested items surface first. Sorting is performed by the proxy over view-model keys, never by displayed strings.
- Row keyboard: Up/Down, PageUp/PageDown, Home/End; Enter/Return = "Go to match" (emits `match_activated`); Ctrl+C copies the selected row's provenance text (7.5); Space toggles the detail pane focus. Tab order: filter combo, search, hide-agreed, Copy, table, detail text, Copy provenance, Go to match, Engines tab content.

### 1.3 Verdict badges
Mapping from `secondary.evidence.Verdict` (code names) to UI badges (user-visible names). The mapping lives in one pure table and is the only place that translates:

| code verdict | UI badge text | glyph | rationale / tooltip WHAT |
|---|---|---|---|
| corroborated | Agree | `=` (two bars) | Every engine that has an address-comparable record pairs the same endpoints as Ghidriff. Not proof; engines can share artifacts. |
| contested | Contested | `!` (triangle) | At least one engine pairs an endpoint differently. Needs analyst review. |
| single-engine | Single engine | `1` (one dot) | Only Ghidriff has a comparable record; absence elsewhere is not contradiction. |
| insufficient | Unknown | `?` | No engine output could be compared to this match. Not a negative vote. |

Special states not produced by `assess_reports`: with ZERO secondary engines the table is not shown (empty state E0) because `assess_reports` returns no rows; per-match verdicts are therefore never fabricated by the UI. A match whose Ghidriff side is a `manual` correction gets an extra annotation "manual correction (not engine output)" in detail; verdict still comes from the report.

The badge is a custom delegate paint (rounded rect, 1 px border, glyph + text), not a stylesheet-only colour. Palette: dark theme existing palette; badge background hues are selected for >= 4.5:1 text contrast; contested uses amber (not red: a conflict is not an error). Badge role data (`Qt.AccessibleTextRole`) is `Verdict: Contested`.

### 1.4 Detail pane
Read-only `PlainTextEdit`-style (`plain_view` equivalent; `setPlainText` only, never `setHtml`/`setMarkdown`) with fixed section headers: Verdict and reason; Per-engine native values (one block per engine, unit-labelled); Alternatives; Limitations (union of `MatchEvidence.limitations` + `ReconciliationReport.limitations` per engine, de-duplicated, order stable); Provenance. Alternatives list = `Reconciliation.secondary` entries whose endpoint pair differs from the Ghidriff pair, and (for rows with agreement) none. One-sided/secondary-only records (`ReconciliationReport.secondary_only`) are listed in a separate "Engine-only records" filter category (see 1.5) and are not part of per-match rows.

### 1.5 Filter/search
Verdict combo: All, Contested, Unknown, Single engine, Agree, "Engine-only records". Search: case-insensitive substring over function names and hex addresses (`0x` optional); debounced 150 ms; operates in the proxy model. "Hide agreed" is a convenience equal to excluding Agree. Filter state persists per user in `QSettings` (`evidence/filter`, `evidence/hide_agreed`, `evidence/show_index`), wrapped in try/except with defaults.

### 1.6 Panel states (every state has a plain-text status line `evidence_status` with role `Status`, and a stacked "state page" replacing the table)

| ID | Trigger | Text (exact, plain) | Controls |
|---|---|---|---|
| E0 no-project | no project open | "Open a project to see engine evidence." | all disabled |
| E1 no-engines | project open, zero secondary sets stored | "No secondary engine results for this project. Ghidriff is the only engine. Import a .BinDiff file or run rz-diff on the Engines tab. No cross-engine comparison is available, which is not a disagreement." | Engines tab link button |
| E2 loading | assessment being computed/loaded on worker | "Loading engine evidence..." + indeterminate bar; table cleared; Cancel not needed (computation bounded) | filters disabled |
| E3 ready | assessment present | table + detail | all enabled |
| E4 partial | some engines ready, some failed/unsupported/missing | table shown and banner: "N engine(s) did not produce results (see Engines tab). Their columns read 'not run'. Missing results are unknown, not disagreement." | |
| E5 failed | assessment failed (exception in load/assess, e.g. one-report-per-engine ValueError, inconsistent match sets) | "Engine evidence could not be assembled: <code>: <message>. The stored Ghidriff results are unchanged." + [Retry] [Copy details] | table hidden |
| E6 stale | `StaleInfo` (4.3) says the stored secondary set's older/newer SHA-256 differ from the project artifacts, the Ghidriff run id differs from the assessed run, or the project revision moved after the assessment | banner above (still shows last good table greyed): "Engine evidence is stale: <reason>. It describes a different run/artifact pair than the one on screen. Values are kept for reference only." Row activation disabled; Copy provenance still allowed and includes "STALE" | [Refresh] |
| E7 unsupported | every engine capability unsupported (no rz-diff >= 0.9.0, no bindiff, no import) and zero sets | like E1 plus per-engine reason lines from `Capability.reason` | |
| E8 too-large | rows > display cap (section 9.3 exceeded, should be impossible by lazy model; kept for failure of the cap guard) | "Too many rows to display (N). Narrow the filter." | |

State precedence when several apply: E5 > E6 (stale shown over ready) > E4 > E3; E2 only while a load is in flight and no table has been shown yet (afterwards show previous table with a "refreshing..." status text, no flicker).

### 1.7 High DPI and layout
No hard-coded pixel sizes except through `QFontMetrics`/`style().pixelMetric`; column widths from `fontMetrics().horizontalAdvance('M')*N` with N chosen per column (Match 28, Verdict 16, engine columns 18) and `Interactive` resize mode with `stretchLastSection=False`; header text elided with tooltip. Row height = `max(2*lineSpacing + 6, 28)` device-independent, applied through `verticalHeader().setDefaultSectionSize(...)` with `Fixed` sections (QTableView does not ask the delegate's per-row `sizeHint` unless rows are resized to contents, which is forbidden); the vertical header is hidden. Badge glyph and text drawn using the widget's current font and `devicePixelRatioF()`; no pixmaps (no blurry scaling). Must remain usable at 125/150/200% and at 1100x750 main window (dock floats or collapses). Text never relies on tiny fonts: minimum point size = view font (default 10pt).

### 1.8 Accessibility
- Every widget sets `setAccessibleName` and `setAccessibleDescription` (the latter automatically via `apply_tooltip`). Names (exact): dock "Engine evidence panel"; tabs "Engine evidence views"; table "Per-match engine evidence table"; filter "Filter by verdict"; search "Search matches by function name or address"; detail "Selected match engine evidence details"; copy button "Copy provenance of selected match"; goto "Go to selected match in navigator"; status label: no fixed name (see the announcement rule below; its text is its name).
- Item roles: each cell supplies `Qt.AccessibleTextRole` = "<Function name>, verdict <Agree>, Ghidriff <text>, BinDiff <text>, rz-diff <text>" for the Match column; engine cells supply "BinDiff similarity 0.97, confidence 0.91" etc. Units spoken.
- Full keyboard operation (1.2); focus visible (existing style plus 2 px focus outline in the delegate); no hover-only information (tooltips duplicate content available in the detail pane).
- Badge colour supplemented by glyph/text; the glyph is part of text for screen readers ("Contested").
- State changes announced: `evidence_status` is a `StaticText` label whose accessible name is deliberately left EMPTY: `QLabel.setText` emits `NameChanged` itself only when no fixed accessible name is set, so a fixed name ("Engine evidence status") would suppress every announcement. The spoken name is the status text. Real screen-reader announcement (WCAG 4.1.3) stays a manual Windows UIA/NVDA gate (C8).
- Non-text contrast (WCAG 1.4.11): badge borders and the 2 px focus ring need >= 3:1 against adjacent colours; the focus ring uses the theme text colour, badge fills are checked >= 4.5:1 against the badge text and >= 3:1 against the border and the dark theme background by a pure contrast-ratio test. Muted/stale cells keep the theme text colour and use italics (no low-contrast grey).

### 1.9 Copy provenance
Button/Ctrl+C copies a deterministic plain-text block (no markup, `\n` newlines, LF only), per selected match:
```
PatchTrace engine evidence (function pairing only; not a vulnerability assessment)
Project: <project id> | Ghidriff run: <run id> | STALE: no
Match: <match id> | older 0x.. <name> -> newer 0x.. <name>
Verdict: Contested (code: contested) | Triage index: hidden by default [only if enabled: 0 (uncalibrated, ordering aid only)]
Ghidriff: types=<..> quality=<..>
BinDiff <ver>: older 0x.. -> newer 0x..  similarity <similarity_text>  confidence <confidence_text>  algorithm <..>  flags <..>  [set sha256 <file_sha256>]
rz-diff <ver>: no record
Older SHA-256: <..>
Newer SHA-256: <..>
Limitations:
- <..>
Scores are engine-native, uncalibrated and not comparable across engines.
```
Strings come through `sanitize_text()` (7.4) before composition; the whole block is length-capped (16 KiB). Multi-row selection concatenates blocks separated by a blank line, capped at 200 rows with a trailing "(N more omitted)" line. Clipboard write happens on the GUI thread only; success reported in status bar ("Copied provenance for N match(es)").

## 2. Layering

```
secondary/{contracts,reconcile,evidence,scheduler}   pure, existing/C1
        v
evidence_view.py        NEW pure: typed view-model, mapping, filtering, formatting, provenance text (no Qt, no I/O)
evidence_panel_service.py NEW pure orchestration (no Qt): load sets -> reconcile -> assess -> EvidenceViewModel; staleness; run requests
        v
ui_evidence.py          NEW Qt widgets: EvidencePanel (dock content), EvidenceTableModel (owns sort/filter order), EvidenceDelegate, EngineStatusModel, EvidenceLoadThread, EngineRunThread, EngineProbeThread
        v
ui.py                   minimal seam (section 8)
```
`ui.py` receives ONLY the seam (<= ~40 lines). All new classes live in the new modules. `evidence_view.py` and `evidence_panel_service.py` must not import PySide6 (checked by the existing subprocess import-test pattern, extended: `test_evidence_view_has_no_qt`). Add both to `docs/modules.md` before implementation (rows: `evidence view (planned)`, `evidence panel service (planned)`, `evidence UI (planned)` with ownership "C6").

## 3. View-model layer (pure Python)

### 3.1 Types (`src/patchtrace/secondary/evidence_view.py`; service in `src/patchtrace/secondary/evidence_panel_service.py`)

```python
from dataclasses import dataclass
from typing import Literal

EngineId = Literal['ghidriff', 'bindiff', 'rz-diff']
ENGINE_COLUMNS: tuple[EngineId, ...] = ('ghidriff', 'bindiff', 'rz-diff')  # fixed display order
UiVerdict = Literal['agree', 'contested', 'single-engine', 'unknown']
CellKind = Literal['value', 'no-record', 'not-comparable', 'pairs-elsewhere', 'not-run', 'failed']
VERDICT_PRIORITY: dict[UiVerdict, int] = {'contested': 0, 'unknown': 1, 'single-engine': 2, 'agree': 3}
VERDICT_FROM_CODE = {'corroborated': 'agree', 'contested': 'contested',
                     'single-engine': 'single-engine', 'insufficient': 'unknown'}   # total; KeyError => bug => E5

@dataclass(frozen=True)
class EngineCell:
    engine: EngineId
    kind: CellKind
    text: str                    # display text, unit-prefixed, already sanitized
    sort_key: int | None         # that engine's OWN native milli (None for no value). Never compared across engines.
    detail: str                  # multi-line plain text for tooltip/detail (native text, milli, algorithm, flags)
    accessible: str              # spoken form with units

@dataclass(frozen=True)
class Alternative:
    engine: EngineId
    older_address: int | None
    newer_address: int | None
    older_name: str | None
    newer_name: str | None
    similarity_text: str
    confidence_text: str | None
    algorithm: str
    note: str

@dataclass(frozen=True)
class EvidenceRow:
    match_id: str
    function_label: str          # sanitized "name" (newer name else older name else 'sub_' hex), no markup
    address_label: str           # "0x.. > 0x.." with '-' for a missing side
    category: str                # FunctionMatch.category (modified/...)
    manual: bool
    verdict: UiVerdict
    verdict_text: str            # 'Agree' | 'Contested' | 'Single engine' | 'Unknown'
    reason: str                  # MatchEvidence.explanation, sanitized
    cells: tuple[EngineCell, ...]            # exactly len(ENGINE_COLUMNS), same order
    alternatives: tuple[Alternative, ...]
    supporting: tuple[EngineId, ...]
    contradicting: tuple[EngineId, ...]
    missing: tuple[EngineId, ...]
    limitations: tuple[str, ...] # de-duplicated, sanitized
    triage_index: int | None     # carried for the opt-in display only
    search_key: str              # lowercased "name 0xaddr ..." precomputed for filtering

@dataclass(frozen=True)
class EngineInfo:
    engine: EngineId
    label: str                   # "BinDiff 8.0"
    state: Literal['ready', 'not-run', 'failed', 'cancelled', 'unsupported', 'stale']
    detail: str                  # reason / stderr tail summary, sanitized
    file_sha256: str | None
    older_sha256: str | None
    newer_sha256: str | None
    limitations: tuple[str, ...]

@dataclass(frozen=True)
class EvidenceViewModel:
    project_id: str
    ghidriff_run_id: str | None
    revision: int
    state: Literal['no-project','no-engines','ready','partial','failed','stale','unsupported']
    engines: tuple[EngineInfo, ...]   # always the 3 ENGINE_COLUMNS in order
    rows: tuple[EvidenceRow, ...]     # already in default order; may be a lazy sequence (9.2)
    engine_only: tuple[Alternative, ...]  # ReconciliationReport.secondary_only, flattened, bounded
    counts: dict[UiVerdict, int]
    warnings: tuple[str, ...]         # EvidenceAssessment.warnings + report limitations header
    stale_reason: str | None
    error: str | None
    older_sha256: str
    newer_sha256: str
```

Rows are plain frozen dataclasses (slots). For 10k matches the model keeps `rows` as a `tuple` of frozen objects (about 2-4 MB); cells' `detail` strings are produced lazily (see 9.2: `EngineCell.detail` is built on first access via `functools.cached_property` on a non-frozen-slots variant, or stored as a small tuple of raw fields and formatted by `format_cell_detail` at tooltip time; implementer picks the latter: store `raw: SecondaryMatch | None` reference and format on demand).

### 3.2 Mapping pseudocode

```python
def build_view_model(project, ghidriff_matches, sets, outcomes, entries_meta, revision) -> EvidenceViewModel:
    # sets: tuple[SecondaryMatchSet] (one per engine, newest non-stale per C5; if duplicates remain,
    #       pick newest by Entry order and add a warning; NEVER let reconcile/assess raise on duplicates)
    if not sets:
        state = 'unsupported' if all_unsupported(outcomes) else 'no-engines'
        return empty_model(state, engines=engine_infos(sets, outcomes))
    reports = tuple(reconcile(ghidriff_matches, s) for s in sets)      # secondary/reconcile.py
    try:
        assessment = assess_reports(reports)                            # secondary/evidence.py
    except ValueError as exc:                                           # e.g. inconsistent id sets
        return failed_model(sanitize(str(exc)))
    by_engine = {r.engine: r for r in reports}
    match_by_id = {m.id: m for m in ghidriff_matches}
    rows = []
    for ev in assessment.rows:                                          # MatchEvidence, sorted by match_id
        m = match_by_id[ev.match_id]
        cells = []
        for engine in ENGINE_COLUMNS:
            if engine == 'ghidriff':
                cells.append(ghidriff_cell(m))                          # types/quality strings only
            elif engine not in by_engine:
                cells.append(EngineCell(engine, 'not-run', 'not run', None, ..., ...))
            else:
                rec = next(r for r in by_engine[engine].rows if r.match_id == ev.match_id)
                cells.append(secondary_cell(engine, rec, ghidriff_pair=(rec.older_address, rec.newer_address)))
        alts = tuple(alternative(engine, sm) for engine in by_engine
                     for sm in by_engine[engine].rows_for(ev.match_id).secondary
                     if (sm.older_address, sm.newer_address) != (rec.older_address, rec.newer_address))
        rows.append(EvidenceRow(..., verdict=VERDICT_FROM_CODE[ev.verdict], ...))
    rows.sort(key=lambda r: (VERDICT_PRIORITY[r.verdict], ghidriff_order[r.match_id]))
    state = 'partial' if any(i.state in ('failed','cancelled','unsupported') for i in infos) else 'ready'
    return EvidenceViewModel(..., state=stale_state_override(state, stale))
```
`secondary_cell(engine, rec, ...)` by `rec.status`:
- `agreement` -> kind `value`, text from the single candidate: bindiff `f'sim {similarity_text}  conf {confidence_text}'`; rz-diff `f'byte sim {similarity_text}'`; sort_key = that record's `similarity_milli`.
- `disagreement` -> kind `pairs-elsewhere`, text "pairs elsewhere", sort_key = the first candidate's similarity_milli (still that engine's own units), detail lists all candidates.
- `absent` -> `no-record`, text "no record". `not-comparable` -> `not-comparable`, text "n/c" with tooltip "many-to-many or unparsable address".
- Engine state `failed/cancelled/unsupported` (from outcomes, no set) -> kind `failed`, text "failed" / "cancelled" / "unsupported", not a vote.
Candidate ordering within a cell: by `(older_address, newer_address)` then similarity_milli desc, deterministic.
Ghidriff cell: `types = ', '.join(sanitize(t) for t in m.match_types[:3]) or 'unknown'`; text `f'{types} / {sanitize(m.quality)}'`; sort_key None (Ghidriff exposes no numeric score here; do not synthesize one; Ghidriff column sorts alphabetically by text).

Formatting functions are pure and tested by table-driven tests: `format_ghidriff_cell`, `format_bindiff_cell`, `format_rzdiff_cell`, `format_alternative`, `format_provenance_block`, `sanitize_text`.

### 3.3 Registry-facing labels (single source, imported by `ui_evidence`)
`VERDICT_LABELS = {'agree': 'Agree', 'contested': 'Contested', 'single-engine': 'Single engine', 'unknown': 'Unknown'}`; `STATE_TEXT` (exact strings of 1.6). Strings are constants in `evidence_view.py`, not scattered in widgets.

### 3.4 Filtering (pure)
`filter_rows(rows, verdicts: frozenset[UiVerdict], search: str, hide_agree: bool) -> Sequence[int]` returns indices (not copies) so the Qt proxy stays cheap. Search normalises: strip, lower, optional leading `0x`; matches `row.search_key` substring.

## 4. Service layer (pure, `evidence_panel_service.py`)

### 4.1 Interface
```python
@dataclass(frozen=True)
class EvidenceRequest:
    project_id: str; run_id: str; revision: int
    older_sha256: str; newer_sha256: str
    matches: tuple[FunctionMatch, ...]          # snapshot copies; worker must not touch live service objects
    sets: tuple[tuple[Entry, SecondaryMatchSet], ...]   # from load_secondary(store, guard) done on the GUI thread or a store-owning thread
    outcomes: tuple[EngineOutcomeView, ...]     # last EngineOutcome per engine from this session (C1), possibly empty

def load_evidence(request: EvidenceRequest, cancel: Callable[[], bool]) -> EvidenceViewModel: ...
def detect_stale(request, current_revision, current_run_id, current_pair) -> str | None: ...
```
SQLite connections are thread-confined (docs/modules.md persistence). Therefore: the GUI thread (service owner) reads `matches` and `load_secondary(...)` and builds the immutable `EvidenceRequest`; the worker only runs the pure `load_evidence`. The worker never receives the service, store or any widget. For 10k matches the snapshot is a tuple of existing pydantic objects (no deep copy; they are frozen-by-convention records read-only in the worker).

### 4.2 Duplicate handling (depends on C5)
Until C5 lands, `load_evidence` keeps the newest set per engine by `Entry` publication order and appends warning "Multiple stored sets for <engine>; showing the newest." C6 must not be merged before C5 per plan order, but this guard makes the panel crash-free regardless.

### 4.3 Staleness
Stale reasons (first match wins, text exact): "secondary results were produced for a different older/newer artifact pair" (set SHA-256s != project artifact hashes), "the Ghidriff run changed after these results were computed" (request.run_id != current), "the project changed after these results were loaded" (revision mismatch). Evaluated on the GUI thread on `project_changed`; produces E6 without re-running.

### 4.4 Additive helper
A read-only `secondary.store.sets_for_project(store, guard)` wrapper around `load_secondary` is optional; do NOT change persisted schema. If scheduler outcomes are session-only, they are not persisted; after restart, engine rows show "ready (stored)" or "not run" based on sets only.

## 5. Qt adapter (`src/patchtrace/ui_evidence.py`)

### 5.1 Classes and responsibilities
- `EvidenceTableModel(QAbstractTableModel)`: holds `EvidenceViewModel.rows` (tuple) and column definitions (2 + len(ENGINE_COLUMNS)); `data()` for `DisplayRole` (cheap: precomputed strings), `ToolTipRole` (calls `format_cell_detail` lazily; escaped via `tooltips.clean_value`/plain registry template), `AccessibleTextRole`, `UserRole` (row object), `UserRole+1` (sort key). `rowCount` is O(1). `set_view_model` uses `beginResetModel/endResetModel` once per data load. `canFetchMore/fetchMore` NOT used (rows are in memory; the view is virtualised by Qt).
- ~~`EvidenceFilterProxy(QSortFilterProxyModel)`~~ REPLACED (measured, PySide6 6.12 offscreen): a proxy sort calls `data()` per comparison (10k rows 1.6-2.3 s, 100k 20-30 s) and a sorted proxy re-sorts on every source reset even with `setDynamicSortFilter(False)`. `EvidenceTableModel` owns the order instead: `view: list[int]` indices into the immutable rows; filtering rebuilds the list from `filter_rows` with one reset; sorting is the model's `sort(column, order)` override over precomputed keys (stable on top of the default order, persistent indexes moved with `changePersistentIndexList`), driven by a header `sectionClicked` slot. No `lessThan`, no proxy, no `ResizeToContents` (grep test).
- `VerdictBadgeDelegate(QStyledItemDelegate)`: paints badge (glyph + text) and the two-line Match cell (`sizeHint` from `QFontMetrics`); never uses rich text; `helpEvent` provides the tooltip from the model's ToolTipRole.
- `EngineCellDelegate` (optional): muted style for `not-run/no-record/not-comparable`, amber outline for `pairs-elsewhere`.
- `EngineStatusModel(QAbstractTableModel)`: columns Engine / State / Version / Detail / Input hashes for the Engines tab; ≤ 3 rows.
- `EvidencePanel(QWidget)`: dock content; owns models/proxy, state pages (`QStackedWidget`), detail pane, buttons. Public API: `set_project(project_view)` , `set_view_model(vm)`, `set_loading(bool)`, `set_failed(msg)`, `set_stale(reason)`, `select_match(match_id) -> bool`, signals below. Contains NO project/service/provider/scheduler logic.
- `EvidenceLoadThread(QThread)`: runs `load_evidence(request, cancel)`; emits `model_ready(object)` / `load_failed(str)`; `cancel: threading.Event` as in `InspectionThread`.
- `EngineRunThread(QThread)`: wraps the C1 scheduler (section 6).
- `EvidenceDock(QDockWidget)`: thin; created by `create_evidence_dock(parent) -> EvidenceDock`.

### 5.2 Signals (all `Qt.QueuedConnection` across threads; payloads are immutable objects or str)
EvidencePanel (outgoing, handled by the MainWindow seam): `match_activated(str match_id)`, `refresh_requested()`, `run_requested(object RunRequest)`, `cancel_requested()`, `import_bindiff_requested()`, `status_message(str)`.
EvidenceLoadThread: `model_ready(object)`, `load_failed(str)`.
EngineRunThread: `engine_started(str engine)`, `engine_progress(str engine, int done, int total)` (total 0 = indeterminate), `engine_log(str engine, str line)` (bounded), `engine_finished(object EngineOutcomeView)`, `all_finished(object tuple[EngineOutcomeView, ...])`, `run_failed(str)`.
Slots on the panel/main thread apply results via `panel.set_view_model` etc.; each slot first checks a monotonically increasing `generation` int captured at launch; stale generations are dropped (and `result.close()`-style cleanup if any).

### 5.3 Thread rules
1. Workers (`QThread.run`) never import, create, read or touch a QWidget/QObject-with-widgets/`QClipboard`/`QSettings`-backed widget state; they receive immutable request objects and emit signals only.
2. Workers never touch `ProjectService`, `ProjectStore` or a SQLite connection (thread-confined). Persisting an engine's `SecondaryMatchSet` (`publish_secondary`) happens on the GUI thread in the `engine_finished` slot, after validating guard/revision (the existing import pattern); a worker only returns the validated `SecondaryMatchSet` plus `EngineOutcomeView`.
3. Cancellation: `threading.Event`; `cancel_requested` sets it; the scheduler fans it to children (process-tree kill via `jobs.run_process`). Closing the window or switching project sets cancel and `wait(5000)`; if still running the thread is kept referenced until `finished` (no `terminate()`).
4. One load thread and one run thread at a time per panel; starting a new load while one runs sets the old cancel event and uses generations to drop its result.
5. Model mutations only on the GUI thread; `set_view_model` is called from the slot only.
6. Threads have NO Qt parent (corrected: destroying a running `QThread`, whether by a deleted parent or by garbage collection of an unreferenced started thread, aborts the process with SIGABRT). Every started worker is held in the module registry `ui_evidence._LIVE_THREADS` until `finished`, then `deleteLater` (pattern of `ui_series.py`); `EvidenceController.shutdown()` (called from `MainWindow.closeEvent`) sets every cancel event and `wait()`s every worker; no `terminate()`. Hiding the dock does not stop a running engine run.

## 6. Engine-run launch UI (Engines tab)

### 6.1 Wireframe

```
+- Engines -------------------------------------------------------------------------+
| Engine      | State        | Version | Detail                          | Action     |
| Ghidriff    | baseline     | 11.3    | Primary result in the project   | -          |
| BinDiff     | imported     | 8.0     | file ab12.. (imported 10-14)    | [Import..] |
| rz-diff     | failed       | 0.9.1   | PT-SECONDARY-RUN: exit 1 ...    | [Run]      |
| [x] BinDiff (not run)  [x] rz-diff   Parallel engines: [1 v]  Timeout: [1800] s     |
| [ Run selected engines ]  [ Cancel ]   ======== rz-diff running 0:42 (indeterminate) |
| Log (selected engine, last 200 lines, plain text)                                    |
| ... "Runs read both stored artifact copies as data; nothing is executed."            |
+--------------------------------------------------------------------------------------+
```
- Engine list rows: state in {baseline, ready (stored), not run, queued, running, failed, cancelled, unsupported, stale}. Stored state text includes engine version and short set hash (12 hex chars, full in tooltip).
- Launch controls: per-engine checkbox (only engines with a successful capability probe are enabled; unsupported ones show `Capability.reason` in Detail), `Run selected engines`, `Cancel`. "Parallel engines" spin 1..2, default 1 (plan C1 default; opt-in 2); timeout spin 60..86,400 s, default 1800 (SPEC-11). BinDiff: only "Import .BinDiff..." until C4 lands; the Run button for BinDiff is hidden, not disabled-with-lie. A "Probe engines" button re-runs capability probes on a worker.
- Run is disabled when: no project, a Ghidriff analysis job is active (`MainWindow.worker` running), an engine run is active, the project is stale (E6), or no engine selected. Reason in tooltip Availability.
- A confirm dialog is NOT required (local, no network, read-only on artifact copies) but a one-line preview label shows: "Will run: rz-diff 0.9.1 on older/newer artifact copies (SHA-256 abcd.., 1234..). Timeout 1800 s." Never shows argv built from untrusted text; argv is displayed only from the verified builder.
- Progress: per-engine row state "running" with elapsed time (a 1 s `QTimer` on the GUI thread, same approach as `MainWindow.timer`), overall `QProgressBar` indeterminate (engines give no counts). On finish: `engine_finished` updates that row immediately; one engine failing does NOT clear another's result (C1 guarantee) and does not fail the run as a whole: status line "rz-diff failed (PT-SECONDARY-RUN). BinDiff result kept."
- Failure display per engine: State "failed", Detail = `error code + first line of message` (sanitized, <= 200 chars), full stderr tail (<= 2 MiB per SPEC-11, shown clipped to last 200 lines) in the log pane under that engine; [Copy details] copies error code, version, input SHA-256s, timing, stderr tail; no auto-retry. Cancel -> state "cancelled" with no partial results stored.
- Success path: GUI-thread slot persists via `publish_secondary` (guard/revision checked; on guard mismatch show E6 and discard) then triggers a new `EvidenceLoadThread`.
- Unsupported path: `Capability(supported=False)` -> state "unsupported", Detail = reason incl. observed version; no run offered.
- Project close / switch / app close during a run: cancel then wait; if it finishes after switch, `generation` mismatch drops the result (never stored into the wrong project).
- All launched work uses the C1 scheduler API: `Scheduler(max_parallel, per_engine_timeout).run(requests, cancel, on_event) -> tuple[EngineOutcome, ...]`. This spec assumes the C1 shape from the plan (`EngineOutcome`: ok / failed / cancelled / unsupported, with `engine`, `status`, `match_set | None`, `error_code`, `message`, `started`, `finished`, `stderr_tail`). If C1 differs, only `evidence_panel_service.EngineOutcomeView` adapts; widgets do not change.

### 6.2 RunRequest (pure)
```python
@dataclass(frozen=True)
class RunRequest:
    project_id: str; revision: int; generation: int
    engines: tuple[EngineId, ...]; max_parallel: int; timeout_s: int
    older_path: Path; newer_path: Path        # verified artifact copy paths resolved on the GUI thread
    older_sha256: str; newer_sha256: str
    capabilities: dict[EngineId, Capability]
```

## 7. Tooltips, text safety

### 7.1 New static registry IDs (add to `tooltips.REGISTRY`; each WHAT/WHY/EFFECT unique; no `<` or `>`; SOURCE and Availability where relevant)
| ID | WHAT (summary) | Availability |
|---|---|---|
| `evidence.dock` | Panel comparing function-pairing evidence from several diff engines. WHY: shows where engines agree or conflict. SOURCE: stored Ghidriff results plus imported/run secondary engine results; uncalibrated. | Needs a project |
| `evidence.action` | Show or hide the engine evidence panel (menu action) | |
| `evidence.tabs` | Switch between evidence table and engine run controls | |
| `evidence.filter` | Show only matches with a chosen verdict | Needs evidence |
| `evidence.search` | Find matches by function name or address | Needs evidence |
| `evidence.hide_agreed` | Hide matches where all comparable engines agree | |
| `evidence.show_index` | Also show the uncalibrated triage index in details. SOURCE: SPEC-27 placeholder constants; ordering aid only, not a probability. | |
| `evidence.table` | Per-match list. Each engine column is that engine's own measure; they are never combined | Needs evidence |
| `evidence.detail` | Read-only details of selected match | Needs selection |
| `evidence.copy` | Copy provenance of selected match(es) to clipboard | Needs selection |
| `evidence.goto` | Select the same match in the navigator | Needs selection |
| `evidence.refresh` | Reload evidence from stored results | |
| `evidence.retry` | Retry assembling evidence after a failure | Shown after failure |
| `evidence.import_bindiff` | Import a .BinDiff file for this pair (reuses existing import validation) | Needs a project, idle |
| `evidence.engine_table` | State of each engine for this project | |
| `evidence.engine_check` | Include this engine in the next run | Needs probe success |
| `evidence.parallel` | How many engines may run at once (1 or 2) | |
| `evidence.timeout` | Wall-clock limit per engine run, 60 to 86400 seconds | |
| `evidence.probe` | Check which engines are installed and supported; runs nothing on the binaries | |
| `evidence.run` | Run selected engines on the stored artifact copies. SOURCE: external user-installed tools; nothing is executed from the binaries, nothing is uploaded | Needs idle project and a supported engine |
| `evidence.cancel` | Stop running engines; partial output is discarded | Needs a running engine job |
| `evidence.engine_log` | Last lines of the selected engine's output (plain text) | |
| `evidence.copy_details` | Copy the selected engine's failure details | Needs a failed or cancelled engine |
| `evidence.stale_banner` | Explains that evidence describes a different artifact pair, run or revision | |

Dynamic TEMPLATES (values passed through `clean_value`, escaped by `_rich`): `evidence.row` (WHAT: "Engine evidence for {function}.", WHY: "Review {verdict} and per-engine native values.", EFFECT: "Read-only.", SOURCE: "Engines: {engines}.", Availability: "{reason}."), `evidence.cell` (WHAT: "{engine} native value {value} in {unit}.", WHY: "Different engines use different scales and are never combined.", EFFECT: "Read-only.", SOURCE: "{provenance}.", Availability: "{reason}."), `evidence.badge` (WHAT: "{verdict}: {meaning}", ...). Note: templates format with `str.format`; UNTRUSTED text appears only as values, never inside the template string.

### 7.2 Tests that must still pass (with required adjustments)
- `test_registry_entries_render_and_are_unique`: the count assertion stays valid; every new entry needs unique What and unique rendered text (do not reuse generic phrases such as "Read-only text"), `What:` first line, no `<`/`>` in static AND template text (the registry uses `{placeholders}` only).
- `test_main_window_every_action_and_control_has_a_registry_tooltip` (audit of `controls(window)`/`actions(window)`): the dock and its children are reachable from `window`, so every interactive control, tab bar, table header-free widget and action in the panel must carry a registry tooltip, including `evidence_action`. Implementation applies tooltips with `apply_tooltips` in `EvidencePanel.__init__`; the dock itself is a container (internal widgets must follow `internal()` exemptions; verify those rules in the test helper first, then set object names to the IDs).
- `test_every_registry_id_is_applied_somewhere`: appends a roots list; C6 PR MUST add `window.evidence_dock` (with the Engines tab built) to `roots`, plus the failure-only controls (`evidence.retry`, `evidence.copy_details`) created in a state-forced panel. Controls shown only in some states (retry, copy_details, stale banner) are always CONSTRUCTED (hidden, not lazily created) so enumeration finds them; hidden widgets are acceptable to `controls()` (confirm the helper does not filter on visibility; if it does, the test constructs the panel in each state).
- `test_disabled_controls_keep_tooltip_and_state_prerequisite`: add a case: with no project, `evidence.run`, `evidence.copy`, `evidence.goto` are disabled and tooltips contain `Availability:`.
- Add `test_evidence_ids_prefix_complete`: every ID starting `evidence.` appears in the registry/templates and every widget with objectName `evidence.*` is in the registry (no orphan).

### 7.3 Delegate/item tooltips
Item tooltips use `tooltips.template('evidence.row'|'evidence.cell', ...)` (escaped) exactly like `ui_inspection.fill_pe_table`. No `setToolTip(untrusted)`. Escaping is a tested requirement, not a convenience: the tooltip widget (`QTipLabel`) auto-detects rich text, so `<b>x</b>` in a raw tool string would render; a test asserts that, after removing the registry's own `<p>`/`<br>` wrapper, no tooltip of any cell contains `<` or `>` for hostile names.

### 7.4 Untrusted text policy (`sanitize_text` in `evidence_view.py`)
`sanitize_text(value, limit=200)`: coerce to str, strip C0/C1 controls, bidi overrides (U+202A..E, U+2066..9, U+200E/F), U+2028/9, NUL; collapse nothing else; truncate with an ellipsis; never HTML-escape here (Qt text roles and `QPlainTextEdit.setPlainText` do not interpret markup; escaping would show `&lt;` to users). Rules: all `DisplayRole` and detail text are plain; widgets set `setTextFormat(Qt.PlainText)` (use existing `PlainLabel`), `QPlainTextEdit` only; item delegates draw with `painter.drawText`, never `QTextDocument.setHtml`; tooltips pass through `clean_value` and `_rich` (escape). Function names that look like `<b>x</b>`, `{0}`, `%s`, `file:///`, or URLs must display literally and not become links.

### 7.5 Clipboard
Only `QGuiApplication.clipboard().setText(plain)` on the GUI thread, content from `format_provenance_block`.

## 8. MainWindow integration seam (the ONLY edits to ui.py)

1. Import: `from .ui_evidence import EvidenceController` (one line).
2. In `MainWindow.__init__` after `_build_workspace()`: `self.evidence = EvidenceController(self)` (stores no state in MainWindow beyond this attribute).
3. `_build_actions`: one `View > Engine evidence` action created by `self.evidence.action` (the controller builds the QAction with `apply_tooltip(action, 'evidence.action')`), added to the existing View menu / ACTION_TIPS untouched.
4. Project lifecycle hooks (existing methods call one-liners): after a project is set/cleared -> `self.evidence.project_changed()`; after Ghidriff import/run completes or a correction/review changes matches -> `self.evidence.matches_changed()`; on close -> `self.evidence.shutdown()`.
5. Navigator link: `EvidenceController.match_activated` connected to an existing `MainWindow` method that selects a match by id; if none exists, add `select_match_by_id(match_id)` (<= 10 lines) that reuses the navigator's existing selection code. Reverse link (navigator selection -> panel highlight) via `self.evidence.select_match(match_id)` guarded by `self._updating` to avoid loops.

`EvidenceController(window)` lives in `ui_evidence.py`; it holds the panel, dock, load/run threads, the generation counter, and reads project data via a narrow protocol (`ProjectPort`: `project_id`, `revision`, `run_id`, `matches()`, `artifact_hashes()`, `artifact_paths()`, `load_secondary()`, `publish_secondary(set)`, `busy()`) implemented by a small adapter class in `ui_evidence.py` over `window.service`. This keeps the seam about 25-40 lines in `ui.py`, with no evidence logic. Integration owner for `ui.py` is the C6 PR author alone (plan: single owner).

## 9. Performance bounds
1. Target: 10,000 matches, 3 engines: load+assess+build view-model <= 1.5 s on a CI runner (off the GUI thread); first paint of table <= 200 ms after `model_ready`; filter/search change <= 100 ms; sort change <= 150 ms; scrolling 60 fps (cells are precomputed strings; no per-paint formatting beyond elision). These hold only with the model-owned order of 5.1 (a proxy cannot meet them). Deterministic gate: `data()` calls for first paint, a sort and a filter change are each <= 7 x visible cells x 1.2 (+20) and independent of the row count, asserted at 10k and 100k rows; wall-clock bounds carry 5x slack.
2. Lazy: rows are prebuilt with short strings; verbose `detail`/`provenance`/tooltip text is generated on demand from `raw` references (`format_cell_detail`, `format_provenance_block`); alternatives lists built only for rows with non-agreeing candidates. Memory budget <= 64 MiB for 10k rows.
3. Hard caps (constants): display rows 100,000 (above: E8), alternatives per row 20 (then "+N more"), cell detail chars 2,000, log lines 200, clipboard 16 KiB, search key 512 chars per row. `Reconciliation` is O(n) via the existing address maps; the view-model builder must not do O(n^2) `next(row for row in report.rows if match_id)` lookups: index `report.rows` by `match_id` once per engine (dict) — the pseudocode above shows the semantic, the implementation must use the dict.
4. `assess_reports` itself does a `next(...)` per match per report (quadratic); if the 10k benchmark fails, C6 PR 1 may refactor `evidence.assess_reports` to pre-index rows (behaviour-preserving, covered by existing `test_secondary_evidence.py`). Flag to the owner of `secondary/*`.
5. A `tests/test_evidence_perf.py` benchmark (marked, not run by default in the full gate; generous 5x wall-clock thresholds) asserts bounds with synthetic 10k matches.

## 10. Test plan

### 10.1 Pure tests (no Qt) `tests/test_evidence_view.py`, `tests/test_evidence_panel_service.py`
- `test_verdict_map_is_total_and_ui_names_exact` (all 4 codes; labels exact).
- `test_cells_never_combine_scores` (property: for a row with BinDiff 0.97/0.91 and rz 0.88, no cell text contains a value derived from more than one engine; no row/view-model field named like `combined`, `average`, `overall`; asserts `sort_key`s independent by engine).
- `test_units_in_every_score_cell` (`sim`, `conf`, `byte sim` prefixes; Ghidriff `types / quality`).
- `test_absent_and_not_comparable_are_not_negative` (cell kind/wording `no record`, `n/c`; verdict single-engine/unknown).
- `test_contested_has_alternatives_and_wins_over_majority` (2 engines agree, 1 disagrees -> contested with alternative listed).
- `test_secondary_only_records_listed_separately`.
- `test_banned_strings_never_appear` (iterate all user-visible strings over a fixture covering all states).
- `test_index_hidden_by_default_and_never_percent`.
- `test_sanitize_text_strips_controls_bidi_and_truncates`.
- `test_provenance_block_is_deterministic_plain_text_and_capped`.
- `test_filter_rows_verdict_search_hide_agree_hex_with_and_without_0x`.
- `test_state_resolution_precedence` (E5 > E6 > E4 > E3; no-engines; unsupported).
- `test_stale_reasons_each` (artifact hash mismatch, run id change, revision change).
- `test_duplicate_sets_do_not_crash_and_warn`.
- `test_inconsistent_match_sets_yield_failed_model_not_exception`.
- `test_evidence_view_has_no_qt` (subprocess import, blocks PySide6; also `evidence_panel_service`).

### 10.2 Offscreen Qt tests `tests/test_evidence_ui.py` (file renamed to stay inside the C6 `tests/test_evidence_*.py` ownership) (`QT_QPA_PLATFORM=offscreen`, pytest-qt; build the panel standalone for speed and also one via `MainWindow`)
Named per state:
- `test_state_no_project_disables_everything` (E0)
- `test_state_no_engines_shows_ghidriff_only_message` (E1; exact text; engines tab link enabled)
- `test_state_loading_shows_indeterminate_and_clears_table` (E2)
- `test_state_ready_three_engines_columns_headers_and_units` (E3; header texts include units; engine columns order)
- `test_state_one_engine_other_columns_read_not_run` (BinDiff only; rz-diff cells "not run")
- `test_state_contested_row_badge_text_glyph_and_alternatives_in_detail`
- `test_state_partial_failed_engine_banner_and_other_columns_intact` (E4)
- `test_state_failed_assembly_shows_error_and_retry` (E5; Retry emits `refresh_requested`)
- `test_state_stale_banner_greys_rows_disables_goto_keeps_copy` (E6)
- `test_state_unsupported_lists_reasons_and_offers_no_run` (E7)
- `test_state_too_large_guard` (E8)
- `test_untrusted_function_name_is_plain_text`: names `<b>pwn</b>`, `<img src=x onerror=1>`, `&lt;`, `{0}`, `%s`, `\x1b[31m`, RLO `\u202e`, `file:///C:/x`; assert `data(DisplayRole)` literal (after control stripping), detail `toPlainText()` literal, `detail.toHtml()` is not used, the label `textFormat() == PlainText`, tooltips escaped (no raw `<b>`), no anchors/links in the document.
- `test_untrusted_engine_error_and_stderr_rendered_plain` (stderr with markup, 5 MB truncated to 200 lines; no hang).
- `test_keyboard_navigation_and_enter_emits_match_activated`; `test_ctrl_c_copies_provenance_to_clipboard` (clipboard text equals `format_provenance_block`); `test_copy_button_multi_selection_caps`.
- `test_accessible_names_and_descriptions_present` (every interactive child has non-empty accessibleName; table cell `AccessibleTextRole` contains unit words).
- `test_sorting_by_engine_column_uses_that_engines_native_value` and `test_default_order_contested_first`.
- `test_filter_and_search_and_hide_agreed_update_row_count`; settings persist/restore with a corrupted QSettings value falling back to defaults.
- `test_highdpi_row_height_scales_with_font` (set `QFont` pointSize 14, assert sizeHint grows; no fixed pixel constants).
- Thread tests with a fake scheduler injected into `EngineRunThread`: `test_run_success_stores_set_on_gui_thread_and_refreshes` (assert `publish_secondary` is called with `QThread.currentThread() is app thread`), `test_run_one_engine_fails_other_result_kept`, `test_cancel_discards_and_marks_cancelled`, `test_project_switch_during_run_drops_result` (generation), `test_run_disabled_while_ghidriff_job_active`, `test_close_window_cancels_and_waits`, `test_worker_never_touches_widgets` (worker callables run with a sentinel that raises if a `QWidget` is constructed; use `QApplication.instance().thread()` comparisons).
- Tooltip suite changes of 7.2 (`tests/test_tooltips.py`) and `test_evidence_ids_prefix_complete`.
- Seam test: `test_mainwindow_seam_is_minimal` (grep-style: `ui.py` contains no `EvidenceTableModel`/`VerdictBadgeDelegate`; `ui.py` line growth <= 60 vs recorded baseline constant).
- Frozen-EXE smoke of the dock is in C8; not here.

## 11. What NOT to claim (UI text, exports, docs)
Ghidra's own Version Tracking help states the rule this panel follows: scores and confidence values "should NOT be compared between different correlator algorithms" (Ghidra VT Matches table help, quoted from the NationalSecurityAgency/ghidra source tree). Ghidriff does not create Version Tracking sessions, so there is no "accepted in Ghidra" state to show (research flag F6 dropped). Ghidriff's `ratio`/`i_ratio`/`m_ratio`/`b_ratio` are difflib ratios over decompiled text of already paired functions; if ever shown they are labelled "text diff ratio", never placed under a match-quality header.
No probability, percent, "confidence %" or calibrated statement; not "AI-verified"; no "vulnerability found/likely fixed/security-relevant"; agreement is "pairs the same endpoints", not "correct"; do not describe Ghidriff as ground truth ("baseline" or "primary engine"); do not say an absent record "disagrees"; do not imply BinDiff/rz-diff scores are comparable to each other or to Ghidriff's quality; do not claim automatic parallel engine execution beyond the C1 scheduler's actual behaviour; do not claim BinDiff execution until C4 lands (import only); the always-visible footer reads: "Scores are engine-native, uncalibrated and not comparable across engines. This panel assesses function pairing only, not vulnerabilities or patch validity."

## 12. PR breakdown (each small, spec -> red tests -> code -> focused tests -> full gate -> CI)
| PR | Content | Tier |
|---|---|---|
| C6-0 | This spec + `docs/modules.md` rows + `tasks/todo.md` entry; no code | low-cost (docs) |
| C6-1 | `evidence_view.py` (+ service) pure view-model, formatting, sanitize, provenance, filters; full pure tests 10.1; perf pre-index refactor of `assess_reports` if needed | mid-tier |
| C6-2 | `ui_evidence.py` read-only panel (Evidence tab only: models, delegate, detail, copy, states E0-E8, load thread), `EvidenceController` with stub `ProjectPort`; tooltips + `test_tooltips.py` updates; offscreen state tests; MainWindow seam | mid-tier (capable) |
| C6-3 | Engines tab: capability probe, import .BinDiff button wiring to existing import, run controls on C1 scheduler, progress/cancel/failure display, thread tests | mid-tier (capable); depends on C1 merged |
| C6-4 | Polish: accessibility audit, high-DPI pass, 10k perf benchmark, QSettings persistence, QA doc entry in `docs/qa.md`; manual clean-profile DPI pass recorded as an open gate for C8 | low-cost + mid-tier review |
Top-tier escalation only for: a demonstrated cross-thread Qt crash, or a nuanced untrusted-text/security finding. Order: C5 and C1 before C6-2/C6-3; C6 files owned by one integration owner; `secondary/*` touched only in C6-1 pre-index refactor (coordinate with C1/C5 owners).

## 13. Risks
1. Presentation risk: users read a column of numbers as a combined confidence. Mitigation: no cross-engine numeric affordances, units in cells and headers, fixed footer, banned-string test.
2. `ui.py` growth/merge conflicts with parallel contributors: keep the seam to the five hooks of section 8; rebase frequently; inspect open PRs touching `ui.py` before each slice.
3. Tooltip enumeration tests are strict (every control tooltip, every ID applied, unique What text): constructing all controls eagerly is required; budget time for iteration.
4. Dependence on unmerged C1/C5: panel must be crash-free with duplicates; scheduler shape may differ (adapter `EngineOutcomeView` isolates it).
5. Thread-confined SQLite: persisting results must stay on the GUI thread; easy to violate in a refactor. Covered by `test_run_success_stores_set_on_gui_thread_and_refreshes`.
6. `assess_reports` raises `ValueError` on inconsistent sets; treated as E5 rather than crash, but a real inconsistency (reconciling against a changed match set) usually means stale; the staleness check must run first.
7. Offscreen Qt cannot assert pixel contrast, DPI rendering or real screen-reader output; those remain a manual gate (C8).
8. Triage index misuse: shown only behind an opt-in checkbox and with placeholder-constant disclosure; if the product owner disagrees, delete the control (no other code depends on it).
9. Quadratic lookups in `assess_reports` at 10k matches (9.4).
10. Untrusted names from `.BinDiff`/rz-diff (e.g. very long, bidi, control characters) reach the UI; covered by sanitize + plain-text tests; any future use of rich text in this panel is a security regression.

## 14. Decisions taken (defaults) and open questions
Defaults chosen here: dock on the right, hidden by default, `Ctrl+Shift+E`; triage index hidden (opt-in); contested sorts first; Ghidriff column sorts alphabetically; columns for non-run engines remain visible as "not run"; parallelism default 1, timeout default 1800 s; BinDiff import only until C4; no confirm dialog for local runs; amber (not red) for contested.
Open for the product owner: (D1) may the uncalibrated 0..83 triage index appear at all (even opt-in), or must it be removed from the UI until calibration (SPEC-27)? (D2) UI wording "Agree/Contested/Single engine/Unknown" vs the code names `corroborated/insufficient`: confirm the user-facing set. (D3) Whether Ghidriff `quality`/`match_types` should be shown raw (current) or mapped to a documented ordinal scale. (D4) Is a confirm dialog desired before running engines on large binaries (hours-long)? (D5) Should evidence status be included in exported reports (provenance export) in this slice or a follow-up?

## 15. Build deviations and evidence (C6 implementation, 2026-10-14)

Recorded by the C6 builder; inputs: `docs/plans/spec-decisions-20261014.md` (D1-D4), `docs/research/phase-c/multi-engine-evidence-ui.md` (measured, flags F1-F8), `docs/plans/hard-problems/evidence-panel-{plan,troubleshooting}.md`.

- Files: `src/patchtrace/secondary/evidence_view.py`, `src/patchtrace/secondary/evidence_panel_service.py` (pure, no PySide6; subprocess import test), `src/patchtrace/ui_evidence.py`; tests `tests/test_evidence_{view,panel_service,ui,perf}.py` plus the `tests/test_tooltips.py` additions of 7.2.
- `ui.py` seam is 8 lines: import; `self.evidence = EvidenceController(self)` after `_build_workspace()`; `project_changed()` at the end of `refresh()` (covers project set/clear, Ghidriff import/run, corrections and reviews, which all refresh); `update_controls()` in `MainWindow.update_controls` (Run disabled while a Ghidriff job runs); `follow_match()` in `select_match` (navigator -> panel); `shutdown()` in `closeEvent`. The action is the dock's `toggleViewAction()` (registry id `evidence.action`, Ctrl+Shift+E) placed in the existing Analysis menu (there is no View menu). Panel -> navigator selection goes through `WindowPort.select_match`, which reuses the navigator list; no new `MainWindow` method.
- Refresh policy: when the dock is visible, a project key change (root, id, revision, run id, artifact SHA pair) reloads in the background while the previous table stays with "Refreshing engine evidence..." (no flicker); a hidden dock only marks itself dirty. E6 stale is therefore shown for stored sets made for another artifact pair or another Ghidriff run (detected in `load_evidence`), for a result discarded by the GUI-thread guard, or via `set_stale`. Run is not disabled by E6 because re-running the engines is what cures a run/pair mismatch.
- Verdict names Agree / Contested / Single engine / Unknown (D2). Secondary-only records are rows with verdict `engine-only` shown only under the "Engine-only records" filter; they never enter the four verdict counts.
- Ghidriff column: raw `match_types` only (F3); `quality` raw in details with the text-diff-ratio label (D3 raw values kept). BinDiff cell: similarity + algorithm (F1). rz-diff caption names its mode (F7). Rows without a value sort last by name/address in engine-column sorts (F8). Selection follows the match id through every reset, filter and sort (F5). F6 dropped (no acceptance state in ghidriff).
- Triage index (D1): opt-in checkbox, default off, persisted in `evidence/show_index`; text `Triage index N (uncalibrated, ordering aid only)` without "of 83" (F2). Calibration display level: `patchtrace.calibration.policy.display_level()` when importable (guarded), else `'ordinal'`; it is printed in the details as "Calibration display level: ordinal (no calibrated values are shown)". No calibrated value is rendered by C6.
- No confirm dialog before runs (D4); the Engines tab shows a one-line preview and a live elapsed timer with Cancel. BinDiff stays import-only until C4 (its probe reports unsupported, so its Run checkbox is disabled with the probe reason).
- Banned-word sweep: the disclaimers that negate banned stems ("not a vulnerability assessment", the upstream `*_LIMITATIONS` "not calibrated probabilities") are whitelisted sentences; stems such as `probab`, `vulnerab`, `exploit` are otherwise matched as prefixes and `safe`, `secure`, `fixed`, `verified`, `proven`, `certain` as whole words (so "Provenance" is allowed).
- Added registry ids beyond 7.1: `evidence.copy_error` (E5 Copy details) and `evidence.open_engines` (E1/E7 link button); template `evidence.engine_row` for the Engines table.
- `secondary/evidence.py::assess_reports` now indexes each report once (behaviour-preserving; first row per match id wins as before).
- Thread safety evidence: worker callables run off the GUI thread (asserted), `persist_outcome` runs on the GUI thread (asserted), a widget constructed on a worker thread fails a test, teardown matrix (close while loading x5, project switch mid-load, GC of an unreferenced started thread, dock deleted while a worker runs, shutdown during an engine run); the evidence UI + tooltip tests were run 20 times in a row without a failure or abort.
- Not automatable here (manual / C8 gates): real screen-reader announcement (NVDA/Narrator), 125/150/200% DPI rendering and glyph fonts on Windows, contrast against the live palette, frozen-EXE dock smoke, GUI-thread cost of `load_secondary` for very large stored sets (it must stay on the GUI thread because the SQLite connection is thread-confined).

## 16. Track G (Phase D): BinDiff + BinExport setup and run inside the Engines tab

Status: built 2026-10-14 (Phase D wave 0, track G; `docs/plans/phase-d-build-coordination.md`). Turns the CLI-only BinDiff execution (SPEC-29, `secondary run --engine bindiff`) and BinExport2 acceptance (SPEC-10b, `secondary binexport-check`) into a GUI flow inside the EXISTING C6 dock. One comparison window: no new top-level window and no new dock tab (the planned SPEC-31 `[Unified]` tab stays the only planned addition). Contract changes: none to persisted data; additive fields on the in-memory `RunRequest` (16.6).

### 16.1 Placement and regression rule
- A checkable button "BinDiff setup" (`engine_setup.toggle`) sits on its own row directly below the Engines tab run controls (Run selected engines ... Import .BinDiff...). It shows/hides a group "BinDiff run setup" (`engine_setup.section`) placed directly below that row. Hidden by default; the open state persists in `QSettings` `engines/bindiff/setup_open` (bool, try/except, default false). Without a project the toggle and the section are disabled (E0 "all disabled").
- The section lives in its own frameless, vertical-only `SectionScrollArea` (stretch 2, minimum six text lines, never a focus stop), so in a short dock only the open section scrolls and the C6 rows keep their layout. The C6 page itself is not wrapped: measured offscreen, a page-level scroll area sized word-wrapped content by its preferred height and clipped the bottom rows. The toggle is not put into an existing row because that would widen the Engines page minimum (440 px measured; 533 px with the toggle in the run-controls row).
- Regression rule: with BinDiff NOT configured (no successful explicit probe in this session) every pre-existing C6 widget, state E0-E8, engine row, capability, preview and `RunRequest` is identical to C6 (`bindiff` capability = the default registry probe result "not configured"; `RunRequest.bindiff is None`; `execute_run` uses the default `REGISTRY`), and the only visible addition is the toggle row: no C6 widget changes width or horizontal position or is pushed off the page. `EvidencePanel(settings, bindiff_setup=False)` builds the exact C6 panel and is the test baseline.
- Widgets live in `ui_engine_setup.py` (`BinDiffSetupPanel`: widgets only, emits intents) with their own controller (`BinDiffSetupController`: threads and state); pure logic lives in `secondary/evidence_panel_service.py`. Both are reusable unchanged by the SPEC-31 dock tab (07-ui-and-cli).

### 16.2 Wireframe (section open)
```
[Run selected engines] [Cancel] [Probe engines] [Import .BinDiff...]  ====
[BinDiff setup]
+- BinDiff run setup -----------------------------------------------------------------------+
| BinDiff executable (absolute path):                                                        |
| [/opt/bindiff/bin/bindiff                                  v] [Browse...] [Probe BinDiff]    |
| Usable: BinDiff 8 (@568181968, Sep 25 2023). Version check: the BinDiff 8 build ...         |
| Older .BinExport (BinDiff primary):                                                         |
| [C:\exports\older.BinExport                                 ] [Browse...]                   |
| Newer .BinExport (BinDiff secondary):                                                       |
| [C:\exports\newer.BinExport                                 ] [Browse...]                   |
| [ ] Accept .BinExport files without a SHA-256 executable id                                 |
| Warning: tick this only for files you exported yourself from exactly ...                   |
| [Validate .BinExport files] [Cancel validation] ======== (indeterminate)                   |
| Both .BinExport files are valid BinExport2 and belong to this project's files.              |
| Older: 3 functions, architecture x86-64, executable id SHA-256, matches the older file.     |
| [ ] Show technical details     (read-only plain text: codes, kinds, reason slugs)           |
| How to produce .BinExport files: Ghidra ... / IDA 9.4+ ...; same "Subtract Imagebase"       |
+--------------------------------------------------------------------------------------------+
```
The executable field is an editable combo box: discovered candidates are its items, the edit text is the chosen path (no inline completion, typed text is never inserted as an item, minimum contents length 16 so long paths never widen the dock). Labels sit above their fields (stacked form) so the open section is no wider than the C6 Engines rows.

### 16.3 BinDiff executable: discovery and probe
- Prefill (read-only, never PATH, never executed): first from `QSettings` `engines/bindiff/path` (written only after a successful explicit probe); otherwise, the first time the section is opened with an empty field, `runtime_discovery.discover_local_runtimes().bindiff_executables` runs on a worker thread: exactly one candidate fills the field, several become combo items. Discovery never starts a probe.
- "Probe BinDiff" runs `bindiff_probe.probe_report(path)` (only `--version` and `--nologo --help`, private workdir, allow-listed env, 30 s, cached per path/mtime/size) on a worker. Relative paths are refused by the probe (`not-found`).
- Status line texts (exact; `{}` filled; plain text):

| State | Text |
|---|---|
| P0 empty | "No BinDiff executable chosen. BinDiff is never looked up on PATH: choose the bindiff executable (bindiff.exe on Windows) of an installed BinDiff 8 and press Probe BinDiff." |
| P1 one found | "Found an installed BinDiff at the path above; it has not been run. Press Probe BinDiff to check it." |
| P1 several | "Found {n} installed BinDiff executables; pick one from the list or use Browse, then press Probe BinDiff." |
| P2 unchecked | "Not checked yet. Probe BinDiff runs only bindiff --version and --help; it never reads the project files." |
| P3 probing | "Checking BinDiff (bindiff --version and --help only)..." |
| P4 usable | "Usable: BinDiff {version}. Version check: {pin}." |
| P5 not usable | "Not usable: {probe reason}" (the SPEC-29 §6 fixed message; never a path or raw tool output) |

Pin status (`{pin}`) compares `Capability.version` with the measured pin `8 (@568181968, Sep 25 2023)` (`tools/bindiff_pin.json` `version_text` without its `BinDiff ` prefix; a test keeps them equal): `pinned` "the BinDiff 8 build PatchTrace was tested with"; `tested` "a BinDiff {major} build other than the one PatchTrace was tested with; accepted because every required option is present"; `untested-newer` "newer than the tested BinDiff 8; accepted because every required option is present, and results are recorded as from an untested version".

### 16.4 BinExport validation
- Older and newer `.BinExport` paths are picked with Browse (or typed). "Validate .BinExport files" runs `validate_binexports(ValidationRequest)` on a worker: the CLI's own `cli_bindiff.c3_acceptor` (C3 `accept_binexport` in the capped worker, including its swapped-file re-classification) for older then newer, then `bindiff_inputs.bind_pair`. Snapshots go to a private temporary directory that is removed afterwards; the run repeats acceptance exactly as the CLI does, so what BinDiff diffs is what was accepted in that run. The same file chosen twice (same path, or same size and SHA-256) is reported before any worker starts.
- Progress: indeterminate bar plus "Validating the {side} .BinExport in an isolated checker (step {n} of 2)..." and then "Checking that the two .BinExport files form this project's pair..."; "Cancel validation" sets the shared cancel event (C3 kills the worker tree) and immediately shows "Validation cancelled; nothing was kept."; the late result is dropped by generation.
- Clicking Validate with a path missing shows "Choose both .BinExport files first: one for the older file and one for the newer file."; an unexpected exception in the check shows "The check stopped unexpectedly ({exception class}); nothing was kept."
- Success text: "Both .BinExport files are valid BinExport2 and belong to this project's files." (with the unbound confirmation: "Both .BinExport files are valid BinExport2; at least one is tied to this project only by your confirmation.") plus one line per side "{Side}: {n} functions, architecture {arch}, executable id {binding}." with binding `SHA-256, matches the {side} file` | `MD5 only, accepted on your confirmation (not checked)` | `none, accepted on your confirmation (not checked)` | `not a SHA-256, accepted on your confirmation (not checked)`. Architecture names are file strings: `sanitize_text`, plain text only.
- Failure text: "Not accepted: {message}" with the mapping below; "Show technical details" reveals code, kind (SPEC-29 §6), reason slug (SPEC-10b §7), side and the fixed-template message. Worker stderr (`SecondaryError.diagnostics`) is never shown in the GUI (the CLI keeps printing it to stderr).

| Source (kind / reason) | Message (plain) |
|---|---|
| `binexport-orientation`, `orientation_swapped` | The two .BinExport files are swapped: the file chosen as older was exported from the newer file (or the reverse). Swap them and validate again. |
| `binexport-wrong-artifact`, `executable_id_mismatch` | The {side} .BinExport was exported from a different file than this project's {side} file (its SHA-256 executable id does not match). |
| `binexport-same-file`, `same_file_twice` | The same .BinExport was chosen for both sides. Choose one export of the older file and one of the newer file. |
| `binexport-arch-mismatch` | The two .BinExport files describe different processor architectures, so they cannot be a patch pair. |
| `binexport-unbound`, `executable_id_md5/empty/other` | The {side} .BinExport {does not record a SHA-256 of its source file / records only an MD5 hash of its source file, not a SHA-256 / records no hash of its source file / records an id that is not a SHA-256 of its source file}, so PatchTrace cannot check that it belongs to this project. Re-export it with an exporter that records SHA-256 (Ghidra does), or tick the confirmation below if you exported it from exactly this file yourself. |
| `address_basis_mixed` | One file uses virtual addresses and the other subtracted the image base. Export both with the same "Subtract Imagebase" choice. |
| `binexport-too-large`, `too_large` | The {side} .BinExport is larger than the 256 MiB limit. |
| `memory_cap`, `record_too_large`, `count_cap:*` | The {side} .BinExport exceeds a size or record-count limit of the checker. |
| `unreadable`, `not_regular_file`, `empty_file`, `file_changed_during_read` | could not be opened / is not a regular file / is empty / changed while it was being read |
| `lookalike_*` | The {side} file looks like {a SQLite database (perhaps a .BinDiff result) / JSON / a ZIP archive / a Windows executable / an ELF executable / a PDF}, not a .BinExport file. |
| other `PT-SECONDARY-INPUT` slugs | The {side} .BinExport is not a valid BinExport2 file (its structure failed a check). |
| `binexport-unsupported`, `protobuf_*`, `descriptor_mismatch`, `worker_unavailable` | BinExport validation is not available in this build (the BinExport2 reader is missing). |
| `worker_timeout` / `worker_oom` / `worker_crash`, `worker_bad_result` | the check took longer than its time limit / needed more memory than allowed / the isolated checker stopped unexpectedly; the file was not accepted |
| `identical-pair`, `identical_pair` | This project's older and newer files are identical, so there is nothing to compare. |
| `workdir-error` | PatchTrace could not prepare a private working folder for the check. Check the free disk space. |
| `cancelled` | Validation cancelled; nothing was kept. |

### 16.5 Accept-unbound override
A checkbox "Accept .BinExport files without a SHA-256 executable id" (`engine_setup.accept_unbound`) with an always-visible warning label (`engine_setup.unbound_warning`): "Warning: tick this only for files you exported yourself from exactly this project's older and newer files. Without a SHA-256 id PatchTrace cannot check which file an export came from, so a wrong file gives meaningless pairings. Your confirmation is stored with the BinDiff result; a SHA-256 id that does not match is still refused." It is never persisted, resets when either path or the project changes, and invalidates the last validation. Validation and the run pass it as `accept_unbound` exactly like `--accept-unbound-binexport`, so `EngineRun.provenance['binexport_binding']` reads `asserted:older=<kind>,newer=<kind>` as the CLI records it (a test compares a GUI run with a CLI run on identical inputs).

### 16.6 Run path (C6 flow unchanged)
- BinDiff capability seen by the Engines tab: the unchanged default probe result while BinDiff is not configured; after an explicit probe: the probe's unsupported capability, or (probe usable) `supported=False` with reason "BinDiff {version} is usable; choose and validate both .BinExport files in BinDiff setup." or "BinDiff {version} is usable, but the .BinExport files were not accepted: {message}", or `supported=True` once the validation of the CURRENT paths, override, project and artifact SHA-256 pair succeeded. The BinDiff checkbox therefore enables only when both checks passed.
- `RunRequest` gains additive optional fields `bindiff: BinDiffSetup | None` (absolute executable, older/newer `.BinExport`, `accept_unbound`) and `bindiff_raw_dir: Path | None` (`<project>/runs/<run_id>/raw/secondary`, exactly the CLI path). `execute_run(registry=None)` then builds `build_registry(bindiff=bindiff_adapter(setup, raw_dir))`, where `bindiff_adapter` calls `cli_bindiff.adapter_from_args` with an equivalent `argparse.Namespace` and an empty environment (only the GUI field counts; never PATH). Everything else is the C6 flow: scheduler on `EngineRunThread`, outcomes persisted by `persist_outcome` in the GUI-thread slot, generation drop, cancel, states E0-E8.
- The run preview adds "BinDiff compares the two validated .BinExport files (older = primary, newer = secondary)." when BinDiff is selected.
- Every change of the setup capability (probe or validation finished, an input edited) refreshes the capabilities, engine rows and run controls at once and reloads the evidence in the background when the dock is visible (else marks it dirty): engine rows, the E1/E7 reasons and the E4 count are built from capability views at load time, so without the reload the BinDiff row kept the old "not configured" reason. Inputs are locked while engines run.

### 16.7 Threads
`ui_engine_setup.TaskThread` (no Qt parent, module registry `ui_engine_setup._LIVE_THREADS`, released with `deleteLater` on `finished`, cancel `threading.Event`) runs discovery, probe and validation on immutable inputs; results arrive through queued bound-method slots that drop stale generations and results that arrive after the section was deleted with its dock. `BinDiffSetupController.shutdown()` (called by `EvidenceController.shutdown()`) sets every cancel event and `wait()`s every thread; no `terminate()`. Workers never touch widgets, `QSettings`, the clipboard, the project service or SQLite.

### 16.8 Tooltips, accessibility, keyboard
Registry ids (WHAT/WHY/EFFECT plus SOURCE/Availability, unique, no `<`/`>`): `engine_setup.toggle`, `.section`, `.bindiff_path`, `.bindiff_browse`, `.bindiff_probe`, `.older_binexport`, `.older_browse`, `.newer_binexport`, `.newer_browse`, `.accept_unbound`, `.unbound_warning`, `.validate`, `.cancel_validation`, `.show_details`, `.details`. Every control has an accessible name (exact strings in `ui_engine_setup.ACCESSIBLE_NAMES`) and the registry text as accessible description; the two status labels keep an empty accessible name so `setText` announces (1.8); status is words, never colour. Tab order: ..., Import .BinDiff, BinDiff setup, executable, Browse, Probe BinDiff, older, Browse, newer, Browse, accept checkbox, Validate, Cancel validation, Show technical details, details, then the engine log and Copy details.

### 16.9 Tests (offscreen pytest-qt + pure; mocked unless stated)
`tests/test_ui_engine_setup_service.py` (pure): message table for every kind/slug, banned-word sweep, pin status and pin constant equal to `tools/bindiff_pin.json`, probe with a fake `bindiff` (ok, version 7, missing option, no version, newer major, relative path), REAL `accept_binexport` on `tests/fixtures/binexport` (valid pair, swapped, foreign SHA-256, MD5 id with and without the override, same file, oversized, architecture mismatch, pre-set cancel), adapter reuse equal to `adapter_from_args`, `execute_run` registry selection. `tests/test_ui_engine_setup.py` (Qt): probe states, discovery prefill without execution and without PATH, validation flow with progress and cancel, override provenance equal to the CLI, end-to-end GUI run with a fake `bindiff` and persistence on the GUI thread, project switch drops results, shutdown joins threads, GUI-thread heartbeat during a real validation, slot time ceilings, tooltips/accessibility/tab order, the regression baseline of 16.1. The new Qt tests run 20 times in one session without an abort.
Manual / Windows-only gates: a real BinDiff 8 `bindiff.exe` from `%ProgramFiles%` through the GUI, native file dialogs, 125/150/200% DPI layout of the section, NVDA/Narrator announcement of the two status labels, a keyboard-only walk through the section.
