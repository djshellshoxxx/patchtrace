# SPEC-31 / 07 UI (one comparison window) and CLI

Owner slice S4 (read model, Qt adapter), S0b (first CLI verbs). Inherits every C6 rule of `../multi-engine-evidence-panel.md` s0 (no combined numbers, no probability wording, missing is not negative, contested wins, untrusted text is plain text, colour never the only carrier) and its thread rules s5.3. Numbers: L-xx (02 s6).

## 1. Principles
1. ONE comparison window (D-18): `MainWindow` keeps one navigator, one pair of code panes, one evidence dock. The unified result is a VIEW MODE of the same window, never a new top-level window; the read-only `SeriesWindow` (N-way) is unchanged and out of scope.
2. The UI is a thin view over `read_model.py` (Qt-free); widgets hold no analysis state.
3. Native per-source values appear only in that source's own column with units; decisions and verdicts are words + ASCII glyphs; display level stays `'ordinal'` (calibration/policy.py:44) until a validated artifact exists.
4. Defaults never hide evidence of disagreement: contested rows sort first; `unchanged` and structurally proven `cosmetic` rows (UNCH/1, COS-ADDR/1, COS-LAYOUT/1) are collapsed by default with a visible count (U-03), one click shows them; COS-PSEUDO/1 rows are listed after `review`.

## 2. `ui.py` seam (<= 25 lines; only edits to `ui.py`; R-20)

Superseded by GUI plan F5: the registry entry `PanelSpec(id='unified', tabify_with='evidence')` replaces these steps. `match_override`, `navigator_stack` and `show_external_pair` come from F5 (`PanelHost`), not from this list; until F5 the steps stand.

1. `from .ui_unified import UnifiedController` (1 line). 2. In `MainWindow.__init__` BEFORE the `self._build_workspace()` call (ui.py:1503; the method is defined at :1565): `self.unified = UnifiedController(self)` (1); the constructor creates no widget, because step 3 runs inside `_build_workspace`. 3. In `_build_workspace`, wrap the existing `self.navigator` (ui.py:1644) in the controller's `QStackedWidget` with a view switch above it: `layout.addWidget(self.unified.navigator_stack(self.navigator), 1)` replacing the `addWidget` line at :1649 (net 0). 4. `current_match()` (ui.py:1840-1843) consults `self.unified.match_override()` first (2 lines): today it reads the navigator's current item, which is hidden in the Unified view and may be filtered, so this is the only way to reuse `render_match` unchanged for unified rows that map to a Ghidriff match. 5. `refresh()` end (:1964): `self.unified.project_changed()` (1). 6. `update_controls()` (:2981): `self.unified.update_controls()` (1). 7. `select_match()` (:2042): `self.unified.follow_match(self.current_match())` (1). 8. `closeEvent` (:3103): `self.unified.shutdown()` (1). 9. New public `show_external_pair(older_text, newer_text, label)` (<= 12 lines): clears `_hunks`, `hunk_list`, `_line_maps`, `_function_offsets` and the extra selections, then sets both panes and `match_label`; used for IR-disassembly rows with no Ghidriff match (ui_unified never touches MainWindow private state). Seam test `test_mainwindow_unified_seam_is_minimal` (grep: `ui.py` has no `UnifiedTableModel`; line growth <= 25 against the recorded baseline) and `test_external_pair_resets_hunk_state`.

## 3. Layout (wireframe, Unified view, 1100 x 750 minimum)
```
+- PatchTrace ------------------------------------------------------------------------------------------+
| View: [Primary (Ghidriff)] [Unified (derived)]   Unified: ude/1, run 14:02, stale: no   [Run unified] |
| Filter: decision [all v] change [material+review v] class [any v] source [any v] [search......]       |
| Summary: 5,214 rows - 12 material - 31 review - 4 contested - 9 older-only - 7 newer-only -           |
|          5,151 cosmetic/unchanged hidden [Show]                                                        |
| Function            | Decision        | Change            | Ghidriff        | BinDiff       | rz-diff     |
| ValidateBuf 0x11000>| [!] Contested   | Material: constant| Exact           | pairs elsewhere| no record  |
| ParseHeader 0x1000> | [=] Matched     | Review: callee    | SymbolsHash     | sim 0.97 ...  | byte sim .. |
|------------------------------------------------- code panes (older | newer) -------------------------|
| older: decompiled (Ghidriff) or disassembly (ProgramIR, Ghidra 12.0.4)  | newer: same; deltas marked   |
+------------------------------------------------------------------------------------------------------+
Dock "Engine evidence": tabs [Evidence] [Engines] [Unified]
 Unified tab = detail of the selected row: Decision + reason | Support by component (K1: Ghidriff SymbolsHash A;
 K2: pt-bytes P05 masked-exact A) | Contest (strength, each conflicting atom with source, step, tier, endpoints) |
 Change facts (verdict, proof id or second channel, deltas: class, older rva, newer rva, old text, new text) |
 Limitations | Provenance (inputs, versions, result id) | [Go to Ghidriff match] [Correct match...] [Copy provenance] [Explain...]
 footer: "Decisions and change classes are rule-based and uncalibrated. Native values are engine-specific and never combined.
          Change verdicts cover function code and unwind data, not global data contents."
```
Columns: Function (name + RVA pair, elided middle), Decision (badge), Change (materiality + first change class), then one column per source in the registry's display order that is present in the result (D-08; absent sources are not shown as columns in the Unified view, their absence is listed in the header line), each cell = that source's native text with unit prefix from `SourceSpec.unit_caption`; `pt-ladder`/`pt-bytes` cells show the pass id and tier (e.g. `P05 masked-exact (A)`).
Code panes: rows that map to a Ghidriff match render exactly as today (`render_match`, ui.py:2049, through the step-4 override); rows with S3b output show that decompiled C (labelled "Decompiled on demand by Ghidra <version>"); other rows render IR disassembly text (Ghidra-produced, `ins.txt`, labelled "Disassembly from ProgramIR (Ghidra <version>); decompiled code unavailable for this pair") through `show_external_pair`, with aligned gaps from `facts/align.py`; nothing is fabricated: missing text reads "unavailable" with the reason. Header lines are never part of the diffed text (C-17).
Badges (ASCII glyph + word): Matched `=`, Tentative `~`, Candidate `?`, Contested `!`, Ambiguous `#`, Older only `-`, Newer only `+`, Unknown `.`; materiality words: Unchanged, Cosmetic (proof <id>), Material, Review, Unknown, Not applicable.

## 4. Read model (`read_model.py`, Qt-free; contract for the view)
```python
@dataclass(frozen=True, slots=True)
class SourceCell:  source: str; kind: Literal['value', 'pairs-elsewhere', 'no-record', 'not-run']; text: str; sort_key: int | None
@dataclass(frozen=True, slots=True)
class UnifiedRowView:
    row_id: str; function_label: str; address_label: str
    decision: Decision; decision_text: str; glyph: str
    materiality: Materiality; materiality_text: str; classes: tuple[str, ...]
    cells: tuple[SourceCell, ...]; ghidriff_match_id: str | None
    sort_keys: tuple[int, ...]       # (decision priority, severity rank 05 s2.6, attention order, rva) precomputed
    search_key: str                  # lowercased names + hex rvas, <= 512 chars
@dataclass(frozen=True)
class UnifiedViewModel:
    project_id: str; run_id: str | None; revision: int
    state: Literal['U0','U1','U2','U3','U4','U5','U6','U7','U8']; state_text: str
    sources: tuple[SourceInfo, ...]; rows: tuple[UnifiedRowView, ...]
    counts: Mapping[str, int]; warnings: tuple[str, ...]; stale_reason: str | None; display_level: str
def load_unified(req: UnifiedLoadRequest, cancel: Callable[[], bool]) -> UnifiedViewModel   # reads pointer row + verified parts
def filter_rows(rows, *, decisions, materialities, classes, sources, search) -> Sequence[int]   # indices, like evidence_view
def row_detail(vm, row) -> str            # plain text detail for the dock tab (fixed section headers)
def provenance_block(vm, rows) -> str     # deterministic, <= 16 KiB, banned-word clean
def explain_context(vm, row) -> ContextFragment   # for the existing context preview only (D-30)
```
Rules: every user-visible string passes `secondary.evidence_view.sanitize_text`; the banned-word sweep (`evidence_view.BANNED`, whitelisted negations) runs over every string the read model can produce (`test_unified_banned_strings_never_appear`); rows are built once, verbose text lazily; `load_unified` never raises for data problems (it returns U5/U6 with a reason).

## 5. States (exact texts; precedence U5 > U6 > U4 > U3; U2 only before the first table)

| ID | Trigger | Text |
|---|---|---|
| U0 | no project | "Open a project to see the unified comparison." |
| U1 | project, no unified result | "No unified result yet. The primary Ghidriff view is unchanged. Run unified analysis to add derived evidence from all stored engines." + [Run unified] |
| U2 | run or load in progress | "Unified analysis: <stage> <done>/<total>" or "... (no counts available)" + Cancel |
| U3 | ready | table + detail |
| U4 | partial: IR missing for a side, a source failed, or a cap hit | banner "Partial unified result: <reasons>. Missing evidence is unknown, not disagreement." |
| U5 | failed | "The unified result could not be produced: <code>: <message>. Earlier results and the primary Ghidriff results are unchanged." + [Retry] [Copy details] |
| U6 | stale | "The unified result is stale: <changed input>. It is shown for reference only." + [Run unified] (inputs compared through `result_key` components, 02 s5) |
| U7 | unsupported: no Ghidra/Python configured | "Ghidra extraction is not configured; the unified result uses stored engine outputs only (no instruction-level change facts)." |
| U8 | more than L-33 rows after filtering | "Too many rows to display (N). Narrow the filter." |

## 6. Run, progress, cancel
`Run unified` is enabled only when a project is open, no Ghidriff job and no engine run is active (C-11), and the feature flag `unified/enabled` (QSettings, default OFF, D-20) is on; the reason is in the tooltip `Availability`. Stages shown: extract older, extract newer, ingest, match, change facts, decompile review pairs (S3b, U-11), publish; counts come from `progress.json` (03 s3) or are indeterminate. Cancel sets the shared event: children are killed with their tree; the previous result stays current; state returns to the previous one with "Cancelled; earlier results unchanged." Closing the window or switching project cancels and waits (`shutdown()`), no `terminate()`.

## 7. Filters, sorting, keyboard, persistence
Filters: decision (multi-select), change (default `material + review + not-applicable + unknown`), class, source present, search (debounced 150 ms; names, hex RVAs with or without `0x`). Sorting: model-owned order (the C6 measured approach; no `QSortFilterProxyModel`, no `ResizeToContents`); default: contested, material, review, cosmetic (COS-PSEUDO/1), tentative/candidate, one-sided, cosmetic (structural), unchanged; then severity (05 s2.6); `library`-flagged rows after first-party rows inside each group (F16). Keyboard: Up/Down/PageUp/PageDown/Home/End; Enter = show in code panes; Ctrl+C = copy provenance; Ctrl+Shift+U = toggle Primary/Unified (free on `cb25132`: MainWindow uses Ctrl+E/I/N/O/R/S, F1, F5; the dock uses Ctrl+Shift+E). QSettings keys `unified/view`, `unified/filters`, `unified/columns` (each read in try/except with defaults).

## 8. Tooltips and accessibility
Tooltip ids via spec `tips` (`PANEL.tips`, GUI plan F5; each with WHAT/WHY/EFFECT, SOURCE and Availability, no `<`/`>`): `unified.view_switch`, `unified.run`, `unified.cancel`, `unified.filter_decision`, `unified.filter_change`, `unified.filter_class`, `unified.filter_source`, `unified.search`, `unified.show_hidden`, `unified.table`, `unified.tab`, `unified.detail`, `unified.goto`, `unified.correct`, `unified.copy`, `unified.explain`, `unified.retry`, `unified.copy_error`, `unified.stale_banner`, `unified.source.<id>` per registry source; templates `unified.row`, `unified.cell`, `unified.badge`, `unified.delta`. All controls are constructed eagerly (hidden when not applicable) so `tests/test_tooltips.py` enumeration finds them; the dock tab is added to its `roots`. Accessibility: accessible names per widget (exact strings defined in `ui_unified.py`), `AccessibleTextRole` per cell with units spoken ("BinDiff similarity 0.97"), status label with EMPTY accessible name so `setText` announces (C6 s1.8), 2 px focus ring, contrast >= 4.5:1 text / 3:1 non-text (pure contrast test), row height from font metrics, ASCII glyphs only (Windows fonts), no hover-only information.

## 9. Threads (`ui_unified.py`)

Threads run through `TaskRunner` (`ctx.tasks`, GUI plan F2) in place of the Qt-parentless threads described here; the generation and GUI-thread rules are unchanged.

`UnifiedRunThread` (runs `pipeline.execute` with an immutable `UnifiedRequest` built on the GUI thread), `UnifiedLoadThread` (runs `load_unified`); both without Qt parent, held in a module registry until `finished`, generation counter drops late results, results applied and pointer rows published ONLY in GUI-thread slots (`store.publish_result` uses the thread-confined connection). Tests mirror C6: `test_unified_publish_runs_on_gui_thread`, `test_project_switch_during_run_drops_result`, `test_close_while_running_cancels_and_waits`, `test_worker_never_touches_widgets`, 20x repeat run with `PYTHONFAULTHANDLER=1` for SIGABRT detection.

## 10. CLI (`unified/cli.py`; adapter `cli_commands/unified.py`; a temporary `COMMANDS += ('unified',)` hook may merge first and move later, GUI plan 8.12)
```
patchtrace unified extract PROJECT [--side older|newer|both] [--mode auto|gzf|analyze] [--timeout S] [--json]
patchtrace unified run     PROJECT [--no-extract] [--no-decompile] [--sources ghidriff,bindiff,rz-diff,...] [--isolate|--in-process] [--json]
patchtrace unified show    PROJECT [--decision D]... [--change M]... [--class C]... [--limit N] [--json]
patchtrace unified explain PROJECT --row ROW_ID [--json]        # full detail text / JSON of one row (atoms, facts, provenance)
patchtrace unified status  PROJECT [--json]                     # current result, staleness reason, IR availability, versions
patchtrace unified _worker --request FILE --result-dir DIR      # hidden; spawned via C3 worker_argv() (frozen: no python -m)
patchtrace unified _worker --self-check                         # hidden; frozen smoke: imports every unified module, exit 0
```
JSON: one `enrichment-cli/1` document; `result` for `run`: `{result_id, status, counts, stages[{stage, status, duration_ms}], limitations, stale: false}`; for `show`: `{rows:[UnifiedMatch subset + materiality], total, filtered}`. Exit codes (existing contract): 0 ok; 2 invalid argument/environment/unsupported with nothing runnable; 3 runtime failure or partial (`status: partial`); 4 complete with zero rows matching the filter (`show`) or zero material+review rows (`run --fail-on-none` only); 5 cancelled. `--isolate` (worker child) is the default for `run`; `--in-process` exists for tests and debugging. The CLI never imports Qt (`test_cli_unified_never_imports_qt`).

## 11. Tests (offscreen pytest-qt and pure)
Pure: `test_read_model_states_and_precedence`, `test_filter_rows_defaults_hide_cosmetic_with_count`, `test_sort_order_contested_first_then_severity`, `test_cells_never_combine_sources`, `test_provenance_block_deterministic_and_capped`, `test_unified_banned_strings_never_appear`, `test_hostile_names_plain_text` (C6 hostile list), `test_read_model_has_no_qt`. Qt: one test per state U0-U8, `test_view_switch_keeps_one_window`, `test_no_new_top_level_window`, `test_code_panes_show_ir_disassembly_labelled`, `test_correct_match_opens_existing_dialog`, `test_explain_goes_through_context_preview`, tooltip suite additions, accessibility names, perf gates on `data()` call counts at 10k and 100k rows (C6 method, wall clock 5x slack). CLI: `test_cli_unified_run_exit_codes` (0/2/3/4/5), `test_cli_unified_show_json_single_document`, `test_cli_unified_worker_hidden_from_help`.

## 12. S0b CLI notes (2026-10-14)
`unified run|show|explain|status` and the hidden `_worker` are built (`extract` arrives with S1). The parser and handler live in `unified/cli.py`; `patchtrace/cli.py` only registers them (4 changed lines: `COMMANDS`, the import, `register(sub, common, HANDLERS)` and the `unified` entry of `_command_name`, so that failure documents say `unified run`). The command is labelled "experimental, derived, ordinal" in `--help`; every JSON `warnings` list starts with the standing note that unified results are experimental, derived and ordinal. The hidden `_worker` is hidden by registering it WITHOUT a `help=` argument (argparse prints `help=argparse.SUPPRESS` of a nested subparser as `==SUPPRESS==`, which C3's `_binexport-worker` still does in `secondary --help`; not touched here). `run` without `--no-extract` adds the warning `extraction is not available in this build; the result uses stored engine outputs only (no instruction-level facts)`. `run` options in S0b: `--no-extract` (S0 mode, the only mode), `--no-decompile` (accepted, no effect), `--sources` (comma list of ghidriff, bindiff, rz-diff, manual; default all; unknown -> exit 2), `--isolate` (default: worker child through `jobs.run_process` with C3's `worker_argv()`, the allow-listed `worker_env()` without the protobuf variable, L-42 memory cap and C3's OOM classification) or `--in-process`, `--timeout` (L-34, 60..86,400), `--fail-on-none` (exit 4 when no material or review row). Exit codes: 0 complete; 2 invalid argument, environment, no completed Ghidriff run, unreadable PE; 3 runtime failure, `LIMIT`, `STORE`, `TIMEOUT`, partial result; 4 `show` with zero rows after filtering (or `run --fail-on-none`); 5 cancelled. Every attempt that has a `result_key` also stores a `unified-run` row; a failure never replaces the current result. `show` filters by `--decision`, `--change` (materiality), `--class`, `--limit` over the current verified result (a stale or invalid one is reported, never crashes); `explain --row` takes a row id or a unique prefix of at least 8 hex digits and prints atoms, contest, facts and provenance; `status` reports state (current, stale with the changed `result_key` inputs, invalid, none), counts, sources, limitations and the last runs. All strings pass `sanitize_text` and the banned-word sweep.
