# SPEC-09b: N-way Series window and per-hop ranking (Phase C, item C7)

Status: developer-ready, 2026-10-14. Extends SPEC-09 (`nway.md`, contract `nway/1` is **unchanged**) and SPEC-07 (`attention/1` is read, never recomputed). Base: `main` after `b7e819a`.
Scope: a read-only GUI window over a stored `series.json`, per-hop attention scores from each pair project's stored default-profile ranking, and tolerance of unreadable sibling projects. No new persisted contract, no new engine runs, no writes to pair projects.

## 1. Verified current behaviour (defects this slice must close)

| # | Fact (file:line) | Consequence |
|---|---|---|
| 1 | `series.discover_pairs` calls `read_project(child)` for every directory with a `project.sqlite3` (`nway/series.py:110`), and `read_project` raises `PT-NWAY-PAIR` for any unopenable one (`:36-38`). | One corrupt, locked or foreign sibling aborts `series create` for the whole root. |
| 2 | `series.save` calls `load(path)` on an existing file (`:197`); `load` raises `PT-NWAY-STORAGE` on any damage (`:212-226`). | A corrupt `series.json` can never be replaced; the user must delete it by hand. |
| 3 | `staleness` (`:238`) catches only `NwayError`; `read_project` converts only `ValueError`. A raw `sqlite3.Error`/`OSError` from a damaged sibling escapes. | `series chains` can crash on a damaged pair instead of reporting it stale. |
| 4 | `ProjectService.open` takes the single-writer lock (`service.py:54`, `persistence.py:182`); a pair open in the main window is "locked" (`test_locked_pair_project_is_respected`). | A GUI window cannot use `read_project` for pairs the user is also viewing. |
| 5 | Raw-derived (unchanged) edges carry `match_id = 'raw:<run>:<hex>'` (`graph.py:~128`), normalized edges carry the real `FunctionMatch.id` (`graph.py:292`). | Only normalized edges can have an attention entry; raw edges must render as "unchanged, not ranked". |
| 6 | `pipeline.load_default(store, project)` returns `(RankingResult|None, sets, note)` for the live project (`pipeline.py:318`) and needs an `EnrichmentStore` on an open `ProjectStore`. | Per-hop ranking is a read of stored rows, no computation; absent rows are a normal state. |

## 2. Layering and files

```
nway/pair_access.py   NEW  pure+IO, no Qt: PairReader protocol, open-read-close with classified failures
nway/view_model.py    NEW  pure, no Qt, no IO: dataclasses + build_view(); the only logic the window uses
nway/series.py        EDIT tolerant discovery, recoverable save, classified staleness (CLI benefits too)
ui_series.py          NEW  Qt only: SeriesWindow(QMainWindow), SeriesLoadThread(QThread), table/detail widgets
ui.py                 EDIT <= 20 lines: action `action.series` (File menu), lazy `from .ui_series import SeriesWindow`
tooltips.py           EDIT new `series.*` IDs (section 7)
```
Rules: `nway/*` and `view_model.py` import no Qt, network or subprocess (extend `test_pure_modules_import_no_qt_or_network`). `ui_series.py` holds no domain logic; it renders a `SeriesView` and forwards intents. `ui.py` must not import `ui_series` at module import time (offscreen import cost, circular import).

## 3. Pair access (`nway/pair_access.py`)

```python
PairState = Literal['ok', 'missing', 'unreadable', 'locked', 'mismatch', 'changed', 'no-run']

@dataclass(frozen=True)
class PairSnapshot:                      # everything the view needs from one pair project, copied out
    state: PairState
    reason: str                          # user-safe, '' when ok; never a traceback or absolute path
    project_id: str | None; revision: int | None; run_id: str | None
    ranking: RankingResult | None        # stored default-profile result, None if absent
    ranking_note: str                    # '' | 'no stored ranking' | 'stored ranking is stale' | ...
    match_names: Mapping[str, str]       # match_id -> display name, only for ids in the series chains

class PairReader(Protocol):
    def read(self, root: Path, ref: PairRef, older_sha: str, newer_sha: str,
             wanted_match_ids: frozenset[str]) -> PairSnapshot: ...
```
`DiskPairReader.read` pseudocode (never raises for per-pair problems; raises only `PT-NWAY-CANCEL` via the thread's cancel event):
```
target = (root / ref.path).resolve()
if not target.is_relative_to(root) or not (target/PROJECT_FILE).is_file(): return Snapshot('missing', ...)
try: service = ProjectService.open(target)
except ValueError as e:
    return Snapshot('locked' if 'locked' in str(e) else 'unreadable', safe_reason(e))
except (sqlite3.Error, OSError): return Snapshot('unreadable', 'database cannot be read')
try:
    project = service.project                           # already validated by open
    try: validate_pair(project, older_sha, newer_sha)
    except NwayError: return Snapshot('mismatch', ...)
    if project.id != ref.project_id: state='mismatch'
    elif (project.revision, current_run_id(project)) != (ref.revision, ref.run_id): state='changed'
    elif ref.run_id is None: state='no-run'
    else: state='ok'
    ranking, note = (None, '') if state in ('mismatch','no-run') else \
        pipeline.load_default(EnrichmentStore(service.store), project)[::2]  # (result, note)
    names = {m.id: m.newer[0].name if m.newer else m.older[0].name for m in project.matches if m.id in wanted}
    return Snapshot(state, ..., ranking, note, names)
except (EnrichmentError, ValueError, sqlite3.Error): ranking unavailable, state stays, note='stored ranking unreadable'
finally: service.close()
```
Notes: `changed` pairs are still displayed (chains through them are marked stale) but their ranking is shown only when `ranking.input_digest` came from the current run; otherwise `ranking=None, note='stored ranking is stale'` (`load_default` already returns this). A `locked` pair is not an error: the window offers "use the open project" only if the main window passes an already-open `ProjectService` through the optional `live: Mapping[str, ProjectService]` argument (keyed by project id; used in place of `open`, never closed by the reader). Without it, `locked` pairs show chains and edges (these come from `series.json`) but no scores.

## 4. Tolerance changes in `nway/series.py` (spec-first, also CLI)

1. `discover_pairs(root, wanted) -> Discovery` where `Discovery(found: dict[(i,j), Path], skipped: tuple[Skipped])`, `Skipped(name: str, code: Literal['unreadable','locked','not-a-project'], reason: str)`. A child that cannot be read is skipped and reported, never fatal. Duplicate holders of one wanted pair stay fatal (`PT-NWAY-PAIR`): that is ambiguity, not damage.
2. `prepare()` creates a missing pair at the deterministic name `pair-<i>-<j>-<h12>-<h12>`; if that directory exists but was skipped as unreadable it raises `PT-NWAY-PAIR` naming it ("exists but cannot be read; repair or remove it"). Other skipped siblings become warnings in the CLI JSON `warnings[]` (`skipped sibling <name>: <reason>`), exit code 0.
3. `save(series, path, *, replace_corrupt=False)`: if `load(previous)` raises `PT-NWAY-STORAGE` and `replace_corrupt` is false, re-raise with the extra sentence "use --replace-corrupt to keep a copy and replace it". With the flag: copy the damaged bytes to `series.json.corrupt-<sha256[:8]>` (O_EXCL, never overwrite), then proceed. A readable file of another series still raises (unchanged). New CLI flag `series create --replace-corrupt`. The GUI never calls `save`.
4. `staleness()` catches `(NwayError, ValueError, OSError, sqlite3.Error)` per pair and records a reason; one bad pair never stops evaluation of the others (reasons list gains a stable prefix `pair i→j:`).
5. `load()` (series.json itself) failing is a **whole-view** failure (state `failed`, section 5), not a per-pair one: without it nothing can be shown.

## 5. View-model (`nway/view_model.py`)

```python
ViewState = Literal['empty', 'loading', 'ready', 'partial', 'stale', 'failed']

@dataclass(frozen=True)
class HopView:
    from_ordinal: int; to_ordinal: int
    label: str                   # '<from label> -> <to label>'
    category: str; match_types: tuple[str, ...]; ratio_text: str | None; manual: bool
    from_name: str; to_name: str # name or '0x<addr>'; never invented
    score: int | None            # attention 0..100 of the hop's pairing, None = not available
    rank: int | None; of: int | None   # position in that pair's ranking
    score_state: Literal['scored', 'unchanged', 'no-ranking', 'pair-unavailable', 'stale-ranking', 'not-ranked']
    match_id: str                # for 'open pair at this function'
    pair_state: PairState

@dataclass(frozen=True)
class ChainRow:
    chain_id: str; title: str; hops: tuple[HopView, ...]
    status: str; stale: bool; weakest_match_type: str; gaps: tuple[int, ...]
    events: tuple[ChainEvent, ...]
    max_score: int | None; sum_score: int | None   # over scored hops only; None if no hop scored
    scored_hops: int; total_hops: int
    degraded: bool              # any hop pair_state not in ('ok',) or score_state in ('no-ranking','stale-ranking','pair-unavailable')

@dataclass(frozen=True)
class SeriesView:
    state: ViewState; message: str
    builds: tuple[BuildRef, ...]; pairs: tuple[PairHealth, ...]   # PairHealth(from,to,state,reason)
    rows: tuple[ChainRow, ...]; total_chains: int; hidden_by_filter: int
    truncated: bool            # rows capped at MAX_ROWS=5000 for display only
    warnings: tuple[str, ...]

@dataclass(frozen=True)
class ViewQuery:
    text: str = ''             # case-insensitive substring over names/addresses/labels, <= 200 chars
    status: frozenset[str] = frozenset()      # inferred/confirmed/contradicted; empty = all
    event: frozenset[str] = frozenset()
    only_stale: bool = False; only_scored: bool = False; min_score: int = 0
    sort: Literal['max-score','sum-score','hops','name','chain-id'] = 'max-score'
    descending: bool = True

def load_view(series_path: Path, reader: PairReader, cancel: threading.Event, live=None) -> LoadedSeries
def apply_query(loaded: LoadedSeries, query: ViewQuery) -> SeriesView      # pure, O(chains log chains)
```
`load_view` pseudocode:
```
try: series = series_store.load(series_path)       # NwayError -> LoadedSeries.failed(message)
except NwayError as e: return failed(e)
stale = series_store.staleness(series, series_path)   # tolerant per section 4.4
wanted = {pair_i: frozenset(edge.match_id for chain in series.chains for edge in chain.edges
                            if edge.from_node.ordinal == i and not edge.match_id.startswith('raw:'))}
snaps = []
for ref in series.pair_projects:                   # direct_project is not ranked: it only confirms/contradicts
    if cancel.is_set(): raise NwayCancelled
    snaps.append(reader.read(root, ref, hashes[i], hashes[i+1], wanted[i]))
score(edge): raw edge -> 'unchanged'; pair state missing/unreadable/locked/mismatch -> 'pair-unavailable';
             snapshot.ranking None -> 'no-ranking' / 'stale-ranking' (by note); entry absent -> 'not-ranked'; else scored
```
State derivation (first match wins): `failed` (series.json unreadable or invalid) > `empty` (valid file, zero chains: message "No 1:1 chain across 3 or more builds was found in the stored pair results") > `stale` (every pair affected or `staleness.reasons` non-empty and no pair `ok`) > `partial` (any pair state != ok, any skipped sibling, or any chain `degraded`) > `ready`. `loading` is produced by the window only. `stale` and `partial` still show rows; their banner names affected pairs ("pair 2->3: locked by another PatchTrace window").
Ordering and determinism: default sort `max-score desc`, ties `sum-score desc`, then `chain_id` ascending; chains without any score sort after scored ones under score sorts. Identical inputs give identical `SeriesView` (tested). No score is ever averaged across pairs for ranking purposes: `max_score`/`sum_score` are display aids, labelled "highest hop" and "sum of hops", and never presented as a probability or a chain-level attention/1 score.

## 6. Qt module (`ui_series.py`) and states

`SeriesWindow(QMainWindow)`: non-modal, one instance per series path, parented to `MainWindow` only for lifetime. Layout (QSplitter): left toolbar+filter row and chain table (columns: Chain, Hops, Highest hop, Sum, Status, Events, Stale); right detail pane with the selected chain's hop table (Hop, From, To, Category, Match types, Ratio, Score, Pair state) and a banner area above the table. Buttons: `Open pair at this function` (enabled for a selected hop whose pair is `ok`/`changed`, emits `open_pair_requested(path, match_id)`; MainWindow decides to switch projects with its usual unsaved-work prompts), `Copy chain` (plain text with labels, ordinals, hashes' first 12 hex chars), `Reload`.
`SeriesLoadThread(QThread)`: runs `load_view` with its own cancel `threading.Event`; emits `loaded(object)`/`failed(str)`; `closeEvent` sets cancel and `wait(2000)`, then `deleteLater` after `finished` (must not repeat the audit's open "inspection thread teardown" defect). Filtering/sorting re-runs only `apply_query` on the main thread (cheap; no re-read of disk).
States and what the window shows:
| State | UI |
|---|---|
| empty | Table hidden; centered message; Reload enabled |
| loading | Indeterminate progress bar; table disabled; Cancel closes the load |
| ready | Table + detail |
| partial | Banner (warning role + text label, not color alone) listing pair problems; table + detail; scores for unavailable hops shown as "n/a" with the reason in the cell tooltip |
| stale | Banner "Stored chains are out of date for: ... Re-run `patchtrace series create`"; table shown with stale column marked; Open-pair stays enabled |
| failed | Message with the `PT-NWAY-*` code and a one-line remedy; no table |
Strings from series/projects (labels, function names) are rendered as plain text (`Qt.PlainText`, `setTextFormat`), never rich text. Window geometry persists in OS settings only.

## 7. Tooltip IDs (registry entries with What/Why/Effect/Source/Availability)

`action.series`, `series.window` , `series.reload`, `series.filter_text`, `series.filter_status`, `series.filter_event`, `series.only_stale`, `series.only_scored`, `series.min_score`, `series.sort`, `series.chain_table`, `series.hop_table`, `series.open_pair`, `series.copy_chain`, `series.banner`, `series.score_cell` (template: state + reason, values escaped via `template()`), `series.pair_state` (template). Source text for scores must say: "Attention score from the pair project's stored default-profile ranking (research prioritization, not exploitability). Not combined across pairs." Chain tooltips say a chain is a labelled hypothesis. Required test edits: add `SeriesWindow` to `roots` in `test_every_registry_id_is_applied_somewhere` and a `series` case to the widget-enumeration audit in `tests/test_tooltips.py`.

## 8. Performance and limits

Series cap is already 100,000 nodes / 8 builds. Targets (Linux, offscreen): `apply_query` over 20,000 chains < 150 ms; `load_view` over 7 pairs with 50,000 matches each < 6 s dominated by `ProjectService.open` + `quick_check` (measure; do not parallelize across pairs because each open holds a lock and a thread-confined SQLite connection). Table uses a `QAbstractTableModel` over `rows` (no per-row widgets); `MAX_ROWS` display cap 5000 with `truncated` banner and "refine the filter". Memory: `PairSnapshot.ranking` is held only until `HopView` creation, then released; names are copied only for ids in chains (`wanted`). Reload while loading cancels the previous thread first.

## 9. Tests

Pure (no Qt), `tests/test_nway_view_model.py`: ordering/determinism and tie-breaks; every `score_state` incl. raw edges; `max_score` None when nothing scored; state precedence table; filter combinations; injected fake `PairReader` returning each `PairState`; one pair `locked` leaves the other hops scored; cancel mid-load; strings with control characters unchanged in model but flagged by tooltip template test. `tests/test_nway_series.py` additions (red first): `discover_pairs` with a garbage `project.sqlite3` sibling and a locked sibling returns the real pairs plus `skipped`; `series create` exits 0 with warnings; deterministic target name collision with an unreadable dir exits 2; `save` over corrupt file refuses, `--replace-corrupt` keeps `series.json.corrupt-*` and writes valid file, second replace never overwrites the first copy; `staleness` with a truncated sqlite file reports a reason and still evaluates other pairs. Qt, `tests/test_ui_series.py` (`QT_QPA_PLATFORM=offscreen`, pytest-qt): each of six states via a fake reader; filter/sort update without disk access (reader call count unchanged); Open-pair signal payload; close during load tears down the thread without warnings; plain-text rendering of `<b>x</b>` labels; tooltip audit. Native: extend the existing three-build Windows fixture job to open `SeriesWindow` offscreen against the real series and assert at least one scored hop.

## 10. PR breakdown (small, mergeable, spec first)

| PR | Content | Tier |
|---|---|---|
| 1 | This spec + update `docs/modules.md` rows (`nway.pair_access`, `nway.view_model`, `ui_series`) and `tasks/todo.md` | low-cost |
| 2 | `series.py` tolerance (section 4) + CLI `--replace-corrupt` + red/green tests; no GUI | mid-tier |
| 3 | `pair_access.py` + `view_model.py` + pure tests (fake reader, real-disk reader test with fixture pairs and a stored ranking) | mid-tier |
| 4 | `ui_series.py`, `ui.py` hook, tooltips, offscreen tests, Open-pair wiring | mid-tier (single `ui.py` owner) |
| 5 | Windows native assertion, frozen-EXE smoke of the window, `docs/qa.md` evidence | low-cost for CI edits; manual DPI pass stays an open gate (C8) |
Gate for every PR: focused tests, `QT_QPA_PLATFORM=offscreen python -m pytest -q`, `python -m ruff check src tests tools`, Linux + Windows CI. Escalate to top tier only if PR 3 shows `load_default` cannot be read without the writer lock (then a read-only `ProjectStore` open is a security-relevant persistence change).

## 11. Decisions made here (revisit only on objection)

Read-only window; no auto-run of missing pairs from the GUI; direct first-to-last pair is not ranked; scores never aggregated into one chain score; locked pairs degrade to "no score" instead of blocking; `series create` stays the only writer of `series.json`; corrupt `series.json` is preserved, not silently replaced.
