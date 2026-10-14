# PT-WB-01: Advanced Investigation Search (SQLite FTS5 + optional RapidFuzz)

**Status:** Developer-ready design, not implemented. **Scope:** offline search of existing project evidence, functions and subsequent optional FLOSS records. **Version:** `workbench-search/1`. **Date:** 2026-10-14. **Parent:** [workbench integration index](README.md).

## 1. Goal and scope

Implement one Search tab/dock in the existing comparison window that searches indexed *project-owned* facts: function names, normalized Ghidriff decompiled C, assembly where present, import/export names already parsed by PE overview, annotation text, future graph labels and FLOSS string records. A result selects the current matched function, artifact side and approximate text occurrence, or opens the relevant metadata/string evidence. Never claim to search every function in a binary: current `ComparisonProject.matches` primarily includes changed/unmatched functions, so **coverage must say exactly which analyzed functions are indexed**. Add unchanged functions only after a validated complete-function enumeration source exists.

### Out of scope first release

Do not build a new decompiler, replace Ghidriff, implement arbitrary SQL, index all raw bytes, process remote records, or add a new matching engine. No search across other projects by default; it is a later opt-in corpus feature with separate consent/privacy design.

## 2. Confirmed current repository seams

- `src/patchtrace/models.py` defines `FunctionRecord` with name, address, address_space, code, assembly, callers, callees and metadata; `FunctionMatch` groups old/new records and carries run_id, category, review, manual state.
- `src/patchtrace/normalization.py` produces records from Ghidriff `functions.added/deleted/modified`. Data can be incomplete for unchanged functions.
- `src/patchtrace/persistence.py` has a ProjectStore with writer/thread ownership, backup and snapshot validation. Do not attach mutable FTS virtual tables to the canonical project data as a first step.
- `src/patchtrace/ui_evidence.py` provides `WindowPort.key()` (project path/id/revision/run/older SHA/newer SHA), `WindowPort.select_match()` and cancellable dock/worker patterns. Reuse these and `src/patchtrace/tooltips.py`.
- `src/patchtrace/cli.py` dispatches headless commands; new `search` command only via thin adapter maintaining existing exit codes 0/2/3/4/5 and one-object --json stdout contract.
- Existing `enrichment.identity.domain_id` creates stable record IDs. Search index remains entirely disposable.

## 3. External dependencies and fallback

SQLite's FTS5 extension is bundled in many Python sqlite3 builds but must be capability-probed in the **actual PyInstaller Windows runtime**, not assumed. Detect `sqlite_compileoption_used('ENABLE_FTS5')` where meaningful and attempt creation/query of an in-memory virtual table; this is authoritative. Separately test whether `tokenize='trigram'` is available. Use `unicode61` full-text for the default mode, with optional trigram for substring searches; trigram queries shorter than three Unicode characters are unsupported and fall back only to bounded exact name filtering.

RapidFuzz, licensed MIT, is optional for fuzzy symbol/name suggestions only. Pin/test an actual released wheel for Python 3.12 Windows x64 and inspect PyInstaller hooks; if unavailable, exact/FTS continues to work. A missing or broken optional library is shown as `fuzzy-unavailable`, never reported as zero search matches. Do not import RapidFuzz when opening the project.

Official FTS5 SQL query reference: https://www.sqlite.org/fts5.html
RapidFuzz process reference: https://rapidfuzz.github.io/RapidFuzz/Usage/process.html

## 4. Domain contracts (Pydantic v2, strict/frozen, extra='forbid')

```python
class SearchSourceRef(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra='forbid')
    project_id: str
    revision: int
    run_id: str | None
    older_sha256: str
    newer_sha256: str
    match_id: str | None
    function_id: str | None
    artifact_side: Literal['older','newer'] | None
    field: Literal['name','decompiled','assembly','annotation',
                   'import','export','floss-string','other']
    source_record_id: str
    source_sha256: str | None = None
    range_start: int | None = None  # text character offset or source-specific RVA
    range_end: int | None = None
    coordinate_system: Literal['text-char','rva','file-offset','unknown']
class SearchRequest(BaseModel):
    query: str
    mode: Literal['words','phrase','substring','name-fuzzy']
    fields: tuple[str, ...]
    sides: tuple[Literal['older','newer'], ...]
    categories: tuple[str, ...]
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0, le=5000)
class SearchHit(BaseModel):
    id: str
    ref: SearchSourceRef
    display_title: str
    plain_snippet: str
    match_spans: tuple[tuple[int,int], ...]  # offsets into snippet, never HTML
    engine: Literal['fts5','trigram','rapidfuzz','bounded-exact']
    score: float | None   # native rank, never a calibrated certainty
class SearchResult(BaseModel):
    contract: Literal['workbench-search/1']
    status: Literal['ok','partial','no-results','indexing','unsupported','stale','error','cancelled']
    coverage: dict[str, int | str | bool]
    hits: tuple[SearchHit,...]
    has_more: bool
    warnings: tuple[str,...]
```

Persist the search index generation key: `(project_id, project_revision, latest_run_id, older_sha, newer_sha, match_override_digest, annotation_digest, extra_source_digest, index_schema_version, sqlite_version)`. A changed key makes prior results stale; no user-visible result may navigate to a mismatched project or run.

## 5. Storage model: disposable, not authoritative

Use `search/index.py`, `search/contracts.py`, `search/extract.py`, `search/query.py`, `search/fuzzy.py`, `search/view_model.py` and `ui_search.py`.

Build one SQLite index per project revision in an application cache directory with a user-specific hashed project identity, or a safe project-local derived cache whose storage is explicitly excluded from portable backups. Directory selection goes through existing `safe_path` and permission controls; no raw arbitrary user-supplied paths. It must be rebuildable solely from verified project rows and immutable optional source records.

A minimal schema:

```sql
CREATE TABLE search_meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE search_docs(
  rowid INTEGER PRIMARY KEY,
  doc_id TEXT NOT NULL UNIQUE,
  source_json TEXT NOT NULL,
  kind TEXT NOT NULL,
  artifact_side TEXT,
  function_id TEXT,
  match_id TEXT,
  field TEXT NOT NULL,
  title TEXT NOT NULL,
  text_sha256 TEXT NOT NULL
);
CREATE VIRTUAL TABLE search_fts USING fts5(
  title, body, tokenize='unicode61'
);
```

Use aligned `rowid` between `search_docs` and `search_fts`, but do not assume any rowid is stable across rebuilds; `doc_id` and evidence location must remain stable. For simple first release, FTS5 stores its own body; enforce size quotas and allow reduced indexing when quota is reached (explicit partial coverage). No hidden triggers required. Optional trigram index is separate; **do not** enable by default before frozen Windows footprint measurements.

The indexing worker receives an immutable snapshot produced on the ProjectService owner thread, then builds a brand-new `.staging` SQLite database using its *own connection*, inside a controlled cache location. This writer never touches `project.sqlite3`. Commit and `PRAGMA quick_check`, close all readers/connections, atomically replace index generation file where the target OS supports it, or publish a generation-specific filename with an atomic pointer in the cache directory. Never replace a live Windows SQLite file while a reader holds it open. Cache files are considered untrusted and must be revalidated before use. Abandon partial builds on cancel. No network operations.

Indexing must be stable: source records sorted by `(side,match_id,function_id,field,source_record_id)`, immutable hashed metadata. Duplicate identical documents stored once but same text originating from different functions stays distinguishable. Always recheck the current `WindowPort.key` or equivalent guard before publishing UI results.

## 6. Safe query grammar and ranking

`MATCH ?` parameterization protects SQL values but **does not** make user text a safe query DSL: arbitrary MATCH syntax can error or expand work. Default parser creates a safe, quoted, length-limited FTS expression from user words; quotes/punctuation are escaped according to FTS5 grammar. Allow explicit `mode='phrase'` with a safely quoted single phrase. No raw `MATCH` operator exposure in first release. Token max 20, request Unicode scalar length max 256, reject NUL, surrogates, bidi controls, empty-only tokens and excessive wildcards. No Python regex execution from user input.

Search fields are selected from an enum, never SQL identifiers taken directly from user input. Query example:

```sql
SELECT d.doc_id,d.source_json,d.title,
       snippet(search_fts,1,'[',']','…',24) AS fragment,
       bm25(search_fts,2.0,1.0) AS relevance
FROM search_fts
JOIN search_docs AS d ON d.rowid = search_fts.rowid
WHERE search_fts MATCH ?
  AND (? IS NULL OR d.artifact_side = ?)
ORDER BY relevance ASC,d.doc_id ASC
LIMIT ? OFFSET ?;
```

This is an illustration, not a license to display delimiter-wrapped source markup as rich HTML. The UI strips/records highlight spans and sends **plain text only**. Arbitrary original text can contain `[` and `]`; robust span highlighting should be computed from tokenizer offsets or a trusted transformation, with fallback to plain snippet if ambiguous.

Filters: side, category, current run, exact function, match review state, future source type, scope `changed-only` vs `all-indexed`. FTS5 bm25 orders lower-is-better; this is text relevance, not patch significance. Combine patch priority only as a separate UI-sort column, never as a probability.

Fuzzy mode: build a bounded vocabulary from at most 100k *unique function/symbol names*; use `rapidfuzz.process.extract(query,names,limit=20,score_cutoff=75)` with a fixed processor/casefold, stable tie sort and timeout/worker budget. Do not run fuzzy comparisons across entire decompiled bodies. Return candidate name hits labelled `approximate-name`; no fake exact occurrence span.

## 7. UI and CLI

Place a **Search** tab within the existing comparison workspace/dock pattern; one `QLineEdit` with `Ctrl+F` only if it does not override existing code-pane search, otherwise `Ctrl+Shift+F`. Modes: Words, Phrase, Filename/name, Substring (if supported), Similar names. Side toggles, fields chips, category selector; search result count, coverage line, `Indexing…`, stale warning. A row displays `Side | Function | Kind | Match/category | Snippet | Source`. Enter/double-click selects match via WindowPort and jumps within current pane when coordinates are grounded. If function not navigable, open read-only detail with source and a reason; never silently jump to a similar name.

CLI extension: `patchtrace search PROJECT --query "Validate" --mode words --side newer --limit 25 --json`. Exactly one contract object to stdout with exit 4 only when index coverage is **complete and zero results**. Status `partial` is not exit 4; use existing status policy and warnings. Worker/outcomes must remain deterministic and work without Qt.

Tooltips show What, Why, Effect, Source and Availability; key accessible actions, keyboard-first focus, zero HTML injection.

## 8. Performance and failure gates

MVP target: 10k indexed documents and 10MB text indexed in <=10s on reference CI hardware; warm typical word query p95 <=250ms; max 200 results/page, limit 32MB memory additional for indexing chunks, default 256MB derived cache/project, bounded 1MB per source field (oversized documents recorded as truncated coverage, original remains accessible). Measure before promoting goals to release promises. UI query debounce ~250ms, generation ID on each query, stale responses ignored; cancel thread cleanly. SQLite busy, FTS unavailable, disk full or corrupt index => actionable status and reindex option, never project corruption.

## 9. TDD fixtures and acceptance

Create `tests/test_search_contracts.py`, `test_search_index.py`, `test_search_query.py`, `test_search_ui.py`, `test_search_cli.py`.

Fixtures: synthetic changed and deleted functions; one string in only old binary; two same-named functions on same side; FTS punctuation injection, apostrophes and surrogate inputs; no unchanged function inventory; missing Ghidriff assembly; invalid old/new hash; stale run, orientation swap, manual match correction; 11k docs; FTS5 absent/trigram absent; fuzzy missing; interrupted build and crash before atomic publish; SQLite corruption and backup restore without index; path traversal attempt; searchable local data stays offline; UI keyboard navigation, close-on-worker, HTML-looking source text and high DPI. Golden JSON schema comparison, determinism under source input order permutation.

Definition of done: existing `rank`, `correlate`, UI evidence, export and stored projects unchanged; search works offline on previously analyzed project with no extra provider; Windows frozen ZIP search smoke passed; exact match click opens correct original function; full coverage accurately described. Never mark `complete` based solely on Linux pytest.
