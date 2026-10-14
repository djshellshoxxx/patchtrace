# WB1 integration plan: unified indexed search ("find anything": SQLite FTS5 + RapidFuzz + QCompleter)

Research output, 2026-10-14, base `d972125` (`prep/program-e`). Reviewed: `workbench/01`, `workbench/04` (QW1, QW2, QW5), `plans/workbench-search-graph-floss-implementation.md` and the code they name. "Probe" = scratch scripts run in this session on a 4 vCPU Xeon 2.1 GHz, CPython 3.12.3, SQLite 3.45.1 (nothing committed; slice S0 ships `tools/bench_search.py` to reproduce them). `[F#]` points into the facts table.

## 1. Verdict and scope
- Build a **find-anything layer**, not a name filter: a pure `patchtrace.search` service turns one safe query plan into explained, side-aware, pair-expanded **leads** over what the project already owns: function names (raw and demangled), signatures, decompiled text, Ghidra strings/symbols, imports/exports, PE and build facts, tool evidence (FLOSS strings, capa rules, DiE), analyst notes, findings, CVE/KB/advisory text and CWE terms.
- Consumers: a Search dock in the single window, `patchtrace search`, and other tracks (PIL anchors, GDE lessons).
- The index is a **disposable segmented cache**: one immutable SQLite file per source group, named by content digest, in the per-user cache dir, never in `project.sqlite3`. FTS5 `unicode61` for words (with index-time identifier splitting), `trigram` for short-name substrings. Staleness = "expected digest file missing"; incremental = rebuild only groups whose digest changed.
- Ranking is **explained lexicographic tiers** (match tier, change class, independent-source count, attention/1 ordinal, native bm25 inside one table, name); no blended number is ever shown. RapidFuzz is optional and names-only: typo suggestions and mutual-nearest "probable counterpart" hints as integer edit distances, never as matches.
- Deliberately NOT built: cross-project corpus search, regex or raw FTS5 syntax, semantic/embedding or body-similarity search, fuzzy over code, percentage "confidence", disassembly search before unified IR exists (Ghidriff stores a hash only [F20]), any network use, any project write except analyst-saved searches.

## 2. Sources and facts
| # | Claim | Source URL | Retrieved | Conf. |
|---|---|---|---|---|
| F1 | CPython 3.12 Windows `sqlite3.dll` is compiled with `SQLITE_ENABLE_FTS5` (also FTS4, RTREE, MATH_FUNCTIONS) at 3.12.0 and at the 3.12 branch head | https://raw.githubusercontent.com/python/cpython/3.12/PCbuild/sqlite3.vcxproj ; same path at tag `v3.12.0` | 2026-10-14 | high |
| F2 | Bundled Windows SQLite: 3.42.0.0 (3.12.0), 3.45.3.0 (3.12.4, 3.12.9), 3.49.1.0 (3.12 head). CI runs `setup-python` `3.12` on `windows-latest` and `ubuntu-latest` (`qa-windows.yml`), so the frozen SQLite is whatever that runner's 3.12.x bundles [unverified which patch]; `search --probe` records it per build. Design floor: nothing newer than SQLite 3.37 (frozen Linux build host Ubuntu 22.04 [unverified: 3.37.2, package page not fetchable]); no `contentless_delete` [unverified: added after 3.42, sqlite.org blocked] | https://raw.githubusercontent.com/python/cpython/v3.12.0/PCbuild/get_externals.bat (also `v3.12.4`, `v3.12.9`, `3.12`); `.github/workflows/qa-windows.yml` | 2026-10-14 | high; floor medium |
| F3 | Linux here: SQLite 3.45.1 with `ENABLE_FTS5`; tokenizers unicode61/ascii/porter/trigram; `detail` full/column/none; fts5vocab; `Connection.setconfig` exists in 3.12. `sqlite_compileoption_used` plus a throw-away `CREATE VIRTUAL TABLE` is the authoritative probe | probe `sqlite_probe.py`; https://www.sqlite.org/fts5.html [unverified: host blocked] | 2026-10-14 | high |
| F4 | The repo pins PyInstaller 6.22.3 (`pyproject.toml`); its `hook-sqlite3.py` collects Python submodules only; `libsqlite3`/`sqlite3.dll` come from the build host's Python. Frozen Linux one-folder probe: bundles `libsqlite3.so.0`; FTS5, unicode61, trigram and LIKE-on-trigram all true | https://raw.githubusercontent.com/pyinstaller/pyinstaller/v6.22.3/PyInstaller/hooks/hook-sqlite3.py ; probe `frozen_probe.py` | 2026-10-14 | high Linux; Windows [unverified until first CI run] |
| F5 | Trigram is built in; its LIKE/GLOB index path exists only for plain trigram (not with `remove_diacritics`); with `detail!=full` any multi-term phrase, NEAR or `^` is rejected ("queries are not supported (detail!=full)") | https://raw.githubusercontent.com/sqlite/sqlite/master/ext/fts5/fts5_tokenize.c ; `.../fts5_expr.c` | 2026-10-14 | high |
| F6 | Raw `MATCH` is a DSL: column filters, NEAR, `^`, `-`, parentheses are accepted; dangling operator, unterminated quote, unknown column raise `OperationalError`; a lone surrogate raises `UnicodeEncodeError` at bind. Wrapping every term in double quotes (inner `"` doubled) made all 26 hostile inputs run harmlessly | probe `bench_fts2.py` | 2026-10-14 | high |
| F7 | `LIKE ... ESCAPE` on a trigram table loses the index (224-279 ms per scan at 1M rows vs 0.1-0.8 ms indexed without ESCAPE at 300k rows) and unescaped `_` `%` are wildcards. A quoted-phrase `MATCH` on `trigram detail=full` is literal and fast (0.1-0.4 ms, 100k names, 8.6 MB) | probe `bench_fts4.py`, `bench_fts5.py` | 2026-10-14 | high |
| F8 | `unicode61 remove_diacritics 2` folds case and diacritics and splits on `_ @ ? : \ ! + -`, keeps `0x7fffffff` whole and splits GUIDs on hyphens, but does NOT split CamelCase (`RtlCopyMemory` is one token), full-width forms, or fold `ß`. `?Validate@CFoo@@QEAAHXZ` -> validate, cfoo, qeaahxz | probe via `fts5vocab` | 2026-10-14 | high |
| F9 | `bm25()` is negative (lower is better) and costs O(matches): a token in 150k of 1M strings = 98-330 ms for the top 50, while a capped count (`LIMIT 20001`) = 1.6-19 ms. Plain bm25 over code text ranked an unchanged decoy above the changed function (-3.45e-06 vs -2.70e-06) | probe `bench_fts.py`, `bench_fts4.py`, `synergy_probe.py` | 2026-10-14 | high |
| F10 | Cost, synthetic: 100k names 0.9 s / 8.6 MB (with split-words column); 1M strings (33 MB) 3.2 s / 75 MB (2.2x); trigram detail=column 1M 14.5 s / 158 MB; 30k decompiled-like bodies (72 MB) 1.6 s / 118 MB (1.65x), plus memoised identifier column 7.5 s / 149 MB (2.08x; 23 s without memoising); `instr()` scan of 1M strings 245-258 ms, aborted in 50 ms by `Connection.interrupt()` | probe `bench_fts*.py` | 2026-10-14 | medium (one machine; budgets add 3x slack) |
| F11 | FTS5 works under a hardened read-only open (`mode=ro&immutable=1`, `trusted_schema=OFF`, `query_only`, DEFENSIVE, fail-closed authorizer) only if the allow-list has functions `match bm25 snippet highlight count char instr lower length`, reads of tables and FTS shadow tables, and `PRAGMA data_version` (FTS5 issues it); ATTACH, DDL, DML, `load_extension`, FTS `rebuild` stay denied. Precedent `secondary/bindiff.py:57-78` | probe `authorizer_probe.py`; repo | 2026-10-14 | high |
| F12 | RapidFuzz 3.14.6 (PyPI 2026-08-30): MIT (`license_expression`; LICENSE (c) Max Bachmann, (c) Adam Cohen), Python >=3.11, no required dependency (numpy optional), wheels cp312 `win_amd64` 1.73 MB and `manylinux_2_28_x86_64` 3.17 MB; a build without CMake falls back to pure Python, so `--only-binary=:all:` is mandatory | https://pypi.org/pypi/rapidfuzz/json ; https://raw.githubusercontent.com/rapidfuzz/RapidFuzz/v3.14.6/pyproject.toml and `/LICENSE` | 2026-10-14 | high |
| F13 | RapidFuzz picks its backend at import (`fuzz.py`: avx2, sse2, cpp, else pure Python through `suppress(ImportError)`; `RAPIDFUZZ_IMPLEMENTATION` forces one). No PyInstaller hook in PyInstaller 6.22.3 or pyinstaller-hooks-contrib (both 404); its `pyinstaller40` entry point only registers tests. Frozen Linux probe loaded `rapidfuzz.fuzz_cpp_avx2` and `distance.metrics_cpp_avx2` (+12 MB) | https://raw.githubusercontent.com/rapidfuzz/RapidFuzz/v3.14.6/src/rapidfuzz/fuzz.py ; probe | 2026-10-14 | high Linux; Windows [unverified] |
| F14 | Over 63-77k unique names: `Levenshtein.distance` 3.6-6.5 ms, `OSA.distance` ~9 ms (a transposition is 1 edit), JaroWinkler 5-6.5 ms, QRatio 4.5-6 ms, partial_ratio 22-47 ms, WRatio 47-66 ms. `process.extract` orders equal scores by choice index (deterministic) | probe `rf_probe.py`; https://raw.githubusercontent.com/rapidfuzz/RapidFuzz/v3.14.6/src/rapidfuzz/process_py.py | 2026-10-14 | high |
| F15 | Qt 6.12.0 `QCompleter::eventFilter` forwards `ShortcutOverride` to the widget and closes the popup on `QKeySequence::Cancel`. PySide6 6.12.0 connects `activated[QModelIndex]`; the `UserRole` payload survives the completer proxy, while `currentCompletion()` returns display text only (duplicate labels are indistinguishable) | https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/widgets/util/qcompleter.cpp ; probe `qt_probe2.py` | 2026-10-14 | high |
| F16 | `MainWindow.cancel_action` ("Cancel job") owns `Escape` and is enabled while a worker runs (`ui.py:1529`, `:3002`). Probe: Esc in a plain `QLineEdit` fires it; accepting `ShortcutOverride` in the field suppresses it. Real popup + Esc on Windows is a manual gate | repo; probe `qt_probe1.py` | 2026-10-14 | high (offscreen) |
| F17 | `QCompleter` over a 100k-name `QStringListModel`: sorted prefix 0.0 ms, unsorted prefix 0.1-11 ms, contains 0.2-22 ms, construction 17-20 ms | probe `qt_probe1.py` | 2026-10-14 | high |
| F18 | `canFetchMore`/`fetchMore` is the documented incremental-model contract (`beginInsertRows` required). Probe: `QTableView` fetched 200 rows at show and 200 more per scroll-to-end | https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/corelib/itemmodels/qabstractitemmodel.cpp ; probe | 2026-10-14 | high |
| F19 | Qt 6.12.0's Windows platform plugin routes accessibility through UI Automation (`QWindowsUiaAccessibility`). Narrator/NVDA output is not testable here | https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/plugins/platforms/windows/qwindowsintegration.cpp ; https://learn.microsoft.com/en-us/windows/win32/winauto/entry-uiauto-win32 [unverified: host blocked] | 2026-10-14 | high / [unverified] |
| F20 | Ghidriff's saved JSON replaces `instructions`/`mnemonics`/`blocks` by hash ints (the normalizer records `assembly_unavailable`); raw `strings`/`symbols` carry added/deleted only; `matches.name_matches` exists. No committed real fixture covers these shapes | `docs/research.md:24-50`; `docs/research/unified-engine/03-ghidriff-rizin.md:53-60`; `src/patchtrace/normalization.py:55-62` | 2026-10-14 | medium |
| F21 | A project is one JSON snapshot (<=256 MiB) in `project.sqlite3`; `ProjectStore.backup` copies only the DB, `artifacts/`, `runs/`, `exports/`; `ProjectLock` makes a second opener (the CLI) fail while the GUI holds the project | `src/patchtrace/persistence.py:30,225-266,504-534` | 2026-10-14 | high |
| F22 | Tool evidence keeps `display_value` <=256 chars, `secret_kind`, and `project_function_id` only when exactly one record starts at the RVA; `delta.py` classes: newly-introduced, newly-detectable, removed-with-code, no-longer-detected, unlocalized, unknown | `src/patchtrace/intelligence/tools/{common,normalize,delta}.py` | 2026-10-14 | high |
| F23 | `intelligence/anchors.py` already derives labelled search anchors (module, feature, string, component, pdb, api) from advisories as "search hints for the analyst and SPEC-30" | `src/patchtrace/intelligence/anchors.py:1-7` | 2026-10-14 | high |
| F24 | House UI rules: model-owned sort (no proxy), unparented registered `QThread`s, generation counters, `data()` call-count gates with 5x wall-clock slack, a registry tooltip id for every focusable control, `test_every_registry_id_is_applied_somewhere` enumerates dock roots | `ui_evidence.py:1-19`; `tests/test_evidence_perf.py`; `tests/test_tooltips.py` | 2026-10-14 | high |
| F25 | Qt widget accessibility hooks: `accessibleName` (short, localized, emits `NameChanged`), `accessibleDescription`, `accessibleIdentifier` (6.9+, for automated tests), item role `Qt::AccessibleTextRole` | https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/widgets/kernel/qwidget.cpp ; `.../src/corelib/global/qnamespace.h` | 2026-10-14 | high |

Blocked from the sandbox (egress policy, not retried): sqlite.org, docs.python.org, doc.qt.io, code.qt.io, learn.microsoft.com, rapidfuzz.github.io, unicode.org, cwe.mitre.org, arxiv.org, dl.acm.org, github.com pages and API. `raw.githubusercontent.com` (upstream source at tags) and `pypi.org` were reachable and are the evidence base; documentation pages are cited only as `[unverified]` pointers.

**Where the ChatGPT specs are wrong or thin** (details in section 10 amendments):
1. `01` names nothing about identifier splitting: with default `unicode61` its own "Validate" example matches only whole-token names and `copy` never finds `RtlCopyMemory` [F8].
2. `01` §5 stores `source_json` + `title` + `text_sha256` per document (about 300 MB of overhead at 1M strings) and one FTS table for every field, mixing bm25 statistics of unlike corpora.
3. `01` §4 `field` enum has `other` and lacks demangled name, signature, capability, rule, advisory, CVE/KB/CWE and build facts; `range_start/end` assumes text offsets exist for every source.
4. `01` §3 leaves substring as an optional `MATCH` mode, without the `detail=full` requirement and the LIKE/ESCAPE trap [F5, F7].
5. `01` §6 / `04` QW2 use `process.extract(..., score_cutoff=75)` with the default WRatio: 5-10x slower than a bounded edit distance, non-explainable percentages [F14]; no wheel or PyInstaller evidence (now [F12, F13]).
6. `01` §8 "10k docs / 10 MB in <=10 s" (about 1 MB/s) is roughly 10x slower than measured (33 MB of strings in 3.2 s) and says nothing about 100k functions or millions of strings [F10].
7. `01` §4 key uses `project_revision`, but `annotate()`/`review_match()` do not bump `revision` (`service.py`), and one monolithic file rebuilds on every note; per-group digests fix both.
8. `01` §1-§2 and `03`/`04` imply assembly search; real Ghidriff JSON holds a hash only [F20], so instruction text needs unified IR.
9. `01` §7 weighs `Ctrl+F` against a code-pane find that does not exist; the real hazard is `Esc` = "Cancel job" [F16], plus the `MainWindow.search` attribute collision and the CLI project lock [F21].
10. `04` QW5 "dedicated lazy model if >10k functions": Qt handles 100k names in <=22 ms [F17]; the true requirement is id payloads, which a `QStringListModel` cannot carry [F15].
11. Implementation plan §5 `PT-WB-*` differs from repo convention `PT-<AREA>-*`. Correct and kept: disposable index outside the project, `WindowPort.key` guard, plain-text snippets, no raw `MATCH`, unsupported is not zero, offline only, coverage honesty.

## 3. Standalone baseline versus PatchTrace value
| Tool alone | What it gives | What PatchTrace context adds |
|---|---|---|
| SQLite FTS5 | Text index, bm25, snippet, prefix; blind to identifiers (F8), sides, pairs, change | Per-kind tables with index-time identifier splitting, older/newer documents, pair expansion, change-aware explained order, coverage honesty, untrusted-text discipline |
| RapidFuzz | String distance | Only where it adds value: typo suggestions on names, **cross-version renamed symbols** (mutual-nearest removed-vs-added names), never a match, never over auto-named `FUN_`/`sub_` |
| QCompleter | Prefix popup | Suggestions carry exact (kind, side, locator) payloads; choosing one opens that exact function |
| Navigator filter today | Substring on changed-match names | Left untouched; search supersedes it for discovery |

Workflows enabled:
- **W1** fragment/typo/CamelCase/mangled lookup lands on the exact pair (`ValdateAcount`, `copy memory`, `CFoo`).
- **W2** advisory anchors from `anchors_for()` run as typed queries and report which anchors hit changed code first.
- **W3** "who touches API X": callee lists and imports, both sides, with presence per side.
- **W4** rename detective: unmatched removed vs added names give hints that open the existing **Correct match...** dialog.
- **W5** recall of analyst notes and findings by words, labelled by origin.
- **W6** the coverage line says what is NOT searchable and why. **W7** scripts and CI call `search --json` with the same plan and ranking.
- **W8** a lead shows its N-way chain position when `series.json` exists (read-only through `nway.view_model`).

## 4. Cross-feature links
| Anchor kind | Search emits (hit locator) | Search consumes (indexed from) | Other tracks use it as |
|---|---|---|---|
| function | `Locator(function, run, side, function_id, rva)` plus `PairExpansion` | `build_views` (today), `unified.ir.reader` all-function table (UE S1) | WB2 seed node; PIL candidate list; GDE "open this function" step |
| string | `Locator(string, source_ref, rva, file_offset, function_id?)`, `Presence` per side | `ToolEvidenceSet.strings` (WB3), raw Ghidriff `strings` added/deleted | WB3 delta jump; PIL string anchors |
| import/API | `Locator(import or export)`; callee-name evidence on function leads | `pe_overview` imports/exports; `FunctionRecord.callees` names | PIL `api_hints`; WB2 edges; KB "module" anchors |
| capability, rule | `Locator(capability or rule)` with rule id, namespace, ATT&CK | `CapabilityEvidence` (CAP), YARA-X rule meta (YRX), `patch-rules/1` ids | CAP deltas; YRX drafts cite the lead |
| build fact | `Locator(pe-field)` or DiE environment label | `pe_overview` (headers, sections, codeview), DiE `EnvironmentEvidence`, later VERSIONINFO/manifest (WBQ) | DIE noise attribution; KB product mapping |
| advisory phrase, CVE, KB, CWE | `Locator(advisory or cve)` with pointer + `facts_id` | `AdvisoryStore.advisories()`, `cve-snapshot` rows, lexicon CWE names, KB sessions | PIL reads leads; `anchors_for()` output is search INPUT (`search/anchors.py`, S10) |
| note, finding | `Locator(note or finding)` | `project.annotations`, `interpretations` (origin `model`) | GDE; reports |
| pair / change fact | `PairExpansion` (section 7) | live project, `load_default`, unified read model, `delta.compute`, `nway` | FAB triage reads the same fields; nothing is copied into the index |

FAB hand-off: hits expose `anchor_kind` and `anchor_key` (= `Locator` fields) so the synergy architect maps them 1:1. An `AnchorSink` Protocol (`pin(locator, note, provenance)`) is defined but unimplemented; "Pin as lead" stays absent until FAB exists.

## 5. Synergy test (known answer, synthetic, committed-fixture friendly)
`tests/test_search_synergy.py::test_container_size_beats_each_channel`. Builders: `tests/search_builders.py` (S3: synthetic PE pair from `sample.synthetic_pe`, Ghidriff-shaped JSON imported like `frozen_smoke._import_pair`) and `tests/search_synergy_builders.py` (S4: `ToolEvidenceSet`, CSAF facts). No Microsoft binary.
- **F1** `ClfsValidateContainerSize` modified (newer adds `if (container_size > 0x10000) return 0xc000000d;`, BND strong, attention rank 1 of 3). **F2** `ClfsCopyRecordHeader` modified, cosmetic, rank 2. **D** decoy `ClfsDumpState`, unchanged, repeats "container size" six times in log strings and comments.
- FLOSS static string "Container size exceeds limit" exists only in the newer build, located in F1 (`project_function_id`), both runs comparable. Advisory note for CVE-2099-10001: "an oversized container size".
- Query `container size`, scope indexed. Expected leads, in order:
```text
1 function  ClfsValidateContainerSize  tier=1 name-words | change=modified | components=2 [ghidra, floss] | attention/1 rank 1 of 3 | string presence: older absent, newer present | older counterpart shown
2 advisory  CVE-2099-10001 (note)      tier=3 text-words | change=- | components=1 [advisory] | locator none: "No code location"
3 function  ClfsDumpState              tier=4 code-words | change=unchanged | components=1 [ghidra]
```
- Each channel alone must fail: navigator filter `container size` returns 0 rows (substring with a space); plain bm25 over code text returns D first [F9]; the string delta alone lists added strings unranked and unlinked; the advisory alone has no locator; attention ranking alone puts F2 second although it never matches the query.
- Assertions: exact ordered `(kind, title, tier, reasons)` tuples and `rank_reasons` text; no numeric score field anywhere; same order under document-order permutation; the string and F1 form ONE lead; the advisory is not fused to F1 (no structural link, only lexical overlap).

## 6. Traps and guards
| Trap | Guard (and test) |
|---|---|
| Raw text reaches FTS5 `MATCH` (column filters, NEAR, errors) [F6] | Only `parse_query` output reaches SQL: every term double-quoted, enumerated filters, bound parameters; property test: no Unicode input raises `OperationalError` |
| Lone surrogate, NUL, bidi/control characters in query or indexed text | Query: reject with `PT-SEARCH-QUERY`; indexed text: `sanitize_text` escapes them (same rules as `tools.common.display_text`, cross-checked by test); STX/ETX therefore never occur in indexed text and are safe snippet markers |
| CamelCase blind spot makes `copy` miss `RtlCopyMemory` [F8] | Index-time `words` column (memoised splitter), trigram table for mid-word fragments; golden table of 40 names |
| Auto-named `FUN_`/`sub_`/`LAB_` flood and absurd fuzzy hits | `flags.auto` from `sym_source==DEFAULT` and a regex; ranked last in tier, excluded from fuzzy and counterpart hints |
| Fake precision (bm25 or edit counts shown as percent) | No numeric score in contracts or UI; bm25 only orders ties inside one table; fuzzy shows integer edits; attention shown as "rank 3 of 41 (uncalibrated ordering)" |
| Averaging channels / double counting one origin | Lexicographic key tuple; `components` counts distinct origins, so Ghidra name + code = 1 (charter 4) |
| "No results" when something is not indexed | `no-results` only if every requested group is `indexed`, else `partial`; CLI exit 4 only in the first case |
| Claiming whole-binary coverage (unchanged functions, instruction text) | Coverage line names populations; asm segment `unavailable` with the Ghidriff-hash reason; unchanged names only from verified raw tables |
| Stale or forged index navigates to the wrong place | Locator validated against the live project (ownership, run, side, `excerpt_sha256`) before any jump; `PT-SEARCH-LOCATOR` text, never "closest name" |
| Orientation swap / re-import / correction | Group digests include `diff_id` and ordered SHAs; pair data resolved live, so corrections need no re-index |
| Secrets or tokens searchable in clear | Secret-looking strings indexed as `[redacted: kind]` + hash only (`secret_kind`); test with `SECRET_PATTERNS` fixtures |
| Hostile text in titles, snippets, tooltips | Plain text only: `Qt.PlainText`, `drawText`, escaping tooltip templates; spans are integer offsets, never markup |
| Escape cancels a running Ghidriff job from the search box [F16] | `ShortcutOverride` accepted for Esc while the field has text or the popup is open; `test_escape_in_search_never_cancels_job` with an enabled Escape action |
| Duplicate display labels in the completer [F15] | Payload on `UserRole`, `activated[QModelIndex]` only; test with two identical names |
| A very common token costs seconds [F9] | Capped count (20,001) first; above it status `too-broad`, first 200 in index order labelled unranked |
| `LIKE` built from user text (wildcards, ESCAPE scan) [F7] | No LIKE/GLOB anywhere: trigram `MATCH` phrase for names, `instr()` scan with `interrupt()` for the rest |
| RapidFuzz silently pure Python [F13] | `search --probe` and the coverage dialog report the backend; frozen smoke fails unless `cpp-*`; wheels only |
| Fuzzy hit mistaken for a pairing | Block titled "Name suggestions (not matches)"; hint text "names only; open Correct match to decide" |
| Poisoned or corrupt cache file | Hardened open [F11], identity PRAGMAs, `quick_check` once per file version, display text treated as untrusted, live re-verification on open |
| OneDrive upload of derived text / backup bloat | Cache root outside the project root (refused if inside), per-user local dir, excluded from `backup()` by construction [F21] |
| Microsoft-derived text reaches the repository | Caches live outside the repo; fixtures are synthetic; existing Tier-W repository guard stays on |
| Model-generated findings look like evidence | Origin `model` badge, own kind chip, outside the "Code and names" scope; analyst conclusions are origin `analyst` |
| Advisory phrase read as causation | Wording "advisory text matches your query words"; never fused to a function without a structural link |
| Hex/decimal constants miss each other | Integer terms >=16 expand to `0x..` lower-case and decimal; address terms resolve through per-side `image_base` to RVA |
| GIL starvation of the GUI during a build | Yield every 4,096 docs; gate: event-loop latency p95 <=100 ms; fallback: hidden `_worker` subprocess (existing pattern) |
| Disk full, permission, AV lock on Windows | Failed `os.replace` tolerated (an equal existing file wins), staging cleaned, status `PT-SEARCH-STORE` with Retry |

## 7. Contracts
Package `src/patchtrace/search/` (Qt-free) plus `src/patchtrace/ui_search.py`. Models are strict, frozen, `extra='forbid'`; contract strings are emitted names.
```text
SearchKind = function|code|asm|string|import|export|capability|rule|build|advisory|cve|cwe|kb|note|finding
Origin     = ghidra|pe-parse|floss|capa|diec|yara-x|advisory|analyst|model      # independence components
QueryPlan  'search-query/1' (built only by parse_query(); canonical() = sorted NFC JSON -> digest)
  text<=256; terms<=8 (each: nfc, fold); phrases; excludes<=4; last_prefix; kinds; sides; scope indexed|changed; is_; in_ {name,code,signature,text}
  mode auto|words|exact|prefix|substring|similar; identity tuple[cve|kb|cwe|address|sha256|guid|module]
SearchRequest: plan; sort relevance|change|name|address; limit 1..200; cursor (opaque keyset bound to index_key); group=True; expand=True; generation
Evidence: kind; side|None; origin; title<=200; snippet<=300; spans ((start,end),..) into snippet; reasons; locator; seen_by (Origin,..); group; digest16   # provenance
Reason:   code in {exact-id,name-words,name-prefix,name-substring,text-words,code-words,typo,delta,corroborated}; field<=16; detail<=80
Locator:  scheme in {function,string,import,export,pe-field,capability,rule,advisory,cve,note,finding}; run_id; side; function_id; rva; file_offset;
          line_start; line_end; excerpt_sha256; source_ref
Presence: older|newer in {present,absent,unknown}; basis<=120
PairExpansion (resolved live per page, never stored): category; counterparts (FunctionRef..); match_types; quality; manual; review;
          attention {rank,of,formula 'attention/1'}|None; signals<=8; unified {decision,materiality,classes}|None; tool_delta (class..); series|None; limitations
SearchHit (a lead): hit_id; tier; change_class; components; evidence<=6 + evidence_total; presence; expansion; rank_reasons (str..)
CoverageEntry: group; kinds; side; status in {indexed,building,missing,unavailable,failed,truncated,not-applicable}; docs; reason<=200; digest16; built_utc
SearchResult 'search/1': status in {ok,partial,no-results,too-broad,indexing,unsupported,stale,cancelled,error}; coverage; hits; total|None; total_capped; cursor;
          interpreted_as<=300; suggestions (NameSuggestion: name, edits, locator); counterpart_hints (older, newer, edits, shared_words); warnings; index_key; timings_ms
SavedSearch 'search-saved/1' (enrichment kind, append-only rows): saved_id; op create|delete; name<=64; plan|None; of|None; created
```
**Ordering key** (ascending; categorical or ordinal fields only, nothing is added or averaged): `(tier, change_class, -components, attention_rank|inf, table_id, bm25_native, casefold(title), side, rva, doc_id)`. Tier 0 exact identity (full folded name, address/RVA, CVE/KB/CWE/hash/GUID); 1 all terms are whole name words; 2 name prefix or substring; 3 non-name text (string, note, finding, advisory, cve, cwe, kb, build); 4 code text; suggestions are a separate list. Name-like kinds (function, import, export, capability and rule names) live in `fts_name` + `tri_name` and can reach tiers 0-2; `code` in `fts_code`; every other kind in `fts_text`. Change class 0: the pairing is not `unchanged`, or a string/capability delta is added/removed with comparable runs; 1: representation/location changed or changed without an attention row; 2: unchanged or unknown; 3: not function-related. `sort=change` swaps tier and change class. Leads group by pairing (`group=True`), so the two sides of a name hit are one row; bm25 is compared only inside one `table_id`.

**Query grammar** (`parse_query`; anything else is plain text or `PT-SEARCH-QUERY` with a hint, never a guess):
| Syntax | Meaning |
|---|---|
| `word word` | AND of whole words; the last word is a prefix when it has >=2 chars (`interpreted_as` says so) |
| `"two words"` | adjacent phrase (tables with `detail=full`) |
| `-word`, `word*` | exclusion (needs a positive term); explicit prefix (>=2 chars before `*`); no other wildcard exists |
| `kind:string side:newer in:name scope:changed is:modified` | enumerated filters, validated against enums; an unknown `key:` stays text (`std::vector` works) |
| identity terms | `CVE-2024-1234`, `KB5012345`, `CWE-787`, `0x140001a40` or bare hex of >=5 digits that contains a digit (address, RVA or constant), 64-hex SHA-256, GUID, `clfs.sys`: also take the exact-identity tier |
| integers >=16 | queried as `0x..` lower-case and decimal |
| rejected | regex, OR, parentheses, NEAR, column syntax, unbalanced quotes, empty query without a filter (browse needs `kind:` or `is:`) |

**Tokenization decisions**:
| Table.column | Holds | Tokenizer | Why |
|---|---|---|---|
| `fts_name.raw` / `.words` | folded name (NFKC + casefold); words of raw + demangled + MSVC-light `Class::method` (flag `derived`, never shown as the name) | `unicode61 remove_diacritics 2` | splits `_ @ ? :` [F8]; CamelCase and digits split at index time |
| `tri_name.name` | folded name | `trigram`, `detail=full` | mid-word fragments >=3 chars; quoted-phrase `MATCH` is literal [F7] |
| `fts_code.body` / `.idents` | sanitized original decompiled text (NFC, case kept so `snippet()` shows real text); deduped split identifier words | `unicode61`, `detail=full` | `probe` finds `ProbeForRead`; constants stay whole tokens |
| `fts_text.title` / `.body` | strings, notes, advisories (tags stripped), build facts, sanitized original | `unicode61`, `detail=full` | phrases keep adjacency; GUID/path tokens split on punctuation |
Compat-form folding (full-width, ligatures) applies to names only. Highlight spans for names come from a Python case-insensitive scan of the display text (no highlight when folding changes length, never a wrong one); code/text spans come from `snippet(..., char(2), char(3), ...)`. Optional ports extend `words` without changing the contract: a `DemangleProvider` (WBQ QW8) adds its display form to `fn.words`; `pe_overview/version_resources.py` (WBQ QW4) adds VERSIONINFO/manifest fields to the `pe` group as `build` documents.

**Index sources** (every text is capped; display via `sanitize_text`):
| Group | Kinds | Text indexed | Source / read API | Today |
|---|---|---|---|---|
| `fn` | function, code | raw and demangled name (`fullname`, `upstream_name`), `parent`, `sig`, callee/caller names, address text; decompiled body + identifier words (<=2 MB and 20,000 lines per function) | `enrichment.views.build_views` | yes, changed set |
| `raw` | string, function | Ghidra `strings` added/deleted (side = list); `symbols` added/deleted and `name_matches` names of unchanged functions (flags `symbol`, `unchanged`) | hash-verified raw JSON, bounded `strict_json` | shape [unverified] |
| `pe:<side>` | import, export, build | imports `DLL!name`, exports, section names, PDB name, packer hints, machine/subsystem, COFF timestamp (labelled untrusted); later VERSIONINFO/manifest | `pe_overview.inspect_pe` | yes (version/manifest: WBQ) |
| `ann` / `fnd` | note / finding | notes, bookmarks, override reasons (not `validation` JSON) / summary, fix purpose, hypothesis, analyst conclusion | `project.annotations` / `interpretations` | yes |
| `tool:<engine>:<side>` | string, capability, build | FLOSS `display_value` (secrets redacted), capa rule id + namespace + ATT&CK/MBC, DiE category/label/version | `ToolEvidencePort` over `ToolEvidenceSet` | contracts yes; store pending (WB3/CAP/DIE) |
| `adv` / `cve` | advisory, cve, cwe, kb | CSAF title, notes, products, remediation (tags stripped, <=64 KiB); NVD/MSRC descriptions; CWE id + name. All revisions stay indexed; superseded or conflicting ones are flagged, never dropped | `AdvisoryStore.advisories()`, `cve-snapshot` rows | yes |
| `rule` | rule | YARA-X rule name, tags, meta; `patch-rules/1` ids | YRX / PIL ports | later |
| `ir:<side>` | function, asm | all functions incl. unchanged, instruction text with addresses masked, mnemonics, constants hex + decimal | `unified.ir.reader` | later (UE S1) |

**Segment file** `<cache>/search/<sha256(project_id)[:16]>/<group>-<digest16>.sqlite3`: `application_id` 0x50545331, `user_version` 1, `meta` (contract `search-segment/1`, group, digest, tokenizer digest, sqlite version, builder version, docs, bytes, truncated, built_utc), `doc(id, kind, side, subject<=64, display<=200, extra<=200, ref, rva, flags, value_sha)` with indexes on `(kind,subject,side)` and `value_sha`, plus only the FTS tables the group needs. `rowid == doc.id`; no JSON per document; `ref` = ordinal in the group's digest-pinned, sorted source list. Line numbers are never indexed: on activation a GUI-thread slot finds the first line containing a matched term in the live function text and passes it to `reveal_lines`. Built as `.staging-<uuid>`, checked, `os.replace`d to the digest name; open files are never replaced (an equal existing file wins).
- **Digest** = `domain_id('search-seg', 1, {group, builder_version, norm_version, tokenizer_digest, sqlite_major_minor, inputs})` (sqlite version because tokenizer tables may differ between releases [unverified: docs blocked]). Inputs: `fn` = `diff_id`, run id, ordered SHAs, sha256 over sorted `(function id, side, name, address, len(code), len(assembly))`; `raw` = `raw_sha256`; `pe` = artifact SHA; `ann`/`fnd` = sha256 of sorted `(id, kind, text, stale)`; `tool` = `ToolEvidenceSet.cache_key`; `adv` = sorted `facts_id`; `cve` = sorted `snapshot_id`; `ir` = `ir_key`. `WindowPort.key()` still gates which project/run is shown.
- **Lifecycle**: nothing runs at project open. First use (dock shown, CLI call, saved search) builds in cheap-first order `ann`, `pe`, `fn` names, `fn` code, `raw`, `tool`, `adv`/`cve`, `ir`; queries use finished segments and report the rest as `building`. After first use, `project_changed` recomputes expected digests (memoised per revision) and schedules only missing groups; background builds pause while `busy()`, explicit searches still build what they need. Cleanup deletes only derived cache files: unexpected segments older than 10 minutes (errors ignored), closed projects' directories LRU above 4 GiB; project data is never touched, and "Clear search cache..." is the analyst's explicit delete.
- **Pair expansion and presence** (resolved live per page): function leads list counterparts from the live `FunctionMatch` (split/merged/ambiguous are listed, never picked) with category, match_types, quality, manual, review; attention from `load_default` only when current, else "attention/1 rank unavailable: run Rank changes" (unknown, not zero); unified decision/materiality/classes when a current result exists. String-like leads take `Presence` from the sibling `tool:<engine>:<other side>` segment by `value_sha`: `absent` only if that segment is `indexed`, its run `produced` and `comparability()` is clean, else `unknown` with the reason. Raw Ghidriff `added` strings set newer `present` and older `unknown`, never `absent`. Advisory/CVE leads have no pairing and show pointer, retrieval date and superseded flag.
- **Saved searches** are analyst data, not cache: enrichment kind `search-saved` (add to `KINDS`, not `DERIVED_KINDS`, so retention never touches it), `Guard(project_id, 'search', sha256(plan), sha256(plan))`, append-only create/delete rows (no DELETE, no backup dance). Recent queries: QSettings `search/recent` (<=20, try/except).
- **Errors** `SearchError(code, message, recoverable=False)`: `PT-SEARCH-QUERY`, `-CAPABILITY` (no FTS5/trigram), `-SOURCE` (one adapter failed, others continue), `-STALE`, `-LIMIT`, `-STORE` (cache dir, corruption, disk, permission), `-LOCATOR`, `-TIMEOUT`, `-CANCEL`, `-INPUT` (CLI arguments). Replaces the plan's `PT-WB-*` for search (convention of `PT-INTEL-*`).
- **Limits** (`SearchLimits`, provisional, each enforced by a test in the slice that owns it): query 256 chars / 8 terms / 4 excludes; page 200; GUI loads <=5,000 rows per query; candidate cap 20,000; query timeout 2 s (`interrupt()`); scan fallback <=5 M rows; per-field text 64 KiB (strings 256); segment build 600 s, total 1,800 s, cancel check every 4,096 docs; <=64 segments and <=768 MiB per project, 4 GiB cache total; suggestions 12; saved searches 200; RapidFuzz candidates <=100,000 unique names, hints <=2,000. Fuzzy rule: `OSA.distance` on folded names, `max_edits` 0 for <=2 chars, 1 for <=4, 2 for <=9, else 3; counterpart hint only when old and new are each other's unique nearest.
- **Versioning**: additive only. New kinds/fields extend `search/1` readers; a changed segment schema or tokenizer changes the digest and the file is rebuilt (nothing migrates); `search-saved/1` rows are never rewritten; project contracts and `project.sqlite3` are untouched.

## 8. CLI and GUI
**CLI** (`search/cli.py`, never imports Qt; adapter `cli_commands/search.py` (<= 25 lines), no `cli.py` hook and no `tools/frozen_smoke.py` `COMMANDS` line, because the collect hook derives `names()` (GUI plan 8.12)):
```text
patchtrace search PROJECT --query TEXT [--kind K]... [--side older|newer|both] [--scope indexed|changed] [--mode auto|words|exact|prefix|substring|similar]
                  [--sort relevance|change|name|address] [--limit N<=200] [--cursor C] [--no-group] [--no-expand] [--rebuild] [--no-index-build] [--cache-dir D] [--json]
patchtrace search PROJECT --status [--json]     # coverage, segment digests, staleness
patchtrace search --probe [--json]              # no project: sqlite version, fts5, unicode61, trigram, rapidfuzz version + backend, cache root writable
patchtrace search PROJECT --anchors-from CVE-ID [--json]    # S10
```
- Envelope `enrichment-cli/1`, `command: "search"`, `result` = `SearchResult`. Progress on stderr only; no absolute paths; missing segments are built synchronously within 600 s.
- Exit: 0 for `ok`, `too-broad`, `partial` with hits, or `stale` results served from an older index (status and a warning say so), and for `--probe` once it ran; 4 only for `no-results` with every requested group `indexed`; 2 for an invalid query or arguments, no FTS5, project locked (message: close the desktop) [F21]; 3 for runtime/store failure, no usable index under `--no-index-build`, or `partial` with zero hits (absence unproven); 5 cancelled.

**Assumed panel interface** (the GUI-architecture worker owns the real one; `ui_search.py` imports only these):
- `PANEL = PanelSpec(..., requires=('project',))` in `search/panel.py` (GUI plan F5 registry; replaces `PanelHost.register`).
- `ProjectPort` = today's `ui_evidence.WindowPort` (`service`, `project`, `key()`, `busy()`, `select_match(match_id)`) plus `NavigationPort.navigate(AnchorRef) -> NavResult(ok, reason)` (replaces `ProjectPort.navigate(locator)`).
- `SettingsPort.get/set` (never raises); `ctx.tasks.lane` replaces `ThreadRegistry.start(worker)`/`shutdown()`; `ShortcutPolicy.claim` is the manifest (`panel_manifest.py`); `apply_tooltip`.
- If absent, S6/S7 ship `SearchController(window)` copying `EvidenceController` (dock, Analysis-menu action, `project_changed`/`shutdown` hooks); the registry shim later replaces only the controller. The `MainWindow` attribute is `global_search`, because `MainWindow.search` is the navigator `QLineEdit` (`ui.py:1613`).

**Placement and widgets**
- One `QDockWidget` (`search.dock`, closable/movable/floatable like `EvidenceDock`), default bottom area, hidden at start, never a new window.
- Query `QLineEdit` (clear button) with `QCompleter`; side group `Both | Older | Newer` (three exclusive checkable `QToolButton`s); Kinds menu button (Functions, Code, Strings, Imports and exports, Capabilities and rules, Build facts, Advisories, Notes and findings); Scope, Mode and Sort combos; `Save...`, `Saved` menu, `Rebuild index`, `Coverage...`.
- Status label (live region), progress bar, result table, detail pane (`QPlainTextEdit`, sections Result / Why it ranks here / Pair / Change facts / Provenance / Limitations), buttons `Go to code`, `Show other side`, `Copy`.

**Model/view and virtualization**
- `SearchResultsModel(QAbstractTableModel)` owns a frozen-slots `ResultRowView` list for one generation (columns Side | Kind | Match | Where | Change | Why; strings precomputed; `data()` O(1); `data_calls` counter).
- `canFetchMore`/`fetchMore` emit `more_requested(cursor, generation)`; the controller appends the arrived page between `beginInsertRows`/`endInsertRows` [F18]. Row height comes from font metrics (fixed, never `ResizeToContents`).
- Header clicks re-query with `sort` (server side, so an order is never a partial local sort). The model stops at 5,000 rows: "Showing the first 5,000. Refine the search."
- Virtualization = pages + O(1) data + fixed rows; tests drive a fake 100k/1M-hit service and prove the GUI never materialises more than the cap.

**Threads**
- One persistent reader (an unparented `QThread` running a `queue.Queue` loop) owns the read-only segment connections, serves the latest request only, and calls `interrupt()` when superseded. Builds run on a second registered `QThread`.
- Both receive immutable requests built on the GUI thread (`build_request(service)` reads store rows there), emit signals only, and results are dropped when `generation` differs. Pair expansion and `Locator` checks run in GUI-thread slots against `service.project`.

**Keyboard**
- `Ctrl+Shift+F` shows the dock and selects the query. Free today: MainWindow uses Ctrl+N/O/S/E/I/R, F1, F5, Esc, Alt+Up/Down; the evidence dock uses Ctrl+Shift+E; unified plans Ctrl+Shift+U; `Ctrl+F` stays free for a future in-pane find.
- Typing searches after 250 ms, Enter immediately; an empty query shows the placeholder, never "everything". `Down` from the field enters the popup or the table.
- Table: arrows, PgUp/PgDn, Home/End; `Enter` or double-click = Go to code; `Space` = focus the detail; `Ctrl+C` = copy lead (title, locator, provenance); `F3`/`Shift+F3` = next/previous lead and open it. Tab order: query, side, kinds, scope, mode, sort, Save, Saved, table, detail, buttons.
- `Esc` (guarded, F16): closes the popup, then clears text, then returns focus to the code pane. It never reaches `Cancel job`. Navigating to a function hidden by navigator filters clears those filters and says so in the status bar.

**QCompleter**
- Model = `SuggestionModel(QStandardItemModel)`, refilled (<=12 rows) by a debounced (80 ms) range query on a folded-name index in the reader thread; `UnfilteredPopupCompletion`, so Qt does not re-filter.
- Row text `name | rva | side | category`; `EditRole` = bare name; `UserRole` = `(kind, locator)`. `activated[QModelIndex]` opens that exact function (`select_match`, or reveal lines) without running a search; Enter with no highlighted row runs the full search.
- Popup gets `setAccessibleName('Search suggestions')`; cleared on project, run or orientation change. A sorted `QStringListModel` would cost 0.0 ms [F17] but cannot carry ids, so it is not used. Empty focused field lists recent queries.

**Highlighting and saved searches**
- `HitDelegate.paint` uses `QTextLayout` ranges with bold + underline (never colour alone; palette colours, so Windows High Contrast works), `ElideMiddle`, `drawText` only.
- `Save...` names the current plan (<=64 chars); `Saved` lists, runs (re-executes; results are never stored) and deletes (append-only tombstone).

**States and exact copy** (plain text, ASCII glyphs)
| ID | Trigger | Text |
|---|---|---|
| Q0 | no project | "Open a project to search it." |
| Q1 | not indexed | "Not indexed yet. Search reads only this project's saved data; nothing is uploaded." [Build index] |
| Q2 | building | "Indexing <group> (<done> of <total> groups). You can already search what is indexed." [Cancel] |
| Q3 | empty query | "Search names, strings, APIs, code, notes and advisories. Use quotes for an exact phrase and -word to exclude." |
| Q4 | results | "<n> leads for '<q>' in <scope>. Showing <k>." |
| Q5 | none, complete | "No results for '<q>' in what is indexed (<coverage>). This does not show the text is absent from the binary." |
| Q6 | none, partial | "No results yet, but the index is partial: <missing>." |
| Q7 | too broad | "More than 20,000 matches for '<q>'. Showing the first 200 in index order, not ranked. Add a word, choose a kind or side, or use a phrase." |
| Q8 | stale | "The project changed after this index was built (<what>). Results are for reference; opening one is checked against the current project." [Update index] |
| Q9 | unsupported | "Full-text search is unavailable in this build (SQLite FTS5 missing). The navigator filter still works." |
| Q10 | error | "Search failed: <code>: <message>. Your project was not changed." [Retry] [Copy details] |
| Q11 | coverage note | "Instruction text is not searchable: Ghidriff keeps only a hash of each function's instructions. Run unified extraction to add it." |

**Tooltips and accessibility**
- Registry ids (What/Why/Effect/Source/Availability, no `<` `>`): `search.dock`, `search.action`, `search.query`, `search.side`, `search.kinds`, `search.scope`, `search.mode`, `search.sort`, `search.save`, `search.saved`, `search.rebuild`, `search.coverage`, `search.table`, `search.detail`, `search.goto`, `search.other_side`, `search.copy`; templates `search.row`, `search.suggestion`, `search.coverage_row`.
- Accessible names (short, localized [F25]): "Search query", "Search side", "Search kinds", "Search scope", "Search mode", "Search sort order", "Search results", "Selected result details"; `accessibleIdentifier` = tip id is rule R9 (GUI plan). Status text is announced through `ctx.announce` (GUI plan F6), not by `setText` on an empty accessible name (C6 rule). `AccessibleTextRole` per row: "<kind> in <side>: <title>; <where>; <change>; <why>". 2 px focus ring; contrast test reused from `ui_evidence`.
- Windows exposure is UI Automation [F19]; Narrator/NVDA, 125/150/200% DPI and High Contrast are owner gates [unverified here; Microsoft Learn blocked].

**Qt/PySide6 pitfalls**
- Unparented registered threads (a parent deleting a running `QThread` aborts); queued connections plus generation guards for every worker signal.
- Connect `activated[QModelIndex]`, never the `str` overload; the completer popup is a top-level widget the tooltip audit's `findChildren` will not see, so name it explicitly; Esc `ShortcutOverride` [F16].
- `beginInsertRows` for pages, `beginResetModel` only on a new generation; no `QSortFilterProxyModel`, no `ResizeToContents`; QSettings reads in try/except.
- IME composition must not fire a search mid-composition [unverified: confirm `textEdited` semantics on Windows].

**Offscreen tests**: `test_search_view_model.py` (pure; banned-word sweep; hostile strings), `test_search_ui.py` (one test per state Q0-Q11, keyboard flow with `QTest.keyClick`, Esc guard, completer payload with duplicate names, fetchMore pages, close while indexing, project switch drops results, no new top-level window, tooltip audit roots), `test_search_perf.py` (fake 100k leads: first paint <=200 ms, `data()` calls <= 3 x visible cells, keystroke to first page <=250 ms with a stub service). 20x repeat with `PYTHONFAULTHANDLER=1`.

**Performance budgets** (3x slack over [F10], enforced at 5x wall clock like `test_evidence_perf`): `fn` segment for 100k functions (names + signatures) <=15 s plus code <=0.1 s per MB; 1M strings <=20 s and <=250 MB; word query p95 <=50 ms (100k names) and <=250 ms (1M strings, under the 20,000 cap); too-broad detection <=25 ms; scan fallback <=2 s with cancel <=100 ms; RapidFuzz suggestions over 100k unique names <=100 ms; completer refresh <=50 ms; build-time event-loop latency p95 <=100 ms; worker RSS <=300 MB; idle cost zero until first use.

## 9. Slice plan (each merges alone; within WB1 no two slices edit one file)
Merge order: S0, S1, S2, S3, S4, then S5 and S6 in parallel, S7; S8, S9, S10 as their dependencies land. S1 freezes every model of section 7 (later additions are additive and go through the integration owner). Shared files that other tracks also touch (`cli.py`, `tools/frozen_smoke.py`, `tooltips.py`, `ui.py`) are edited by exactly one WB1 slice each, and the integration owner serialises them against the other tracks' hooks.
| Slice | Scope | Exclusive files | Depends | Tier, reason | Size | Gate | Fallback |
|---|---|---|---|---|---|---|---|
| S0 | Capability probe, cache paths, limits, errors, bench harness, runtime check | `search/{__init__,limits,errors,capability,paths}.py`, `tools/bench_search.py`, `tools/check_search_runtime.py`, `tests/test_search_{capability,paths}.py` | none | sonnet (Windows path rules) | S ~350 LOC | probe green on Linux and Windows CI; paths refuse in-project roots | none needed |
| S1 | `fold`, `sanitize_text`, identifier splitter, auto-name detector, `parse_query`, safe MATCH builder, contracts | `search/{normalize,tokenize,query,contracts}.py`, `tests/test_search_{normalize,query,contracts}.py`, `tests/fixtures/search/{queries,names,hostile}.json` | S0 | sonnet (property tests) | M ~700 | hypothesis: no input raises `OperationalError`; goldens for 40 names and the hostile list | drop `last_prefix` and numeric forms |
| S2 | Segment store: schema, staging build, publish, hardened open, GC, corruption handling | `search/segment.py`, `tests/test_search_segment.py` | S1 | sonnet (pattern exists in `bindiff.py`) | M ~600 | crash-point tests; authorizer allow-list test [F11]; immutable read-only open; replace-over-open-file on Windows CI | one file per project, rebuilt whole |
| S3 | Sources v1 (`fn`, `raw`, `pe`, `ann`, `fnd`) and build orchestration (`build_request`, per-group digests, cancel, coverage) | `search/sources/{base,functions,raw,pe,notes}.py`, `search/build.py`, `tests/search_builders.py`, `tests/test_search_{sources,build}.py` | S2 | sonnet | L ~900 | determinism under permutation; incremental == from-scratch; exact coverage text | skip `raw` until a real Ghidriff golden exists |
| S4 | Query engine, ranking, pair expansion, fuzzy, `SearchService` facade | `search/{service,rank,expand,fuzzy}.py`, `tests/search_synergy_builders.py`, `tests/test_search_{rank,expand,fuzzy,synergy}.py` | S3 | sonnet; opus review only if ordering is non-deterministic | L ~900 | synergy test green; 100k perf gates; RapidFuzz absent = `similar` reports unavailable, never zero | drop counterpart hints |
| S5 | CLI (carries `--anchors-from`, importing `search.anchors` lazily; before S10 it exits 2 with `PT-SEARCH-CAPABILITY`) | `search/cli.py`, adapter `cli_commands/search.py`, `tests/test_search_cli.py` | S4 | haiku/sonnet (mechanical, exit-code table) | S ~300 | exit codes 0/2/3/4/5; one JSON document; frozen `--probe` | none |
| S6 | View model and Qt panel | `search/view_model.py`, `ui_search.py`, `tests/test_search_{view_model,ui,perf}.py`, `search.*` block appended to `tooltips.py` (integration owner serialises) | S4 | sonnet | L ~1,200 | offscreen states, keyboard, Esc, completer, 20x repeat | table without completer |
| S7 | MainWindow seam, `reveal_lines` extracted from `jump_signal`, saved searches, `KINDS` line, tooltip audit roots | `ui.py` (<=25 lines), `search/saved.py`, `enrichment/storage.py` (1 line), `tests/test_tooltips.py`, `tests/test_search_saved.py` | S6 | sonnet (single owner of `ui.py` in the wave) | M ~400 | seam test (line growth); old-reader test for the new kind | recent queries only |
| S8 | Tool, advisory, CVE sources | `search/sources/{tools,advisory}.py`, `tests/test_search_sources_tools.py` | S3 plus WB3/CAP/DIE stores, KB | sonnet | M ~500 | presence/delta semantics; secret redaction | advisory only |
| S9 | Unified IR source (all functions, asm, constants) | `search/sources/unified.py`, tests | S3 plus UE S1/S4 | sonnet | M ~500 | asm no longer `unavailable`; 100k-function gate | none |
| S10 | Anchor bridge for PIL (`Anchor` to `QueryPlan`, per-anchor coverage) | `search/anchors.py`, `tests/test_search_anchors.py` | S4, S5 plus PIL | sonnet | S ~300 | each `Anchor` kind (module, feature, string, component, pdb, api) maps to a plan; coverage per anchor | none |

## 10. Amendments required, and test and QA plan
| File | Section | Change |
|---|---|---|
| `docs/specs/workbench/01-search-fts5-rapidfuzz.md` | §3-§9 | Mark superseded by this plan: trigram via phrase `MATCH` on `detail=full` (not `LIKE`); kind enum replaces `field`/`other`; drop `source_json`; segments instead of one file and atomic pointer; WRatio replaced by `OSA`/`Levenshtein` distance; `Ctrl+Shift+F` plus Esc guard; budgets from [F10]; renamed modules (`index.py` to `segment.py`, `extract.py` to `sources/`) |
| `docs/specs/workbench/04-quickwins.md` | QW2, QW5 | QW2 scorer and pin 3.14.6; QW5 payload on `UserRole`, `activated[QModelIndex]`, DB-backed suggestion model |
| `docs/plans/workbench-search-graph-floss-implementation.md` | §2, §5 | module list; error family `PT-SEARCH-*` for search |
| `docs/modules.md` | new rows | `search.*` modules, `ui_search.py` |
| `pyproject.toml`, `third_party/notices/rapidfuzz-3.14.6/{LICENSE,MANIFEST.txt}`, `docs/notices.md`, `tools/build_windows.py`, `tools/build_linux.py` | deps, notices, inventory | `rapidfuzz==3.14.6` in extra `search` and in `dev`; wheel SHA-256s in MANIFEST; builds list RapidFuzz in versions, require its notices, assert `rapidfuzz/fuzz_cpp*` in the inventory |
| `.github/workflows/qa-windows.yml` | after `pip check` | `python tools/check_search_runtime.py` (FTS5, trigram, RapidFuzz backend), as `check_protobuf_runtime.py` does |
| `src/patchtrace/cli_commands/search.py` | adapter file only (GUI plan 8.12); no `cli.py`, `COMMANDS` or frozen-smoke edit | add `search` (S5); `names()` feeds the A1 list and the parser choices, so no shared list is edited |
| `src/patchtrace/enrichment/storage.py` | `KINDS` | add `'search-saved'` (one line; not in `DERIVED_KINDS`) |
| `src/patchtrace/ui.py` | `__init__`, `refresh`, `update_controls`, `closeEvent`; `jump_signal` | `self.global_search` seam; extract `reveal_lines`; optional Esc `ShortcutOverride` guard for the existing navigator `self.search` |
| `src/patchtrace/tooltips.py`, `tests/test_tooltips.py` | registry, `roots` | `search.*` block; add the dock to `test_every_registry_id_is_applied_somewhere` |
| `docs/specs/unified-engine/07-ui-and-cli.md` | §7 | record `Ctrl+Shift+F` as taken by search |
| `docs/specs/REGISTRY.md` (referenced by the roadmap, absent in this tree) | WB1 row | integration owner creates or adds |
| `.gitattributes`, `docs/qa.md`, `tasks/todo.md` | fixtures, gates | `tests/fixtures/search/*.json text eol=lf`; gate rows from this section |

**Test plan.** Fixtures without Microsoft binaries: `tests/search_builders.py`, `tests/search_synergy_builders.py`, `tests/fixtures/search/{queries,names,hostile}.json`. Goldens: canonical plans, MATCH expressions, `rank_reasons`, CLI JSON. Properties (hypothesis): query builder never raises; identifier splitting stable under re-run; incremental equals from-scratch; results independent of source order; snippet spans reconstruct the marked substring. Red/green order per slice as in `phase-d-build-coordination.md`; ruff and the full suite twice.
Windows pitfalls (roadmap checklist plus search-specific): CRLF in goldens (`.gitattributes`); short explicit parametrize ids for the hostile corpus (`PYTEST_CURRENT_TEST` limit); `>=` on coarse `time.monotonic()`; wheels-only installs; hermetic tests (no network); `os.replace` onto an open segment; cache path under 260 characters with non-ASCII user names; read-only copies chmod'ed before cleanup; case-insensitive file names (lower-case hex dirs); SQLite 3.42-3.49 differences (no features newer than 3.37).
**Live gates only CI or the owner can close** (reported separately, never counted as done): frozen `PatchTrace.exe search --probe --json` on Windows shows FTS5, trigram and a `cpp-*` RapidFuzz backend with `rapidfuzz` binaries in the inventory; a real Ghidriff JSON for the `strings`/`symbols`/`name_matches` shapes (`live-backend` workflow); real `QCompleter` popup + Esc, Narrator/NVDA on the table and status line, 125/150/200% DPI and High Contrast; OneDrive-backed project plus local cache; first-index latency under antivirus; 100k-function timing on the owner machine.

## 11. Open questions (defaults; none blocks)
1. RapidFuzz as optional extra (default) or hard pin like protobuf? Default: extra `search` plus `dev`, bundled in frozen builds, import guarded.
2. Cache root: `--cache-dir` > `PATCHTRACE_CACHE_DIR` > profile `cache_dir` > per-user platform default (`%LOCALAPPDATA%\PatchTrace\cache`, `$XDG_CACHE_HOME/patchtrace`); never inside a project.
3. Index unchanged function names from raw `name_matches`? Default: only after a real golden confirms the shape; until then coverage says "unchanged functions: not indexed".
4. Model findings in the default scope? Default: own kind chip, off in "Code and names", on in "All indexed", always badged.
5. Trigram for strings (>=500k)? Default: no; `instr()` scan with a 2 s bound and cancel.
6. Shortcut `Ctrl+Shift+F` vs `Ctrl+K`? Default `Ctrl+Shift+F`; `Ctrl+F` reserved for in-pane find.
7. Saved searches in the project (default, append-only rows) or QSettings only?
8. Group leads by pairing by default? Default yes; `--no-group` and a toggle show raw evidence rows.
9. Strings beyond 256 chars (tool evidence stores only `display_value`)? Default: search the stored prefix and flag `truncated`.
10. Search for N-way series projects? Default: per pair project only; chain position appears in `PairExpansion.series` when `series.json` is present.
