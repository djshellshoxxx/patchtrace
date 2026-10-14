# PT-WB-QW: Additional Very-Low-Effort, High-Value Integrations

**Status:** Ranked proposals, not implementation. **Rating scale:** 1/5 means relatively easy compared with PatchTrace's planned engines: small adapter, bounded UI seam, no new Ghidra analysis, no data-format migration. These are **estimates**, not measured engineering durations. Date: 2026-10-14. Parent: [workbench index](README.md).

## 1. Ranking and selection

| Rank | Project / built-in | Feature | Value /5 | Integration difficulty /5 | New runtime | Critical dependency | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| QW1 | Python's `sqlite3` + built-in **SQLite FTS5** | indexed text, function, string and evidence search | 5 | 1 (core backend), 2 (full UI) | none if SQLite build supports FTS5 | PT-WB-01 | **Build first** |
| QW2 | **RapidFuzz** | typo-tolerant symbol/function lookup and search suggestions | 4.5 | 1 | optional Python wheel, MIT | PT-WB-01 | **Quick add-on** |
| QW3 | **Pygments** | decompiler C and assembly syntax highlighting in existing paired panes | 4.5 | 1 for bounded token pass; 2 for thoroughly tested Qt highlighting | optional pure Python, BSD-2-Clause | Existing code panes | **Best independent UI win** |
| QW4 | **pefile** | VERSIONINFO, manifest, resource names and optional PE metadata missing from current inspector | 4 | 1 for parser, 2 for complete view | optional Python library, MIT | `pe_overview` | **Best metadata win** |
| QW5 | **PySide6 QCompleter** (already bundled) | function/symbol jump-to autocomplete and recent selections | 4 | 1 | none | current navigator + search | **Easy/no third-party dep** |
| QW6 | Python standard library `difflib` + existing `alignment` | bounded token/intraline change emphasis and copy a concise before/after snippet | 4 | 1 if existing pipeline exposes stable aligned line spans; 2 otherwise | none | current diff hunks | **Pilot only, avoid duplication** |
| QW7 | DOT text format (stdlib exporter; optional external **Graphviz** viewer) | share call graphs outside PatchTrace | 3.5 | 1 | none in app | PT-WB-02 graph contract | **Add after graph model** |
| QW8 | Windows `dbghelp.dll` **UnDecorateSymbolName** or external `llvm-undname` (optional) | readable MSVC C++ mangled function names | 4 for C++-heavy cases | 1 for Windows-only simple probe; 2 cross-platform/robust | OS DLL or optional binary | exact source symbol identity | **Optional, verify source/version** |

### Value/difficulty caveat

`1/5` denotes a *small bounded feature*. 'Pygments syntax highlighting for current 8 KiB viewport' qualifies; 'perfectly highlight all decompiled code while retaining diff span offsets' does not. 'pefile VERSIONINFO extraction' qualifies; 'all signature/catalog/manifest provenance and patch attribution' does not. 'FTS5 indexing' is 1/5 but an accessible full search GUI is 2/5, and a complete semantic search across binaries would be much harder.

Never present high-value but more complex tools (capa, Ghidra BSim, Version Tracking, IDA integration, a full runtime debugger, angr) as 1/5 work.

## 2. QW3 Pygments: complete small-module spec

**Purpose:** Make existing decompiled C and assembly panes readable, without changing their content, source identities, diff alignment or copy/export bytes.

Implementation: `src/patchtrace/highlighting/tokens.py` (pure, optional import, Pygments CLexer and appropriate assembly lexer if verified), `highlighting/qt_adapter.py` (QSyntaxHighlighter over existing QPlainTextEdit), `highlighting/config.py` (theme token-to-QTextCharFormat maps), `tests/test_highlighting.py` and `tests/test_ui_highlighting.py`. Do not replace text panes with QTextBrowser/HTML; preserve selectable and original text exactly. Never use Pygments HTML formatter for untrusted code, and never save markup into source evidence.

Interface:
```python
def tokenize_visible(text: str, language: Literal['c','asm'],
                     max_chars: int=64_000) -> tuple[TokenSpan,...]: ...
def apply_syntax_formats(spans: tuple[TokenSpan,...], diff_spans, palette) -> tuple[FormatSpan,...]: ...
```

Guard: skip highlight when text >64k chars, tokenize asynchronously for slow cases, retain original text, code line numbers, diff backgrounds and active hit selection as highest priority. Cache by (code sha, language, lexer version, theme). Keep a measured UI frame budget <=20 ms for applying 8 KiB visible code; fall back to plain-text on latency overrun or import failure. Test inline quotes, raw strings, C-like Ghidra output, malformed Unicode and 100k-line files; no change to clipboard/copy/line navigation; Windows frozen ZIP has Pygments assets loaded or feature gracefully unavailable.

Upstream references: https://pygments.org/docs/lexers/ ; https://pygments.org/docs/quickstart/ .

## 3. QW4 pefile: complete small-module spec

Current `pe_overview` extracts headers, sections, directories, imports/exports, entropy, certificates and RSDS; task tracker still lists version resources and manifest details as missing. Only implement new missing fields.

One adapter `pe_overview/version_resources.py` reads from verified original bytes via `VerifiedArtifactReader`, using pefile over **bounded** bytes with `fast_load=True` + explicit resource directory parse as supported by version; no arbitrary file opens. Parse `VS_VERSIONINFO` product/file version, CompanyName, ProductName, OriginalFilename, InternalName, FileDescription, and language/codepage identities; parse RT_MANIFEST XML using a defensive parser, no DTD/external entities. If pefile's API does not satisfy memory budget for selected user binaries, fall back to dedicated bounded resource reader. Preserve raw contradictory version blocks rather than arbitrarily selecting one. Compare old/new field by canonical identity (locale/codepage/key), showing added/removed/changed values and source offsets where validated. Do not trust VERSIONINFO to establish Windows OS build or Microsoft authenticity.

Typed `VersionResourceEntry` includes artifact SHA, resource RVA/offset, locale, codepage, key, value, parse status; `ManifestObservation` includes requestedExecutionLevel, dependencies, file hashes, parse/source warnings. Limit entire PE input by existing max 1 GiB but bounded parser memory; resource section data cap 16 MiB and XML max 2 MiB in initial adapter. Hard cap recursive tree depth 32, node count 20k. Test malformed length, overlapping resources, UTF-16 odd byte lengths, duplicate keys/locales, enormous names, manifest DTD, broken resource RVA, compressed/packed PE and legitimate no-version-resource case. All results are informational and side-attributed.

Upstream: https://github.com/erocarrera/pefile ; integration only if existing inspector does not already supply that exact field.

## 4. QW2 RapidFuzz: extension of PT-WB-01

Use the optional dependency **only for symbol/name suggestions**. Example: user types `ValdateAcount` and sees `ValidateAccount` among indexed names. No vague function similarity and no fake CVE evidence.

Minimal `search/fuzzy.py` adapter receives bounded list of source-backed `(name,source_id)` items (<=100k unique); normalize with Unicode casefold and optional ASCII-lower canonicalization; process top 20, cutoff 75, deterministic stable ties, typed `SearchHit(engine='rapidfuzz')`. Native score is string similarity only and must display `Name suggestion`. Tests measure 100k names and reject unbounded requests, missing optional wheel and PyInstaller import issues.

## 5. QW5 PySide6 QCompleter: no new dependency

A `QCompleter` on the navigator/Search field with a case-insensitive, bounded `QStringListModel` (or dedicated lazy model if >10k functions). Every suggestion maps to a true ID and side, not just a name. If duplicate names exist show `name • RVA • side`; selecting a suggestion opens exact `WindowPort.select_match`. Never reconstruct IDs from display label. Restrict to current project/run, clear on orientation swap or project change; tests 100k names, duplicate labels and stale selection. Shortcut must not conflict with existing `Ctrl+F` in paired code pane.

## 6. QW6 intraline diff: only incremental enhancement

Use existing `alignment.py`/ `diff_hunks` rather than implementing a second diff engine. Where existing hunks already convey per-line modifications, run `difflib.SequenceMatcher(autojunk=False)` on **bounded displayed line pairs** and mark differing spans. Maximum 4096 Unicode chars/line, max 100 paired lines per refresh; disable for binary/base64/hex mode and unmatched/unequal alignment. A change from register `ecx` to `edx` is lexical evidence, not semantic. Preserve original code, cursor and theme behavior; only additional underline, no evidence changes.

## 7. QW7 DOT export

Pure serializer of PT-WB-02 typed `GraphView`, not a new graph construction path. Export nodes with stable machine IDs, display labels safely DOT-escaped, one edge per observed relation and explicit `inferred`/ `verified` labels, bounded max nodes. Save UTF-8 `.dot` file with safe filename/atomic replace; no invocation of shell Graphviz or external viewer. Test malicious labels, quotes/backslashes, newlines, cycles and reproducible byte-identical exports.

## 8. QW8 demangler

Separate optional name beautifier `symbols/demangle.py` returns `{original,display,tool/version,status}`. On Windows `dbghelp.UnDecorateSymbolName` exists but requires version and buffer bounds check; compare Windows API output vs pinned `llvm-undname` fixtures. Never replace underlying canonical symbol identity or map functions by demangled name without unambiguous verified IDs. On unsupported systems return original label with `unavailable`. Test nested templates, huge decorated names, duplicate demangled names, Unicode and corrupt names. Do not load arbitrary DLL path from a user directory.

## 9. Adoption order and guardrails

**Recommended very first:** QW5 QCompleter (no new dependency) and QW3 Pygments on visible code; in parallel build QW1 FTS5 core. Then QW2 fuzzy search and QW4 pefile version resources. QW6 only after auditing existing diff lines; QW7 after graph contract; QW8 as Windows-specific optional.

Release strategy: each small feature receives its own PR and toggle with default OFF until regression and Windows frozen acceptance. Use existing tooltips, PySide6 accessibility and project guard semantics; no huge dependency copied into repo. Pin dependencies and vendor notices after license review. Do not enable external network, implicit new binary analysis or project DB writes.

## 10. Evidence / licenses to verify in implementation

- SQLite FTS5 built-in: https://www.sqlite.org/fts5.html ; exact feature support in frozen Python runtime must be probed.
- RapidFuzz MIT: https://github.com/rapidfuzz/RapidFuzz .
- Pygments BSD-2-Clause: https://github.com/pygments/pygments .
- pefile MIT: https://github.com/erocarrera/pefile .
- Qt QCompleter: bundled with PySide6 but test Qt dependency/version.
- NetworkX: license metadata appears as NOASSERTION in GitHub API, so **review its actual LICENSE file and transitive dependencies** before optional distribution; do not infer license string from API.
