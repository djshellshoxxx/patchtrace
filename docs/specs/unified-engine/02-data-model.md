# SPEC-31 / 02 Data model: contracts, storage, keys, limits (contract freeze)

Repo conventions apply: persisted records are strict frozen pydantic v2 (`extra='forbid', strict=True, frozen=True`), every record carries a `contract` literal, JSON is canonical (`enrichment.identity.canonical_json`), identities are `domain_id(domain, version, payload)`, schemas are generated (`tools/generate_schemas.py` -> `docs/schemas/unified/`, CI fails on drift). All types below are planned (S0a freezes them).

## 1. Shared types

```python
Sha256   = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Rva      = Annotated[int, Field(ge=0, le=2**32 - 1)]            # PE32+ SizeOfImage < 4 GiB
SourceId = Annotated[str, Field(pattern=r'^[a-z][a-z0-9-]{1,31}$')]   # NOT a Literal (D-08)
StepId   = Annotated[str, Field(min_length=1, max_length=64)]   # pass id or upstream algorithm text, sanitized
Tier     = Literal['M', 'A', 'B', 'C', 'W']                     # manual, accept key, corroborating, candidate, weak
Card     = Literal['1:1', '1:N', 'N:1', 'N:M', 'non-exclusive']
Decision = Literal['matched', 'tentative', 'candidate', 'contested', 'ambiguous', 'older-only', 'newer-only', 'unknown']
Materiality = Literal['unchanged', 'cosmetic', 'material', 'review', 'unknown', 'not-applicable']
ChannelId = Literal['C0', 'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8']
ChannelState = Literal['equal', 'differs', 'unavailable', 'not-applicable']
ChangeClass = Literal['constant', 'comparison', 'condition', 'callee', 'call-added', 'call-removed', 'data-ref',
    'struct-offset', 'cfg', 'block-added', 'block-removed', 'string', 'size-only', 'refcount-only',
    'address-only', 'register-only', 'layout-only', 'name-only', 'unknown']
RowFlag = Literal['tiny', 'thunk', 'import', 'hub', 'icf', 'oversize', 'truncated', 'ir-missing', 'pdata-confirmed']
```
`UnifiedError(code, message, *, reason=None)`; `code` is one of 01 s6, `reason` a slug (`[a-z0-9-]{1,48}`).

## 2. Extractor output `ir-extract/1` (UNTRUSTED, JSON Lines, UTF-8)
One file `ir.jsonl` per side in the extractor's private output dir, plus `progress.json` (L-37). Line types, in this order: one `header`, N `fn` (strictly increasing `rva`), one `footer`. Unknown keys, NaN, duplicate keys, out-of-order or missing footer -> `PT-UNIFIED-IR`.

| Field | Type / bound | Meaning |
|---|---|---|
| header `contract` | `'ir-extract/1'` | |
| header `artifact_sha256`, `program_sha256` | Sha256 | file hash re-computed by the script; Ghidra `getExecutableSHA256()`; both must equal the project artifact |
| header `image_base`, `size_of_image` | int | from the Ghidra program / PE header; cross-checked with `pe_overview` |
| header `language`, `compiler` | str <= 64 | must be `x86:LE:64:*`, else `UNSUPPORTED` |
| header `producer` | `{mode: 'gzf'|'analyze', ghidra, pyghidra, java, python, script_sha256, analysis_options_digest}` | versions are probed strings, `unknown` allowed but makes the IR cache-ineligible |
| fn `rva`, `ranges` | Rva; `[[rva, len], ...]` <= 64 ranges | entry RVA; body ranges (chunks) |
| fn `name`, `name_src`, `aliases` | str <= 512; `DEFAULT|ANALYSIS|IMPORTED|USER_DEFINED`; <= 16 names | Ghidra symbol and source type; aliases = other symbols at the entry (ICF) |
| fn `kind`, `thunk_target`, `import` | `normal|thunk|external`; Rva|null; `{dll, name|null, ordinal|null}`|null | |
| fn `raw` | hex, <= L-06 bytes per function | body bytes in range order; absent -> flag `oversize` |
| fn `blocks` | `[[rva, len, n_insn, [succ_rva...], [kind...]], ...]` <= L-02 total | Ghidra basic-block model; kinds `fall|jump|cond|switch|call-return` |
| fn `insns` | `[[off, len, mnem, imask_hex, [[optype, omask_hex, vkind, value, target_rva|null], ...], flow], ...]` <= L-06 per fn | SLEIGH instruction mask and per-operand masks; `vkind` in `none|scalar|address|register` |
| fn `calls`, `strings` | `[[site_rva, target_rva|null, import_key|null, 'call|jump'], ...]`; `[[site_rva, sha256, len, prefix<=64], ...]` | resolved references |
| fn `text` | list of str, one per instruction, each <= 256 | Ghidra instruction text, for display only |
| footer | `{functions, instructions, status: 'complete'|'partial', warnings[<=64]}` | counts must equal what was read |
Validation is hand-written and streaming for `fn` lines (pydantic only for header/footer; 2 M pydantic objects would cost minutes, R04 s7) and is fuzzed (08 s5).

## 3. ProgramIR `program-ir/1` (canonical, written by PatchTrace, read-only after publish)
Location: `runs/<run_id>/unified/ir/<ir_key>/{ir.sqlite3, manifest.json}`; optional global copy in `DerivedCache` stage `program-ir` (payload = stored-zip of both files, U-08). Opened with `file:...?mode=ro&immutable=1`, `trusted_schema=OFF`, an authorizer that allows only SELECT on the tables below (pattern of the hardened `.BinDiff` importer, secondary/bindiff.py).

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);   -- contract, ir_key, content_digest, versions
CREATE TABLE mnem (id INTEGER PRIMARY KEY, text TEXT NOT NULL UNIQUE);
CREATE TABLE fn (fid INTEGER PRIMARY KEY, rva INTEGER NOT NULL UNIQUE, size INTEGER NOT NULL,
  kind INTEGER NOT NULL, name TEXT, name_src INTEGER NOT NULL, aliases TEXT, import_key TEXT, thunk_target INTEGER,
  n_bb INTEGER NOT NULL, n_edge INTEGER NOT NULL, n_insn INTEGER NOT NULL, n_call INTEGER NOT NULL, loops INTEGER NOT NULL,
  h0 INTEGER, h1 INTEGER, h2 INTEGER, h3 INTEGER, hm INTEGER, hms INTEGER, md_td INTEGER, md_bu INTEGER,
  extent_src INTEGER NOT NULL, flags INTEGER NOT NULL);           -- fid = rank by rva (0..n-1)
CREATE TABLE bb (fid INTEGER NOT NULL, ord INTEGER NOT NULL, rva INTEGER NOT NULL, size INTEGER NOT NULL,
  n_insn INTEGER NOT NULL, h1 INTEGER, hms INTEGER, succ TEXT NOT NULL, PRIMARY KEY (fid, ord));
CREATE TABLE call (fid INTEGER NOT NULL, site INTEGER NOT NULL, callee INTEGER, import_key TEXT, kind INTEGER NOT NULL);
CREATE TABLE str (fid INTEGER NOT NULL, site INTEGER NOT NULL, sha TEXT NOT NULL, len INTEGER NOT NULL, prefix TEXT);
CREATE TABLE cst (fid INTEGER NOT NULL, site INTEGER NOT NULL, value INTEGER NOT NULL, ctx INTEGER NOT NULL);
CREATE TABLE ins (fid INTEGER PRIMARY KEY, blob BLOB NOT NULL, txt BLOB);   -- zlib of packed `ins/1` records / of text
```
Key columns (computed by `ir/features.py`, all 64-bit `blake2b(digest_size=8)` stored as signed INTEGER; NOP-family instructions skipped from h1..hms under normalisation `norm/1`):

| Column | Level | Definition (R04 s5 ladder) |
|---|---|---|
| `h0` | L0 | raw body bytes in range order |
| `h1` | L1 | bytes with address-bearing operand bits zeroed: relative branch/call targets, RIP-relative displacements, absolute values inside [image_base, image_base+size_of_image) or covered by a base relocation (`ir/pe_tables.py`) |
| `h2` | L2 | L1 plus every immediate and non-RIP displacement zeroed (opcode and register fields kept) |
| `h3` | L3 | SLEIGH instruction mask applied (all operand fields zeroed; = Ghidra ExactInstructions) |
| `hm` / `hms` | M / MS | ordered mnemonic sequence / sorted mnemonic multiset (exact, not a prime product: R02 s6) |
| `md_td`, `md_bu` | topology | BinDiff-style flow-graph MD index top-down / bottom-up, `round(md * 10**12)` (D-16); NULL when `n_bb < L-11` |
| `extent_src` | | 0 = Ghidra function body, 1 = confirmed by a `.pdata` RUNTIME_FUNCTION with the same begin/end, 2 = conflict (flag) |
`content_digest` = SHA-256 over canonical JSON of every table's rows in primary-key order (file bytes are not deterministic). Manifest `program-ir/1`:
```json
{"contract":"program-ir/1","ir_key":"<64hex>","content_digest":"<64hex>","artifact_sha256":"<64hex>",
 "program_sha256":"<64hex>","image_base":5368709120,"size_of_image":1048576,
 "producer":{"kind":"ghidra","mode":"gzf","ghidra":"12.0.4","pyghidra":"3.0.2","java":"25","python":"3.12.10",
             "script_sha256":"<64hex>","analysis_options_digest":"<64hex>","gzf_sha256":"<64hex>"},
 "ingest_version":"ir-ingest/1","norm_version":"norm/1",
 "counts":{"functions":1210,"blocks":18833,"instructions":201544,"call_edges":7120,"strings":904,"consts":2210,
           "thunks":88,"imports":312,"pdata_confirmed":1004},
 "limits_hit":[],"warnings":[],"file_sha256":"<64hex>","created_utc":"2026-10-14T12:00:00+00:00"}
```

## 4. Results (DERIVED; never written into `ComparisonProject`)
Layout: `runs/<ghidriff_run_id>/unified/results/<result_id>/{manifest.json, rows.jsonl.gz, facts.jsonl.gz}` (inside `runs/`, so backups copy it). Write path: worker writes into a private temp dir; owner verifies every part hash, `os.replace`s the directory, then publishes the pointer row (D-07). Readers trust a directory only if the pointer row exists AND every hash matches; otherwise state "stale: re-run" (never a crash).

```python
class Atom(_Strict):                      # one piece of pairing evidence from one source
    source: SourceId                      # 'ghidriff', 'rz-diff', 'bindiff', 'pt-ladder', 'pt-bytes', 'manual', 'diaphora'
    step: StepId                          # 'P06-masked-exact', 'SymbolsHash', 'name hash matching', 'levenshtein-bytes'
    tier: Tier; cardinality: Card
    older_rva: Rva | None; newer_rva: Rva | None
    native: tuple[tuple[str, str], ...] = ()    # <= 4 (label, upstream text); display only, never parsed for decisions
    ref: str | None = None                # stored set entry id, EngineRun id, FunctionMatch id or ladder round

class SideRef(_Strict):
    rva: Rva; name: str | None = Field(default=None, max_length=256)
    kind: Literal['function', 'thunk', 'import', 'external', 'unknown']

class Support(_Strict):
    component: str = Field(pattern=r'^K[0-9]{1,2}$')     # independence component id, stable per registry digest
    tier: Tier; atom_index: int = Field(ge=0)             # strongest atom of that component (max-pool)

class Contest(_Strict):
    strength: Literal['strong', 'weak']; against: tuple[int, ...]   # atom indexes proposing another partner

class UnifiedMatch(_Strict):
    contract: Literal['unified-match/1'] = 'unified-match/1'
    row_id: Sha256                        # keys.row_id(older_sha, newer_sha, sorted older rvas, sorted newer rvas)
    older: tuple[SideRef, ...]; newer: tuple[SideRef, ...]   # 0..N; groups carry several
    decision: Decision
    support: tuple[Support, ...] = ()
    contest: Contest | None = None
    atoms: tuple[Atom, ...]               # <= L-39, sorted (component, tier, source, step)
    ghidriff_match_id: str | None = None
    materiality: Materiality = 'unknown'
    change_classes: tuple[ChangeClass, ...] = ()
    flags: tuple[RowFlag, ...] = ()
    hints: tuple[str, ...] = ()           # advisory, e.g. 'ghidriff-diff-types:address,refcount'

class Delta(_Strict):
    cls: ChangeClass; channel: ChannelId
    older_rva: Rva | None; newer_rva: Rva | None
    old: str | None = Field(default=None, max_length=120); new: str | None = Field(default=None, max_length=120)

class ChangeFacts(_Strict):
    contract: Literal['change-facts/1'] = 'change-facts/1'
    row_id: Sha256
    verdict: Materiality
    proof: Literal['COS-ADDR/1', 'COS-LAYOUT/1', 'COS-PSEUDO/1'] | None = None
    second_channel: ChannelId | None = None
    channels: tuple[tuple[ChannelId, ChannelState], ...]   # all nine, fixed order
    deltas: tuple[Delta, ...] = ()        # <= L-28; rest counted in deltas_omitted
    deltas_omitted: int = 0
    limits_hit: tuple[str, ...] = ()

class UnifiedResultManifest(_Strict):
    contract: Literal['unified-result/1'] = 'unified-result/1'
    result_id: Sha256                     # == keys.result_key(...) (s5)
    older_sha256: Sha256; newer_sha256: Sha256; orientation: Literal['older->newer']
    ghidriff_run_id: str; ghidriff_raw_sha256: Sha256
    ir_older: IrRef | None; ir_newer: IrRef | None          # IrRef = {ir_key, content_digest, producer_mode, functions}
    sources: tuple[SourceRef, ...]        # SourceRef = {source, entry_id, file_sha256 | None, version}
    manual_digest: Sha256; config_digest: Sha256; engine_version: Literal['ude/1']
    status: Literal['complete', 'partial']; limitations: tuple[str, ...]
    counts: dict[str, int]                # fixed keys: one per Decision and per Materiality
    parts: tuple[Part, ...]               # Part = {name, sha256, bytes, records}
    created_utc: str                      # not part of result_id
```
Pointer rows (enrichment kinds; bodies <= L-31):

| Kind | Entry id | Body | Guard |
|---|---|---|---|
| `unified-result` | `result_id` | `{contract:'unified-result-ptr/1', result_id, relative_dir, manifest_sha256, status, counts, config_digest}` | `Guard(project_id, ghidriff_run_id, raw_sha256, input_digest=result_id)` |
| `unified-run` | `domain_id('unified-run', 1, {result_key, started_utc})` | `UnifiedRun` (`unified-run/1`): `run_id, result_id|None, status ok|partial|failed|cancelled|timeout|unsupported|cached, error_code, stages[{stage, status, duration_ms, reason}], provenance (<= 16 keys x 256 chars), stderr_tail <= 64 KiB, started_utc, duration_ms` | same |
Retention (own, D-07): after a publish keep the newest L-32 results per `(older, newer, config_digest)` plus the current one; delete older pointer rows (only kinds `unified-*`) and their directories after a verified project backup exists (reuse `_write_backup` label `unified-retention`); orphan result dirs older than 5 minutes without a row are removed on the next publish. `unified-run` keeps the newest 8 per pair (same number as `RUN_KEEP`, storage.py:33). Staleness: the guard covers the Ghidriff run; the read model ALSO recomputes `result_key` from current inputs and reports which input changed (s5 inputs) as state U6.

In-memory only (frozen dataclasses, never persisted): `IrReader` / `FunctionTable` (columnar `array('q')` per column + CSR adjacency, R04 s7), `CorrPair(older_fid, newer_fid, pass_id, tier, round, votes, via)`, `CorrGroup(kind, older_fids, newer_fids, reason)`, `UnifiedRequest`, `StageEvent(stage, done, total|None)`, `UnifiedViewModel`/`UnifiedRowView` (07 s4).

## 5. Identities and cache keys (every input digest, nothing else)

| Key | `domain_id(domain, 1, payload)` payload | Notes |
|---|---|---|
| `ir_key` | `{artifact_sha256, producer_kind, mode, ghidra, pyghidra, java, python, script_sha256, analysis_options_digest, gzf_sha256|null, ingest_version, norm_version, limits_digest}` | any `unknown` version -> IR usable but never cached globally (RuntimeFingerprint rule, cache.py:114) |
| `result_key` | `{older_sha256, newer_sha256, orientation, ghidriff_raw_sha256, ir_older_digest|null, ir_newer_digest|null, sources: sorted [(source, entry_id, file_sha256, version)], manual_digest, config_digest}` | swapped orientation -> different key |
| `config_digest` | `{engine_version, pass_table_digest, registry_digest, channel_versions, proof_versions, limits_digest}` | changes on any rule change |
| `manual_digest` | sorted `[(category, older addresses, newer addresses)]` of `manual=True` matches | |
| `row_id` | `{older_sha256, newer_sha256, older_rvas: sorted, newer_rvas: sorted}` | stable across runs for the same pairing |
| `limits_digest` | canonical JSON of `UnifiedLimits` | |
Timestamps, absolute paths and display preferences are never hashed (SPEC-07 s3 rule).

## 6. Limits (single source of numbers; `UnifiedLimits` defaults; measured by the named bench or test)

| ID | Limit | Default | Measured / enforced by |
|---|---|---|---|
| L-01 | functions per side | 250,000 | ingest counter -> `LIMIT` |
| L-02 | instructions per side (blocks counted alike) | 20,000,000 | ingest counter; warn above 5,000,000 |
| L-03 | extractor JVM heap `-Xmx` | 50 % of RAM, max 16 GiB | argv; `bench_extract` peak |
| L-04 | extractor timeout | analyze 7,200 s, gzf 1,800 s (range 60..86,400) | `run_process` |
| L-05 | extractor output | 2 GiB per side, 64 MiB per line, 64 KiB per string | output guard (`check_output`) + ingest |
| L-06 | per-function detail | raw bytes 16 MiB; 100,000 instructions | ingest; beyond -> `oversize`/`truncated` flags, keys NULL |
| L-07 | `ir.sqlite3` size | 1 GiB | ingest |
| L-08 | ingest budget | 1,800 s, target RSS 1.5 GiB | `bench_ingest` |
| L-09 | minimum body for content keys | 10 bytes | pass gates (Ghidra/ghidriff minimum, R03 s1) |
| L-10 | tiny function | <= 5 instructions: no content-key acceptance | pass gates (R04 s4.5) |
| L-11 | MD index minimum blocks | 5 | `ir/mdindex.py` |
| L-12 | multiset keys minimum | 10 instructions | pass gates |
| L-13 / L-14 | string key: min length / rare if referenced by <= N functions per side | 5 / 4 | `ir/features.py` |
| L-15 | constant filter | abs >= 0x1000, not a contiguous bit mask, not a single bit; rare if <= 2 functions per side | `ir/features.py` (Diaphora idea, own code) |
| L-16 | set keys minimum elements | 2 (or 1 rare + size ratio guard L-21) | pass gates |
| L-17 / L-18 | hub fan-in / neighbour set cap | 64 / 64 | propagation |
| L-19 | implied matches | >= 2 votes, 0 conflicts | propagation (Ghidra AutoVT defaults, R03 s1) |
| L-20 | reference vectors | cosine >= 0.95, confidence >= 10.0, margin to runner-up >= 0.05 | P16 |
| L-21 | size-ratio guard | 0.5 .. 2.0 | name and gap passes |
| L-22 / L-23 | blocking: candidates per function / bucket cap | 20 / 300 | `ladder/blocking.py` |
| L-24 | assignment bucket cap / total budget / score floor | 200 / 30 s / 0.6 | `ladder/assign.py` |
| L-25 | BB vote | >= 2 distinct rare blocks of >= 4 instructions | P17 |
| L-26 | layout gap | exactly one unmatched function per side between two ladder-accepted anchors | P18 |
| L-27 | L2 alignment | 20,000 instructions per side per pair (beyond: prefix/suffix only, verdict `review`) | `facts/align.py` |
| L-28 | stored deltas per pair | 64 | `ChangeFacts` |
| L-29 | canonical pseudo-code input | 20,000 lines / 2,000,000 chars per side (= enrichment views bound) | `facts/pseudo.py` |
| L-30 | result part / result dir | 512 MiB / 1 GiB | worker + owner |
| L-31 | pointer row body | 64 KiB | store |
| L-32 | results kept per (pair, config) | 3 | retention |
| L-33 | displayed rows | 100,000 (= `evidence_view.DISPLAY_ROW_CAP`) | read model |
| L-34 | worker timeout | 3,600 s (range 60..86,400) | `run_process` |
| L-35 | performance targets [inf, unmeasured] | ladder 10k fns <= 15 s, 60k <= 120 s; ingest 60k fns / 3 M insns <= 600 s; facts 5,000 changed pairs <= 60 s; worker peak RSS <= 1.5 GiB at 60k; UI first paint <= 200 ms, filter <= 100 ms, sort <= 150 ms at 100k rows | `tools/unified/bench.py`, `tests/test_unified_perf.py` (5x slack) |
| L-36 | retained GZFs per run | 4 GiB total, else not retained (analyze-mode fallback) | backend seam |
| L-37 | `progress.json` | 4 KiB, polled every 50 ms | runner |
| L-38 | rows per result | 2 x L-01 | worker |
| L-39 | atoms per row | 64 (rest counted in `hints`) | arbiter |

## 7. Versioning and migration rules
1. Additive only: new kinds `unified-run`, `unified-result` (KINDS only); no DDL in `project.sqlite3`; no change to `secondary/1|2`, `engine-run/1`, `enrichment/1`, `features/1`, `nway/1`, model `schema_version` 1.
2. Sidecars are derived: a future `program-ir/2` or `unified-result/2` is re-computed, never migrated in place; a reader that sees a newer contract reports `stale: produced by a newer PatchTrace` and stays read-only (fail closed).
3. Old readers: never see unified kinds (query by kind); retention ignores them; their 128 MiB total counts the tiny pointer rows only. Test `test_old_reader_ignores_unified_kinds`.
4. Every publish that may delete anything takes the verified backup first (existing `_write_backup` discipline) and is idempotent: re-publishing the same `result_id` upserts the same row and finds the same directory.
5. Schema generation covers `UnifiedMatch`, `ChangeFacts`, `UnifiedResultManifest`, `UnifiedRun`, `ProgramIrManifest`, `ExtractRequest` and the `ir-extract/1` header/footer.

## 8. JSON examples (synthetic)
```json
{"contract":"unified-match/1","row_id":"9c1f...e2","older":[{"rva":4096,"name":"ParseHeader","kind":"function"}],
 "newer":[{"rva":4368,"name":"ParseHeader","kind":"function"}],"decision":"matched",
 "support":[{"component":"K1","tier":"A","atom_index":0},{"component":"K2","tier":"B","atom_index":3}],
 "contest":null,"atoms":[{"source":"pt-ladder","step":"P03-name-exact","tier":"A","cardinality":"1:1","older_rva":4096,"newer_rva":4368},
  {"source":"ghidriff","step":"SymbolsHash","tier":"A","cardinality":"1:1","older_rva":4096,"newer_rva":4368,"ref":"m-17"},
  {"source":"bindiff","step":"name hash matching","tier":"A","cardinality":"1:1","older_rva":4096,"newer_rva":4368,
   "native":[["similarity","0.97"],["confidence","0.99"]]},
  {"source":"pt-bytes","step":"P06-masked-exact","tier":"B","cardinality":"1:1","older_rva":4096,"newer_rva":4368}],
 "ghidriff_match_id":"m-17","materiality":"material","change_classes":["constant"],"flags":["pdata-confirmed"],"hints":[]}
```
```json
{"contract":"change-facts/1","row_id":"9c1f...e2","verdict":"material","proof":null,"second_channel":"C6",
 "channels":[["C0","differs"],["C1","differs"],["C2","differs"],["C3","equal"],["C4","equal"],["C5","differs"],
             ["C6","differs"],["C7","unavailable"],["C8","unavailable"]],
 "deltas":[{"cls":"constant","channel":"C2","older_rva":4130,"newer_rva":4402,"old":"cmp esi, 0x100","new":"cmp esi, 0x200"}],
 "deltas_omitted":0,"limits_hit":[]}
```
Invalid examples (must be rejected): `decision:'removed'` (not a Decision); a `cosmetic` verdict with `proof:null`; a `material` verdict with `second_channel:null`; an atom with `tier:'A'` and `cardinality:'non-exclusive'`; `older_rva: -1`; a manifest whose part SHA-256 differs from the file.
