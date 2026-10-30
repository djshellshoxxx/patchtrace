# SPEC-31 / 02 Data model: contracts, storage, keys, limits (contract freeze)

Repo conventions apply: persisted records are strict frozen pydantic v2 (`extra='forbid', strict=True, frozen=True`), every record carries a `contract` literal, JSON is canonical (`enrichment.identity.canonical_json`), identities are `domain_id(domain, version, payload)`, schemas are generated (`tools/generate_schemas.py` -> `docs/schemas/unified/`, CI fails on drift). Status: S0a implemented the records, limits, keys and store (2026-10-14, `src/patchtrace/unified/{limits,contracts,keys,store}.py`); details frozen by S0a and its deviations are in s9; the registry is not built yet (s9).

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
    'address-only', 'register-only', 'layout-only', 'name-only', 'frame', 'eh', 'unknown']   # frame, eh: R-14, R-16
RowFlag = Literal['tiny', 'thunk', 'import', 'hub', 'icf', 'oversize', 'truncated', 'ir-missing', 'pdata-confirmed', 'library',
    'mask-missing', 'mask-unlocated']
ProofId = Literal['UNCH/1', 'COS-ADDR/1', 'COS-LAYOUT/1', 'COS-PSEUDO/1']     # 05 s2.5; UNCH/1 makes 'unchanged' auditable too
EvidenceClass = Literal['E-NAME', 'E-BODY', 'E-CFG', 'E-CALL', 'E-DATA', 'E-DECOMP', 'E-LAYOUT', 'E-RESID', 'E-MANUAL', 'E-UNKNOWN']
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
| header `producer` | `{mode: 'gzf'|'analyze', ghidra, pyghidra, java, python, script_sha256, analysis_options_digest, analyzed: bool, symbols: 'primary'|'none'}` | versions are probed strings, `unknown` allowed but makes the IR cache-ineligible; `analyzed` false -> `gzf-not-analyzed` (03 s9) |
| fn `rva`, `ranges` | Rva; `[[rva, len], ...]` <= 64 ranges | entry RVA; body ranges (chunks) |
| fn `name`, `name_src`, `aliases` | str <= 512; `DEFAULT|ANALYSIS|IMPORTED|USER_DEFINED`; <= 16 names | Ghidra symbol and source type; aliases = other symbols at the entry (ICF) |
| fn `kind`, `thunk_target`, `import` | `normal|thunk|external`; Rva|null; `{dll, name|null, ordinal|null}`|null | |
| fn `lib` | bool | Ghidra Function ID (FID) matched this function to a known library body [unv API]; tag only (F16) |
| fn `raw` | hex, <= L-06 bytes per function | body bytes in range order; absent -> flag `oversize` |
| fn `blocks` | `[[rva, len, n_insn, [succ_rva...], [kind...]], ...]` <= L-02 total | Ghidra basic-block model; kinds `fall|jump|cond|switch|call-return` |
| fn `insns` | `[[off, len, mnem, imask_hex|null, [[optype, omask_hex|null, objs, refs], ...], flow], ...]` <= L-06 per fn | raw Ghidra facts only (D-04): `optype` = OperandType flag int; `objs` = `[[kind, value], ...]` with kind `reg|scalar|addr` (register name, signed int, RVA); `refs` = `[[reftype, target], ...]` with target `rva:<int>`, `stack:<int>`, `ext:<import key>`; the ingest derives `vkind` and the address field (03 s6) |
| fn `calls`, `strings` | `[[site_rva, target_rva|null, import_key|null, 'call|jump'], ...]`; `[[site_rva, sha256, len, prefix<=64], ...]` | resolved references |
| fn `text` | list of str, one per instruction, each <= 256 | Ghidra instruction text, for display only |
| footer | `{functions, instructions, status: 'complete'|'partial', warnings[<=64]}` | counts must equal what was read |
Validation is hand-written and streaming for `fn` lines (pydantic only for header/footer; 2 M pydantic objects would cost minutes, R04 s7) and is fuzzed (08 s5).

## 3. ProgramIR `program-ir/1` (canonical, written by PatchTrace, read-only after publish)
Location: `runs/<run_id>/unified/ir/<ir_key[:16]>/{ir.sqlite3, manifest.json}` (16-hex directory name keeps Windows paths short; the manifest holds the full key and a mismatch is `STORE`); optional global copy in `DerivedCache` stage `program-ir` (payload = stored-zip of both files, U-08). Opened with `file:...?mode=ro&immutable=1`, `trusted_schema=OFF`, an authorizer that allows only SELECT/READ on the tables below (pattern of the hardened `.BinDiff` importer, secondary/bindiff.py:57-78).

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);   -- contract, ir_key, content_digest, versions
CREATE TABLE mnem (id INTEGER PRIMARY KEY, text TEXT NOT NULL UNIQUE);
CREATE TABLE fn (fid INTEGER PRIMARY KEY, rva INTEGER NOT NULL UNIQUE, size INTEGER NOT NULL,
  kind INTEGER NOT NULL, name TEXT, name_src INTEGER NOT NULL, aliases TEXT, import_key TEXT, thunk_target INTEGER,
  n_bb INTEGER NOT NULL, n_edge INTEGER NOT NULL, n_insn INTEGER NOT NULL, n_call INTEGER NOT NULL, loops INTEGER NOT NULL,
  h0 INTEGER, h1 INTEGER, h2 INTEGER, h3 INTEGER, hm INTEGER, hms INTEGER, md_td INTEGER, md_bu INTEGER,
  extent_src INTEGER NOT NULL, flags INTEGER NOT NULL, eh TEXT);  -- fid = rank by rva (0..n-1); eh = 03 s7 signature or NULL
CREATE TABLE bb (fid INTEGER NOT NULL, ord INTEGER NOT NULL, rva INTEGER NOT NULL, size INTEGER NOT NULL,
  n_insn INTEGER NOT NULL, h1 INTEGER, hms INTEGER, succ TEXT NOT NULL, PRIMARY KEY (fid, ord));
CREATE TABLE call (fid INTEGER NOT NULL, site INTEGER NOT NULL, callee INTEGER, import_key TEXT, kind INTEGER NOT NULL);
CREATE TABLE str (fid INTEGER NOT NULL, site INTEGER NOT NULL, sha TEXT NOT NULL, len INTEGER NOT NULL, prefix TEXT);
CREATE TABLE cst (fid INTEGER NOT NULL, site INTEGER NOT NULL, value INTEGER NOT NULL, ctx INTEGER NOT NULL);
CREATE TABLE ref (fid INTEGER NOT NULL, ord INTEGER NOT NULL, opi INTEGER NOT NULL, kind INTEGER NOT NULL,   -- code|data|import|stack
  target INTEGER, import_key TEXT, PRIMARY KEY (fid, ord, opi, kind, target));    -- DATA-MAP votes (05 s2.7), no decoding needed
CREATE TABLE ins (fid INTEGER PRIMARY KEY, blob BLOB NOT NULL, txt BLOB);   -- zlib of packed `ins/1` records / of text
```
Key columns (computed by `ir/features.py`, all 64-bit `blake2b(digest_size=8)` stored as signed INTEGER; NOP-family instructions skipped from h1..hms under normalisation `norm/1`):

| Column | Level | Definition (R04 s5 ladder) |
|---|---|---|
| `h0` | L0 | raw body bytes in range order |
| `h1` | L1 | bytes with the located address FIELD of each `address` operand zeroed (03 s6): relative branch/call targets, RIP-relative and RVA-form displacements, in-image absolute values, relocated values; SIB/ModRM register bits never |
| `h2` | L2 | L1 plus every immediate and every stack/memory displacement field zeroed (opcode and register fields kept) |
| `h3` | L3 | SLEIGH instruction mask applied (all operand fields zeroed; the bytes Ghidra's ExactInstructions hashes, over the non-NOP instructions only: its classes equal that hasher's on every function without a skipped NOP or INT3-padding instruction and are coarser, never finer, on the others; A-27) |
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
           "refs":30411,"thunks":88,"imports":312,"pdata_confirmed":1004,"mask_unlocated":0},
 "limits_hit":[],"warnings":[],"file_sha256":"<64hex>","created_utc":"2026-10-14T12:00:00+00:00"}
```

## 4. Results (DERIVED; never written into `ComparisonProject`)
Layout: `runs/<ghidriff_run_id>/unified/results/<result_id[:16]>/{manifest.json, rows.jsonl.gz, facts.jsonl.gz}` (inside `runs/`, so backups copy it; full id in the manifest). Write path: worker writes into a private temp dir; owner verifies every part hash, `os.replace`s the directory, then publishes the pointer row (D-07). Readers trust a directory only if the pointer row exists AND every hash matches; otherwise state "stale: re-run" (never a crash).

Same-id decompile refreshes preserve the previously committed directory until the replacement pointer commits.
Only a completed decompile stage with text for every requested pair and a successfully stored code part permits
a same-id replacement. A skipped,
failed or partial decompile must preserve any previously committed result and its code part; differing content
is refused as `result-drift`, as for a refresh with decompilation disabled.
Before replacing it, the owner moves the prior directory to a sibling
`prev-<result_id[:16]>-<previous_manifest_sha256[:16]>`; installation or pointer failures restore it.
If the process stops before rollback, readers may use only that exact sibling after verifying its full manifest hash,
result id, parts and pointer ownership. This fallback is read-only and also applies when the canonical directory is
absent. Orphan cleanup must retain any previous directory named by a valid pointer, and must retain all previous
directories while any result pointer is unreadable. An unreferenced previous directory may be swept after five
minutes. No persisted result or pointer schema changes.

An optional `decomp.jsonl.gz` part is deeply verified before publication: strict JSON objects with exactly
`side`, `rva`, `status`, `code`; side/RVA must occur in a result row and may occur once; `ok` requires nonempty
bounded UTF-8 text, and `failed`/`timeout` require null. The display cache is keyed by the manifest part hash,
bytes and record count, because a valid decompile refresh can change the part without changing the result id.

```python
class Atom(_Strict):                      # one piece of pairing evidence from one source
    source: SourceId                      # 'ghidriff', 'rz-diff', 'bindiff', 'pt-ladder', 'pt-bytes', 'manual', 'diaphora'
    step: StepId                          # '<pass id>-<pass name>' e.g. 'P05-masked-exact'; 'SymbolsHash'; 'name hash matching'; 'levenshtein-bytes'
    tier: Tier; cardinality: Card; cls: EvidenceClass        # class from the registry at run time (05 s1.1), persisted for audit
    older_rva: Rva | None; newer_rva: Rva | None
    native: tuple[tuple[str, str], ...] = Field(default=(), max_length=4)   # (label, upstream text); display only, never parsed
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
    proof: ProofId | None = None          # required iff verdict in ('unchanged', 'cosmetic')
    second_channel: ChannelId | None = None   # required iff verdict == 'material' (anchored, 05 s2.5)
    channels: tuple[tuple[ChannelId, ChannelState], ...]   # all nine, fixed order
    targets: tuple[int, int, int] = (0, 0, 0)               # address operands (mapped, unmapped, conflict), 05 s2.7
    eh: Literal['equal', 'differs', 'absent', 'unavailable'] = 'unavailable'
    deltas: tuple[Delta, ...] = ()        # <= L-28; rest counted in deltas_omitted
    deltas_omitted: int = 0
    limits_hit: tuple[str, ...] = ()

class UnifiedResultManifest(_Strict):
    contract: Literal['unified-result/1'] = 'unified-result/1'
    result_id: Sha256                     # == keys.result_key(...) (s5)
    older_sha256: Sha256; newer_sha256: Sha256; orientation: Literal['older->newer']
    ghidriff_run_id: str; ghidriff_raw_sha256: Sha256
    ir_older: IrRef | None; ir_newer: IrRef | None
    sources: tuple[SourceRef, ...]
    manual_digest: Sha256; config_digest: Sha256; engine_version: Literal['ude/1']
    status: Literal['complete', 'partial']; limitations: tuple[str, ...]
    counts: Counts                        # one int field per Decision and per Materiality value (no free dict)
    parts: tuple[Part, ...]
    created_utc: str                      # not part of result_id

class IrRef(_Strict): ir_key: Sha256; content_digest: Sha256; producer_mode: Literal['gzf', 'analyze', 'binexport', 'rizin']; functions: int
class SourceRef(_Strict): source: SourceId; entry_id: str; file_sha256: Sha256 | None; version: str = Field(max_length=64)
class Part(_Strict): name: Literal['rows.jsonl.gz', 'facts.jsonl.gz', 'decomp.jsonl.gz']; sha256: Sha256; bytes: int; records: int
```
Pointer rows (enrichment kinds; bodies <= L-31 = 128 KiB, so a `unified-run` row with a 32 KiB stderr tail fits; R-10):

| Kind | Entry id | Body | Guard |
|---|---|---|---|
| `unified-result` | `result_id` | `{contract:'unified-result-ptr/2', result_id, relative_dir, manifest_sha256, status, counts, config_digest, older_sha256, newer_sha256}` (`/1` rows lack the pair; they stay readable, S0a-FIX, s9.1) | `Guard(project_id, ghidriff_run_id, raw_sha256, input_digest=result_id)` |
| `unified-run` | `domain_id('unified-run', 1, {result_key, started_utc})` | `UnifiedRun` (`unified-run/1`): `run_id, result_id|None, status ok|partial|failed|cancelled|timeout|unsupported|cached, error_code, stages[{stage, status, duration_ms, reason}] (<= 16), provenance (<= 16 keys x 256 chars), stderr_tail <= 32 KiB (sanitised), peak_rss_bytes | None, started_utc, duration_ms` | same |
Retention (own, D-07): after a publish keep the newest L-32 results per `(older_sha256, newer_sha256, config_digest)` of the pointer (never per `config_digest` alone: another pair or orientation must not evict a result) plus the current one; delete older pointer rows (only kinds `unified-*`, through the public `EnrichmentStore.backup_once(label)` and `delete_own(ids, kinds)` wrappers of A-04, never the private `_write_backup`/`_delete`) and their directories after a verified project backup exists (label `unified-retention`); orphan result dirs older than 5 minutes without a row are removed on the next publish. `unified-run` keeps the newest 8 per pair, grouped by the Ghidriff run in the row guard (same number as `RUN_KEEP`, storage.py:33). Staleness: the guard covers the Ghidriff run; the read model ALSO recomputes `result_key` from current inputs and reports which input changed (s5 inputs) as state U6.

In-memory only (frozen dataclasses, never persisted): `IrReader` / `FunctionTable` (columnar `array('q')` per column + CSR adjacency, R04 s7), `CorrPair(older_fid, newer_fid, pass_id, tier, round, votes, via)`, `CorrGroup(kind, older_fids, newer_fids, reason)`, `UnifiedRequest`, `StageEvent(stage, done, total|None)`, `UnifiedViewModel`/`UnifiedRowView` (07 s4).

## 5. Identities and cache keys (every input digest, nothing else)

| Key | `domain_id(domain, 1, payload)` payload | Notes |
|---|---|---|
| `ir_key` | `{artifact_sha256, producer_kind, mode, symbols, ghidra, pyghidra, python, script_sha256, analysis_options_digest, ingest_version, norm_version, ingest_limits_digest}` | computable BEFORE extraction (Ghidra version from `application.properties`, pyghidra/python from the run settings of the Ghidriff run); `gzf_sha256` and `java` are provenance only (R-09); any `unknown` version -> IR usable but never cached globally (RuntimeFingerprint rule, cache.py:114) |
| `result_key` | `{older_sha256, newer_sha256, orientation, ghidriff_raw_sha256, ir_older_digest|null, ir_newer_digest|null, sources: sorted [(source, entry_id, file_sha256, version)], manual_digest, config_digest}` | swapped orientation -> different key |
| `config_digest` | `{engine_version, pass_table_digest, registry_digest, channel_versions, proof_versions, limits_digest}` | changes on any rule change |
| `manual_digest` | sorted `[(category, older addresses, newer addresses)]` of `manual=True` matches | |
| `row_id` | `{older_sha256, newer_sha256, older_rvas: sorted, newer_rvas: sorted}` | stable across runs for the same pairing |
| `limits_digest` | canonical JSON of the content-affecting limits: every `UnifiedLimits` field except `OPERATIONAL_LIMIT_FIELDS` (timeouts, memory, store/pointer caps, retention, UI and performance targets), domain version 2 | in `config_digest` only; an operational knob never re-keys cached results |
| `ingest_limits_digest` | canonical JSON of the limits that change IR content: L-01, L-02, L-05, L-06, L-07, L-11 | a ladder or facts threshold change never invalidates IR (which costs Ghidra minutes to hours, R-09) |
Timestamps, absolute paths and display preferences are never hashed (SPEC-07 s3 rule).

## 6. Limits (single source of numbers)
Defaults of `UnifiedLimits`; each is enforced or measured by the named code, bench or test. Other files repeat a number only next to its L-id.

| ID | Limit | Default | Measured / enforced by |
|---|---|---|---|
| L-01 | functions per side | 250,000 | ingest counter -> `LIMIT` |
| L-02 | instructions per side (blocks counted alike) | 20,000,000 | ingest counter; warn above 5,000,000 |
| L-03 | extractor JVM heap `-Xmx` | 50 % of RAM, max 16 GiB | argv; `bench_extract` peak |
| L-04 | extractor timeout | analyze 7,200 s, gzf 1,800 s (range 60..86,400) | `run_process` |
| L-05 | extractor output | 2 GiB per side, 64 MiB per line, 64 KiB per string | output guard (`check_output`) + ingest |
| L-06 | per-function detail | raw bytes 16 MiB; 100,000 instructions | ingest; beyond -> `oversize`/`truncated` flags, keys NULL |
| L-07 | `ir.sqlite3` size | 1 GiB | ingest |
| L-08 | ingest budget | 1,800 s, target RSS 1.5 GiB (prototype: 28.9 s / 304 MiB at 60k functions, 2.84 M instructions [own]) | `bench_ingest` |
| L-09 | minimum body for content keys | 10 bytes | pass gates (Ghidra/ghidriff minimum, R03 s1) |
| L-10 | tiny function | <= 5 instructions: no content-key acceptance | pass gates (R04 s4.5) |
| L-11 | MD index minimum blocks | 5 | `ir/mdindex.py` |
| L-12 | multiset keys minimum | 10 instructions | pass gates |
| L-13 / L-14 | string key: min length / rare if referenced by <= N functions per side | 5 / 4 | `ladder/passes.py` (the IR stores every string; rarity is never IR content) |
| L-15 | constant filter | abs >= 0x1000, not a contiguous bit mask, not a single bit; rare if <= 2 functions per side | `ladder/passes.py` (Diaphora idea, own code; IR stores every constant) |
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
| L-31 | pointer row body (`unified-result`, `unified-run`) | 128 KiB (`stderr_tail` <= 32 KiB inside it) | store |
| L-32 | results kept per (pair, config) | 3 | retention |
| L-33 | displayed rows | 100,000 (= `evidence_view.DISPLAY_ROW_CAP`) | read model |
| L-34 | worker timeout | 3,600 s (range 60..86,400) | `run_process` |
| L-35 | performance targets | ladder 10k fns <= 15 s, 60k <= 120 s; ingest 60k fns / 3 M insns <= 600 s; facts 5,000 changed pairs <= 60 s; worker peak RSS <= 1.5 GiB at 60k; UI first paint <= 200 ms, filter <= 100 ms, sort <= 150 ms at 100k rows. Prototypes [own, synthetic, 2.1 GHz vCPU]: ingest 28.9 s / 304 MiB at 60k; ladder global passes + propagation 0.4 s / 93 MiB at 60k, 2.2 s / 362 MiB at 250k; extractor dump 68-70 us per instruction through JPype (dominant cost, about 3.5 min per side at 3 M) | `tools/unified/bench.py`, `tests/test_unified_perf.py` (5x slack) |
| L-36 | retained GZFs per run | 4 GiB total, else not retained (analyze-mode fallback) | backend seam |
| L-37 | `progress.json` | 4 KiB, polled every 50 ms | runner |
| L-38 | rows per result | 2 x L-01 | worker |
| L-39 | atoms per row | 64 (rest counted in `hints`) | arbiter |
| L-40 | DATA-MAP | votes per data pair kept 8; region-shift search within the same section only; 1,000,000 data pairs | `facts/datamap.py` |
| L-41 | S3b on-demand decompile | 64 pairs per run, 60 s per function, 600 s per run | `extract` decompile mode |
| L-42 | worker child memory cap | min(4 GiB, 50 % of RAM) via `run_process(memory_limit_bytes=...)`, OOM classified as in C3 (`binexport_run._out_of_memory`); never applied to the JVM child (RLIMIT_AS breaks JVM reservations; `-Xmx` bounds it) | `pipeline.py` |

### 6.1 Borrowed thresholds are hypotheses (R-12)
L-09..L-12, L-16, L-19, L-20, L-24 floor, L-25 and the gate targets of 08 are other tools' priors (Ghidra VT/AutoVT, BinDiff, Diaphora, QBinDiff), not PE measurements. Rules: (1) every A/B acceptance gate is a floor, so a wrong value can only cost recall, never admit a pair a stricter value rejects; (2) tier-C-only thresholds (L-20, L-24, L-25, L-26) never make a row `matched`; (3) values change only through the 08 s3 dev-lineage procedure, frozen before a locked run, each change recorded in `config_digest`; (4) the per-pass precision table of G-U3 demotes a pass whose CI lower bound is < 98 %.

## 7. Versioning and migration rules
1. Additive only: new kinds `unified-run`, `unified-result` (KINDS only); no DDL in `project.sqlite3`; no change to `secondary/1|2`, `engine-run/1`, `enrichment/1`, `features/1`, `nway/1`, model `schema_version` 1.
2. Sidecars are derived: a future `program-ir/2` or `unified-result/2` is re-computed, never migrated in place; a reader that sees a newer contract reports `stale: produced by a newer PatchTrace` and stays read-only (fail closed).
3. Old readers: never see unified kinds (query by kind); retention ignores them; their 128 MiB total counts the tiny pointer rows only. Test `test_old_reader_ignores_unified_kinds`.
4. Every publish that may delete anything takes the verified backup first (existing `_write_backup` discipline) and is idempotent: re-publishing the same `result_id` upserts the same row and finds the same directory.
5. Schema generation covers `UnifiedMatch`, `ChangeFacts`, `UnifiedResultManifest` (with `IrRef`, `SourceRef`, `Part`, `Counts`), `UnifiedRun`, `ProgramIrManifest`, `ExtractRequest` and the `ir-extract/1` header/footer.
6. Fixtures under `tests/fixtures/unified/` are byte-stable across Windows checkouts: S0a adds `.gitattributes` lines `tests/fixtures/unified/*.json text eol=lf`, `tests/fixtures/unified/*.jsonl text eol=lf` and `tests/fixtures/unified/*.bin binary`, as e61f7c8 did for secondary fixtures.
7. Additive means a new `/N`: records are `extra='forbid'`, so a field added to `unified-x/1` would make every older reader reject the row. A change of a persisted field set therefore introduces `unified-x/2` (own model and schema file) and a version-gated reader that still accepts `/1` (`contracts.parse_pointer`); a reader that meets a higher `/N` reports `PT-UNIFIED-STALE` with reason `newer-contract` and keeps the row untouched.

## 8. JSON examples (synthetic)
```json
{"contract":"unified-match/1","row_id":"9c1f...e2","older":[{"rva":4096,"name":"ParseHeader","kind":"function"}],
 "newer":[{"rva":4368,"name":"ParseHeader","kind":"function"}],"decision":"matched",
 "support":[{"component":"K1","tier":"A","atom_index":0},{"component":"K2","tier":"B","atom_index":3}],
 "contest":null,"atoms":[{"source":"pt-ladder","step":"P03-name-exact","tier":"A","cardinality":"1:1","cls":"E-NAME","older_rva":4096,"newer_rva":4368},
  {"source":"ghidriff","step":"SymbolsHash","tier":"A","cardinality":"1:1","cls":"E-NAME","older_rva":4096,"newer_rva":4368,"ref":"m-17"},
  {"source":"bindiff","step":"name hash matching","tier":"A","cardinality":"1:1","cls":"E-NAME","older_rva":4096,"newer_rva":4368,
   "native":[["similarity","0.97"],["confidence","0.99"]]},
  {"source":"pt-bytes","step":"P06-operand-class","tier":"B","cardinality":"1:1","cls":"E-BODY","older_rva":4096,"newer_rva":4368}],
 "ghidriff_match_id":"m-17","materiality":"material","change_classes":["constant"],"flags":["pdata-confirmed"],"hints":[]}
```
```json
{"contract":"change-facts/1","row_id":"9c1f...e2","verdict":"material","proof":null,"second_channel":"C6",
 "channels":[["C0","differs"],["C1","differs"],["C2","differs"],["C3","equal"],["C4","equal"],["C5","differs"],
             ["C6","differs"],["C7","unavailable"],["C8","unavailable"]],
 "deltas":[{"cls":"constant","channel":"C2","older_rva":4130,"newer_rva":4402,"old":"cmp esi, 0x100","new":"cmp esi, 0x200"}],
 "deltas_omitted":0,"limits_hit":[],"targets":[3,0,0],"eh":"equal"}
```
(C6 here is the anchored second channel: its token diff contains the literal pair 0x100 -> 0x200 of the same instruction, 05 s2.5.)
Invalid examples (must be rejected): `decision:'removed'` (not a Decision); an `unchanged` or `cosmetic` verdict with `proof:null`; a `material` verdict with `second_channel:null`; an atom with `tier:'A'` and `cardinality:'non-exclusive'`; an atom without `cls`; `older_rva: -1`; a manifest whose part SHA-256 differs from the file; `counts` with an unknown key.

## 9. S0a freeze notes and deviations (2026-10-14)
1. `UnifiedError` and the codes live in stdlib-only `limits.py` and are re-exported by `contracts.py`, so `Budget` raises `BudgetExhausted(UnifiedError)` (`PT-UNIFIED-CANCEL` / `-TIMEOUT`) and contracts read caps (L-28, L-31, L-39, L-41, L-03) from `DEFAULT_LIMITS` (01 s2: contracts may also import limits). `Budget(deadline, cancel)`: deadline is an absolute `time.monotonic()` of the calling process (`Budget.after(seconds)`), checked every 4,096 units.
2. `UnifiedLimits` fields are `l<NN>_<slug>`; fractions are integer milli units (identity payloads reject floats); L-24 also carries the P19 margin 0.05 of 04 s6.4 (`l24_margin_milli`); L-38 is derived (`2 x L-01`).
3. Identity domains: `unified-ir`, `unified-result`, `unified-config`, `unified-manual`, `unified-row`, `unified-run`, `unified-limits`, `unified-ingest-limits`, `unified-sources`. `result_key` uses the IR `content_digest` and sources sorted by (source, entry_id, file_sha256, version); `manual_digest` addresses are lower-case text (ints as `0x..`), each side sorted. `config_digest` takes explicit component digests; the registry that supplies `registry_digest`/`pass_table_digest` is DEFERRED to the next wave.
4. `ir-extract/1` lines carry `"type": "header" | "fn" | "footer"`; `program-ir/1` producer adds `kind` and `symbols` (F1 needs the symbol policy); its `program_sha256` must equal `artifact_sha256`.
5. `Counts` = `{decisions: {...}, materiality: {...}}`, hyphens spelled `_` (`older_only`, `not_applicable`); both sums equal the rows part record count. Pointer body = `UnifiedResultPointer` (`unified-result-ptr/1`); `UnifiedRun.run_id` = entry id; `stderr_tail` <= 32 KiB UTF-8 without control/bidi characters except tab/newline; provenance as `engine-run/1`.
6. `Part.sha256/bytes/records` describe the DECOMPRESSED JSON Lines (one sorted-key JSON object per `\n` line); gzip is written with mtime 0 and no name and is never hashed (zlib builds differ; G-U4 needs identical manifests across OSes).
7. Model invariants beyond s8: atoms need an endpoint and `non-exclusive` implies tier W; sides sorted and unique; one-sided decisions have one side and materiality not-applicable/unknown; `contested` needs a contest, a contest appears only on contested or manual matched rows, `strength` is strong iff an against-atom has tier M/A/B; support points at an atom of its tier; unchanged/cosmetic need targets (x, 0, 0), no semantic delta, the proof's channel equal (UNCH C0, COS-ADDR C1, COS-PSEUDO C6) and EH-EQ for structural proofs; `material` needs a semantic or block delta and a differing second channel outside the bytes group (C0, C1, C2, C5).
8. Wrappers (A-04, deviation): per the phase D coordination S0a does not edit `enrichment/storage.py`; `backup_once(store, label)` and `delete_own(store, ids, kinds)` live in `unified/store.py` and use only public attributes (`EnrichmentStore.store.connection/.root`, `ingestion.safe_path`). Backup: `.part` copy via the SQLite backup API, re-opened read-only, `integrity_check`, snapshot and unified rows compared, renamed; a trusted existing `project-pre-unified-retention-*` backup of the same project is reused. `delete_own` refuses non-`unified-*` kinds.
9. Deferred (next wave): `registry.py` (families, sources, passes, channels, proofs), IR sidecar placement (`place_ir`/`find_ir`), orphan result-directory sweep, the spec status lines A-01, A-01b, A-03, A-06, A-08, A-09, A-10, A-11, A-14 and the `.gitattributes` lines (no `tests/fixtures/unified/` file exists yet).

### 9.1 S0a-FIX amendments (2026-10-14, independent audit C `docs/audits/20261014-C-unified-s0a.md`, F-01..F-26)
1. **Pointer `/2`** (F-01): `unified-result-ptr/2` = `/1` plus `older_sha256`, `newer_sha256` (model `UnifiedResultPointerV2`, own schema file; `/1` model and schema untouched). `contracts.parse_pointer` is the version-gated reader: `/1` rows stay valid (their pair is read from the manifest; an unreadable manifest means the row is never evicted), a higher `/N` is `newer-contract`. Results are retained per `(older_sha256, newer_sha256, config_digest)`, `unified-run` rows per Ghidriff run (`guard.run_id`).
2. **Free text** (F-08, F-09, F-23): display text (`Atom.step/native/ref`, `SideRef.name`, `Delta.old/new`, notes, `provenance` values, `stderr_tail`) is sanitised on construction: C0/C1 controls, DEL, bidirectional controls, zero-width and other invisible format characters become U+FFFD (length-preserving), so a hostile symbol never makes a record unbuildable; `stderr_tail` also folds CRLF and CR to LF. Identifier and protocol text (`SourceRef.entry_id`, `Version`, `ghidriff_match_id`, `ExtractRequest` options, `IrExtractHeader.language/compiler`) is rejected when it holds such characters or is not NFC. Lone surrogates are rejected everywhere.
3. **Time, ids, paths** (F-06, F-10, F-11): `Utc` takes ASCII digits, calendar-valid values, `Z` or `+00:00`, and canonicalises to `+00:00` (also inside `keys.unified_run_id`). Run ids are `fullmatch` validated and refuse Windows device names and a trailing dot; result ids are `[0-9a-f]{64}`; on Windows the sidecar path stays below 240 characters. `ExtractRequest` paths refuse control characters, a leading `//` (UNC is unsupported), a bare root, trailing dot/space and device names; the dot-prefixed-component rule stays (01 s7.6); `limits` keys must be `UnifiedLimits` fields with values 1..2**63-1; `decompile` needs its GZF and at least one RVA.
4. **Store** (F-02..F-05, F-07, F-17..F-19, F-26): `verify_result_dir(deep=True)` (default) re-parses every row and fact strictly in the pass that hashes it (duplicate JSON keys, LF-only framing, row ids, unique rows, facts linked to rows with the row's materiality, counts recomputed against the manifest; pointer rows are checked for duplicate keys on their raw text); `load_result`/`cached_result` verify hashes only, because the pointer pins the manifest that publish verified deeply, and they refuse a pointer that disagrees with its manifest. `publish_result` checks ownership (guard project is the open project, the run exists with this raw hash, the older/newer hashes are the project artifacts in either orientation), refuses a different payload under an existing `result_id` (`PT-UNIFIED-INTERNAL`, reason `result-drift`; result ids bind inputs, not parts) and sweeps orphans (result dirs without a row older than 5 minutes, staging dirs older than L-34 max). A line above `LINE_MAX_BYTES` (4 MiB) is refused when written (`PT-UNIFIED-LIMIT`). `backup_once` reuses a backup only if it holds the rows about to be deleted.
5. **Facts, runs, keys** (F-12..F-16, F-21, F-22, F-25): unchanged/cosmetic facts carry no `cfg`/`unknown` delta and only COS-LAYOUT/1 carries block deltas; every `Delta` has an endpoint; `deltas_omitted` <= 8 x L-06. `failed` never carries a cancel/timeout/unsupported code; `partial` is neither cancelled nor unsupported and names its cause. `IrKeyInputs`/`IrProducer` enforce kind/mode and the ghidra digests; `ir_cache_eligible` needs a digit-bearing version. `config_digest` inputs are 64-hex digests and non-bool ints; `manual_digest` folds `0x` text, drops duplicate addresses and needs a text category. `provenance` and the `ExtractRequest` maps are immutable. `UnifiedLimits` checks more orderings; `Budget.tick` refuses negative or non-int units; `BudgetExhausted` takes only CANCEL or TIMEOUT. `contracts.py` bakes the `DEFAULT_LIMITS` caps (L-03, L-28, L-31, L-39, L-41): a custom `UnifiedLimits` changes store paths and keys, not contract caps. Golden vectors for every key are pinned in `tests/test_unified_keys.py`.
6. **Deliberately unchanged**: gzip trailing zero padding (only decompressed content is hashed, s9.6); `_replace` retry set (CPython maps WinError 5 and 32 to `PermissionError`); existence of non-Ghidriff `SourceRef.entry_id` rows (per-source ids belong to the S0b adapters); the `.gitattributes` lines (no fixture file exists yet, s9.9); `PT-UNIFIED-STALE` for both `newer-contract` and `read-only-store` (the `reason` slug already distinguishes them).
## 10. S0b freeze notes and deviations (2026-10-14; S0 mode: sources, fusion, S0 facts, pipeline, worker, CLI)
1. `registry.py` was deferred by S0a and is delivered by S0b because fusion cannot run without it (no other wave-1 slice builds it; S2 EXTENDS `PASSES`, it never recreates the file). `Registry` is a frozen dataclass of plain data (families with joining D-tags, `SourceSpec` rows, Ghidriff/BinDiff step -> (tier, class) maps, `PassSpec` rows P00..P19 with tiers/classes/family kind but no key functions, channel and proof versions); `REGISTRY` is the default instance and every fusion function takes `registry=` so a new source is one row (D-08, `test_new_source_needs_only_adapter_and_registry_entry`). `registry_digest()` and `pass_table_digest()` feed `config_digest`.
2. In-process types (never persisted): `sources.SourceGroup` (kind, source, RVA tuples, decision hint, atoms; S2's fid-based `CorrGroup` converts at the boundary), `NodeRecord(side, rva, name, kind)`, `AdapterOutput(atoms, groups, nodes, limitations, source_refs)` (a tuple of refs, unlike 06 s1: the secondary adapter serves two engines), `Availability`. Adapters are pure readers of ALREADY LOADED inputs (`SourceInputs`); the worker never opens the project database.
3. Worker exchange files live in a private temp directory and are not persisted, so they are NOT generated into `docs/schemas/`: strict frozen models `unified-worker-request/1` and `unified-worker-report/1` (in `exchange.py`, with the request/report file helpers), snapshot lines `s0-match/1` (`matches.jsonl`, in `sources/__init__.py`: one line per non-engine-only `FunctionMatch` of the current run with name, address text, bounded `code`, callees, diff types), one JSON file per stored secondary set (`SecondaryMatchSet` plus entry id). Every input file is listed in the request with its SHA-256 and size and re-hashed by the worker; the raw Ghidriff JSON is passed by absolute path plus SHA-256 and is size/hash checked again in the worker. The worker writes only the staged result directory (inside the project, so the owner's rename stays atomic) and its report; the owner verifies the manifest against the `result_key` it computed BEFORE the run (a mismatch is `STORE`, reason `result-id-mismatch`). Every private worker report is subject to the same strict JSON parsing as the worker request and refacts exchange: reject duplicate keys (including canonically equivalent Unicode key spellings), non-finite numbers and malformed JSON before validating `WorkerReport`. A rejected report is treated as absent/invalid (`None`) by the owner; it must never be accepted as a successful run.
4. Claims (fusion): manual tier-M claims (pair rows, one-sided declarations, manual groups) beat group claims, which beat edge selection; two manual claims on one node are `PT-UNIFIED-INPUT` (`manual-overlap`, 04 s8). Edges of other sources that touch a claimed node are attached to the claiming row as atoms (a manual pair row records them as the contest; a group row lists them) and the free endpoint of such an edge gets its own one-sided row listing the lost proposal. Groups of different sources that share a node are merged (union-find). Group rows are `ambiguous` (Ghidriff 1:N, manual `ambiguous`) or `matched` (manual `split`/`merged`, analyst control) with materiality `not-applicable` (B-13).
5. Order and caps: atoms are sorted by (component number, tier rank desc, source, step, older rva, newer rva, class, cardinality, ref); rows by (min older rva or 2**33, min newer rva or 2**33, row id); `Support.atom_index` points at the strongest chosen-edge atom of the component; beyond L-39 atoms the chosen-edge atoms keep priority, one slot stays for the strongest against-atom, and `atoms-omitted:<n>` goes to the hints. Hints are fixed templates: `uncontested:<decision>`, `one-sided-by:<source>`, `ghidriff-diff-types:<csv>`, `partner-taken`, `lost-to-group`, `proposal-lost:<n>`, `manual-group:<category>`, `manual-one-sided`, `atoms-omitted:<n>`. Row flags stay empty in S0 (they are IR facts).
6. Ghidriff adapter: ONE atom per edge with the strongest known `match_types` entry (ties: registry order); the other names go to `native` ('match types'); unknown names are tier C, class E-UNKNOWN. `functions.modified` rows and `matches.address_matches` entries for the same edge are merged (union of types, `ref` = `FunctionMatch.id`); raw pairs touching a manual correction stay as atoms so the manual row shows its contest (unlike N-way chaining, which lets manual relations win silently).
7. Result status: `partial` iff a DEGRADING limitation exists (`raw-missing`, `raw-hash-mismatch`, `raw-unparsable`, `<source>-address-basis-not-comparable`, `<source>-pair-mismatch`); informational limitations (`ir-not-extracted`, `externals-skipped:<n>`, `no-address:<n>`, `pseudo-cap:<n>`, `rz-diff-untested-version:<v>`, `bindiff-stub-rows-not-identified`, `secondary-alternatives-unused:<n>`) keep `complete`. S0 mode is complete on its own (B-00).
8. Deviations and gaps recorded by S0b: (a) A-16 assumed `function.basicblocks` is available to the adapter, but the stored `SecondaryMatch` does not carry it (importer unchanged, as A-16 says), so stub rows (imports, thunks) cannot be told apart in S0: they are tier-labelled like code matches and the limitation `bindiff-stub-rows-not-identified` is recorded; fixing it needs an additive `secondary/2` field (owner of SPEC-10). (b) `ChangeFacts.Delta.older_rva/newer_rva` are FUNCTION entry RVAs in S0 (no instruction addresses without IR). (c) G-U1 X-vs-X in S0 yields 0 contested, 0 one-sided, 0 material, 0 review and all rows `matched`, with materiality `cosmetic` where the stored decompiler text is identical (COS-PSEUDO/1) and `unknown` where none is stored: UNCH/1 needs IR bytes, so "100 % unchanged" is an S3 gate. (d) The L-42 cap needs total RAM; stdlib `os.sysconf` gives it on POSIX, on Windows no ctypes is allowed under `unified/` (01 s3), so the absolute 4 GiB cap applies (`UnifiedLimits.worker_memory_cap(None)`). (e) `tools/frozen_smoke.py` `COMMANDS` gains `unified` (one token, owner S1) because `tests/test_acceptance_smoke.py` requires parser and smoke list to agree. (f) CLI `extract` is not registered (S1); `run --no-decompile` is accepted and has no effect (S3b absent); `run` without `--no-extract` runs S0 mode with the warning `extraction is not available in this build`.
9. Module layout (deviation from 01 s2, which lists only `pipeline.py` and `worker.py` and lets the worker import the pipeline): S0b splits the pure compute step and the exchange models out of `pipeline.py`. `exchange.py` (request/report models, `StageEvent`, error templates, file helpers) and `compute.py` (`plan_identity`, `compute_result`, `run_request`) sit between `facts` and `pipeline` in the layer order of 01 s3; `pipeline.py` is the owner side and spawns the child; `worker.py` is the hidden entry (exit codes) and imports `compute` and `exchange` only. `pipeline` never imports `worker` or `cli`, so a later slice can add worker modes (`ingest`, `refacts`) without a cycle and the child never loads owner-side code paths it does not use. `tests/test_unified_import_dag.py` enforces the order, the forbidden modules and the spawn rule by AST.
10. Owner/run split (for S4): `pipeline.prepare` (owner thread, read-only: completed Ghidriff run, PE layouts, stored engine sets, corrections -> immutable `UnifiedRequest` with the planned `result_id`), `cached`, `execute` (any thread, no SQLite, returns a `WorkerOutput` value and never raises for a worker failure), `publish` (owner thread: re-derives the identity from what the worker observed, verifies every part, publishes the pointer row, records the `unified-run` row) and `run_unified` (all four, for the CLI). The report carries `raw_status` (what the worker found when it parsed the preserved output); the owner recomputes `plan_identity` with it and refuses a different `result_id` (`STORE`, `result-id-mismatch`), so a raw file that changed between the owner's size/hash check and the worker's read yields a `partial` result under the id that was actually seen. Every attempt with a plan is recorded (`ok`, `partial`, `cached`, `failed`, `cancelled`, `timeout`); a cancel set before anything started records nothing.
11. Reading never creates enrichment tables: `status`, `show` and `explain` check for the table first (`S0a` `ensure()` would create it and take a backup). `ProjectService.open` refuses a project whose preserved raw output changed (`PT-STORAGE`), so `raw-missing` and `raw-hash-mismatch` are reachable only for a project that is already open (the GUI, the pipeline API); the CLI reports the open failure (exit 2).
12. Defect found while building and fixed by S0a-FIX (s9.1): `store._lines` caught `OSError` and `EOFError` but not `zlib.error`, which a damaged byte inside a deflate stream raises, so a damaged part escaped as an untyped exception. S0b had mapped it on the owner side; that mapping is removed now that the store types it (`tests/test_unified_pipeline.py` keeps the end-to-end tests: typed error, cache miss, a rerun repairs the result).
13. Identity covers everything that changes the content (S0a-FIX `result-drift`: one `result_id` never has two contents): every stored set of a selected engine is a `SourceRef`, one for another artifact pair included (it is refused with a degrading limitation), and the failure kind of an unusable raw file is part of the Ghidriff ref (06 s10 item 7). `config_digest` covers CONTENT limits only (`limits_digest`, s9.1): the limits the S0 compute step reads (L-01, L-28, L-29, L-39) are content limits and re-key results, timeouts, memory, store and display numbers do not.
14. The `source`s of a result are reported twice: `RunReport.sources` / JSON `sources` are the inputs of the result (the manifest's `SourceRef`s, a refused set included); `selected_sources` is what the run was asked to use.
