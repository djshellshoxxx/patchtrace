# SPEC-31 / 01 Architecture: layers, modules, import DAG, processes, data flow

Scope: static comparison of two explicit artifacts (older -> newer), Windows PE x64 first, offline, CPU only, Python 3.12 stdlib + existing pins (PySide6 6.12.0, pydantic 2.13.5). Decisions referenced as D-xx are in [00-decisions](00-decisions.md); numbers as L-xx in [02-data-model s6](02-data-model.md#6-limits-single-source-of-numbers).

## 1. Layers

```text
 artifacts (verified bytes)   primary Ghidriff run (raw JSON + FunctionMatch)   stored secondary sets (rz-diff, BinDiff, later Diaphora)
        |                              |                                                  |
 E1 ProgramIR per side  <-- GZF reuse / headless analysis (external Python, D-04/D-05)   |
        |                              |                                                  |
 E2 PairEvidence atoms: sources/{ghidriff, secondary, diaphora, manual} + in-house {pt-ladder, pt-bytes}
        |
 E3 L1 ladder (in-house, needs E1): anchors -> exact keys -> propagation -> structure -> references -> residual (04)
        |
 E4 Fusion + arbiter: independence components, max-pool by tier, decisions, contest strength (05 s1)
        |
 E5 L2 ChangeFacts on accepted/probable/candidate pairs: channels C0..C8, proof tiers (05 s2)
        |
 E6 UnifiedResult (sidecar + pointer row) -> UnifiedReadModel (Qt-free) -> ONE window (07)
```
Without E1 (no Ghidra configured, or extraction failed) the pipeline still runs E2 (external sources only) -> E4 -> E5 with S0 channels -> E6: the minimum viable unified engine ([backups](../../plans/unified-engine-backups.md) B-00).

## 2. Module map (all under `src/patchtrace/unified/` unless noted; every module is planned)

| Module | Purpose (typed I/O) | May import | Slice |
|---|---|---|---|
| `contracts.py` | strict frozen pydantic records of 02 (persisted), `UnifiedError`, error codes | pydantic, `enrichment.identity` | S0a |
| `limits.py` | `UnifiedLimits` frozen dataclass (every L-xx number), `Budget(deadline, cancel).tick(n)` | stdlib | S0a |
| `keys.py` | `ir_key`, `result_key`, `row_id`, `config_digest`, `source_set_digest` | `enrichment.identity`, contracts | S0a |
| `registry.py` | `SourceSpec`, `PassSpec`, `ChannelSpec`, `ProofSpec`, `DTAGS` (joining flags) | contracts | S0a |
| `addressing.py` | VA<->RVA per side (`pe_overview` image base), `EXTERNAL:` keys, address-basis checks | contracts, `pe_overview`, `artifact_bytes`, `enrichment.identity` | S0b |
| `store.py` | sidecar dirs, manifests, pointer rows (`unified-run`, `unified-result`), retention, load/verify | `enrichment.storage`, `ingestion.safe_path`, contracts, keys | S0a |
| `sources/ghidriff.py` | `FunctionMatch` + verified raw JSON (`address_matches`, `match_types`, `diff_type`, ratios) -> atoms | models, addressing, contracts | S0b |
| `sources/secondary.py` | `secondary.store.current_sets()` rows -> atoms (rz-diff tier W, BinDiff algorithm -> tier) | `secondary.store`, `secondary.contracts`, addressing | S0b |
| `sources/manual.py` | manual corrections -> tier-M atoms | models | S0b |
| `sources/diaphora.py` | DA-01 `diaphora-matches` rows -> atoms (after DA-01 D3 merges) | its contracts (read-only) | later |
| `fusion/components.py` | union-find over joining D-tags -> components | registry | S0b |
| `fusion/arbiter.py` | atoms -> `UnifiedMatch` decisions, contests, groups | components, contracts | S0b |
| `facts/pseudo.py` | C6 canonical pseudo-code over stored Ghidriff code (alpha-rename, L1-id substitution) | contracts | S0b |
| `facts/channels.py` | C0..C5, C8 per pair; S0 subset without IR | ir.reader, facts.align, facts.operands | S0b/S3 |
| `facts/align.py` | bounded instruction-stream alignment (patience + LCS fallback) | stdlib | S3 |
| `facts/operands.py` | operand-class deltas (address-shift, callee/data change, constant, struct offset, register rename) | ir.reader | S3 |
| `facts/verdict.py` | proof tiers -> `ChangeFacts` (05 s2) | registry, contracts | S0b/S3 |
| `ir/schema.py` | sidecar SQLite DDL `program-ir/1`, open read-only with authorizer | stdlib sqlite3 | S1 |
| `ir/ingest.py` | strict line-by-line validation of extractor JSONL -> sidecar; computes hashes, masks L0-L3, MD | ir.features, ir.mdindex, ir.pe_tables, limits | S1 |
| `ir/features.py` | pure key functions (blake2b-64 hashes, mnemonic multiset, CFG shape, string/const sets) | stdlib | S1 |
| `ir/mdindex.py` | BinDiff-style MD index (flow graph and call graph, top-down/bottom-up) with attribution header | stdlib `math` | S1 |
| `ir/pe_tables.py` | `.pdata` RUNTIME_FUNCTION and base-relocation parsing via `VerifiedArtifactReader` | `artifact_bytes`, `pe_overview` | S1 |
| `ir/reader.py` | `IrReader`: columnar `FunctionTable`, CSR adjacency, on-demand blocks/instructions | ir.schema | S1 |
| `extract/ghidra_script.py` | runs INSIDE the external Python; stdlib + pyghidra/Ghidra only; never imports `patchtrace` | stdlib, pyghidra (external) | S1 |
| `extract/runner.py` | private dirs, script copy, argv/env, `jobs.run_process`, progress file, output guard, ingest call | `jobs`, `backend` (env builders), ir.ingest | S1 |
| `ladder/passes.py` | pass table P01..P19 (key fn, gate, tier, tags) | ir.reader, registry | S2 |
| `ladder/engine.py` | ladder driver to fixpoint, uniqueness gates, provenance | passes, propagate, groups | S2 |
| `ladder/propagate.py` | neighbour cascade, call-site implied matches with votes/conflicts, thunk-target | ir.reader | S2 |
| `ladder/groups.py` | N:M duplicate and ICF alias groups | ir.reader | S2 |
| `ladder/blocking.py` | candidate generation for 60k images (size/token/MinHash buckets) | ir.reader | S5 |
| `ladder/residual.py` | P16 reference vectors, P17 BB votes, P18 layout gaps, P19 assignment with rejection | blocking, assign | S5 |
| `ladder/assign.py` | pure-Python LAP (Jonker-Volgenant style) with reject cost, bucket cap L-31 | stdlib | S5 |
| `pipeline.py` | stage orchestration (inputs -> result), cancel, partial status | everything above except UI | S0b..S5 |
| `worker.py` | hidden `_worker` entry: request JSON -> result files in a private dir | pipeline | S0b |
| `read_model.py` | Qt-free `UnifiedViewModel`, filters, sort keys, detail/provenance text | contracts, store, `secondary.evidence_view.sanitize_text` | S4 |
| `cli.py` | `unified` subcommands (dispatched by `patchtrace/cli.py`) | pipeline, store, read_model | S0b/S4 |
| `src/patchtrace/ui_unified.py` | Qt adapter: `UnifiedController`, table model, navigator view, dock tab, threads | Qt, read_model, tooltips | S4 |
| `tools/unified/*` (dev only) | parity harness, A/A and planted-mutation recipes, bench | unified, secondary | S2/S6 |

## 3. Import rules (DAG) and enforcement
1. Nothing under `unified/` imports PySide6, `patchtrace.ui*`, `urllib`, `http`, `socket`, `ssl`, `subprocess`, `ctypes`, `ghidriff`, `pyghidra` or `jpype` (exception: `extract/ghidra_script.py`, which is never imported by PatchTrace code).
2. Spawning happens only in `extract/runner.py` and `pipeline.py` (worker), and only through `jobs.run_process`.
3. Layer order (an arrow means "may import"): contracts/limits/keys/registry <- addressing, ir/* <- sources/*, ladder/* <- fusion/* <- facts/* <- pipeline <- worker, cli, read_model <- ui_unified. `ladder` never imports `fusion` or `facts`; `fusion` never imports `ladder` (it only sees atoms); `facts` never changes a decision.
4. `secondary/*`, `enrichment/*`, `calibration/*`, `nway/*` are read-only dependencies; none of them imports `unified`.
Tests: `test_unified_import_dag` (AST walk of `src/patchtrace/unified`, allow-list per module), `test_unified_has_no_qt` (subprocess import with PySide6 blocked, the existing pattern), `test_ghidra_script_imports_no_patchtrace`.

## 4. Process and thread model

| Actor | Runs in | Does | Never does |
|---|---|---|---|
| Owner thread (GUI thread or CLI main) | PatchTrace process | builds immutable `UnifiedRequest`, reads project/store, validates worker output, moves sidecars into `runs/<run_id>/unified/`, publishes pointer rows | heavy computation; touching worker objects |
| `UnifiedRunThread` (QThread, no Qt parent, `_LIVE_THREADS` registry) | PatchTrace process | calls `pipeline.execute(request, cancel)` which spawns children and waits; emits stage events | SQLite access, widgets |
| Extractor child (one per side, sequential default) | external Python + JVM | dumps IR facts to a private dir; writes `progress.json` | network, PDB download, writing outside its private dirs |
| Worker child `patchtrace unified _worker` | `sys.executable` (frozen EXE or python) | E2..E5 pure computation from request + IR + snapshot files -> result parts | SQLite project DB access, publishing |
| CLI | PatchTrace process | same pipeline in-process OR via worker (`--isolate`, default on Windows frozen) | Qt import |
Rules: one analysis job per window (C-11): the unified run is disabled while a Ghidriff job runs and vice versa. Cancellation: shared `threading.Event` -> `run_process` kills the Job Object / process group; the owner discards partial output; the previous result row stays current. Progress: children write `progress.json` atomically (`.part` + replace); the parent polls it through `run_process(check_output=...)` (already polled every 50 ms, jobs.py:223-233) and emits events; absent file = indeterminate. Memory: the JVM gets `-Xmx` from L-03; the worker has no hard cap in v1 (U-09).

## 5. Data flow (normative pseudocode)

```python
def execute(req: UnifiedRequest, cancel: Event, emit: Callable[[StageEvent], None]) -> WorkerOutput:
    budget = Budget(req.deadline, cancel)
    ir = {}
    for side in ('older', 'newer'):                       # sequential: two JVMs may exhaust RAM (L-03)
        if not req.extract:                                # S0 mode or extraction unsupported
            ir[side] = None; continue
        ir[side] = store.find_ir(req.ir_keys[side]) or extract.runner.extract_side(req, side, budget, emit)
    if (ir['older'] is None) != (ir['newer'] is None):    # F1 symmetry: never mix IR and no-IR sides
        ir = {'older': None, 'newer': None}; limitation('ir-asymmetric')
    atoms = [*sources.ghidriff.atoms(req.snapshot, req.raw), *sources.secondary.atoms(req.sets),
             *sources.manual.atoms(req.snapshot)]          # all addresses normalised to RVA (D-17)
    if ir['older']:
        corr = ladder.engine.run(ir['older'], ir['newer'], anchors=manual_anchors(atoms), budget=budget)
        atoms += corr.atoms()                              # pt-ladder and pt-bytes atoms with pass provenance
    result = fusion.arbiter.decide(atoms, registry=REGISTRY)   # UnifiedMatch rows, deterministic order
    for row in result.rows_needing_facts():                # accepted, probable, candidate, contested pairs
        budget.tick()
        row.facts = facts.verdict.judge(facts.channels.collect(row, ir, req.snapshot, result))
    return write_parts(result, req.private_dir)            # rows/atoms/facts JSONL.gz + manifest; owner publishes
```
Owner side: `store.publish_result(output, guard)` re-hashes every part, checks the manifest against `result_key`, moves the directory with `os.replace`, then writes the pointer row through `EnrichmentStore.publish` (stale if the guard moved). Any failure leaves the previous pointer row current.

## 6. Error taxonomy `PT-UNIFIED-*`

| Code | Meaning | CLI exit | Recoverable |
|---|---|---|---|
| `INPUT` | bad request, unreadable artifact, unknown option | 2 | yes |
| `PAIR` / `ORIENTATION` | IR or source hashes do not match the project pair / are reversed | 2 | yes |
| `UNSUPPORTED` | no Ghidra/Python configured, pyghidra missing, non-x64 PE | 2 (only if nothing else can run) | yes |
| `EXTRACT` | extractor exited non-zero, produced no footer, or `program_sha256` != artifact | 3 | yes |
| `IR` | extractor output failed strict validation (reason slug) | 3 | yes |
| `LIMIT` | an L-xx cap was hit (reason names the cap) | 3 | yes |
| `TIMEOUT` / `CANCEL` | deadline or user cancel; process tree killed | 3 / 5 | yes |
| `STALE` | inputs changed between request and publish; stored as stale | 3 | yes |
| `STORE` | sidecar write, hash or pointer publish failure | 3 | yes |
| `INTERNAL` | unexpected exception (class name only, never message) | 3 | no |
Messages are fixed templates with labels and numbers only; untrusted text (names, stderr) goes to sanitized provenance fields, never into messages (pattern of SPEC-28 s8).

## 7. Extension points (what changes, what does not)

| Add | Files touched | Untouched |
|---|---|---|
| new external source (e.g. Diaphora) | `sources/<id>.py`, one `SourceSpec` in `registry.py`, tooltips | fusion, facts, read model, UI widgets |
| new L1 pass | `ladder/passes.py` row + key fn + tests; `config_digest` changes automatically | fusion, UI |
| new L2 channel or proof | `facts/channels.py` or `facts/verdict.py` + `ChannelSpec`/`ProofSpec`; `facts_version` bump | ladder, fusion, UI |
| new IR producer (BinExport2, rizin) | `extract/<producer>.py` emitting the same `ir-extract/1` JSONL | ingest, ladder, everything downstream |
| calibrated display (after SPEC-28 gates) | `read_model.py` reads `calibration.policy.display_level()` | decisions (a model never overrides `contested`, SPEC-28 calibration s9.5) |

## 8. Relation to existing packages

| Package | Relation |
|---|---|
| `secondary/` | read-only: `store.current_sets()`, `SecondaryMatchSet`, `EngineRun` provenance; engines are still run by the SPEC-28 scheduler/Engines tab; unified never writes `secondary-matches` or `engine-run` |
| `enrichment/` | storage (two new kinds), identity (`domain_id`, `canonical_json`, `parse_address`), optional `DerivedCache` stage `program-ir`; `attention/1` scores may be displayed beside unified rows that map to a Ghidriff match, never recomputed |
| `calibration/` | consulted for `display_level()` only; unified evidence families proposed to C9 as `features/2` (U and F families), not built here |
| `nway/` | unchanged in v1; IR reuse across adjacent pair projects via the global cache (same artifact SHA); P2 fixes its `EXTERNAL:` crash |
| `backend.py` | one additive seam: `BackendConfig.retain_gzf` (D-05); raw-cache fingerprint unchanged (argv unchanged) |
| `jobs.py` | P1 spawn lock (D-28a); otherwise used as is |
| `ui.py` | seam <= 12 lines (07 s2); `ui_evidence.py` gains a tab through its controller |
| `cli.py` | `COMMANDS` gains `unified` and one dispatch line |

## 9. Security invariants (each has a named test in 08 s6)
1. Targets are never executed; Ghidra loads them as data; no emulation, debugger or scripts from the project. 2. No network: extractor runs with symbol downloads disabled and a private `XDG_CONFIG_HOME` (same isolation as backend.py:533-546); the engine imports no network module. 3. Every child: absolute argv[0], `shell=False`, private cwd, `stdin=DEVNULL`, bounded streams, env from the existing builders (`backend.build_child_env` / `_environment`), tree kill. 4. Extractor output, secondary sets and Ghidriff JSON are untrusted: strict parsers, size caps (L-xx), no `eval`/pickle, names rendered as plain text (C6 `sanitize_text`). 5. The extractor script is copied into an empty private directory before it runs, so no planted module next to it can be imported. 6. Paths given to Ghidra contain no dot-prefixed component and stay below 240 characters on Windows (backend.py `_validated_ghidra_output_path` rule). 7. Results are published only after every part hash verifies; a failure never deletes the previous result.
