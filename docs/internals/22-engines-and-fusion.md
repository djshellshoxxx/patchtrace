# 22. Engines, reconciliation and fusion

How PatchTrace gets function pairings from several engines, keeps them apart, compares them, and (experimentally) fuses them into a derived ordinal view. Also: what is calibrated (nothing yet). User view: [12](../guide/12-evidence-and-engines.md). Specs: SPEC-27/28 `docs/specs/multi-engine-*.md`, SPEC-10/11/29, SPEC-31 `docs/specs/unified-engine/`. Previous: [21](21-data-model-and-storage.md). Next: [23 GUI framework](23-gui-framework.md).

## Ghidriff (primary)

`backend.py` adapts the **separately installed, unmodified GPL-3.0 Ghidriff CLI**; PatchTrace builds a verified argv (absolute paths, no shell, dot-prefixed Ghidra directories refused, Windows path-length guard) and `jobs.run_process` supervises it. It never forks Ghidriff's matching (DEC-02, reworded in SPEC-31 A-01: never fork Ghidriff; a *separate derived* engine may match).

- `BackendConfig` fields: `python_executable`, `ghidra_dir`, `timeout_seconds` (3600), `allow_symbol_downloads` (False, passes `--no-symbols` otherwise), `java_home`, `cache_dir`/`no_cache`/`refresh` (raw cache), `restrict_env`/`env_passthrough` (child environment allow-list, off by default until a native Windows run validates it), `bundle` (isolated mode: `-I`, forced restricted env, `JAVA_HOME_OVERRIDE`, scratch-directed TEMP), `retain_gzf` (SPEC-31 D-05: keep the two analysed programs for later extraction).
- Output lands in a staging directory, is hash-checked, normalized by `normalization.normalize_ghidriff` (defensive adapter; unknown top-level roots fail closed) and published as `runs/<id>/raw/result.ghidriff.json`. Failure keeps `runs/quarantine-<id>/`.
- Ghidriff's categories map to `FunctionMatch.category`; its correlator names stay in `match_types`; its ratio text stays text in `quality`.

## Secondary engines (`secondary/`)

| Engine | Module | What PatchTrace does | Hardening |
|---|---|---|---|
| BinDiff 8 | `bindiff*.py`, `binexport*.py` | runs `bindiff` on two user-supplied `.BinExport` files with a fixed CLI-only argv, requires exactly one `older_vs_newer.BinDiff`, preserves it, then imports the preserved copy | `.BinDiff` is untrusted SQLite: read-only immutable URI, `trusted_schema=OFF`, `query_only`, authorizer allowing only SELECT on fixed tables, rejection of triggers/views/virtual tables, deadline via progress handler. `--md_index` is a forbidden flag. Size cap 512 MiB |
| BinExport2 | `binexport_*.py` | validates a `.BinExport` in a capped worker: bounded snapshot (TOCTOU-safe), wire pre-scan without protobuf, upb-only parse against a checked-in descriptor, structural checks, identity and basis checks | memory/time-capped child; pure-Python protobuf refused (about 85x memory, 125x slower on hostile input); cap 256 MiB; MD5/empty `executable_id` refused unless the explicit override is recorded |
| rz-diff | `rzdiff.py` | optional byte-level engine; stdout (JSON) and stderr captured independently with `run_process(separate_streams=True)`; stdout that is not strict JSON is an error, not salvaged | looked up on PATH (BinDiff never is) |

`secondary/engine_env.py` is the single child-environment allow-list. `secondary/registry.py` holds an immutable adapter registry with `DISPLAY_ORDER = (rz-diff, bindiff, ghidriff-baseline)`. `secondary/scheduler.py` runs engines bounded (at most 2 in parallel), cancellable and failure-isolated, never writing to a store or spawning processes itself. `secondary/runs.py` defines `EngineRun` (`engine-run/1`, statuses ok/failed/cancelled/unsupported/timeout/cached, never updated after write) and a content-addressed cache key over engine version, argv digest and input hashes. `secondary/store.py` keeps one current match set per engine (`secondary/2`); re-running upserts. Headless orchestration is `secondary/cli_run.py` (partial success exits 3).

## Reconciliation and evidence adjudication

`secondary/reconcile.py` compares a secondary match set with Ghidriff by address, read-only. Each Ghidriff match gets a status: `agreement` (same endpoints), `disagreement` (conflicting endpoints; optionally "matches alternative rank N" of that engine), `absent` (no record), `not-comparable` (multi-function or unparsable endpoints). `agreement` is explicitly *not independent proof*.

`secondary/evidence.py` turns reports into per-match `MatchEvidence`:

| Condition | Verdict | Tier | Index |
|---|---|---|---|
| any engine disagrees | `contested` | low | 0 |
| at least one agrees, none disagrees | `corroborated` | high if index >= 75 else moderate | `min(83, 55 + 20 [bindiff] + 8 [rz-diff])` |
| all not-comparable | `insufficient` | unassessed | none |
| otherwise | `single-engine` | low | 55 |

A contradiction takes priority over any majority. Upstream similarity or confidence values are *never* used (different scales). The numbers 55/20/8/83 are hand-set ordinal triage constants, not fitted. Absence is never contradiction. `secondary/evidence_view.py` renders per-engine cells in native units with `CellKind` (value, no-record, not-comparable, pairs-elsewhere, not-run, failed) and maps verdicts to UI names (corroborated to agree, insufficient to unknown). Reports must hold exactly one report per distinct engine and the same Ghidriff match set, else `ValueError`.

## The unified engine (SPEC-31, experimental, derived)

Package `unified/`, contract family `unified-match/1`, `change-facts/1`, `unified-result/1`. Decisions are in `00-decisions.md` (D-01..D-36); the key ones:

- **Derived and separate**: never writes `ComparisonProject.matches`; results are sidecars plus `unified-run`/`unified-result` pointer rows (kinds outside `DERIVED_KINDS`). A snapshot-hash test proves a run does not mutate the project.
- **Layers**: E1 ProgramIR (facts extracted once per artifact by a PatchTrace-owned script in the user's external Python/Ghidra, preferring the analysed GZFs Ghidriff already wrote) to E2 pair evidence from every source to E3 the pass ladder to E4 fusion/arbiter to E5 change facts (L2) to E6 read model. L2 never feeds L1.
- **Sources are data**: `SourceSpec` registry rows (ghidriff, bindiff, rz-diff, diaphora [reserved], pt-ladder, pt-bytes, manual). A new source is an adapter plus one registry row.
- **Pass ladder** (`unified/ladder/`, `registry.PASSES`): P00 manual (tier M); P01/P02 import/export key and P03 exact name; P04 bytes-exact and P05 masked-exact (tier A); P06 operand-class, P07 register-agnostic, P08 mnemonic-sequence, P09 mnemonic-multiset, P10 MD-index flowgraph, P11 MD-index callgraph, P12 string set, P13 import-callee set, P14 constant set, P15 rehash (tier B); P16 reference vectors, P17 block votes, P18 layout gap, P19 assignment (tier C). Ordered, uniqueness-gated, run to a fixpoint with neighbour propagation; tier C is never auto-accepted. The MD index is a plain left-to-right sum over sorted terms, then rounded to an integer key (determinism across OS).
- **Fusion** (`unified/fusion/`): families carry dependency tags (`D_ghidra`, `D_bytes`, `D_symbols`, `D_callgraph`, `D_rizin`, `D_pe_tables`, `D_analyst`, ...). `components.py` runs **union-find over the joining tags** into independence components, so two engines reading the same Ghidra database are one component. The arbiter is pure and rule-based: **no number is computed, summed or compared across sources**. `matched` needs tier A, or tier B confirmed by atoms from *different components and different evidence classes* (D-32). Any source pairing an endpoint differently makes a row `contested` (strong/weak is for ordering only); a one-sided observation never contests (hint `one-sided-by:<source>`). Claims are processed manual first, then engine groups (abstain on ambiguity), then strength-ordered greedy 1:1 edges.
- **Change facts (L2)**: channels for the chosen pair: C0 raw body bytes, C1 address-masked bytes, C2 aligned operand-class deltas (including target consistency of every address operand), C3 CFG shape (a filter, never a proof), C4 callee multiset, C5 constants and string hashes, C6 canonical pseudo-code (modified pairs only, or the on-demand decompile), C7 BSim-style features (not in v1), C8 BinDiff flags of the exact pair; plus an unwind/handler (EH) comparison. Verdicts by proof, first match wins: `unchanged` (UNCH/1: raw bytes equal and every address operand target-consistent) then `cosmetic` (COS-ADDR/1, COS-LAYOUT/1; COS-PSEUDO/1 is decompiler-relative and stays visible) then `material` (a semantic delta plus a second channel observing the same change, MAT-ANCHOR) then `review` then `unknown`. Every proof validates every address operand through target consistency (functions via tier A/M rows, data via DATA-MAP/1); `unmapped` blocks proofs. Scope is function code plus unwind/handler metadata; data-only patches are out of scope and stated so in the UI.
- **Process model**: `pipeline.py` owner thread reads and publishes; `execute` runs the capped worker child (`unified _worker`, memory cap L-42 = min(4 GiB, 50% RAM), never on the JVM). `limits.py` holds the numbered limits and error base `PT-UNIFIED-*`. S3b optionally decompiles the top review pairs through the extractor child over the retained programs.
- **Built vs planned**: S0a/S0b (contracts, store, sources, fusion, CLI), S1 (Ghidra extractor, ingest), S2 (ladder), S3/S3b (IR channels, proofs, on-demand decompile), S4a/S4b (read model, panel), S5 (residual passes P16..P19), S6a (Tier R corpus, mutants, gate-report skeleton) are on `main`. The feature flag `unified/enabled` is OFF by default in the alpha (U-05). Evaluation gates G-U1..G-U8 are advisory CI (`unified-corpus.yml`, `live-unified.yml`); **default-on waits for them to pass** on real Tier R builds. Live unified extraction was green on Windows (MSVC DLLs) and Linux per ledger A; a Windows/real-binary run of every gate is not recorded.

## What is calibrated

**Nothing.** `calibration/` ships the runtime only (`features/1` extraction shared with training, `predict`, `policy`, `artifact` loader, `ood`, `ledger`, `scope`); `tools/calibration/` holds fitting, evaluation, the Tier R/W corpus builders and gates. No `patchtrace-calibration-model/1` artifact ships, so `calibration.policy.display_level()` returns `'ordinal'` and the Evidence panel and the Unified read model both read it that way. The target, if a model ever passes, is *"both endpoints are the same source-level function"*, never "is a vulnerability". Synthetic (Tier R only) evidence can never raise the level; at least a minimum number of independent lineages and passing gates G0/G2 (bands) or G0/G2/G3 (numbers) are required (`policy.artifact_display_level`). The pre-registration is `docs/plans/c9-preregistration-v1.md`; labels for Microsoft binaries stay local (Tier W). Consequently: Ghidriff ratios, BinDiff similarity and rz-diff byte similarity are shown as native labelled values, never as probabilities, and the 55..83 index and the attention score are ordinal.

## Attention ranking (`enrichment/`)

`signals.py` runs eight deterministic, lexical detectors over Ghidra's decompiled C text (not typed IR) of the changed hunks; `ranking.py` computes an exact **integer** score 0..100 with default weights BND 30, INT 22, OVF 28, VAL 20, ERR 12, SIZE 24, WIL 12, SCRUB 34, grouping signals on the same underlying edit so one edit is not counted twice; `wil.py` recognises `Feature_<uint32>` controlled-feature sites. A detector without its evidence is `unavailable` (shown `[ — ]`), never zero. The ranking never reads AI output and is unchanged by CVE context (`correlate` reranks separately).

## Reference tables

### Reconciliation statuses

| Status | Condition | Effect on verdict |
|---|---|---|
| `agreement` | the secondary engine pairs the same two endpoints | supports `corroborated` |
| `disagreement` | the engine pairs an endpoint differently (`conflicting-endpoints`, or `matches-alternative-rank-N` of its own alternatives) | forces `contested` |
| `absent` | the engine has no record for this match | listed as missing; not a vote |
| `not-comparable` | the match has several functions on a side, or an address that cannot be parsed | listed as a limitation; all-not-comparable gives `insufficient` |

### How Ghidriff correlators map to unified tiers (`registry.GHIDRIFF_TYPES`)

| Tier | Evidence class | Correlators |
|---|---|---|
| A | E-NAME | `SymbolsHash`, `ExternalsName` |
| A | E-BODY | `ExactBytesFunctionHasher`, `ExactInstructionsFunctionHasher` |
| B | E-BODY | `ExactMnemonicsFunctionHasher`, `BulkInstructionHash` |
| B | E-DATA | `StringsRefsHasher`, `StrUniqueFuncRefsHasher` |
| B | E-DECOMP | `BSIM`, `Decomp Match` |
| C | E-CFG | `StructuralGraphExactHash`, `StructuralGraphHash`, `BulkBasicBlockMnemonicHash`, `SwitchSigHasher` |
| C | E-CALL | `SigCallingCalledHasher`, `Implied Match` |
| C | E-UNKNOWN | any correlator name not in this table |

### How BinDiff function steps map (`registry.BINDIFF_STEPS`, first hit wins; the step's confidence is never read)

| Tier | Class | Steps |
|---|---|---|
| A | E-NAME / E-BODY / E-CFG | `name hash`; `hash matching`; `edges flow` |
| B | E-CALL / E-CFG / E-BODY | `edges call`; `md index matching (flow` and `(call`; `prime signature` |
| C | various | `relaxed md index`, `instruction count`, `address sequence` (E-LAYOUT), `string references` (E-DATA), `loop count`, `call reference`, `call sequence` |

### Dependency tags and families (`registry.FAMILIES`)

| Family | Tags | Notes |
|---|---|---|
| F-GHIDRIFF | `D_ghidra`, `D_symbols`, `D_callgraph`, `D_compiler` | primary |
| F-BINDIFF | `D_ghidra`, `D_symbols`, `D_callgraph` (Ghidra BinExport) | joins F-GHIDRIFF into one component when its export came from Ghidra; an IDA export would use `D_ida` |
| F-RZDIFF | `D_rizin`, `D_bytes` | |
| F-PT-BYTES | `D_bytes`, `D_ghidra_decode` (only `D_bytes` joins) | in-house masked-byte comparator |
| F-PT-NAMES | `D_symbols` | |
| F-PT-PE | `D_pe_tables`, `D_symbols` | |
| F-PT-STRUCT | `D_ghidra`, `D_ghidra_decode`, `D_callgraph` (`D_ghidra` and `D_callgraph` join) | |
| F-MANUAL | `D_analyst` | component `K0` |
| F-DIAPHORA | `D_ida`, `D_hexrays`, `D_symbols`, `D_callgraph` | reserved; AGPL, ideas only, no code |

Consequence: Ghidriff and BinDiff-from-Ghidra are the same component, so their agreement is one opinion, not two; rz-diff and the in-house byte comparator share `D_bytes`; only an atom from a different component *and* a different evidence class corroborates a tier-B atom (D-32).

### Unified decisions and what each means

| Decision | Meaning |
|---|---|
| `matched` | tier A (or M), or tier B confirmed across components and classes |
| `tentative` | a tier-B atom without cross-component, cross-class corroboration; never counted as matched, never a `mapped` target for proofs |
| `candidate` | tier C only; never auto-accepted |
| `contested` | some source pairs an endpoint differently (strength strong or weak orders rows, never hides them) |
| `ambiguous` | an engine group is ambiguous; the arbiter abstains |
| `older-only`, `newer-only` | one-sided; "added" or "removed" appear only as a Ghidriff source atom |
| `unknown` | no usable evidence |

Row flags include `tiny`, `thunk`, `import`, `hub`, `icf`, `oversize`, `truncated`, `ir-missing`, `pdata-confirmed`.
