# PatchTrace: repository-grounded extension specification and phased delivery plan

**Specification revision:** PT-EXT-2026-10-11.1 (proposal; no code changes)  
**Repository:** https://github.com/djshellshoxxx/patchtrace  
**Repository audit:** 2026-10-11; `main` at `0f1b4ce5a0b51526fdceb5533f0553321899fd2a`  
**Target:** Windows 11 x64, Python 3.12 desktop; deterministic, optional offline enrichment  
**Authority:** repository code at pinned commit, then `AGENTS.md`, published specifications, documented upstream interfaces. All file paths marked **proposed** do not currently exist.  
**Stop boundary:** design and planning only. No implementation, commit, merge, PR, or release performed.

## A. Verified repository assessment

### A1. Actual code and interfaces

| Area/status | Source and confirmed contract | Integration decision/risk |
|---|---|---|
| Desktop: implemented | `src/patchtrace/__main__.py:main()` constructs a Qt application, starts `MainWindow`; accepts `--self-test`. `src/patchtrace/ui.py:MainWindow`, `Worker(QThread)`, `SetupDialog`, `ContextDialog`; PySide6 6.12.0. | Extend list/sort, evidence detail and setup incrementally. The unified headless CLI is **not on main**. Avoid a competing CLI implementation until its foundation lands. |
| Domain: implemented | `src/patchtrace/models.py` strict Pydantic v1 records: `Artifact`, `AnalysisRun`, `FunctionRecord`, `FunctionMatch`, `EvidenceReference`, `ComparisonProject`, `Finding`, etc. `extra='forbid'`; nested ownership checks. | Do not attach arbitrary enrichment data to v1 objects or silently change their schema. Keep existing UUIDs for UI routing, add deterministic derived identities. |
| Inputs: implemented | `ingestion.py:inspect_artifact`, `validate_pe`, `verify_artifact`, `safe_path`; SHA-256 immutable project-owned copies; PE AMD64, <=1GiB. | Keep old/new order, source hashes and path containment. No target execution. |
| Ghidriff: implemented | `backend.py:BackendConfig`, `diagnose`, `_probe_backend`, `run_comparison`, `quarantine_failed_run`; argv to external Python `-m ghidriff`; private temporary `--project-location` and `--gzfs-path`, `--no-symbols` by default; 100MiB raw JSON bound. | Analysis cache may wrap run, not duplicate child lifecycle. Backend reports `java_runtime_version='unverified'`; resolve identity conservatively before cross-run cache reuse. |
| Process supervisor: implemented | `jobs.py:run_process`; containment, timeout, cancel, bounded log; per-run `JobEvent`. | Reuse for future acquisition/tools and CLI; no UI worker or independent subprocess framework in pure stages. |
| Normalize: implemented | `normalization.py:verify_diff_identity`, `normalize_ghidriff`; requires ordered old/new `old_meta`/`new_meta` hashes; handles added/deleted/modified; `FunctionRecord` carries code, optional assembly, calls, metadata. | Source is *diff output*, not complete call graph, typed p-code, reliable instruction stream or full PDB. New detectors must report unavailable evidence. |
| Persistence: implemented | `persistence.py:ProjectStore`, `ProjectLock`, `strict_json`, `validate_project`; SQLite `user_version=1`, `current_snapshot` and append-only `history`; 256MiB aggregate bound, backup via SQLite backup API. | Exclusive writer per project; same-thread SQLite connection. Prefer additive tables in **same database**, not independent file-store for project-derived records. |
| Project transaction owner: implemented | `service.py:ProjectService`, `_invalidate`, `prepare_analysis`, `apply_import`, `add_interpretation`, correction/undo; preparation off UI thread, commit on service owner's thread. | New publication methods must use existing service, never mutate `project.matches`/raw artifacts during enrichment. Revision/run change invalidates derived views. |
| Evidence: implemented | `evidence.py:build_context`, `evidence_id`, `resolve_evidence`; exact context/run/function scoped citations for AI. | New binary evidence location contract must be distinct from AI-context-only line references, but permit conversion when valid. |
| Providers: implemented | `providers.py:ProviderConfig`, `request_completion`; loopback Ollama and HTTPS OpenAI-compatible chat, credentials session-only. | CVE intelligence HTTP needs its **own bounded read-only data-source adapter**, not AI provider or shared credentials. |
| Reports: implemented | `reports.py:_snapshot`, `_render`, `export_project`; HTML/Markdown/JSON, 20MiB limit, provenance, path redaction and atomic write. | Add optional enrichment snapshot input after validation; never assume `ComparisonProject` itself contains derived scores. |
| Build/test: implemented | `pyproject.toml` Python >=3.12, Pydantic 2.13.5, pytest/pytest-qt/Ruff; `.github/workflows/qa-windows.yml`, `.github/workflows/live-backend.yml`, `tools/build_windows.py` PyInstaller onedir. | Windows-only release proof requires Windows runner and frozen executable smoke test; do not claim the planning document was executed/tested. |

**Existing normalization limitations.** `FunctionRecord` sets `address_space='virtual'` if an upstream address is present; a resolved instruction-to-source-line map is not available. Ghidriff serialized `instructions` may be an integer hash, in which case `assembly=None`. `calling/called` are text lists, not confirmed edges. `FunctionMatch.quality` contains an uncalibrated upstream similarity string. New algorithms cannot use these as machine-code-semantic proof.

**Foundation status on inspected main:** dot-prefix protection, scratch isolation and explicit symbol setting are present; a central CLI parser with `rank`, `flags` and `correlate` is absent; versioned shared CLI/GUI nonsecret config is absent; analysis/result cache, B1-B3 signal engines and CVE transport are absent. Current GUI `QSettings` stores backend paths; CLI config contract is reserved, *not shipped*. Terminal analysis run has status `completed/failed/cancelled/identical`; the proposed numeric exit codes have not been integrated.

### A2. Open and diverged work

GitHub comparison against inspected `main` on 2026-10-11:

| Branch/PR | Relationship | Files of concern | Action for later implementation |
|---|---|---|---|
| `feat/local-runtime-discovery`; draft PR #5 | diverged, +9/-1 commits | **proposed on branch:** `runtime_discovery.py`, `ui.py`, discovery tests, setup docs | Reserve runtime discovery and setup UI; consume runtime candidate interface after PR review/merge. |
| `fix/backend-exit-diagnostics` | diverged, +2/-1 | `tests/test_jobs.py`, architecture spec | Verify changes before new error taxonomy or CLI mapping. |
| `fix/explicit-offline-symbol-policy` | diverged, +12/-2 | `backend.py`, `ui.py`, reports/tests/docs | Inspect for unique unmerged changes; main already has symbol setting. Avoid reimplementing. |
| `fix/ghidra-dot-paths` | diverged, +6/-4 | `backend.py`, jobs/UI tests | Main already has dot-prefix path protection. Reconcile rather than blindly merge. |
| `fix/isolate-ghidra-scratch` | diverged, +8/-3 | `backend.py`, native workflow, docs | Main already passes isolated Ghidra dirs; determine which branch commits remain unique. |
| `codex/patchtrace-beta` | behind main by 6 | historical implementation branch | Do not merge stale branch automatically. |

A diverged branch is *not* necessarily unfinished work. Future merge decisions require actual commit-level inspection and passing CI; none are authorized now. Key shared-file contention: `backend.py`, `ui.py`, `docs/specs/architecture.md`, `tests/test_jobs.py`. This document is a specification artifact outside GitHub and does not alter those branches.

### A3. Discrepancies and risks

1. `docs/specs/completeness-audit.md` says the original brief's stop-after-spec boundary was superseded **for the earlier beta**; this extension request explicitly restores a new specification-only boundary.
2. `docs/specs/schemas.md` describes 15 generated schemas and v1 aggregate validation; new enrichment record schemas do not yet exist. Do not quietly mutate v1 contracts.
3. `docs/audits/2026-10-11-runtime-reliability.md` lists symbol lookup as pending at that audit point, but current `backend.py` already implements the opt-in setting. Code at audited SHA prevails.
4. `tasks/todo.md` tracks the previous beta/reliability gates; it does not contain B1-B4 work. Future integration should add task IDs instead of reusing old completed IDs.
5. The inspected GitHub workflow and `docs/qa.md` report prior Windows/Linux/fixture passes. **This specification session ran no local tests or live Ghidra checks.** Prior CI evidence is not validation of the proposed extension.
6. High-risk issues: false semantic claims from decompiled text, cross-project evidence misownership, query data poisoning, stale cached results, partial write promotion, optional network leakage, poor GUI responsiveness and migrations that make existing backups unusable.

### A4. Immediate architectural decisions

* Keep `ghidriff` default and original diff import as the sole raw evidence authority. Pure enrichment operates on a validated `ComparisonProject` + immutable run JSON identity.
* Use a new `EnrichmentCoordinator` (**proposed** `src/patchtrace/enrichment/pipeline.py`), with independent `flags`, `signals`, `ranking`, `cve` and `cache` packages. Never import Qt inside enrichment.
* Store project-specific enrichment in **additive `enrichment_*` SQLite tables** in `project.sqlite3` under the existing `ProjectStore` lock, retaining `PRAGMA user_version=1`, v1 aggregate JSON and existing historical records. Own extension schema version in `enrichment_meta`. Before first write, test open/quick_check, create a full backup, and atomically create extension tables. Old PatchTrace versions will ignore these tables and can continue to read their existing v1 snapshots. All new reads validate current `project.revision` and raw run hash; an old client reanalysis may leave entries *stale* but will not make them authoritative. Do **not** rewrite v1 snapshots/history. Migration gate is mandatory before implementing this choice; if tests demonstrate old-client incompatibility, switch to a separately specified coordinated v2 migration, not silent schema drift.
* Raw cross-project cache resides under `%LOCALAPPDATA%/PatchTrace/cache/v1` (configurable). It is not project state; project backup does not need to include reusable global caches. Persisted run evidence **must** remain with the project and must stand alone when offline.
* Pipeline order: validate existing diff -> optional B2 detection -> B1 signal extraction/ranking -> optional B3 context and reranking -> service publication -> CLI/GUI/reports. B4 surrounds raw execution and individual deterministic stages; it does not consume upstream scoring as a post-stage.

## B. Phase 2 developer-ready specifications

### B0. Shared contracts and dependency rules

**Proposed module structure, not existing files:**

```text
src/patchtrace/enrichment/
  __init__.py
  contracts.py          # strict Pydantic v1 enrichment records and schemas
  identity.py           # canonical hashing and evidence-location identities
  pipeline.py           # pure stage orchestration, cancellation/progress contracts
  signals.py            # deterministic feature-change detectors
  ranking.py            # weights, grouping, scoring and sorted results
  wil.py                # Windows controlled-feature recognition
  cve.py                # normalized CVE context + correlation
  intelligence.py       # provider-specific bounded HTTP transports
  cache.py              # local reusable content-addressed analysis/stage cache
  storage.py            # additive SQLite adapter through ProjectStore
```

Initially prefer flat modules shown above; split detector/provider files only when complexity or ownership makes it necessary. No `Qt`, `pyghidra`, Java or network import in `identity.py`, `contracts.py`, `wil.py`, `signals.py` or `ranking.py`. Optional analyzer fields are accepted only by explicit versioned adapters.

**Canonical hashing `H(domain, object)`**: normalize every string as Unicode NFC, encode UTF-8, use JSON with `ensure_ascii=False`, sorted keys, no incidental whitespace (`separators=(',',':')`), forbid NaN/Infinity and floats in score inputs, restrict unordered sets to sorted deduplicated arrays, include a `domain` prefix such as `pt/evidence/v1\0`, then SHA-256 and lowercase hex. Never hash local paths, run UUID, creation timestamps or GUI display preferences into cross-run content identities unless behavior genuinely depends on them. Store the digest algorithm and canonicalization version. SHA-256 collision resistance is a content-addressing property, *not* authorization: still validate ownership and content hashes.

**Existing IDs vs stable IDs:** retain `AnalysisRun.id`, `FunctionMatch.id`, `FunctionRecord.id`, and `EvidenceReference.id` unchanged for v1 UI/save functionality. New `diff_id=H('pt/diff/v1', [ordered_binary_hashes, raw_json_sha256, engine_identity, parameters])`; `occurrence_id=H('pt/occ/v1', [diff_id, side, source_collection, source_ordinal, exact_function_name, source_address_or_null, normalized_code_digest_or_null])`; `pairing_id=H('pt/match/v1', [diff_id, sorted_old_occurrences, sorted_new_occurrences, category, manual_override_fingerprint])`. A changed manual match forces a new pairing identity; no assertion of semantic equivalence results from the ID. Source ordinal is saved on normalization/enrichment ingestion as the position in the immutable raw PDiff collection. When source provenance is absent, use a deterministic sorted signature plus collision ordinal, mark identity `degraded`, and **do not** reuse that record cross-run unless the original input blob is identical. `signal_id=H('pt/signal/v1', [diff_id, pairing_id, detector_id/version, change_group, source evidence digest])`. Raw `run_id` and project UUID are stored as ownership references, not hashed into reusable analytic identities.

**Evidence location schema `EvidenceRefV1`:** `schema_version=1`, `id`, `diff_id`, `project_id`, `run_id`, `artifact_sha256`, `side: older|newer`, `occurrence_id`, `source_kind: decompile|assembly|pcode|call|symbol|raw-json`, `raw_sha256`, `json_pointer|null`, `line_start|null`, `line_end|null` (both 1-based inclusive), `address_kind: va|rva|file|unknown|null`, `address_hex|null`, `excerpt_sha256|null`, `quality: verified-structure|derived-structure|text-heuristic|unavailable`. Validation: either a trustworthy JSON pointer or typed address/line coordinate is required for actionable navigation; `0x0` is valid and distinct from absent; if one line endpoint exists the other must exist; nonempty excerpt must hash to its digest; run/pair/side ownership checked by service before saving; source input cannot be an arbitrary analyst path.

**Stage-result types** (excluding the static ranking configuration and cache manifest; each strict, `extra='forbid'`, with `schema_version=1`, `algorithm_version`, `config_digest`, `input_digests`, `created_utc`, `status=complete|partial|unavailable|cancelled|failed`, `warnings[]`, `provenance[]`):

| Record | Required extra fields | Owner and consumer |
|---|---|---|
| `BinaryAnalysisIdentityV1` | ordered old/new sha256, engine name, engine version, ghidriff revision, Ghidra/Java/Python versions or `unverified`, symbol mode, settings digest | pipeline/cache; affects all stages |
| `FeatureGateV1` | feature numeric ID or null; original symbol/name or null; old/new location refs, gate relation `introduced|removed|condition-changed|guarded-behavior-changed|unchanged-around-change|unknown`; gated pairing IDs; resolution source and certainty | B2 -> B1/GUI |
| `ChangeSignalV1` | `signal_id`, detector ID/version, pairing ID, `category`, `change_group_id`, integer base weight, evidence quality, confidence tier, `refs[]`, explanation, old/new presence, ignored_unsupported flag | B1 detector -> B1 score |
| `RankingConfigV1` | weights object, confidence multipliers, per-group cap, score cap, formula version, deny/allow detectors | B1 |
| `FunctionRankingV1` | pairing ID + project match ID, `score:int(0..100)`, ordered signal IDs, group subtotals, evidence coverage, match certainty, missing reasons, tie key | B1 -> UI/report/B3 |
| `CVEContextV1` | CVE ID, per-field source lists, descriptions, CWEs, products, affected versions, severity records, published/modified, retrieved timestamp, `snapshot_digest`, disagreement flags | B3 provider->correlator |
| `ContextualRankingV1` | CVE snapshot digest, base ranking digest/score, evidence-backed context matches, signed integer adjustment, final score (0..100), original rank index, contextual rank index | B3 -> UI/report |
| `CacheManifestV1` | content key, stage kind, input/config/tool digests, file digests, byte sizes, created/last-access time, integrity and completeness states | B4 |
| `PipelineExecutionV1` | project/run/revision, stage statuses/digests, warnings, cancellation/failure reason, effective offline and cache policy | pipeline -> persistence/CLI |

**Examples (synthetic; not observed CVE data):**

```json
{"schema_version":1,"algorithm_version":"ranking/1","pairing_id":"synthetic-pair-a","score":58,"signal_ids":["synthetic-s1"],"group_subtotals":{"synthetic-group-1":46},"evidence_coverage":"decompiled-only","match_certainty":"unverified","missing_reasons":["pcode not available"],"tie_key":"synthetic-pair-a"}
```

This brief inline record is **intentionally invalid/incomplete** because a group score of 46 exceeds the proposed 40-point cap and shared stage fields are omitted. The separately supplied `PatchTrace-Phase2-Synthetic-Examples-v1.json` contains nine fully populated examples that validate against `PatchTrace-Phase2-Contracts-v1.schema.json` and nine intentionally invalid examples. Each is synthetic specification data, not an authentic binary observation. For the scoring example, one 40-point group yields score 50.

**Error contract:** `PT-ENRICH-INPUT` invalid identity/evidence, `PT-ENRICH-SCHEMA` unsupported record, `PT-ENRICH-UNAVAILABLE` required evidence absent, `PT-WIL-AMBIGUOUS`, `PT-CVE-UNAVAILABLE`, `PT-CVE-PROVIDER`, `PT-CACHE-CORRUPT`, `PT-CACHE-LOCK`, `PT-CANCEL`, `PT-STORAGE`; errors are typed with `code`, `message`, `stage`, `recoverable`, `details` (redacted), `cause_chain` (developer log only). `unavailable` is a result state, not proof of no finding. No stage may produce completed output from truncated, cancelled or invalid sources.

**Pipeline API proposal:**

```python
class EnrichmentInput(Protocol):
    project_id: str
    run_id: str
    revision: int
    raw_sha256: str
    # immutable matches + validated artifacts + optional source offsets

def detect_flags(data: EnrichmentInput, cancel: Cancellation) -> FeatureResultV1: ...
def extract_signals(data: EnrichmentInput, flags: FeatureResultV1 | None,
                    cancel: Cancellation) -> SignalResultV1: ...
def rank_functions(data: EnrichmentInput, signals: SignalResultV1,
                   config: RankingConfigV1) -> RankingResultV1: ...
def correlate_cve(base: RankingResultV1, context: CVEContextV1,
                  evidence: EnrichmentInput) -> CorrelationResultV1: ...
def enrich(data: EnrichmentInput, options: EnrichmentOptions,
           cancel: Cancellation, progress: ProgressSink) -> PipelineResultV1: ...
```

`Cancellation` is a `is_cancelled()` protocol; check at stage boundaries and every 256 functions. `ProgressSink(stage, done:int|None, total:int|None, status)` is best-effort and cannot control success. Each stage is pure except explicit acquisition/cache/store boundaries; no background Qt dependencies. Persist only after full stage validation; partial statuses can coexist with completed prior stages. Failed/cancelled stages keep earlier committed project evidence intact. Repeat execution pins raw SHA, schema and algorithm/config digests. Sorting always uses full stable tie key, not process-generated UUIDs or dictionary iteration.

### B1. Explainable change-signal extraction and ranking

**Purpose.** Prioritize changed functions likely to merit vulnerability investigation, using deterministic observable changes. Ranking reflects *research attention/relevance*, never probability of exploitation, CVE attribution or proven vulnerability. B1 works with no B2 result, network, Qt or Ghidra installed. `FunctionMatch.category` determines available before/after side; added/removed functions cannot be described as newly introduced guards relative to a nonexistent comparison side.

**Detector catalog v1 (base integer weights; default):**

| ID/version | Category / weight | Minimum evidence and matching rule | Caveat |
|---|---|---|---|
| `BND/1` | new bounds/size/length guard, 30 | explicit new comparison with length/index/size expression plus guarded memory access on changed side, old-site absence and corresponding context; typed IR for strong or aligned code for moderate | textual bounds-like expression with no recognized guarded use => weak context signal only, not `BND` |
| `INT/1` | integer comparison semantics, 22 | compare normalized two-sided operands, strict/inclusive predicate, signedness/width/casts when represented; changed constant boundary with conserved operand identity | decompiled `>` to `>=` alone with unstable mapping => weak; do not assert signedness without typed IR |
| `OVF/1` | overflow/underflow guard, 28 | added high/low bound or arithmetic check with identified arithmetic variable/dataflow and changed control-flow relationship | no proof on renamed variable or unrelated arithmetic |
| `VAL/1` | validation/probe/guard call, 20 | added call to identifiable validation-like API OR added branch-to-error using its return value; record exact new callsite and signature | API name alone only text-heuristic; calls may be moved, inlined, or renamed |
| `ERR/1` | new early-return/error path, 12 | new return/goto-to-exit branch with newly introduced controlling predicate; diff positions recorded | compiler refactor may manufacture apparent early exits |
| `SIZE/1` | buffer-size/length argument change, 24 | same resolved API/call across sides with changed argument position/value for size-related parameter; establish typed or known signature | unknown signature => limited evidence, avoid assuming argument semantics |
| `WIL/1` | feature-gate transition, 12 | B2 `introduced` or `condition-changed` with proved control relationship to changed function | co-located flag with ambiguous control relation => weak contextual note, no primary score |
| `SCRUB/1` | pre-copy sensitive-field sanitization, 34 | newly introduced zeroing/field masking before a copy, linked same data object and optional restore; proof via typed dataflow for strong | this general-purpose detector is needed for information-leak fixes; do not special-case `clfs.sys` |

**Algorithm order:** (1) validate unchanged raw artifact and revision; (2) obtain old/new function bodies; (3) normalize whitespace/comments/declared auto-generated identifiers conservatively, without rewriting literals, signedness, pointer dereferences or operand width; (4) align compatible matched functions using existing bounded `alignment.diff_hunks` to find candidate edit regions; (5) run typed-IR detectors if independent IR provenance exists, otherwise run conservative paired decompiler-pattern detectors; (6) attach exact older/newer citations and uncertainty; (7) group signals by underlying edit region and dataflow/callsite identity; (8) deterministic scoring. Do not treat a display diff hunk as an instruction-address map. Suppress boilerplate produced by layout-only changes when absence of semantic evidence can be established; otherwise mark weak/unknown, not `benign`.

**Detector requirements:** each detector owns immutable `id/version`, recognized grammar or normalized IR predicates, applicable match categories, minimum source requirements, output evidence locators, false-positive/false-negative notes and fixtures. A detector *must not* promote an old/new claim if only one side is observable. A generated `ChangeSignalV1` has `confidence=strong|moderate|weak`, `quality` and explicit limitations. `confidence=unavailable` suppresses score and retains diagnostic; confidence values are **quality tiers**, not probability.

**Default exact scoring (integer arithmetic):**

1. Weights are configurable whole integers `0..100`; unknown IDs and negative/noninteger/bool weights rejected; schema enumerates the eight allowed v1 IDs. Defaults from catalog. `score_version='attention/1'` and canonical config digest included.
2. Within a pairing, collapse identical `signal_id`; identical evidence detected by multiple versions must be grouped by normalized source span + predicate/callsite + underlying edit operation. Overlapping changed lines alone are a *fallback* grouping criterion; disjoint AST nodes in same hunk may form separate groups if verified.
3. Confidence multiplier is `strong=100`, `moderate=70`, `weak=35`, `unavailable=0` (integer percentage). Per signal adjusted weight `q=(weight*multiplier+50)//100`.
4. In each change group sort adjusted weights descending (tie by signal ID). `group_score = min(40, largest + min(12, second_largest//4))`; third and later corroborating detectors add no points. Deduped separate groups may contribute independently. This discounts redundant signals.
5. `raw=min(80, sum(group_score))`. `attention_score=(raw*100+40)//80`, integer `0..100` rounded half up. E.g. one 40-point group scores 50; two independent 40-point groups score 100.
6. **Negative or contradictory evidence:** never invent a negative vulnerability probability. Store `counterevidence[]` with citations and adjust *confidence descriptor* (e.g., inferred-only, contested), leaving the deterministic attention score defined only by positive verified/heuristic signals. If a detector can disprove its own prerequisite, suppress that signal rather than subtract points.
7. Sort descending score, then descending count of strong independent groups, then ascending `pairing_id` as UTF-8 string. Missing match-quality metadata does not change score. Display separate `match_certainty=manual|upstream-reported|ambiguous|unverified`, not mathematically mixed into score.
8. An independent detector update, even same ID, requires version bump and cache invalidation. No AI fields enter score or sort order.

**Pseudocode:**

```text
for pairing in sort_by_stable_identity(validated_changed_matches):
    source = collect_available_old_new_evidence(pairing)
    signals = sorted(deduplicate(all_detectors(source, optional_flags)), id)
    buckets = group_by_underlying_edit_identity(signals)
    subtotals = []
    for bucket in sorted(buckets):
        weights = sorted((adjusted_weight(s), s.id) for s in bucket, descending=True)
        subtotal = min(40, weights[0].weight + min(12, weights[1].weight//4 if len(weights)>1 else 0))
        subtotals.append(subtotal)
    score = (min(80, sum(subtotals))*100 + 40)//80
    emit(score, signals, subtotals, evidence_quality, missing, stable_pairing_id)
return sorted_results
```

**CLI reserved contract** (activate only after foundation): `PatchTrace.exe rank --project DIR [--run RUN_UUID] [--format table|json] [--output FILE] [--weights FILE] [--no-cache|--refresh] [--offline]`. Default latest completed, current raw run; refuse ambiguous active results. `--format json` stdout must be a stable versioned JSON envelope (no logging on stdout); table is only presentation. `--weights` is strict local UTF-8 JSON; never eval. `--refresh` incompatible with `--no-cache` -> exit 2. GUI: add score column with numeric sort role, text confidence/quality, a signal breakdown region linking exact match/old/new text, “Rank changes” action, “No scored signals” empty state, clear synthetic/demo tags and cancel. Store sort preference in existing `QSettings`, not analytic config. Reports append base score, signals, missing evidence and formula version to the existing safe snapshot/export preview; default source excerpts omitted unless `include_code=True`.

**Acceptance tests:** exact score arithmetic and canonical ordering; duplicate detector group discount; missing code/assembly/p-code; strict/inclusive and signedness negatives; strong evidence vs text-only downgrade; addition/removal; mismatched match ownership; manual correction changes pairing identity; malicious/unbounded excerpts; sorted output identical on repeated Linux/Windows fixture; current navigator still points to correct match; CLI/GUI/report numbers identical; offscreen Qt tests; no live Ghidra required. The detector signal is labelled a research heuristic in every display.

### B2. Windows WIL/controlled-feature detection

**Purpose and boundary:** identify feature-management symbols/checks, characterize changes in control flow, and expose auditable evidence to B1. No symbol invention, no live feature toggling, no execution of Windows binaries, no mandatory symbol downloads. Input is available `FunctionRecord` text/metadata plus any independently sourced and hash-verified symbol or IR records. Pure parser operation must succeed in isolation without Windows, Ghidra, Qt or network.

**Recognition rules v1:**

| ID | Trigger | Output confidence / required proof |
|---|---|---|
| `WIL-SYM/1` | exact identifier `Feature_([0-9]+)` delimited by C/C++ symbol boundaries, numeric decimal uint32 0..4294967295 | identifier confirmed from exact evidence; name is unresolved if no separately verified mapping |
| `WIL-ACCESS/1` | candidate `__private_IsEnabled...NoInline`, `IsEnabled` wrappers and validated mangled/demangled WIL helper shapes | candidate wrapper; do not assert gating without reachable call and conditional use |
| `WIL-CALL/1` | resolved call to feature-check accessor, or paired code containing a verified WIL wrapper call with a passed/associated feature ID | a callsite only; no assumption that the checked flag necessarily gates modified code |
| `WIL-GATE/1` | resulting branch/ternary/control-flow predicate dominates the changed operation and has corroborated source location; compare old/new control dependence | high certainty only if CFG + operands are available; textual branch enclosing an edited operation is heuristic/moderate |
| `WIL-CHANGE/1` | aligned old/new condition or guarded branch body differs; classify introduced, removed, condition-changed, behavior-changed or unchanged | if no valid paired relationship, `unknown` rather than a false introduced/removal claim |

**Pattern research gate WIL-R1:** Microsoft's open-source WIL repository supplies only one class of reference implementation, not the complete private Windows feature-staging ABI. Prior to implementing `WIL-ACCESS` beyond exact symbol recognizers, inspect versioned `microsoft/wil` feature-management headers and small authorized Windows/PDB-derived specimens. Establish mangling, wrapper families, compiler x64 variants and negative examples. `__private_IsEnabled*NoInline` is a search candidate until backed by actual specimens; do not invent an exhaustive calling convention. Trace symbol provenance as `embedded-symbol|public-PDB|private-PDB|analyst-import|heuristic`. Check symbol cache/PDB GUID+age and PE debug directory signature; mismatches never silently match.

**Feature record:** `feature_id:int|null`, `feature_name:str|null` (unknown is null), `original_symbol`, `original_artifact_hash`, `resolution_source`, `resolved_symbol_hash`, `old_sites[]`, `new_sites[]`, `gated_pairings[]`, `condition_evidence[]`, `control_relation=proven-cfg|heuristic-lexical|adjacent-only|unavailable`, `transition` enum, `confidence_tier`, `nested_parent_feature_ids[]`, `detector_version`. Duplicate callsites are separate locations under one feature/build; nested gates use explicit parent-child site references and cycle rejection; name overrides are analyst-authored annotation, not a replacement of derived symbol evidence.

**Algorithm:** build a per-side symbol index; parse candidate IDs and wrappers with bounded regular expressions; follow known wrapper-to-feature references where uniquely supported; correlate caller/callee textual identities only as candidate edges; identify conditional regions surrounding changed diff blocks; test domination with CFG only if available, otherwise require explicit branch body enclosure and mark heuristic; compare corresponding gate signatures and guarded edits across sides; deduplicate by `(artifact hash, feature id, site canonical reference, wrapper identity)`; sort feature IDs numerically then sites canonically. A check nearby, an unknown feature ID, or changed function calling a feature helper is insufficient to assert causal gating. Split/merged/manual matches inherit explicit ambiguity.

**CLI reserved:** `PatchTrace.exe flags --project DIR [--run UUID] [--format table|json] [--feature-id N] [--offline] [--output FILE]`; produce `FeatureResultV1`, with an independent `unresolved` count. GUI: optional Feature flags column/badge-like text, expandable site/guarded-change details, per-source symbol provenance, navigation to both sides; never show guessed friendly name as certain. Reporting adds structured WIL evidence, not external claims.

**Missing-data / errors:** symbol lookup unavailable => detect numeric identifiers from existing text; ID found but name absent => `feature_name=null`; both absent => `unavailable` detector capability, not `feature_id=0`; stripped binary => lower confidence; unsupported mangling => recorded unknown pattern; contradictory multiple feature mappings => `ambiguous`, preserve candidates, no confident gate classification. PDB mismatches => reject symbol enrichment but retain raw diff. Parsing is size/CPU bounded; no network in unit tests. Cancellation checks every N functions and before result publish.

**Acceptance:** strict `Feature_326875449` synthetic recognizer positive; numbers `-1`, >uint32, textual partial matches negative; missing PDB; conflicting mappings; nested and duplicate sites; old/new unchanged gate vs newly introduced gate; nearby-but-not-dominating guard negative; no invented names; Linux fixture pure tests; GUI/CLI roundtrip; only traceable `proven-cfg|heuristic` links feed B1 `WIL` scoring.

### B3. CVE intelligence and deterministic correlation

**Purpose:** retrieve and pin vulnerability context and *rerank existing B1 results* without changing the base score or inventing code evidence. Full offline operation with cache/import; remote access only on explicit user action. The CVE input regex is `^CVE-(19[0-9]{2}|20[0-9]{2})-[0-9]{4,}$` with total 32-character cap for v1, case normalized uppercase. Reject ambiguous or malformed values before HTTP.

**Providers, verified research and gates (2026-10-11):**

* Microsoft maintains the [MSRC Security Updates API](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API) and its v3 OpenAPI. Its schema lists `/updates/{key}` (CVE/year/update lookup) and `/cvrf/{id}` (month CVRF details). Endpoint base, authenticated access and field shapes **must be live-probed before shipping**; developer portal login should not be confused with a universal runtime API-key requirement. Never assume a CVE maps one-to-one to one monthly document or KB.
* NVD 2.0 official interface: `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-...`, optional `apiKey` header; treat `vulnerabilities[]/cve`, descriptions, weaknesses, metrics, configurations, published/lastModified as separately attributed fields. API 1.0 is retired. Live 200/404/empty/rate-limit behavior must be fixture captured from the current API before release.
* Source records are *snapshots*, not live truth. Respect source license/attribution and store provider, endpoint host (redacted), retrieval time UTC, HTTP status, ETag/Last-Modified if present, response SHA-256 and normalized field provenance. Never store bearer/API keys or unredacted URLs containing secrets. If sources differ on CWE, severity, scope, or affected versions, emit both with source IDs and `disagreement=true`.

**Transport contract `IntelligenceProvider`:**

```python
class IntelligenceProvider(Protocol):
    provider_id: str
    def retrieve(self, cve_id: str, *, transport: SafeHTTPTransport,
                 cancel: Cancellation) -> RawProviderSnapshotV1: ...

def normalize_context(records: tuple[RawProviderSnapshotV1, ...]) -> CVEContextV1: ...
def load_context_snapshot(path: Path) -> CVEContextV1: ...
```

HTTPS only, allowlisted provider hostnames, redirects disabled by default (or same-host HTTPS only after explicit implementation decision), `Accept: application/json`, read cap 4MiB per source, connect timeout 10s, total 30s, 3 attempts maximum for transient 429/502/503/504, exponential 1/2/4 seconds bounded by `Retry-After <=30s`, never retry schema-validation failure. Application-level default conservative rate 1 request/7s anonymous NVD and 1/2s keyed; these are local courtesy limits, *not* statements of provider guarantees. MSRC uses its own configurable bound. Cancellation between waits and reads; no remote call in pure unit tests. Return typed `PT-CVE-PROVIDER` vs `PT-CVE-UNAVAILABLE` vs invalid context; one provider's failure must not discard a valid pinned other-provider snapshot. An HTTP 200 with no matching CVE identifier is *invalid*, not evidence of no vulnerability.

**Normalization:** preserve official English description plus language code; CWE IDs as validated `CWE-[0-9]+` or explicit `CWE-noinfo`/`CWE-other` with source; CVSS version/vector/score in source-labeled nested records; products as CPE and provider product IDs with affected predicates rather than invented version intervals; KB/advisory IDs separately; publication/modification timezone-normalized ISO 8601; absent fields null/empty list with `availability` metadata. Canonical snapshot identity hashes all retained normalized values, source response digests and normalization version, *not* retrieval wall-clock time when response bytes are identical. Persist first-party and second-party records separately to permit disagreements; show retrieved date and stale threshold 30 days (warning only; offline cached data is allowed and visibly stale).

**Deterministic correlation:**

1. Keep `FunctionRankingV1` unchanged. Build a bounded context token set from official description/CWEs/product names and explicit technical terms. Tokenization: Unicode NFC, casefold, split camelCase/snake_case/dot and non-alphanumeric separators, preserve meaningful C++ identifiers and hexadecimal constants, drop a published, versioned stopword list; dedupe tokens; cap context terms to 256. Never use user-supplied free-form provider text to generate SQL or executable expressions.
2. Build per-function evidence text from existing function/symbol names, known calls/imports, verified changed constants/strings and **previously emitted B1/B2 signals**. Source text is untrusted and length-limited; matches cite concrete `EvidenceRefV1` and specific CVE context field/source. Terms appearing only in CVE description must not create a new code-change signal.
3. Technical equivalence dictionary (versioned JSON) maps bounded synonyms to concepts; initial mapping: buffer/heap/stack/oob -> `memory-bounds`, integer overflow -> `integer-arithmetic`, path traversal -> `path-validation`, object lifetime/UAF -> `lifetime`, information disclosure/uninitialized memory -> `data-exposure`, access control -> `authorization`. More mappings require fixtures, negative cases and version bump.
4. CWE lookup maps `CWE-122, CWE-119, CWE-125, CWE-787` to the `memory-bounds` concept; `CWE-190, CWE-191` to `integer-arithmetic`; `CWE-200, CWE-201, CWE-209` to `data-exposure`; other CWEs are unmapped unless a versioned mapping exists. **These are context weights only**; no synthetic B1 signal.
5. For each pairing compute deterministic adjusted context contributions: `+12` if a normalized technical identifier/entity appears in both authoritative description and cited function evidence (`max one per distinct evidence field; cap 24`); `+10` if published CWE concept aligns to a corresponding *existing* B1 strong/moderate signal (`one per concept; cap 20`); `+8` if verified feature identifier from official advisory appears in B2 **and** in CVE context (rare, usually unavailable; require actual source citation); `+4` if product module identifier appears in advisory and the analyzed artifact metadata (`one cap`). Pure generic words (`security`, `patch`, `driver`, `memory`) receive zero without a technical qualifier. Total positive adjustment max 30. No binary-derived evidence => adjustment zero. Conflicting provider statements block the associated concept increment rather than selecting a winner.
6. `context_score=min(100, base_score + min(30, sum(contributions)))`. This is a presentation relevance index, **not** calibrated vulnerability probability. Preserve original score and original rank; sort contextual results by context score descending, then base score descending, then stable pairing ID. A CVE mismatch or missing metadata yields the original ordering with `degraded` status, never a fabricated zero-probability conclusion.
7. Store `context_evidence[]` with context field, provider ID, exact field digest, matching tokens, supporting B1/B2 signal and binary evidence IDs, contribution points and rule version. Show why each increment occurred.

**CLI reserved:** `PatchTrace.exe correlate --project DIR --cve CVE-YYYY-NNNN [--run UUID] [--offline] [--context FILE] [--format table|json] [--refresh] [--output FILE]`. Default offline is governed by shared profile; **no implicit network**. `--context` provides imported strict JSON and forces snapshot pinning; `--refresh` permitted online only with explicit fetch consent and stage selection. GUI: CVE ID field, `Use cached/imported context` default, separate `Fetch context online` action showing provider/URL/source policy, freshness, raw vs contextual rank columns, field provenance, disagreement and absent-data notices; do not transmit target binaries or decompiled text to CVE providers. Reports include pinned source IDs and digests and original/context ranking, excluding API keys.

**Acceptance:** independent fixtures for MSRC and NVD normalizer; no network unit tests; schema mismatch/oversized response/429/backoff/offline/no cache; malformed CVE; conflicting CWE; missing CWE; meaningless keyword noise; same context snapshot deterministic rerank; base ranking unchanged; different snapshot changes only contextual cache; correct offline import; report source provenance; UI never auto-fetches when project opens. Live endpoint probe is a separate, explicit release gate.

### B4. Crash-safe raw analysis and enrichment cache

**Scope:** reuse successful immutable raw analyses across identical *ordered* binary pairs and reuse stage results where all relevant algorithm, configuration and source identities match. No cached failed/partial run promotion; no shared mutable Ghidra project reuse in v1. A cache hit generates a new project-owned `AnalysisRun.id` and **copies or safely verifies** immutable raw output into `runs/{new_run}/raw`, with identical parent hash/provenance and `cache_origin_key`, then uses existing `ProjectService.prepare_analysis` / `apply_import`. This preserves per-project evidence and history. The parent project does not depend on the global cache after publication.

**Raw key** `H('pt/cache/raw/v1', {old_sha256,new_sha256,orientation:'older-newer',engine_id,engine_revision,ghidriff_revision,ghidra_version,pyghidra_version,python_version,java_version,symbol_mode,symbol_cache_digest_or_null,ghidra_analysis_options,backend_args,loader_settings,backend_adapter_version,platform_arch})`. If required version information is `unverified`, default **disable cross-project raw cache reuse** (an exact same-run result remains available as project history). Java environment and Ghidra extension versions need explicit probes or controlled manifest. Ignore Qt font, window layout and report preferences. If symbols can change nondeterministically online, require a pinned symbol-input digest or mark result cache-ineligible. Both binary SHA hashes must be computed from immutable project-owned copies; identical reversed pair is only a hit if `old_sha==new_sha` and other requirements hold.

**Stage keys:** flags = `H('pt/cache/wil/v1', [diff_id, raw_sha256, B2_rules_version, available_symbol_digest, schema_version])`; signals = `H(... [diff_id, B1_detector_versions, B2_result_digest_or_null, normalized_evidence_digest, schema_version])`; ranking = `H(... [signal_digest, ranking_config_digest, score_version])`; CVE contextual = `H(... [ranking_digest, pinned_cve_snapshot_digest, cwe_dictionary_version, correlation_version])`. Do not expire deterministic results by wall-clock alone; refresh intelligence snapshots separately. Changes in weights invalidate ranking/context, not raw Ghidriff results or B2 flags. Detector revisions invalidate only dependent enrichment stages.

**Filesystem layout (proposed):**

```text
%LOCALAPPDATA%/PatchTrace/cache/v1/
    raw/ab/<64hex>/manifest.json
    raw/ab/<64hex>/payload.ghidriff.json
    derived/ab/<64hex>/manifest.json
    derived/ab/<64hex>/result.json
    locks/<64hex>.lock
    quarantine/<uuid>/
```

`ab` is first two key hex characters; path components never directly reflect untrusted filenames. Root override must be validated as an absolute local path with sufficient disk space, no symlink escape, and compatible permissions. A manifest is strict v1 JSON with `state=complete`, exactly known path names, key/input/config/version digests, file digest+size, total bytes, created/access timestamps, provenance, and dependency fingerprint. Validate payload and manifest before use; parse with strict duplicate-key detection. Write: stage in private UUID directory on same volume; stream bytes and hash; fsync files and staging dir where OS supports; rename payload into final content-addressed entry; publish `manifest.json` **last** with atomic replace; no unvalidated partial entry can be read. If destination exists under lock, verify it and reuse; never overwrite unrelated valid keys. On Windows handle AV/locked-file rename failures with bounded retries or actionable error; never claim power-loss durability where platform cannot guarantee directory fsync.

**Concurrency:** one writer per key via cross-process lock with PID, start timestamp, host ID and random nonce; a stale lock is recovered only after OS lease/pid-liveness check, not elapsed age alone. Multiple readers permitted for complete entries; readers validate manifest/payload hashes. Use OS-safe advisory file/handle locking, no static shared Ghidra DB. If a writer crashes, incomplete stage directory has no published manifest and is quarantined or cleaned on the next maintenance pass. Cancel before promotion keeps partial unpublished; cancel after promotion returns valid completed cache entry while canceling current project publication if appropriate. Per-stage cache access cannot mutate source project history.

**Eviction and bounds:** default user-configured global cache budget 20GiB, hard entry max raw 100MiB JSON plus bounded metadata; reserve `max(2GiB,10% of volume capacity)` free before admission (policy configurable). LRU by durable last-access field with deterministic `(access_time,key)` tie; skip live locks/leased readers; eviction removes only complete unreferenced *global* cache entries, never project-owned outputs, and tolerates races. On admission when new payload exceeds budget, skip caching without failing analysis; report reason. Provide `cache status`, `cache verify`, `cache prune --dry-run` (future CLI subcommands through shared parser). Limit automated verification work to manifest/hash on hit, rather than scanning all entries at startup. Quarantine corrupt entries, never delete unrelated user files.

**Flags:** `--no-cache` = no cache reads or writes at every stage; `--refresh` = bypass reads for selected stage+descendants and replace canonical entry only after successful recomputation with same key or new key (old valid entry not removed before commit); both together invalid exit 2. Raw run `--refresh` requires separate expensive rerun confirmation in GUI. Cached CVE provider data respects explicit offline state; `--refresh` must not quietly enable network. Cache-hit log includes identity and stage, reports cache provenance.

**Ghidra project reuse:** defer to separate feasibility spike; mutable project directory reuse disabled until pinned Ghidra/Ghidriff version compatibility, exclusive open/checkpoint, clean-close proof, stale db detection, symbol/cache provenance, concurrent isolation and crash restoration tests all pass. Directory existence is never success evidence.

**Acceptance:** valid ordered repeat hit; swapped pair miss; single engine/settings/Java/symbol mode version change miss; detector-only version change targeted cache miss; corruption/partial payload reject; two concurrent writers one canonical entry; interrupted writer cleanup; lock ownership; empty disk/restricted folder/budget cap; CLI flag precedence; cache provenance and source integrity; offline copied project opens without global cache; no modification of old raw evidence/analyst findings; Windows locking and frozen-path verification. B4 may initially cache only deterministic derived stages until runtime fingerprint/provenance preconditions are met; report raw-cache unavailability explicitly.

### B5. Shared CLI, GUI, migration, security and performance gates

**Reserved exit status contract, pending actual CLI foundation:** `0=successful operation`, `2=invalid config/arguments/environment`, `3=analysis/enrichment internal failure`, `4=legitimate no binary differences or no requested results` (only where user requested result-set semantic success is defined; empty `rank` on valid zero-change comparison may use 4), `5=cancelled`. Retrieval unavailable offline with no context is `2` if user misconfigured input and `3` if a configured provider failed at runtime; successful *partial* enrichment stays `0` only with `status=partial` and warnings in machine-readable result. Informational `--help/--version/cache status` return 0. All commands run headless without constructing Qt; plain `PatchTrace.exe` launches GUI; logging to stderr only; `--format json` stdout is exactly one JSON document. When foundation interface does not exist, preserve contracts as pending and do not add a parallel argument parser.

**Database approach and migration:** add `enrichment_meta(key PRIMARY KEY,value NOT NULL)` storing extension schema version; `enrichment_entries(entry_id TEXT PRIMARY KEY, project_id, run_id, revision INT, raw_sha256, kind TEXT, input_digest TEXT, algorithm_version TEXT, status TEXT, json_payload TEXT, payload_sha256 TEXT, created_utc TEXT, UNIQUE(project_id,run_id,revision,kind,input_digest))` plus indexes `(project_id,run_id,kind)`; enforce declared kind/status/size in `storage.py`. Store stage outputs as normalized UTF-8 JSON envelopes, per-row size max 32MiB and aggregate derived record budget 128MiB/project by default. No untrusted interpolated SQL. Use service transaction and original `ProjectStore` lock/connection; same-thread writes; prepare validated output on worker then commit on project service thread. Transaction must check exact project id, current revision/run status, raw hash and input digest immediately before `INSERT`. Original raw artifacts and `current_snapshot` remain unchanged. On opening a project, stage rows with outdated revision, nonexistent run or mismatched raw hash are returned **stale** (not silently deleted); optionally prune by explicit user action after backup. Future extension schema unknown => read-only view or fail `PT-ENRICH-SCHEMA` without dropping data. Creating the extension tables requires a tested backup and repeatable migration; old-client open/read/save and old-client full backup round-trip are regression gates.

**UI:** `MainWindow` navigator retains current selection by `FunctionMatch.id`; append stable `score` column, toggle base/context; defer large list sorting/filtering to worker-model or Qt sort proxy with numeric value role, bounded batch updates, selected-run badge/text, empty/unavailable states and accessible tooltips. Use existing job cancellation and `JobEvent`; UI thread only handles result presentation and service commits. No analysis work on UI thread. CVE requests require explicit online action. Existing evidence navigation must verify run/revision and never jump a signal to a stale/new run by name alone. Preserve current dark/keyboard workspace and onedir packaging. Report view/export must draw from an immutable, validated combined snapshot for preview and final bytes.

**Target performance budgets, subject to measured fixtures:** on a reference Windows 11 x64 4-core CPU/16GiB RAM/SSD, ranking 10,000 function pairings with <=100,000 total decompiled lines should complete in <=10s with no live Ghidra and with peak added Python memory <=512MiB; more complex data may exceed this and must be benchmarked. Stage cache hit (not importing project data) target <=500ms for <=10MiB payload on SSD; GUI remains interactive within 100ms event latency during background enrichment; list repaint batch max 200 rows and 16ms per batch target. Full Ghidra run is intentionally excluded from these targets. Benchmark p50/p95 elapsed time, peak RSS, signal coverage, cache hit/miss, and detector false positives/negatives on representative synthetic and held-out real binary fixtures. Treat targets as engineering objectives, not verified benchmarks.

**Security:** never run input binaries or AI-authored commands; bound strings, JSON recursion/arrays, p-code records and memory; strict ownership prevents forged `run_id`, path traversal and cross-project evidence; shell=False and explicit argv; cache paths content-addressed, symlink checked; no automatic network; HTTPS provider responses are untrusted data, not instructions. No decompiled text or project binaries uploaded by CVE lookup. Private credentials not logged, stored or included in exports; remote AI has existing separate explicit preview boundary. New code must not reinterpret unsigned matching metrics as security probabilities.

## C. Phase 3 architectural and interface specifications (deferred)

The following are **design-only**. Their minimal contracts are proposed so Phase 2 data remains reusable; none are a Phase 2 implementation dependency except a generic engine identifier already present in the shared analysis identity.

### C1. Binary acquisition `fetch`

**Feasibility:** Winbindex supplies indexed Windows file/update metadata, Microsoft Symbol Server can supply objects referenced by symbol identity, Microsoft Update Catalog/servicing packages may contain complete/delta payloads, but no source guarantees retrieving *arbitrary* filename + arbitrary KB + arbitrary version as a directly executable PE. Source capabilities must be declared `search_by_name/version/date/KB`, `binary_download`, `symbol_download`, `package_download`, `delta_reconstruct`, `strong_hash_available`. Query plan is provider-specific and may return ambiguous candidates. Winbindex and third-party distribution may be unavailable/offline. Redistribution of Windows binaries is outside the app's presumed license rights; original vendor license/terms review required.

**Proposed portable API:**

```python
@dataclass(frozen=True)
class BinaryQueryV1:
    filename: str | None = None
    version: str | None = None
    kb: str | None = None
    date_from: str | None = None
    date_to: str | None = None
    arch: str = 'x64'

class BinaryProvider(Protocol):
    def search(self, query: BinaryQueryV1, cancel: Cancellation) -> list[BinaryCandidateV1]: ...
    def plan(self, candidate_id: str) -> AcquisitionPlanV1: ...
    def acquire(self, plan: AcquisitionPlanV1, destination: Path,
                cancel: Cancellation, progress: ProgressSink) -> AcquiredArtifactV1: ...
```

`BinaryCandidateV1`: provider ID/URL, product, filename, version/build, architecture, KB, release metadata, size, source-reported digest, identity certainty, payload type and source terms. Never auto-select among multiple plausible candidates. `AcquisitionPlanV1` pins provider capabilities, exact content URLs/hash policy, expected format, reconstruction base dependency, estimated disk, consent and provenance. `AcquiredArtifactV1` stores downloaded SHA-256, **independent** source hash state `verified|mismatch|not-provided|untrusted`, PE header metadata and provenance. Do not call a file independently verified if only local self-hash exists.

**Workflow:** parse bounded query -> search candidate metadata -> disambiguate product/architecture/build -> explicit selection and disclosure -> download to quarantined temp with size/time limits and HTTP allowlist -> signature sniff (`MZ` then PE header `PE\0\0`, or PA30 delta candidate, plus unknown) -> if delta, require exact base image + supported reconstruction variant -> apply with `msdelta.dll` under a separately tested Windows adapter, free allocated output via `DeltaFree` -> verify independent digest if supplied -> run existing `ingestion.validate_pe` and hash, compare version/resource metadata where trustworthy -> atomically import project-owned copy -> append immutable provenance. A `.dll` filename with PA30 bytes is never fed to Ghidriff as a PE. Windows MSDelta `ApplyDeltaB(DELTA_FLAG_TYPE, DELTA_INPUT Source, DELTA_INPUT Delta, LPDELTA_OUTPUT Target)` returns a new allocated target and requires `DeltaFree`; not every Microsoft servicing delta can be reconstructed by the same flags/algorithm. Unsupported PA30 variant => recoverable unsupported result, never fabricated target bytes.

**CLI proposal:** `fetch search --name clfs.sys [--version ...|--kb ...|--from ... --to ...]`; `fetch download --candidate ID --dest DIR [--base FILE] [--offline]` with confirmation on non-interactive external download via explicit `--allow-network`. GUI wizard permits review/swap and verified status; no silent download. No network in mock tests. Test MZ/PA30/unknown, wrong base, corrupted output, truncated response, mixed architectures, unmatched KB, hash mismatch, path traversal in archives, duplicate version candidates, cancellation and cleanup. **Gateway:** verified provider API and license/redistribution policy before implementation. For reference use `clfs.sys` June 23 2026 26100.8737 (KB5095093) and July 14 2026 26100.8875 (KB5101650), with *actual file PE hash* verification still required.

### C2. Cross-version / N-way comparison

**Public API:** `analyze_sequence(builds: Sequence[BinaryIdentityV1], pairwise_runner, policy) -> TimelineV1`, at least 2 and capped (initial proposal 16). Input is strictly ordered by user-selected chronology; reject duplicate build SHA unless user deliberately marks alias. Run adjacent pairs `(v0,v1),(v1,v2)...`; use B4 directional raw cache; optionally first-to-last summary only when explicitly requested. `TimelineV1`: ordered binary identities, per-pair diff digests, function occurrence nodes, match hypothesis edges with confidence/provenance, changed first-observed interval, unresolved gaps, derived per-function matrix and source-run references. Create a **versioned match graph**, not union-find transitive equivalence. Distinct edges can compete; inlining/split/merge are many-to-many evidence; an unverified A->B, B->C does not prove A->C. Stable sequence-group IDs are hashes of ordered build identities plus explicit chosen edge hypotheses, never absolute addresses alone. Explicit `missing_intermediate_build`, `unresolved_branch`, `analysis_unavailable`, `possible_revert` states. GUI timeline and per-function history open corresponding existing pair/match/evidence view. No rewritten historical project artifacts; persist timeline as new derived record family with own contract and cache keys. Tests include ambiguous chains, splits/merges, missing build, unchanged function, changed ABI and flip-flop/revert. Feasibility gate: determine whether to use a new sequence container or coordinate multiple existing projects without violating their two-artifact invariant. **Default proposal: a separate sequence manifest that references existing pair projects; never mutate `ComparisonProject.artifacts` count.**

### C3. BinExport / BinDiff interoperability

BinExport's maintained repository describes its Ghidra extension producing the actual protocol-buffer `.BinExport` from a Ghidra database. The BinDiff source accepts `.BinExport` and can output native `.BinDiff` databases using its engine. Therefore:

* **Supported planned path:** export *real* `.BinExport` via an installed compatible BinExport Ghidra extension (or import an already-generated `.BinExport`) -> invoke separately installed compatible BinDiff engine with appropriate flags -> verify genuine `.BinDiff` result using native schema/tool -> import its documented match metadata using an adapter. Preserve original BinExport and BinDiff hashes, versions, tool paths and exact run identity. This path may require Ghidra reanalysis if mutable scratch was removed; do not assume existing PatchTrace PDiff contains complete CFG/flow graphs required for valid BinExport.
* **Safe partial path:** export a documented PatchTrace JSON/CSV match/evidence mapping with a format clearly named `patchtrace-*`; never write `.BinExport` or `.BinDiff` extension for a synthetic approximation.
* **Schema/tool gate:** inspect and pin `google/binexport` `.proto` revision and `google/bindiff` database schema/CLI version, verify ABI/license and standalone Windows use. Check available instructions, address spaces, call graph, basic blocks, symbols, architecture, function match IDs and similarity semantics; preserve unsupported fields as `missing/unsupported` with an explicit loss report.

CLI proposal: `interop binexport --project DIR --run UUID --ghidra-exporter PATH`; `interop bindiff --older-binexport FILE --newer-binexport FILE --engine PATH`; `interop import --bindiff FILE --project DIR`. GUI external tool launcher shows installed version, source paths and loss warnings. Negative tests include renamed JSON pretending to be `.BinDiff`, malformed protobuf, mismatched binary identities, wrong architecture and tool version. Not part of initial release.

### C4. Secondary Rizin / rz-diff analysis backend

Rizin documents `rz-diff` for comparing raw data or analyzed executables. Validate its current Windows binary availability, exact CLI switches, output schema, function-match method, resource behavior and version before implementation; do not treat textual `rz-diff` output as a ready Ghidriff-equivalent structured model. `DifferAdapter` protocol: `capabilities() -> DifferCapabilitiesV1`, `compare(old,new,settings,cancel,progress) -> RawEngineResultV1`, `normalize(raw, identity) -> EngineEvidenceV1`; the adapter returns available features (function matching/code/call edges/IR/identity) and explicit unsupported features. Keep `ghidriff` default. Cross-engine reconciliation produces `agreement|disagreement|only-in-A|only-in-B|identity-unresolved` records with both source evidence references, versions and match hypothesis links; it does not silently replace original manual corrections. Algorithmic agreement may increase an **uncalibrated qualitative confidence annotation**, not a probability or independent corroboration when engines share underlying logic. Test small compiled fixture with Ghidriff and Rizin, many-to-one matches and missing fields. Only install second engine on explicit user action with verified license/notice.

## D. Phase 4 high-level future design (conceptual only)

| ID / priority | Capability and minimum interface | Research prerequisite / key risk |
|---|---|---|
| D1 / highest | Semantic diff: optional `NormalizedIRV1` containing source-addressed p-code instructions, canonical opcodes, width/type/casts and control/data-flow references; compare AST/IR structure and emit labeled `proven-structural|probable-semantic|text-only|unknown` differences with old/new evidence. | Need Ghidra script/typed IR extraction schema/version + compiler-regression corpus. General semantic equivalence undecidable; never assert universal proof. |
| D3 / second | Capability and call graph: import optional `capa` findings and verified static call graph into `CapabilityEvidenceV1`, `CallEdgeV1`; lazy breadth-limited UI graph and navigate original function matches. | Capa rules/license compatibility, false positives, inlining/import ambiguity, large graphs. No graph database unless benchmarks justify it. |
| D2 / third | Optional native Anthropic Messages transport plus local-model presets under existing `ProviderConfig`/`providers.py`; produce separately persisted AI interpretation of structured B1/B2/B3 context with exact evidence citations, model/prompt digest and session-only keys. | Endpoint/auth and privacy research, prompt injection from decompiled data, uncertainty, provider JSON constraints and output budget. No AI effect on deterministic ranking. |

Any future Phase 4 work requires separately approved feature scopes. AI never silently fetches intelligence, executes shell commands, sends binary content or changes analyst findings.

## E. Reference CVE/CLFS fixture and validation

### E1. What is confirmed, supported, or still unknown

| Assertion | Evidence assessment as of 2026-10-11 | Required follow-up |
|---|---|---|
| KB5101650 corresponds to Windows 11 OS build 26100.8875 on July 14, 2026 | **Officially corroborated** by Microsoft Windows 11 release information, which also lists June 23, 2026 build 26100.8737 as KB5095093. | Pin update documentation in fixture manifest and record product/architecture. |
| CVE-2026-50697 is associated with Windows CLFS privilege escalation | **Supported by published third-party aggregation/patch analysis** at OnlyPatch, which links Microsoft/NVD and identifies official severity/CWE; direct official advisory page is JavaScript-only in this research view. | Retrieve verifiable MSRC/NVD JSON snapshot, confirm CNA summary, classification, CWE, affected products and July KB mapping directly. |
| Pre/post `clfs.sys` versions 10.0.26100.8737/8875 | **Reported by third-party patch analysis**, consistent with official OS build chronology; executable *file* version identity has not been independently recovered. | Obtain both authentic files, capture PE version, signature, SHA-256, size, PDB identifiers and acquisition sources; do not substitute OS build for file hash. |
| `CClfsBaseFileSnapshot::CopyImage` changed and is associated with `Feature_326875449` | **Third-party ghidriff-derived claim**, with a published matching report listing addresses and other changes; not independently reanalyzed in this session. | Reproduce matching on pinned local Ghidriff/real files; verify code bytes, symbol provenance, exact gate relationship and dataflow. |
| Patch scrubs context pointer from snapshot before copy | **Third-party technical interpretation**, not official patch semantics or reproduced firsthand. | Compare decompiled and, where possible, typed IR/assembly control flow; verify pointer-store, save/restore, ordering and dataflow; classify uncertainty. |
| Official weakness category vs inferred mechanism | Third-party page reports `CWE-200` information exposure and elevation of privilege impact, but independently verify official CVE/CWE field before treating as official. | Include source-specific distinction in fixture. |

References: [Microsoft Windows 11 release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information), [MSRC advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-50697), [NVD details](https://nvd.nist.gov/vuln/detail/CVE-2026-50697), [third-party detailed patch analysis](https://onlyfm252.starlabs.sg/patch-tuesday/2026-07/cve-2026-50697/).

### E2. Fixture structure and provenance

**Proposed local test data (not created or acquired by this specification):**

```text
tests/fixtures/patch_clfs_2026/
  manifest.json                 # origin URLs, retrieval timestamps, legal/licensing, SHA256, PE & PDB IDs
  provenance.md                 # exact commands/tool versions/chain of custody
  normalized-diff.min.json      # selectively derived source-identified, redistributable records
  wil-evidence.json             # original symbol + old/new site refs + uncertainty
  official-context-snapshot.json  # pinned redacted MSRC/NVD output, source digests
  expected-ranked.json         # reviewed expectations + non-guaranteed confidence tiers
  scripts/README.md            # reproducible local regeneration procedure
```

Keep copyrighted full `.sys` binaries **outside tracked Git** in a user-provided fixture directory; record SHA-256 and source location, never silently redistribute them. Derive a minimal anonymized or suitably licensed representation only if review confirms that distribution is permitted. Every record's old/new hash and raw PDiff SHA must match the manifest; identify source function via stable occurrence/pairing IDs, not supplied addresses alone. Fixture generation: acquire trusted builds -> file SHA and PE validation -> pin Python/Ghidra/Ghidriff version+flags (offline/no-symbol vs symbol-enabled documented separately) -> run comparison -> preserve immutable Ghidriff JSON -> validate ordered identity -> extract exact CopyImage and related old/new evidence under a hash-addressed artifact -> review expected B1/B2 claims manually -> pin NVD/MSRC context -> generate offline test files. Record whether missing symbols block an exact feature name. Any unverified claim becomes an `expected_unknown`, not a fabricated positive assertion.

**Golden acceptance, conditional on verifying the underlying records:** B1 makes CopyImage **comparatively prominent** by explicit B1 signals, with exact relative expected rank determined by confirmed fixture; B2 identifies feature ID 326875449 if truly evidenced and marks actual gate relation with certainty; B3 correlates only published CVE context and supported change signals; identical inputs yield byte-identical canonical output after excluding diagnostic wall-clock metadata; both CLI and GUI can navigate to the same source; offline mode never requests HTTP; loss of symbols lowers confidence or gives `unresolved`; negative cases prove text-only/surrounding feature flags do not imply control relation. If observed binary shows other changes more compelling than CopyImage, update the reviewed expectation rather than rig weights to force rank 1.

**Independent MZ vs PA30 acquisition fixture:** make small test fixture from a legally generated PE AMD64 stub whose MZ+PE fields pass `ingestion.validate_pe` and separately a synthetic byte sequence beginning `PA30` (clearly labelled a mock delta signature, **not** a reconstructable authentic payload); assert the former routes to PE validation and the latter is rejected as `delta-needs-base/unsupported` rather than passed to Ghidriff. A second Windows-only integration uses an actual authorized MSDelta-generated compatible delta + exact base, checks reconstructed output hash, wrong-base rejection and `DeltaFree` resource handling. No test should pretend a four-byte PA30 mock is sufficient to validate reconstruction.

## F. Dependency-aware Phase 2 implementation roadmap

**Complexity scale:** S <= 1 focused developer day, M 2–4, L 5–10, XL >10 under tested prerequisites; these are *relative planning ranges*, not time commitments. **Model assignment:** Strong = high reasoning for security/architecture contracts; Fast = lower-cost capable coding assistant for mechanically specified implementation. **File ownership:** default one owner per touched existing file; shared integration modules are merged in serial order. The first work item performs documentation and tests only after a separate implementation authorization.

| ID / phase | Scope and completion artifact | Depends on | Existing files likely touched / proposed new files | Tests/acceptance and risk | Size/model/parallel |
|---|---|---|---|---|---|
| `F0` / foundation gate | Recheck SHA/AGENTS and branches; decide actual CLI contract and runtime discovery status; document ownership matrix | none | `docs/modules.md`, `tasks/todo.md`, `docs/specs/architecture.md`; no code required | inspect PR #5/unique diverged commits; no parallel conflicting changes | S/Strong/serial |
| `S1` / shared design | Finalize Pydantic enrichment v1 records, stable IDs, registry/schema examples; no storage mutation yet | F0 | **proposed** `enrichment/contracts.py`, `identity.py`, `tests/test_enrichment_contracts.py`, `tools/generate_schemas.py`, `docs/specs/schemas.md` | deterministic hash cross-process, malformed coordinates, UUID ownership, unknown schema, generated examples | M/Strong/serial |
| `S2` / storage | Add optional additive enrichment tables and migration/old-client compatibility plus service publication | S1 | `persistence.py`, `service.py`; **proposed** `enrichment/storage.py`, `tests/test_enrichment_storage.py` | backup+upgrade, version guard, failure rollback, one-writer, old-client backup/load, stale rows | L/Strong/serial, critical |
| `B2a` / detector | Verify WIL source patterns and implement pure exact identifier/callsite/gate candidate extraction | S1 | **proposed** `enrichment/wil.py`, `tests/test_wil.py`, `docs/specs/wil.md` | positive/negative/no-symbol/ambiguous and binding evidence; no app integration | M/Strong/parallel with B1a,B4a |
| `B1a` / detector | Implement pure `signals.py` on validated paired evidence (BND/INT/OVF/VAL/ERR/SIZE/SCRUB), missing-evidence states | S1 | **proposed** `enrichment/signals.py`, `tests/test_enrichment_signals.py` | positive/negative/optimizer-noise, added/removed, bounds, capacity, stable refs | L/Strong/parallel with B2a,B4a |
| `B1b` / ranking | Implement typed deterministic grouping/weights/scoring on synthetic `ChangeSignalV1` | S1 | **proposed** `enrichment/ranking.py`, `tests/test_enrichment_ranking.py` | formula golden values, dedup, negative/empty, stable tie, invalid config, cross-platform | M/Strong/parallel with B1a only if interfaces frozen |
| `B4a` / derived cache | Pure cache identity/canonicalization + crash-safe store for derived stage JSON, raw cache gated off | S1 | **proposed** `enrichment/cache.py`, `tests/test_enrichment_cache.py` | corruption, collision, lock, cancellation, eviction, no disk space | L/Strong/parallel with B1a/B2a |
| `P1` / pure pipeline | Compose B2->B1a->B1b without Qt/Ghidra, attach run/version provenance; resource/cancel behavior | B2a,B1a,B1b | **proposed** `enrichment/pipeline.py`, `tests/test_enrichment_pipeline.py` | stage failure/partial, repeatability, exact evidence refs, unchanged raw | M/Strong/serial |
| `P2` / project integration | Read committed diff, publish coherent enrichment through service/storage, invalidate on corrections/reanalysis | P1,S2 | `service.py`, `persistence.py`, **proposed** `enrichment/storage.py` | transactional publication, stale invalidation, backup and historical run preservation | M/Strong/serial |
| `B4b` / raw cache | Wrap `backend.run_comparison` only when version/tool fingerprint and symbol state verified; copied, normalized project-owned output | B4a,P2 and verified foundation | `backend.py`, `service.py`, `tests/test_jobs.py`; proposed `tests/test_raw_cache.py` | raw cache hit/miss, directional, no shared mutable Ghidra, quarantine, hash validation | L/Strong/serial with backend owners |
| `B3a` / provider | Write bounded HTTP NVD/MSRC adapters with transport mocks and strict data normalization | S1 | **proposed** `enrichment/intelligence.py`, `tests/test_cve_providers.py` | versioned snapshots, rate limits, 429, unknown schema, offline, privacy | M/Strong/parallel with P1/P2 |
| `B3b` / correlation | Implement fixed-version terms/CWE concept mapping and contextual score evidence | B3a,B1b,B2a | **proposed** `enrichment/cve.py`, `tests/test_cve_correlation.py` | disagreement, no code evidence, deterministic base vs context, false keyword controls | M/Strong/parallel once contracts ready |
| `P3` / CLI | Extend agreed first-class CLI with `rank`,`flags`,`correlate`, JSON/table/exit codes/cache flags | P2,B3b,F0 CLI verified | `__main__.py` **only if foundation landed**, proposed `cli` adapter and tests | no Qt import headless, stdout only JSON, exit contracts, frozen CLI | M/Fast/serial integration |
| `P4` / GUI | Score column, evidence pane, feature and CVE views; no UI-owned analytics | P2,B3b and PR #5 reconciled | `ui.py`, `tests/test_ui.py`; proposed lightweight model adapter | sort, stale navigation, responsive worker, no auto HTTP | L/Fast/serial UI owner |
| `P5` / reports | Enrichment-aware preview and JSON/Markdown/HTML export with hash/pinned context/redaction | P2,B3b | `reports.py`, `tests/test_core.py` + proposed report tests | output byte agreement with preview, sanitize code/paths/source URLs | M/Fast/parallel with P3/P4 if function signature frozen |
| `Q1` / QA and docs | Audit functional wiring and error cases; performance benchmarks and regression against existing beta | P3,P4,P5,B4b | `docs/qa.md`, `docs/modules.md`, `tasks/todo.md`, tests, workflows | Linux + Windows pytest/Ruff, fake backend, native fixture, frozen smoke, per-stage deterministic QA | L/Strong/serial |
| `Q2` / future release gate | Windows end-to-end user acceptance, airgap tests and reviewed fixtures; packaging evidence only | Q1 and explicit release authorization | `tools/build_windows.py` (only if needed), `.github/workflows/*` | clean Windows, 0-network fixture, real Ghidra, signed manifest/checksums | L/Strong/serial; **not authorized now** |

**Critical path:** `F0 -> S1 -> S2 -> P2 -> P3/P4/P5 -> Q1`, with `B1a + B1b + B2a -> P1 -> P2`, and `B3a -> B3b -> P3/P4/P5`. `B4a -> B4b -> Q1` is independently gated by exact runtime fingerprint; raw caching may defer without blocking B1-B3. Sequencing `S2` before `P2` ensures results persist through the same service/storage boundary. Avoid running separate `ui.py`, `backend.py`, or `service.py` writers in parallel.

**Ownership/merge checkpoints:** (1) F0 decision record/spec first; (2) S1 contract/schema merged after tests; (3) parallel B1/B2/B4 work only in separate proposed files, rebase and merge individually after own CI; (4) S2 and P2 service/storage owner merges; (5) B3 provider and pure correlation merge; (6) B4 backend-only wrapper after runtime/reliability fixes reconciled; (7) sequential CLI/UI/report hookups by explicit owner; (8) Q1 integration tests and docs; (9) Windows frozen QA gate. No force merge; compare actual branches for duplicate commits; old stale branch is not automatically merged. Existing `tasks/todo.md` gets one checkbox per ID and actual test/PR/commit links once implementation begins. Do not delete stalled branches unless no unique work remains and owner review permits.

**Phase 3 planning tasks (not scheduled for implementation):** `C1-R` provider/legal/Winbindex/symbol/MSDelta research then acquisition fixtures; `C2-R` sequence identity model and many-to-many test graph; `C3-R` pinned BinExport/BinDiff schema/tool compatibility; `C4-R` Rizin `rz-diff` Windows CLI/contract evidence. These may be researched independently after Phase 2 stabilization, never merged into Phase 2 code without separate authorization.

## G. Per-module implementation guides (for separately authorized development)

Each guide is an independent checklist. All share: refresh `main`+AGENTS and active PRs, read A/B contracts, update spec and `docs/modules.md` before coding, test-first, strict Pydantic schema ownership, project/run/revision validation, cancellation at boundaries, bounded resources, no Qt import in analytics, Ruff and existing full suite, same-thread ProjectStore commit, Windows build assessment, accurate verification report. Completion means actual tests recorded, no orphaned branches, and no invented successful CI assertions.

### G1. B1 ranking guide

**Prerequisites:** S1 contracts+stable identity+`AnalysisRun` mapping, B1 detector catalog/weight formula approved. B1b scoring can begin before B2a; optional B2 result is nullable. Inspect and reuse `FunctionMatch`, `FunctionRecord`, `normalization.normalize_ghidriff`, `alignment.diff_hunks`, `EvidenceReference` and `ProjectService` before adding adapters. Extension boundary is **proposed** `enrichment.signals.extract_signals` returning validated `SignalResultV1`, and `enrichment.ranking.rank_functions` returning `RankingResultV1`; neither writes projects, calls Ghidra or invokes UI.

**First failing tests:** `two_independent_strong_40_groups_score_100`, `one_strong_40_group_scores_50`, `same_change_detected_twice_not_double_counted`, `unsupported_signedness_does_not_emit_semantic-proof`, `old_new_swap_changes_direction`, `missing_optional_assembly_is_not_error`, `identical_input_byte_stable`. Include `SCRUB` pre-copy sanitization positive and nearby unrelated assignment negative. Fixtures synthetically constructed with explicit source lines/offsets. Run red-green-refactor for each detector, add real-source fixture only after independent verification.

**Sequence:** typed detector registry and static input schema -> exact old/new source mapping/quality tier -> BND/ERR/VAL then INT/OVF/SIZE then SCRUB -> no-B2 path -> evidence dedup/group IDs -> exact fixed-point score formula -> per-signal explanations -> sorted envelope -> metadata provenance -> stage cache -> project storage via S2/P2. Only after pure tests pass, expose `rank` in the shared CLI, numeric Qt column and expandable breakdown, and the existing `reports._snapshot` optional enrichment input. Emit progress by processed function count; every 256 functions cancellation check. Batch very large functions and avoid copying raw body strings repeatedly. Errors for invalid evidence raise typed `PT-ENRICH-INPUT`, unsupported optional IR is an explicit lower quality result.

**Targeted verification:** full weights table and signal schema examples generated; unit/property/negative/boundary/corruption tests; score independent of dict ordering, clock and random UUID; no reliance on missing `assembly`; cloned binary pairs and override revisions; sorted JSON consistent across OS. Regression: `pytest -q`, `ruff check src tests tools`, offscreen UI evidence selection and existing report preview. **Review gate:** no detector can claim a signed/unsigned semantic change without typed metadata; source refs resolve to correct side/run; ranking labelled heuristic; static code does not run target binaries; score formula matches doc and is stable after optimization.

### G2. B2 WIL/feature-flag guide

**Prerequisites:** S1, WIL-R1 external pattern research with pinned source + compiler specimen, function/side source refs. Start in **proposed** `enrichment/wil.py` with no network and no symbol downloader. Reuse `FunctionRecord.name`, `metadata`, `callers/callees`, `raw JSON` provenance and proposed `EvidenceRefV1`. Do not treat `backend.allow_symbol_downloads=True` as permission to contact servers inside WIL detector; symbol acquisition is separately consented/owned.

**First failing tests:** `exact_Feature_326875449_yields_numeric_id`, `Feature_4294967296_rejected`, `unresolved_feature_name_null`, `nearby_flag_does_not_dominate_change`, `nested_sites_keep_separate_refs`, `new_gate_vs_existing_unchanged_gate`, `pdb_signature_mismatch_ignores_symbols`, `stripped_binary_partial_result`, `symbol_without_call_no_proven_gate`. Synthetic fixtures explicitly named. Add broad pattern fixture matrix after compiler and WIL source investigation.

**Sequence:** identifier regex / numeric range -> symbol provenance/parsing -> callsite candidates -> bounded cross-side pairing -> guarded block relation with confidence -> typed CFG path only when verified IR exists -> transitions and nested gate graph -> dedup/cancellation -> fixed-format JSON -> B1 `WIL` input -> derived cache -> ProjectService publication -> shared CLI `flags` -> GUI column/evidence detail -> report. Every emitted gate relation references source evidence and declares `proven-cfg|heuristic-lexical|adjacent-only|unavailable`. Log unsupported compiler patterns without code leaking secrets/paths. `PT-WIL-AMBIGUOUS` may coexist with partial signal output, but cannot create a confident B1 gating score.

**Targeted verification:** exact line/offset citations and unknown/null semantics, nested graph cycle rejection, high-volume pattern rejection/performance, missing symbols, wrong PDB. Run Qt-free unit tests first; later offscreen GUI, CLI JSON schema and report. Windows native test may be blocked until authentic specimens acquired; report blocked rather than passed. **Review gate:** no unsupported feature name or gate relationship asserted as fact, and module remains independently importable.

### G3. B3 CVE correlation guide

**Prerequisites:** S1 schemas, validated B1 signals/rankings and optional B2, defined provider snapshots, pinned CWE/term mapping. Source code boundary: **proposed** `enrichment/intelligence.py` owns remote transport; `enrichment/cve.py` owns pure context normalization/matching/score; existing `providers.py` is reserved for AI, and `service.py` remains project transaction owner. Do not add a new persistent API-key config system; use session-only or user-selected key as supported by the CLI foundation.

**First failing tests:** `invalid_CVE_never_requests_HTTP`, `offline_missing_context_is_unavailable`, `MSRC_NVD_disagreement_preserved`, `CWE200_with_no_code_evidence_adds_zero`, `CWE122_supports_existing_bounds_only`, `generic_memory_token_no_adjustment`, `same_pinned_context_same_order`, `expired_context_warns_not_disappears`, `API429_retry_budget_bounded`, `remote_response_never_uploads_code`. Fixtures are captured/redacted provider JSON or explicitly synthetic mock responses; no unit live network.

**Sequence:** strict CVE parser -> provider capability probe/fixtures (separate verified manual test) -> defensive HTTPS transport allowlist/timeouts/content limit/backoff -> two source-specific normalizers -> provenance-preserving snapshot -> offline import/cache -> canonical term dictionaries -> context matching with existing evidence references -> fixed integer contribution caps -> preserve B1 rank comparison -> S2 store -> shared CLI `correlate` -> GUI explicit online fetch and provenance panel -> reporting. External requests only from a user-invoked controller, never from module import/project open. Use staged files; no provider raw JSON executed or trusted as instructions. Capture 4xx/5xx, empty, inconsistent schema and cancellation. Network retries are separate from deterministic score calculation and never create fabricated evidence.

**Targeted verification:** provider schema roundtrip, official field-level attribution, 30-point cap, no score change when context missing, offline with pinned snapshot, no network in tests, redaction and no credential logs, user approval in UI. Add separately authorized live NVD/MSRC smoke probes and record dates/status. **Review gate:** original B1 rankings untouched; the matched term and CVE field plus binary evidence explain every score adjustment.

### G4. B4 cache guide

**Prerequisites:** S1 canonical identity and raw run SHA; review current `backend.run_comparison`, `jobs.run_process`, `ProjectService.prepare_analysis` and raw quarantining; F0 branch conflicts resolved before touching backend. Pure cache code proposed `enrichment/cache.py`; do not duplicate project SQLite snapshots or Ghidra scratch ownership.

**First failing tests:** `ordered_pair_reversed_is_miss`, `symbol_mode_differs_is_miss`, `unverified_java_version_disables_raw_reuse`, `cancelled_writer_has_no_valid_manifest`, `corrupt_payload_refused`, `two_writers_one_entry`, `detector_version_invalidates_only_enrichment`, `cache_disabled_does_not_write`, `refresh_and_no_cache_conflict`, `project_opens_after_global_cache_deleted`. Add negative symlink, bad free space, permission and Windows lock fixtures.

**Sequence:** `RawAnalysisIdentityV1` strict fingerprint -> derived keys -> manifest validation -> private staging, hash/fsync, atomic publish -> concurrency locks -> corruption quarantine -> usage and LRU bounded policy -> derived stage caching and independent tests -> integration with P2 and pipeline -> *then*, if fingerprint is verifiable, raw cache hook around existing backend without changing its process runner or success/quarantine semantics -> per-project copied raw JSON revalidation and new run ID -> CLI flags/status/prune -> GUI cache info/refresh -> report provenance. Keep `--no-cache` and `--refresh` behavior consistent in all commands. A 100MiB raw JSON entry may be large; stream, validate before publication, avoid unbounded memory and do not cache Ghidra project/GZF scratch.

**Targeted verification:** race stress with independent processes, kill writer during stage, corruption/repair, cancellation before/after publish, manual cache pruning while reader active, bounded eviction, offline reopen, Windows filesystem behaviour, latest real native Ghidriff fixture. Benchmark raw cache savings separate from enrichment hit. **Review gate:** cache never changes semantic output, incomplete results never look valid, and no existing original analysis artifact, project backup, reviewer correction or finding is overwritten. If version capture remains `unverified`, raw caching stays intentionally disabled while derived cache can ship.

## H. Documentation update and source map

The following changes are **planned only**; no repository files were edited. This specification package also includes `PatchTrace-Phase2-Contracts-v1.schema.json` (JSON Schema 2020-12; nine record families) and `PatchTrace-Phase2-Synthetic-Examples-v1.json` (nine valid and nine invalid synthetic records, locally checked with the `jsonschema` metaschema and validator). These are contract proposals and not implementation or runtime verification.

| Existing destination | Planned change |
|---|---|
| `docs/modules.md` | add B0/B1/B2/B3/B4 stable IDs, exact ownership, public API/test seam, optional future C1-C4 IDs; reserve PR #5 ownership. |
| `docs/specs/architecture.md` | append shared enrichment diagram, same-db side tables, CLI foundation gate, cancellation/cache/data-flow, security/offline boundaries, decision log and future engine interface. |
| `docs/specs/schemas.md` | register strict enrichment v1 JSON schema names/versions, canonical identities, persistence entity ownership and additive extension schema strategy; include generated valid/invalid fixture index. |
| `docs/specs/ui.md` | add numeric ranking column, signal detail, feature gating provenance, explicit CVE-fetch consent, base/context ranking toggle, responsive sorting, keyboard navigation and stale-source controls. |
| `docs/specs/completeness-audit.md` | add B1-B4 statuses as planned, distinct from implemented/tested, score/fixture/Windows acceptance traceability; correct audit-scope note for the new stop boundary. |
| `tasks/todo.md` | add F0,S1,S2,B1a/B1b,B2a,B3a/B3b,B4a/B4b,P1-P5,Q1-Q2; dependency checklists and actual run links only after implementation. |
| `docs/qa.md` | label new extension tests `not run` now; record future actual targeted/full/native/Windows tests separately, existing beta claims unchanged. |
| `docs/research.md` | append source/date/URI research ledger for MSRC CVRF v3, NVD v2, WIL, MSDelta, BinExport/BinDiff, Rizin/Winbindex, with exact compatibility gates. |
| `docs/windows.md`, `README.md` | after implementation only: user-facing CLI, offline modes, cache and ranked/CVE workflow, runtime prerequisites. No feature claims until shipped. |
| `docs/schemas/` | **proposed:** generated extension schemas e.g. `FeatureGateV1.json`, `ChangeSignalV1.json`, `RankingConfigV1.json`, `RankingResultV1.json`, `CVEContextV1.json`, `ContextualRankingV1.json`, `CacheManifestV1.json`, `PipelineExecutionV1.json`. |

**Justified new documentation, proposed only:** `docs/specs/enrichment.md` for B0/B1 and shared scoring; `docs/specs/wil.md` for researched WIL signatures and negative patterns; `docs/specs/intelligence.md` for current CVE interfaces/source attribution; `docs/specs/cache.md` for identity/locking/crash recovery; `docs/specs/phase3.md` for C1-C4; `docs/specs/phase4.md` for D1-D3. This groups maintained domains rather than fragmenting into every detector. This downloadable document is the pre-implementation source package; later copy its approved sections to the mapped repo documents.

### External primary and corroborating sources, researched 2026-10-11

* Repository snapshot: https://github.com/djshellshoxxx/patchtrace/tree/0f1b4ce5a0b51526fdceb5533f0553321899fd2a ; current code, `AGENTS.md`, tests/specs/CI as cited above.
* MSRC official API reference repository: https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API ; OpenAPI schema: https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API/blob/main/docs/swagger.json ; MSRC API/developer FAQ: https://www.microsoft.com/en-us/msrc/faqs-security-update-guide .
* NVD official developers: https://nvd.nist.gov/developers/vulnerabilities ; API 2.0 root: https://services.nvd.nist.gov/rest/json/cves/2.0 ; legacy retirement noted at https://nvd.nist.gov/developers/vulnerabilities-1 .
* Microsoft OS build chronology: https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information .
* Microsoft MSDelta `ApplyDeltaB`: https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta-applydeltab .
* Google BinExport source and Ghidra export usage: https://github.com/google/binexport ; Google BinDiff source/CLI: https://github.com/google/bindiff .
* Rizin and `rz-diff`: https://github.com/rizinorg/rizin .
* Windows Implementation Library source requiring versioned audit: https://github.com/microsoft/wil .
* Third-party CVE patch interpretation, **not official binary proof**: https://onlyfm252.starlabs.sg/patch-tuesday/2026-07/cve-2026-50697/ .

## I. Readiness, open verification gates, and first implementation task

**Ready for separate implementation authorization:** deterministic core contract/identity tests S1; pure B1 score arithmetic and grouping once those contracts are frozen; synthetic WIL numeric recognition; derived cache key and crash safety tests. **Not ready to claim:** full C/C++ semantic detection without IR, complete WIL semantics across compilers, automatically verified CVE context or CLFS patch without authentic data, safe Ghidra project reuse, arbitrary binary acquisition, full Windows standalone/new release.

**External verification required:** WIL private/accessor signature corpus and compiler variants; current MSRC endpoint/version/auth/response shapes; NVD API 2.0 live provider responses; exact Windows build vs `clfs.sys` PE identity/PDB; authenticated old/new CLFS binary-derived diff; Winbindex/source trust and Windows delta reconstruction; BinDiff/BinExport schema compatibility; Rizin Windows CLI schema; frozen Windows native quality gates.

**Foundation-blocked:** headless `rank/flags/correlate` CLI commands and consistent exit codes await the *actual* unified parser/configuration integration. Runtime discovery PR #5 must be reconciled before overlapping setup/UI edits. Raw cross-project analysis caching cannot safely ship until deterministic Java/Ghidra/symbol provenance is available or explicitly cache-ineligible cases are excluded.

**Recommended first Phase 2 work unit: S1a (small subset of S1) — identity and evidence-record contracts only.** Scope: write `docs/specs/enrichment.md` and `docs/specs/schemas.md` amendments, then add pure typed `EvidenceRefV1` and identity canonicalization in proposed `enrichment/contracts.py`/`identity.py`, plus `tests/test_enrichment_contracts.py`, without database, GUI, backend, network or implementation of any detector. Required tests: deterministic canonical hash across mapping order, ordered old/new swap yields different diff ID, zero offset versus missing offset, invalid line ranges and wrong-side ownership rejected, duplicate source identity rejected, malformed hashes/unsupported schema rejected, immutable old `ComparisonProject` JSON unchanged, pure package imports with no Qt/Ghidra. Red-green-refactor; generate valid and invalid examples; `pytest` and Ruff must actually pass; then request review/merge. **No implementation of S1a occurred in this specification-only run.**

**Status of this specification session:** repository integration read-only inspection complete; relevant external source research completed to the extent reported; design/roadmap authored; no application code written, no test suite executed, no GitHub writes, no commit, no merge and no release. Unresolved technical facts are clearly gated rather than presented as test successes.
