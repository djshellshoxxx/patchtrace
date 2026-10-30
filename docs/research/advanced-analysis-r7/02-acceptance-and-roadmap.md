# R7 / 02 — Experiment results, acceptance design, engineering roadmap and unresolved gates

**Checkpoint:** 2026-10-30. **Implementation basis:** `research/r7-advanced-binary-analysis-20261030` from main `a04f5a299a8d4afef023261e52e08d14678cf1e7`. Research only; no product contract or materiality decision was changed.  
**Read with:** [README](README.md), [methods](01-literature-and-methods.md), [synthetic-benchmark.json](synthetic-benchmark.json), `tools/research/r7/slicer.py`, `tools/research/r7/patterns.py`, `tests/test_r7_slicing.py`, `tests/test_r7_patterns.py`.

## 1. What actually executed — versus what remains a hypothesis

| Item | Verified run / state | Limits |
|---|---|---|
| Synthetic ephemeral P-code-shaped bounded def-use/control slicer | **IMPLEMENTED** `tools/research/r7/slicer.py` | User-supplied control edges and hash fields have syntactic validation, **not** Ghidra/artefact provenance authentication |
| Synthetic unit tests | **40 passed**, **0 failed**, **0 skipped**, Linux CPython 3.13.5, `python3 -m pytest -q tests/test_r7_patterns.py tests/test_r7_slicing.py` | 27 slicing + 13 pattern tests on tiny hand-authored graphs; no real PE/native Ghidra |
| Syntax check | `python3 -m compileall -q tools/research/r7 tests/test_r7_slicing.py tests/test_r7_patterns.py tests/test_r7_patterns.py`: passed | Not a full-project Ruff/Pytest gate |
| Synthetic guard-to-sink motif prototype | **IMPLEMENTED** `tools/research/r7/patterns.py`; `R7-STRUCTURAL-GUARD-DELTA/0` outcomes `candidate` / `not-observed` / `inconclusive` | Caller-provided old/new matching, control edges and SSA labels; no CWE, exploitability or security proof |
| Static trace / generator caps | Tests include memory/call/indirect unknowns, missing/ambiguous definitions, missing controls, bounded depth/node frontier, unknown opcode, duplicate IDs, invalid scope, generator cap, cancellation | Does not prove actual coverage or correctness of unobserved dependencies |
| Synthetic benchmark | **Executed**; data and harness committed; see below | No baseline full PatchTrace run; no measured security detection |
| P-code native extractor | **NOT EXECUTED / not implemented** | No analyzed GZF/native Ghidra environment in this research execution |
| Real binary patch precision/recall | **NOT MEASURED** | Requires expert-labelled corpus R1 and cross-compiler R3 |
| Interprocedural call/alias summary | **NOT IMPLEMENTED** | Existing `ProgramIR` has callgraph, but not authenticated effects/param mapping |
| Rule taxonomy & CWE mapping | 14-category **research-only** taxonomy; one **synthetic structural guard motif** implemented, no CWE classifier | No claimed real-binary accuracy |
| AI interpreter/model benchmark | **NOT EXECUTED** | Local/remote provider consent, models, known-answer annotations required |
| Symbolic solver | **NOT EXECUTED** | Limited feasibility memo only, no Z3 integration |
| Full Linux/Windows CI | **NOT VERIFIED** | Must inspect exact PR head results; local environment lacks full checkout |

### Local red-green observations

The original 25 tests passed for the first isolated prototype. Added failing regression tests for (1) unbounded `list(ops)` generator materialization and (2) missing unknown flags for `INDIRECT`/unrecognized opcodes. Changed implementation to read at most `MAX_INPUT_OPS + 1` elements and disclose unknown operation/effect classes. Slicer subtotal **27/27 passed**. An additional red-green pattern case caught a qualified new guard incorrectly ignoring a second unresolved control; it now abstains. Pattern subtotal **13/13 passed**; combined **40/40 passed**. These verify intended local behavior only; baseline native Ghidra and integrated Windows tests remain unrun.

### Reproducible synthetic benchmark

Run from repository root (requires Python >=3.12, no network, no paid provider):
```bash
python3 -m pytest -q tests/test_r7_patterns.py tests/test_r7_slicing.py
python3 -m tools.research.r7.bench
python3 -m compileall -q tools/research/r7 tests/test_r7_slicing.py
```

| Synthetic operations | Slice sites | Input-site reduction | Median of 30 (ms) | p95 (ms) | Slice-only peak tracemalloc |
|---:|---:|---:|---:|---:|---:|
| 128 | 8 | 93.75% | 0.0562 | 0.0709 | 35.74 KiB |
| 1,024 | 8 | 99.22% | 0.3861 | 0.4314 | 262.70 KiB |
| 4,096 | 8 | 99.80% | 1.8314 | 2.3387 | 1,036.01 KiB |

Platform: Python 3.13.5, Linux-6.18.57-x86_64-with-glibc2.41. Every input consists of independent eight-operation `INT_ADD` chains using uniquely named SSA variables. The selected seed is the final operation; the expected backward slice consists of eight sites. Graph construction happens **outside** timed and traced region. `median_ms` measures one whole slicing call including its graph-index build but not synthetic operation creation; peak tracemalloc is from one call, not process RSS or native Ghidra heap. Cache/warmup, CPU affinity, background noise and cross-machine replication were not controlled. These numbers must never be reported as a security-detector speed/accuracy metric. The source JSON preserves the observed values.

## 2. Candidate pattern taxonomy and fixture specification

Every rule is a **candidate** hint until validated against both old/new binary behavior, source/state and sink evidence. Reuse existing `enrichment/signals` BND/INT/OVF/VAL/ERR/SIZE/SCRUB and `intelligence/hypotheses` rules without changing their conclusions. The following *unimplemented* root-cause constraints are the extra research dimension.

| Candidate pattern | Machine-evidence minimum | Positive fixture construction | Negative / compiler-noise fixture |
|---|---|---|---|
| Bounds check | New/tightened predicate, data link from index/len to read/write, control dependence from predicate to sink, safe failure edge | Untested length-check before copy, changed-boundary comparison | Check guards logger or unrelated variable; length known constant; old code already guards |
| Integer overflow / underflow | Exact width/signedness, checked arithmetic and constrained sink size/index | Multiplication overflow check before allocation | Same arithmetic with no sink; compiler switch of signed compare; safe constant range |
| Null pointer | Predicate tests pointer-producing value, dereference dominated on success path and blocked on failure | Checked allocator result before field load | Defensive check after dereference; dead branch; failed match |
| Authentication | State/credential decision changes with verified authenticated/unauthenticated path distinction | Failure branch added on credential check | UI text/telemetry branch, allowlist change without proven auth effect |
| Authorization | Subject/object/action policy condition linked to access sink | Role/state condition added before privileged operation | Logging/feature-flag change, renamed ACL helper |
| Allocation size | Allocation argument derived from bounded length/count, corrected overflow/size relation to later access | Checked size arithmetic before alloc-copy | Reallocation for performance only, no unsafe old path |
| Length validation | Input field def-use flows to access length or parser offset | New early reject for length > buffer | Input length only used for stats; unrelated zeroing |
| Error-path hardening | Return code checked before use/retry/cleanup path | Explicit failure return after failed parse | Branch reordering with identical effect; no use-after-failure |
| Unsafe API replacement | Equivalent operation and parameter semantics, unsafe destination/length discipline removed | Unbounded copy replaced by length-limited call with validated cap | Wrapper API swapped but same unchecked length |
| Resource lifetime | Producer/acquire, all uses, release and alias/callback reachability ordering | Release moved after last use in all paths | Unrelated cleanup/RAII refactor; alias may remain (unknown) |
| Race mitigation | Verified lock/atomic synchronization around shared state and all relevant paths | Lock around read-modify-write with unlocks | Lock only surrounds logging; a race still exists on another path |
| State validation | State-machine transition + invalid transition rejection before sensitive action | Guard before operation requiring initialized state | State renaming or diagnostic-only check |
| Input sanitization | Tainted input to sensitive parser/command/format sink; verified transformation | Encoding/validation before sink | Formatting applied only to output; untrusted source never reaches sink |
| Crypto parameter correction | Relevant algorithm/mode/key-size/IV validation site, security property and source provenance | Weak mode disabled or key length validated | Changed constant controls unrelated timeout or test fixture |

For **every** category, the data owner must supply at least:
- 1 obvious positive and 2 hard negatives (unrelated guard / refactor) in C, compiled as x64 PE by supported toolchains; preserve source labels and binary SHA256/flags;
- one positive and one negative with changed compiler optimization or layout noise, plus same-source A/A controls;
- one intentional unresolved alias/indirect-call variant, which must produce abstention;
- independently reviewed labels for source, guard, sink and candidate CWE, **not** just a known CVE tag;
- older/newer orientation, function correspondence and exact instruction source sites;
- tests for different signedness, 32/64-bit overflow, merged basic blocks, inlining, and compiler/CRT changes where applicable.

Proposed future rule minimum: semantic delta + confirmed control/data link + reachable sink + unchanged/negative controls cleared; missing any mandatory evidence = candidate with unknown, **not** "confirmed fix".

## 3. CWE mapping rules and examples

MITRE source: https://cwe.mitre.org/documents/cwe_usage/guidance.html and https://cwe.mitre.org/documents/cwe_usage/quick_tips.html. Prefer a Base or Variant weakness **when its own mapping notes allow** and evidence supports precision; otherwise class-level if allowed or abstain. A symbolic comparison with no data-flow to sink does not identify a root cause.

| Observed support (if genuine) | Candidates requiring extra proof | Abstain / alternative |
|---|---|---|
| Indexed **read** beyond buffer with missing bounds | CWE-125 may fit; distinguish CWE-126 if actual buffer over-read context supports | A new check alone can be ordinary defensive coding |
| Indexed **write** beyond object end | CWE-787 may fit; distinguish CWE-119 breadth and CWE-129 invalid index if most accurate mapping | No memory write / destination size unknown |
| Unsigned integer wrap in checked size arithmetic | CWE-190 if overflow is causal; CWE-191 if arithmetic **underflow** causal | Underflow vs overflow is not inferred from opcode alone |
| Null pointer dereference follows a failed lookup | CWE-476 if dereference path proven | No reachable null path |
| Identity check missing/incorrect | CWE-287 only when authentication proof is present | Denial changes do not prove authentication |
| Authorized-identity access-policy bypass | CWE-863 only with verified policy and access sink | Distinguish missing auth vs incorrect authorization; unverified role state |
| Unsafe resource use after release | CWE-416 if lifetime/reachability proved | Cleanup change with no possible later use |

Each mapping output must preserve: candidate CWE; hierarchy specificity; MITRE mapping permission verified; physical evidence (run/side/hash/RVA/operation/guard/sink); alternatives; counters; distinct `origin = binary-derived` versus `origin = advisory-claim`; and explicit `insufficient-evidence` state. External advisory CWE is not a discovered binary CWE. **No R7 CWE classifier was run on real binaries.**

## 4. Explainable finding contract proposal — reuse first

Do **not** introduce a parallel permanent `finding` or `intelligence/1` contract. Add a research-only **read model** that can be mapped to existing `UnifiedMatch`, `ChangeFacts`, persisted evidence context and `IntelligenceReport`; propose an additive version only after owners and tests approve. Required fields for a later contract:

```text
finding_id                       stable derived hash, versioned recipe
comparison_run_id                persisted owner, not arbitrary user text
older/newer_artifact_sha256      exact validated artifacts
older/newer_function_rva         selected matching identity, may be groups
change_fact_row_id               match under same run
semantic_delta_refs              exact instructions + change-facts channels/proof
source_sink_control_refs         signedness, width, path, callable origin
evidence_ids                     IDs validated by existing evidence resolver
unknowns                          aliases, indirect calls, unsupported opcodes, data gaps
rule_candidates                  stable rule ID, supported premises, contradiction list
cwe_candidates                   explicit basis and specificity, no implied certainty
ai_hypotheses                    structured untrusted proposals, provider/model+prompt hash
analyst_review                   separately authenticated analyst-only state
toolchain                        Ghidra/pyghidra/Java/IR and tool versions + digests
analysis_limits                  caps reached + incompleteness status
schema_version                   versioned format with migration/degradation semantics
```

Acceptance: immutable source facts, deterministic JSON canonicalization, owner-consistent typed IDs, no path traversal or unbounded text, exact hash confirmation, no counterevidence elision, deterministic UI navigation to the actual binary and corresponding lines, stable behaviour on missing source. A model response **must not** update `UnifiedMatch`, materiality, severity, CVE association, origin, or analyst review.

## 5. AI explanation fidelity protocol (planned; no provider runs)

Create a fixture set stratified by patch class, real/synthetic label, compiler and binary family. Include deliberately adversarial copied text in strings, symbol names and decompiled C (prompt injection must be treated as data). Separate local Ollama and explicitly consented remote HTTPS provider; never silently upload proprietary target snippets.

Scoring per *claim*, not only entire paragraph:
1. Factual assertions about code reference one or more existing exact evidence IDs and owner/run/RVA valid in both context and persisted source.
2. Cited evidence actually entails the stated observable change; unsupported/mis-scoped claims fail even if the cited ID exists.
3. Structured output passes existing provider/interpretation schema; no extra fields, malformed JSON, injected URLs or invented citations.
4. Candidate CWE follows the MITRE hierarchy and cannot silently adopt advisory metadata as newly recovered binary evidence.
5. States alternatives/counterevidence and unknowns, does not convert solver timeouts or partial slices into certainty.
6. Separate *recall* of human-labelled root-cause aspects from fabricated details; score omitted major changes and overclaiming.
7. Verify reproducibility at fixed model revision/config/prompt; repeated model agreement alone is not validation.
8. Report latency, memory, token counts, outbound bytes/endpoints, cancellation and cost; remote data transmission only via existing explicit preview/consent.

Report metrics with exact denominators and Wilson/confidence intervals where appropriate: **citation existence** (# valid evidence references / # attempted), **citation entailment** (# supported assertions / # factual assertions), **unsupported-claim rate**, **CWE accuracy only on eligible labeled examples**, **abstention coverage**, **false security attribution rate**, **counterevidence recognition rate**, **reviewer time**. Always record the model, version, temperature, exact context hashes, local/remote transport and consent. Provisional design goals (not adopted acceptance thresholds): zero fabricated evidence IDs; 100% correct run ownership; no unsupported vulnerability-certainty language. No model accuracy percentages are currently available.

### Root-cause reasoning prompt contracts (proposed)

Fact extractor produces only: `observations[]` with evidence IDs and old/new side, `assumptions[]`, `unknowns[]`, `candidate_hypotheses[]` (evidence references, counterevidence, alternative), `verification_tasks[]`. Reject claims about exploitability, vulnerable CVE or security fix without independently verified support. Store model text as a failed or hypothetical result until deterministic evidence verification succeeds. Distinguish *analyst conclusion* in a separate owner-controlled step.

## 6. Comparative evaluation matrix

Use `corpus/ours/cwe-patterns`, R1 known-answer and R3 compiler-noise matrix, R2 matching uncertainty, R4 advisory provenance, R5 calibration holdouts. Never use the same lineage/family or compiler-repacked adjacent pair in both training and locked evaluation. A/A and cross-opt same-source fixtures are **negative** security controls. Rejected matches cannot contribute positive semantic evidence.

| Gate | Measure / denominator | Baseline | Prototype / accept requirement |
|---|---|---|---|
| Evidence site coverage | labeled guard/source/sink sites recovered / labeled eligible sites | current ProgramIR / unified findings | improve or show justified limits, no ownership errors |
| Pattern precision/recall | TP/(TP+FP), TP/(TP+FN) per family and compiler; report 95% CI | existing enrichment + human rule triage | beat baseline on locked holdouts without collapsing abstention |
| False positive attribution | declared security pattern on benign/noise/A-A controls / controls | existing rules | must not increase unboundedly |
| Crossfunction benefit | new authenticated guard/source/sink connections attributable to call context | same-function only | show nonzero verified gain at acceptable cost; unresolved calls abstain |
| CWE fidelity | right allowed MITRE weakness among **eligible expert labels** | advisory-only hypotheses separate | accuracy with uncertainty/abstention, not CVE metadata leakage |
| AI factual fidelity | entailed factual assertions / all factual assertions | existing evidence-grounded interpretation | no invented IDs; report hallucination/omission/cost |
| Native compatibility | Ghidra 12.x variants, Windows / Linux, PDB/symbol policy | current GZF extraction & C decompile | full native fixture success + meaningful failure taxonomy |
| Performance | per-function p50/p95/p99 time, peak resident memory, disk bytes, JVM startup, cancellation latency | current unified pipeline | bounded and agreed by owner; baseline comparisons use same hardware |
| Reproducibility | identical canonical outputs on identical input hashes, flags and tool versions | existing manifest/IR key | exact hash and determinism or explicit measured drift |
| Hostile input / privacy | malformed op graphs, oversized IR, invalid paths, untrusted advisory/LLM text | current security suite | no expanded attack surface, no silent external transfer |

A benchmark **without labeled real binary truth** must never be counted as pattern precision/recall or confidence calibration. The current synthetic 8-site reduction is a structural property of the fixture, not validation that 99.8% of real binary instructions are irrelevant to a vulnerability.

## 7. Production integration work order and exit gates

**P0 — contract and ownership review:** Recheck all R1–R6 draft heads; read exact changed files on their PRs; confirm their integration/accepted test fixture versions; do not land spec changes into concurrent owners' files. Define new R7 research-only versioned sidecar, test scopes and provenance, get engineering review.

**P1 — native P-code extraction:** Add opt-in external Ghidra script mode, version/architecture/hash checks, strict limits and typed failure. Compare output from a pinned small analyzed GZF pair on Windows and Linux; record negative controls and unmatched functions. Store raw high-pcode op data separately. Keep production toggle off. Native extraction **not yet done**.

**P2 — authenticated graph + slicing:** Build SSA input mapping and concrete postdominator control-dependence on CFG; verified program/IR owner IDs. Separate unknown RAM alias and opaque call effects. Use R7 slicer as learning prototype; change or replace it only after tests show deficiencies. Prove no edges cross function/artifact/run ownership. Native validation **not yet done**.

**P3 — pattern prototypes:** The synthetic guard-to-memory-operation candidate exists and has 13 focused regression cases, but does not establish control dominance or a security fix. Extend with (a) proven bounds/length vs memory access and (b) arithmetic width/overflow vs allocation/copy; require real positive/hard negatives, source controls and compiler-noise trials. No validated production classifier exists.

**P4 — bounded cross-function analysis:** Include direct call argument/return checks for 1-2 hops, record imported and indirect unresolved edges, evaluate incremental true explanation coverage. Not done.

**P5 — CWE and AI:** Build expert blind labels and independent CWE-mapping audit, strictly evidence-grounded AI interpretation with citation entailment, local provider first. Do not call out-of-repo paid providers automatically. Not done.

**P6 — optional solver spike:** Only if P2-P5 reveal a measurable question P-code alone cannot answer. Keep Z3 optional, no target execution, strict resource cap, SAT/UNSAT/UNKNOWN distinction. Not done.

**P7 — staged product acceptance:** exact-head Linux full offscreen Pytest, Ruff, synthetic & real Ghidra, Windows native Ghidra+package, compatibility across at least required toolchains, security regression/consent, expert review; merge docs/research independently if permitted, production only on documented benefit. Not done.

**No production integration recommended at this checkpoint.**

## 8. Technique decisions (per supplied R7 classification, provisional)

| Technique | Current research decision | Evidence / rationale |
|---|---|---|
| Bounded synthetic def-use slicing | **PROMISING — MORE VALIDATION REQUIRED** | 27 local tests + bounded synthetic benchmark; not native/control dominance/alias proof |
| Synthetic guard-to-sink motif | **PROMISING — MORE VALIDATION REQUIRED** | 13 local positive/negative/abstention tests; declared graph/control edges only, no security classification |
| High-P-code semantic delta extraction | **PROMISING — MORE VALIDATION REQUIRED** | Official `getHighFunction`/PcodeOps API exists, no verified extraction against PatchTrace GZF yet |
| Deterministic guard-to-sink patterns | **PROMISING — MORE VALIDATION REQUIRED** | Patch motifs supported by prior literature/existing hints; no R7 detector/precision measures |
| Bounded cross-function context | **PROMISING — MORE VALIDATION REQUIRED** | Existing call graph; no verified context/alias semantics or result yet |
| Automated CWE root-cause classification | **DEFER** | MITRE requires cause-specific evidence; no trusted labeled validation, vendor metadata risk |
| Optional symbolic execution / solver | **DEFER** | No proof of incremental value/cost, path feasibility not tested, hard resource constraints |
| AI-assisted explanations beyond existing contract | **DEFER** | Existing evidence validation; missing known-answer human benchmark and privacy evaluation |
| Unbounded whole-program analysis or autonomous exploit creation | **REJECT** | Outside R7 scope / product resource budget and acceptance requirements |

None is **READY FOR INTEGRATION**. Labels are decisions based on current limited evidence, not a negative scientific verdict on the technique itself. Preserve negative results.

## 9. Reliability / security gate

- **Input:** untrusted PE, GZF, JSONL, SQLite, advisory, C decompile, symbol names and model output; strict structural/version/hash/owner validation before use; no direct execution of target binary.
- **Resource:** byte and record caps before materializing lists; read bounded streams; external Ghidra child isolation, cancellation and timeouts; check processes/temporary dirs; bound decompiler calls, call depth, slices, model contexts and response bodies. Python's `tracemalloc` is not process RSS; separately measure Java RSS.
- **Persistence:** no write of unverified sidecar into `ProgramIR`; preserve previously committed outputs on error; atomic temp replacement and digest; older incompatible schema reads must fail closed and not corrupt project.
- **Execution:** no model-suggested commands, no automatic uploads, no external target execution, no unaudited dynamic instrumentation. Local only by default; explicit remote request preview and consent.
- **Output:** evidence references are immutable owner-checked paths/IDs; escape HTML/Markdown; never trust a prompt-injected binary string as instructions; prevent misattribution from fabricated function labels/addresses.
- **Licensing:** no GPL Ghidriff copied into product; no borrowed research implementation without license check; optional tools remain separate until review.

## 10. Deliverables checklist and checkpoint status

| Requested R7 deliverable | Current |
|---|---|
| 1 literature review | **Draft research delivered**, primary references and limitations |
| 2 existing inventory | **Delivered**, baseline main and R1–R6 owners |
| 3 P-code feasibility | **Design/official APIs delivered**, native probe still open |
| 4 slicing research and prototype | **Synthetic prototype delivered**, native missing |
| 5 patch-pattern taxonomy | **14-category design plus synthetic guard-to-sink motif**, native fixtures and broader detectors missing |
| 6 cross-function evaluation | **Research/design only**, no measured improvement |
| 7 optional symbolic feasibility | **Memo delivered**, solver experiments pending |
| 8 AI explanation benchmark | **Evaluation protocol delivered**, no model runs |
| 9 CWE evaluation | **Mapping policy delivered**, no labeled test run |
| 10 evidence-backed findings contract | **Additive read-model proposal**, contract not accepted |
| 11 prototype implementations | **Synthetic bounded slicing and guard-to-sink motif**; native extractors and other types open |
| 12 comparative benchmark | **Synthetic throughput only**, baseline comparison missing |
| 13 resource measurements | **Local tracemalloc/time only**, no native Java/Windows RSS |
| 14 security/reliability review | **Threat/controls design**, native adversarial run missing |
| 15 production integration roadmap | **Delivered**, with staged ownership gates |
| 16 update root docs/qa.md + tasks/todo.md | **tasks/todo.md updated** with isolated R7 section; root `docs/qa.md` remains protected because connector truncates source and R3 PR #129 edits it; R7 `qa.md` holds full record |
| 17 limitations/unresolved questions | **Delivered**, above and R7 README |
| 18 GitHub verified PR | **Draft #134 opened**, exact-head remote CI not yet accepted |

## 11. Next executable tasks and blockers

- Reconcile research PR heads and changes after main moves; preserve all active R1–R6 work.
- Confirm native execution environment (analyzed GZF or reproducible source->PE/GZF pipeline) and external Ghidra/pyghidra versions. Create explicit P-code extraction spike with recorded hash, timing, RSS, JVM failure modes.
- Construct an expert-labeled R7 fixture manifest with independent positive/negative controls across toolchains; calculate baseline first.
- Run native validation before changing product public contracts or UI.
- Inspect exact-head CI on draft #134; local no-clone environment supports only research-module Pytest/compileall.
- Preserve the root `tasks/todo.md` R7 section; coordinate root `docs/qa.md` with R3 owner, after safe full-file source retrieval. Update PR text and handoff. No force-push, no bypass of protection, no merge before review.

**Release/merge status:** prototype research is not a production engine change; R7 acceptance criteria are **NOT COMPLETE**. No vulnerability detection or CWE accuracy has been demonstrated.
