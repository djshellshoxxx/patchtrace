# R7 / 01 — Advanced binary-analysis literature, concrete methods and feasibility

**Research date:** 2026-10-30. **Repository baseline:** main at a04f5a299a8d4afef023261e52e08d14678cf1e7.  
**Status:** primary-source methods assessment and synthetic exploration; **not** native Ghidra validation, real-binary security accuracy, or an accepted product architecture. Research-code tests and separate measurements are listed in [02-acceptance-and-roadmap.md](02-acceptance-and-roadmap.md).

## 1. Evidence discipline and reuse

Evidence levels:
- **DOC**: official API/vendor/CWE documentation inspected at a publicly available source.
- **PAPER**: method and reported experiments taken from an article's abstract/publisher record; figures belong to the authors, not PatchTrace.
- **REPO**: implementation and specification read on the stated PatchTrace baseline. Existing modules are not assumed fully accepted; some concurrent PRs remain unmerged.
- **LOCAL**: synthetic R7 experiments actually executed locally and recorded in the benchmark or test record.
- **PROPOSAL**: a suggested algorithm or integration. Not proven by available real binaries.
- **UNKNOWN**: missing validation, licensing, assumptions, timings, or artifact provenance.

Use the canonical \`program-ir/1\` representation, \`change-facts/1\` semantics, \`enrichment\` rules, \`intelligence/1\` caveats, existing \`interpretation\` citation validator and \`tools/calibration\` evaluation before proposing any new representation. Match identity, applicability, CVE correlations and security attribution are four **separate** decisions. A vendor says a CVE was fixed != binary evidence independently demonstrates the root cause.

## 2. Research source ledger — methods, inputs, evidence and limits

| Technique / primary reference | Algorithm and necessary data | Evidence of accuracy | Limits / PatchTrace feasibility | Software / redistribution licensing |
|---|---|---|---|---|
| Weiser, *Program Slicing* (ICSE 1981); Horwitz, Reps, Binkley, *Interprocedural Slicing Using Dependence Graphs* (TOPLAS 1990, DOI:10.1145/77606.77608) [PAPER] | Backward/forward program dependence from a selected program point/variable; system dependence graph with call/return and parameter linking for interprocedural flow. Requires dependence, call context, alias analysis, CFG. | Foundational algorithms, **not** binary patch-detection accuracy statistics. | Start intraprocedural + bounded call contexts. Missing aliases/indirect calls must yield unknowns. No external research code copied. | Scholarly publications, no code redistribution. |
| Ghidra official *P-Code Reference Manual* (2026-01-16); \`HighFunction\` and \`DecompileResults\` Java API [DOC] | Processor instructions -> raw P-code (register-transfer). Decompiled HighFunction -> normalized, SSA-like high P-code including \`MULTIEQUAL\` and \`INDIRECT\` operations; varnodes encode space/offset/size; operation source has sequence number. Requires analyzed GZF, correct versions and decompiler success. | Official API semantics only; **no** measured PatchTrace accuracy. | Natural low-cost opt-in source of data/control facts through existing external Ghidra worker. P-code reconstructed differently by compiler/decompiler analysis; sequence mappings can be many-to-one; varnode IDs cannot be blindly compared across artifacts. | Ghidra distribution is Apache-2.0, verify specific embedded components and notices before redistribution; no Ghidra source copied. |
| Gao, Reiter and Song, *BinHunt: Automatically Finding Semantic Differences in Binary Programs* (ICICS 2008, DOI:10.1007/978-3-540-88625-9_16) [PAPER] | Control-flow graph alignment, symbolic execution and theorem proving to identify changed behaviour despite structural noise. Inputs: corresponding binaries, CFG/lifter, path constraints. | Authors demonstrate **three case studies**; not a PatchTrace benchmark. | High solver and path-explosion cost; limited targeted later feasibility, not default engine. | Academic publication; no license inference for implementation. |
| Xu et al., *SPAIN: Security Patch Analysis for Binaries towards Understanding the Pain and Pills* (ICSE 2017, DOI:10.1109/ICSE.2017.49) [PAPER] | Changed traces (sequences of blocks), semantic screening of security/nonsecurity changes, taint analysis of patched function, motif summaries. Inputs: matched binaries/trace graph plus sources/sinks. | Author abstract reports five patch/vulnerability pattern families and several real-world cases, no reproducible PatchTrace numbers. | Changed-trace selection and taint-inspired unknowns promising; avoid deriving a vulnerability solely from a signature. | Publication; implementation licensing not verified. |
| Xu et al., *Patch Based Vulnerability Matching for Binary Programs* / BinXRay (ISSTA 2020, DOI:10.1145/3395363.3397361) [PAPER] | Map vulnerable/patched basic blocks, generate patch signatures as block traces; prune by patch semantics and compare traces. Inputs: two labeled binaries and candidate target binaries. | Paper abstract reports 479 CVEs across 12 projects, 93.31% accuracy and 296.17 ms/function. These are **author-reported** for a different vulnerability-match task and dataset, not root-cause/CWE accuracy. | Useful design ideas for patch-specific evidence; do not adopt detection claims without same-task, same-corpus replication. | Scholarly paper; don't copy unlicensed implementation. |
| Ghidra semantic evidence + PatchTrace \`unified/facts\` / \`enrichment/signals\` [REPO] | Existing machine-level deltas, guarded proof tiers and heuristic flags. \`program-ir/1\` already stores control/basic-block, instruction, call/ref and constants. | Current baseline's R1–R6 research still in progress; see respective PR records. | **Must reuse** these materials; R7 adds explanatory evidence, not second semantic verdict. | Repository LICENSE; Ghidriff is isolated unmodified component per SECURITY.md. |
| angr project (official symbolic execution docs) [DOC] | Lifts executable to an intermediate form, executes selected paths symbolically, supports constraints and state exploration. | Technical API documentation, no verified patch-pair acceptance data in this review. | Optional and bounded, resource-heavy; projects needing native binary execution are outside ordinary static mode. | Dependency and transitive redistribution licensing require independent review before adoption. |
| Z3 official theorem prover (Microsoft Research/GitHub) [DOC] | SMT feasibility or equivalence on a bounded, correctly specified logic formula. Requires bit-width, signedness, memory and path constraints. | Solver documentation, no PatchTrace model soundness claim. | A \`sat\` witness is only as sound as formula; \`unsat\` applies only to modeled paths; \`unknown\` / timeout are inconclusive. | MIT per official repository; optional experiment, no dependency added. |
| MITRE CWE root-cause mapping guidance [DOC] | Map *demonstrated underlying weakness* to accurate Base/Variant where supported, consult abstraction, mappings and warnings. | Authoritative taxonomy and mapping advice, not a binary model benchmark. | CWE candidate must remain hypothetical unless evidence connects input/state -> defective operation/guard -> risk. Vendor CWE is separate sourced metadata. | Terminology referenced; no CWE data or full taxonomy vendored. |

Primary URLs (not an exhaustive literature survey; read titles/abstracts and official API where cited):
1. Ghidra P-Code manual: https://ghidra.re/ghidra_docs/languages/html/pcoderef.html
2. Ghidra \`DecompileResults\`: https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html
3. Ghidra \`HighFunction\`: https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html
4. Ghidra \`Instruction.getPcode\`: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html
5. Horwitz/Reps/Binkley author-hosted abstract: https://research.cs.wisc.edu/wpis/abstracts/toplas90.abs.html
6. BinHunt author/publisher summary: https://ink.library.smu.edu.sg/sis_research/306/
7. SPAIN IEEE record: https://ieeexplore.ieee.org/document/7985685/
8. BinXRay ISSTA record: https://conf.researchr.org/details/issta-2020/issta-2020-papers/28/Patch-Based-Vulnerability-Matching-for-Binary-Programs
9. MITRE mapping: https://cwe.mitre.org/documents/cwe_usage/guidance.html
10. Z3 official repository: https://github.com/Z3Prover/z3
11. angr official symbolic overview: https://docs.angr.io/en/stable/core-concepts/symbolic.html

## 3. Concrete Ghidra high-P-code extraction experiment [PROPOSAL]

Existing \`src/patchtrace/unified/extract/ghidra_script.py\` supports GZF reuse and bounded optional C decompilation. Add an *isolated opt-in experiment* to that external-script boundary, not to the \`ProgramIR\` database contract initially. \`DecompileResults.decompileCompleted()\` and \`getHighFunction()\` are required checks; \`HighFunction.getPcodeOps()\` is inherited from \`PcodeSyntaxTree\`. Java API existence is documented; availability under PatchTrace's pinned Ghidra/pyghidra versions is **not** tested here.

Proposed per-side extraction sequence:
1. Verify input bytes SHA-256, \`ir_key\`, GZF SHA-256, Ghidra analysed state, language/processor and comparison run ownership; document whether symbols/options differ by side.
2. Select **only** a bounded list of matched functions with material/review/unknown verdicts, not every function by default. Cap pairs, operations, bytes, JVM heap and wall time.
3. Obtain an individual decompile result, abort on unsuccessful, timed-out, cancelled, or null HighFunction. Preserve original failure diagnostics with safe redaction.
4. Iterate \`getPcodeOps()\`, retaining opcode, fixed sequence reference, originating instruction address, operands (varnode space, offset, size), def/use and output, block identity and original function RVA. Use stable sorted ordering on source address/sequence, never on incidental Python object identity.
5. Normalize machine addresses to **RVA** only for verified in-image addresses; preserve distinct RAM / register / stack / constant / unique address spaces; represent external imports and unresolved pointers distinctly. Carry bit widths, sign/zero extension and constant widths. Do not treat two different varnodes as equal solely because textual names look alike.
6. Record \`MULTIEQUAL\` (phi) and \`INDIRECT\` side effects explicitly. A high-level value may have multiple reaching definitions or represent unknown memory alias effects. The emitter should include def/use IDs if validated, not manufacture a single definition.
7. Derive CFG and postdominators to establish **actual** control-dependence edges; a conditional jump being nearby is not proof that it guards a memory operation. Compare prior/newer on aligned blocks plus instruction evidence, noting missing/conflicted block matches.
8. Produce a size-limited, versioned **research sidecar** signed by input and tool hashes; validate it before use. Avoid replacing \`program-ir/1\`, \`ins/1\` or the existing proof engine.
9. Run positive and negative fixtures under Ghidra on Windows and Linux; measure disagreement with assembly-level changed facts, use a blind expert label set, and reject anything that silently hides uncertain flow.

API mapping subtleties to test:
- High P-code is an analyzed transform, not a byte-for-byte annotation of each original machine instruction.
- Raw P-code has a processor instruction sequence; HighFunction operations may be folded, reordered or absent. Some operations may carry ambiguous original-source correspondence: retain unknown, not a fabricated precise line.
- Condition polarity, signedness, integer widths, branch target reordering, 64-bit overflows and decompiler synthetic variables matter.
- Calls can have implicit memory/global side effects not captured by simple output-value SSA.
- SLEIGH language/compilers and PDB/symbol policy may affect decompilation; see unified spec 03 for existing provenance contracts.

## 4. Bounded slicing algorithm and what the current code does **not** prove

The local research-only \`tools/research/r7/slicer.py\` accepts **caller-supplied** synthetic operation facts \`(uid, rva, opcode, inputs, output, controls)\` and a caller-declared artifact hash/function RVA. It builds a **within-supplied-graph**, forward or backward def-use/control walk, caps at 4096 input operations / 4096 visited / depth 64, and reports truncated frontiers. It does not parse or verify binaries, prove real control dominance, model aliasing, or handle path feasibility.

Backward criterion: selected changed operation/site, collect unique SSA operand definitions recursively plus explicit control predecessors. A missing operand definition or duplicate definition is an **unknown**, never treated as a constant. Record external parameters as boundaries. Forward criterion: uses of produced values and operations supplied as control dependents. Include caller-specified provenance and original RVAs but do not treat them as authenticated.

Conservative unknowns: \`memory-alias:<uid>\`, \`call-effects:<uid>\`, \`indirect-target:<uid>\`, \`indirect-effect:<uid>\`, \`missing-def:<var>\`, \`multiple-defs:<var>\`, \`missing-control:<uid>\`, \`unknown-op:<opcode>:<uid>\`, node/depth caps. The status string \`bounded-within-supplied-graph\` is **not** a statement of complete real-world dependence coverage. The graph currently lacks a postdominator-derived control model, interprocedural data dependencies, symbol-to-source mapping and authenticated persisted citations.

Validation path:
- First: real operations extracted from target pairs, consistency with assembly references.
- Second: compare bounds-check slices, compiler-noise controls, aliasing/call unknown rates, function match errors.
- Third: prototype *bounded* interprocedural summary (call depth <= 2 initially, documented budgets), with callsite context, global reads/writes and unresolved effect sets. No unrestricted whole-program analysis.

## 5. Patch pattern root-cause method

A pattern hit is **not** a vulnerability finding. A rule candidate requires all of: (a) a machine-grounded changed comparison/operation, (b) identity and orientation of older/newer pair, (c) control/data link from relevant input/state to an actual source and sink, (d) new/old guard condition reachability, (e) negative controls that rule out incidental refactoring. Evidence should distinguish newly-added checks, tightened conditions, hardened error paths, removed unsafe calls, changed return-value handling and lifetime changes.

Example candidate: new \`length <= capacity\` branch reaches a potentially length-dependent write. A complete candidate needs comparison width and signedness, def-use of \`length\` and \`capacity\`, actual control dependence over that write, proof that failure path avoids the write, and an old/new counterpart comparison. If \`length\` originates from a literal or known-safe parameter the rule must not infer untrusted input. If control dependence is absent, report \`unrelated-guard\` unknown/negative, not a security fix.

Use the existing \`enrichment/signals.py\` and \`intelligence/hypotheses.py\` taxonomies as starting *hints*. The next file specifies structured positive and negative fixtures per class, with and without compiler transformations.

## 6. Cross-function reasoning [PROPOSAL]

Input is the existing \`program-ir/1\` call/refs graph. For a changed caller/callee site, follow bounded adjacency only, preserving \`run_id, side, function_rva, callsite_rva, target_kind, target_state, depth\`. A resolved direct call may contribute a return-value check or argument propagation if its parameter conventions are validated. Unknown indirect targets, callbacks, imported external functions, exception edges, recursive SCCs, shared globals, and unresolved aliases must contribute limitations. Expansion limits: <= 2 call hops to begin, <= 32 functions, <= 256 callsites, <= 4096 operations, <= 2 seconds CPU (proposed; measure and tune), deterministic ordering. Compare a *matched* old/new callsite separately; never equate reordering with a security change.

Success criterion is measured incremental analyst-relevant evidence coverage (guard-source-sink explanation and human reviewer time) minus added false positives, complexity and runtime. No interprocedural prototype was executed in this checkpoint.

## 7. Optional symbolic feasibility [PROPOSAL]

Prefer a pure bounded SMT differential *query* over verified SSA predicates using an optional Z3 developer dependency. Formulate a path-limited predicate: given same explicit input state and modeled side effects, can old/new branch outcomes differ? Use exact bitvector widths, signed/unsigned operators, overflows, memory separation, loop unrolling limits, guard dominance and record assumptions. A solver \`sat\` result is a witness *within the model*, not exploitability; \`unsat\` is not full program equivalence unless coverage/formula are complete; timeout/\`unknown\` are inconclusive. Store solver version and normalized formula digest, cap constraints and wall time, never execute the target binary. Defer angr/Triton and path-explosion-heavy differential engines until this limited model demonstrates benefit. **No symbolic native experiment executed yet.**

## 8. Remaining research uncertainties

- Actual Ghidra version compatibility and fidelity for high P-code extraction, loss of source-address traceability and GZF import.
- Whether decompiler-derived SSA produces repeatable graph IDs under PDB changes, options and minor Ghidra updates.
- Alias summaries and call effects required for a small useful slice, plus control postdominator correctness.
- Whether pattern precision/recall generalizes beyond synthetic patches to real MSVC/clang-cl/MinGW Windows PE samples.
- CWE granularity agreement with independent expert review.
- The need for licensed cross-binary research code versus independent implementation.
- Real Windows process/memory impact, network/provider privacy and error handling.

All these must be explicitly recorded as **UNKNOWN** until verified; the mere existence of the documented API is not a measured product capability.
