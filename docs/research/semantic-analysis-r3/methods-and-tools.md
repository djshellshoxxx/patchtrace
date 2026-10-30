# R3 methods and tool selection — evidence, assumptions, integration

**Checked 2026-10-30.** This note distinguishes (A) published/maintainer capability, (B) PatchTrace source code observed at baseline `a04f5a2`, and (C) a *proposed* integration. Capabilities are not proof that a specific version works with the current PatchTrace binaries. Production compatibility and peak resource numbers are **not established** without native paired-image benchmarks. Preserve existing SPEC-31 and licensing rules.

## 1. What “equivalence” means in this project

A program behavior claim needs an observation model. Let `P_old` and `P_new` be the two binary functions and `O(P,x,E)` an observation over input `x` and environment `E`: return value, memory writes, calls, exceptions, externally visible effects and possibly termination. Strict observational equivalence requires equal observations for **all** admissible `x,E`. No finite set of successful test inputs proves that claim. Proving a *bounded* formula under restricted path count, loop depth, memory model and call assumptions cannot imply universal equivalence.

Three useful kinds of evidence are not interchangeable:

- **Identity evidence:** byte-identical image and verified references under a known loader mapping, with required metadata. This is the scope of `UNCH/1`, not arbitrary source-language equivalence.
- **Named transformation proof:** the difference has a specific validated representation transformation, with mapped targets and appropriate EH metadata. This is `COS-ADDR/1` / `COS-LAYOUT/1`; `COS-PSEUDO/1` is lower-strength *decompiler-relative* and must be visually distinguished.
- **Semantic delta evidence:** a changed branch relation, constant, call target, data reference, memory operation or control-flow path, tied to an independent observation (`MAT-ANCHOR`). This is a change hypothesis backed by concrete channels, not necessarily a vulnerability.

**L1 vs L2:** Correspondence can be certain even where equivalence is false; never promote a unique BinDiff match to an unchanged verdict. Security attribution is a separate R4 chain (verified patch + affected build + evidence of changed behavior).

## 2. Method taxonomy and assumptions

| Family | Mechanism | What it can validate | Known failure / false-proof danger | R3 treatment |
|---|---|---|---|---|
| Relocation-aware instruction normalization | Compare exact instruction operands after identifying *located* relocation and RIP-relative fields | Known address displacement with identical target mapping | Masking constants or an unlocated field; a relocation symbol can change while bytes remain equal | Already in `unified/ir/operands.py`, `facts/datamap.py`; strengthen negative fixtures |
| CFG matching/isomorphism | Match basic blocks and outgoing edge types, preserve conditional polarity | A closed set of reorder/jump transformations | Equal block/edge counts but swapped then/else; irreducible graphs and switch targets | Existing `COS-LAYOUT/1`; do not weaken |
| Data-flow and SSA | Compare dependencies, register renames, values reaching writes/calls | Scheduling/register allocation under well-defined alias model | Unknown alias, volatile, atomic order, exception/flags/clobbers | Potential small scoped research channel, not a benign verdict yet |
| Program dependence graph & slicing | Isolate forward effects from changed predicate/value to output/call/write | Prioritizes guard/size changes, reduced solver search | Incomplete indirect-call/memory dependencies can hide observable effect | Candidate analyst evidence; cannot itself prove unchanged |
| Abstract interpretation & value-set analysis | Compute conservative overapproximated ranges/alias sets | Show a bound is reachable/unreachable **only within a sound modeled domain** | Widening imprecision; unsound loader/call assumptions | Optional early filter or evidence; cannot treat unknown as equivalent |
| Dynamic/symbolic execution | Lift instructions, explore paths and compare expressions | Counterexample *under the modeled states*; bounded equivalence under clear constraints | Path explosion, alias/external effects, unsupported SIMD/FP/SEH, timeouts | Feasibility study only, optional capped worker |
| SMT refinement/translation validation | SMT query for differing output/refinement of two SSA bodies | Exact or bounded expression semantics for supported IR | IR mismatch, poison/undef/UB, model simplifications, solver unknown | Small targeted SSA/P-code proof experiment |
| Decompiler pseudocode diff | Canonicalize recovered high-level code | Human-friendly change localization, literal and operator anchor | Unsound if decompiler omits side effects, prototype args, unseen metadata | Existing C6 `COS-PSEUDO/1` is visible and marked relative |
| Stochastic similarity/ML embeddings | Rank candidate matches | L1 ranking, change triage | Learned similarity has no proof obligation | Must not assign L2 benign verdicts |

### Soundness checklist for a single differential query

Record architecture and ABI, exact ISA flags, entry state and pointer aliases, stack alignment, calling convention/return registers, external calls, globals/TLS, memory permissions and updates, loader relocations, indirect branch policy, exception model, floating-point flags and rounding, volatile/atomic order, interaction with undefined behaviors, solver version and query digest. Distinguish **SAT counterexample**, **UNSAT under explicit bounds**, and **UNKNOWN / timeout**. Only SAT with a validated model supports a witnessed difference. A timeout does not establish equivalence.

## 3. Primary-source tool assessment

Versions are deliberately *not* inferred from an upstream `master` page. The “version” column is the version of documentation or the pin that this study can actually identify; check release artifacts before production use. Architecture listings are the tool's published scope, not complete coverage of every opcode/Windows subsystem. Runtime estimates are qualitative **expectations**, not measured performance.

| Candidate | Algorithm / inputs | ISA and offline Windows fit | License & constraints | Expected integration/decision |
|---|---|---|---|---|
| **Ghidra P-code / High P-code** | Register-transfer IR, per-ISA raw P-code; decompiler HighFunction has SSA-like expressions, MULTIEQUAL etc.; feed analyzed program database with typed instruction and data context | Ghidra is multi-architecture; PatchTrace's **supported product** remains PE AMD64. Ghidra pinned runtime external to standalone; offline if installed locally | Apache-2.0 primary license, secondary license inventory needed; Java/JDK/Ghidra external | **HIGH priority / medium complexity**: add a bounded *extraction-only* P-code evidence record to existing `ProgramIR` or opt-in sidecar after spec/schema review; no new mandatory engine |
| **BinDiff 8** | Unique structural signatures and graph matching; callgraph/CFG propagation, function correspondences; input analyzed BinExport files | Ghidra/IDA exporters and external tool; can operate offline; Win environment depends on installed exporter/tool | Apache-2.0; existing `unified/sources/bindiff.py` evidence remains external | **Already L1 source**. Do **not** treat BinDiff similarity/confidence as semantic proof |
| **Ghidriff** | Ghidra-based diff and decompiler text, match types and code. PatchTrace already consumes it | Offline external Python/Ghidra runtime subject to local symbol mode and native verification | GPL-3.0 external component; no copied code | **Existing baseline**, preserve raw outputs and pin; C6 provenance; real-version drift tests |
| **Diaphora 3.x** | IDA/Hex-Rays function attributes, graph matches, pseudocode/microcode, heuristic ranking; previously exported SQLite | Requires supported IDA for producing databases; optional SQLite import can be offline; not default Windows alpha runtime | AGPL-3.0 current; no copying into proprietary/incompatible parts; commercial IDA dependency | **Already optional research**; preserve separate evidence source, never semantic proof by similarity; coordinate #100 |
| **Rizin RzIL / ESIL** | RzIL models instructions as typed semantic expressions (successor of weaker ESIL) and can support emulation; `rz-diff` is currently weak evidence | Rizin multi-architecture, command-line/offline; Windows supported by project, exact tool build must be verified | LGPL-3.0 with component notices | **LOW–MEDIUM** as a parallel checker. Do not use `rz-diff` Levenshtein-like result as a benign classifier |
| **angr / VEX / Claripy / pypcode** | Loader CLE, PyVEX/pypcode lifters, CFG/slicing, symbolic state with Claripy solver; input binary or constrained function | Published multi-architecture; PE loading exists, but accurate Windows environment models are separate work | BSD-family license for angr; transitive dependencies require SBOM | **MEDIUM research, HIGH production integration cost**: optional Linux research worker; no mandatory Windows dependency |
| **LLVM IR & Alive2** | LLVM SSA refinement checker/translation validation over source and transformed LLVM IR; loop bounding and SMT; *not* a generic lifted-PE equivalence checker | LLVM IR-centric cross-platform; source/LLVM provenance needed. Not directly feed two arbitrary Ghidra function bodies | Project license and LLVM/Z3 toolchain must be reviewed at pinned tag | **Useful methodological oracle** for compiler-only source-generated fixtures; **not** in product pipeline |
| **Z3** | SMT bitvector/array/formula validity and satisfiability; requires fully specified semantics | Can run locally on Windows; solver library itself is multi-platform | MIT license; version-pin, runtime/cancel/CPU limits | **Optional bounded backend**, can disprove expression equivalence for supported fragments; zero benefit without sound lifting |
| **Triton** | Dynamic symbolic execution, ASTs and taint, x86/x64/ARM/AArch64/RISC-V models; user supplies instruction stream/state | Docs show Windows support; accurate function extraction/relocation/runtime assumptions remain custom | Apache-2.0, dependencies (Capstone/solver) | **Medium–low priority**, high ABI/runtime modeling work; use as research comparator, not mandatory |
| **BINSEC/Rel** | Relational symbolic execution for binary constant-time / secret-erasure properties under explicit path and memory models | Old extension README notes x86-32-era limitation; repository is no longer maintained and functionality moved to main BINSEC. Do not promise x64/PE native compatibility | Main/tool licensing and build chain must be verified independently | **Method reference**, not proposed PatchTrace integration |
| **BinHunt (Gao et al., 2008)** | CFG correspondence, symbolic execution and theorem proving for patch semantic differences | Historical proof of feasibility on case studies, not a currently supported Windows drop-in | Paper; software licensing/version unspecified | **Literature reference**, not an implementation dependency |

**Source anchors and reproducibility:**

1. Ghidra P-code reference (2026-01-16 page): https://ghidra.re/ghidra_docs/languages/html/pcoderef.html ; instruction semantics https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html ; Ghidra license https://github.com/NationalSecurityAgency/ghidra/blob/master/LICENSE
2. BinDiff official concepts: https://github.com/google/bindiff/blob/main/docs/concepts.md ; project/licensing https://github.com/google/bindiff
3. Ghidriff source and current pinned version (verify project pin rather than upstream `main`): https://github.com/clearbluejar/ghidriff ; PatchTrace `tools/backend_pin.json` and `docs/specs/unified-engine/06-adapters.md`
4. Diaphora official README and licensing: https://github.com/joxeankoret/diaphora ; upstream feature list and AGPL-3.0 license described there.
5. Rizin RzIL: https://github.com/rizinorg/rizin/blob/dev/doc/rzil.md ; book https://book.rizin.re/src/disassembling/rzil.html ; existing `src/patchtrace/secondary`.
6. angr stable docs: https://api.angr.io/en/stable/index.html ; https://docs.angr.io/en/v9.2.164/ ; license https://github.com/angr/angr/blob/master/LICENSE
7. Alive2 primary paper, Lopes et al. (PLDI 2021), DOI 10.1145/3453483.3454030: https://web.ist.utl.pt/nuno.lopes/pubs.php?id=alive2-pldi21 ; implementation https://github.com/AliveToolkit/alive2 (README explicitly warns interprocedural transformations unsupported).
8. Z3 project/license and Windows builds: https://github.com/Z3Prover/z3
9. Triton project and architecture list: https://github.com/JonathanSalwan/Triton
10. BINSEC/Rel paper: https://binsec.github.io/assets/publications/papers/2020-sp.pdf ; historical repo/readme https://github.com/binsec/rel
11. BinHunt: Gao, Reiter & Song (2008), https://scholars.duke.edu/publication/1493992 ; original evidence has *three case studies*, not broad measured accuracy.

## 4. PE relocation and address-target proof

Microsoft PE/COFF format: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format . **COFF object relocations and loaded PE base relocations are different stages.** An object instruction can use a zero or fixed placeholder for a relocation whose *symbol* changes; after linking, the instruction displacement may also change, but can still be numerically identical for different target identities. Therefore:

1. Resolve each effective target as an identity tuple `(kind, module/symbol or section, RVA, import key, mapping provenance)` with explicit unknown state. Preserve target identity independently from instruction bytes.
2. A changed address is cosmetic only when the older and newer targets are linked by an accepted mapping with no inconsistent matches; unknown and conflicting are separate states. Handle RIP-relative displacements, direct branches/calls, relocated jump tables, import thunks, data refs and function reordering.
3. Do not assume raw relocation equality proves behavior when image base, loader tables, link flags, external imports or memory state differ.
4. Validate a **linked PE** pair after the preliminary COFF object studies, with inspect-only Ghidra extraction; do not execute the binary.

Existing `unified/facts/datamap.py` handles matched functions/imports, unique strings, pair-voted data target consensus and cautious region shift. Threat cases: globally duplicated constants; changed target of an unresolved indirect call; reference to an existing other global with the same type; inter-image layout shift; code/data type confusion; switch dispatch table permutation; ICF/inlining changed identity. Each should be an explicit falsification fixture.

## 5. Compiler flags and environmental equivalence

LLVM documents `poison`, `undef` and `freeze`, and why apparently equivalent source expressions are not automatically valid optimizations under UB: https://llvm.org/docs/UndefinedBehavior.html . The C fixture in this study uses unsigned operations and no runtime entrypoint; it does **not** prove equality of all emitted functions, APIs or environment effects.

Microsoft confirms that `/guard:cf` inserts checks and link-time metadata: https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard . MSVC `/GS` stack-cookie instrumentation: https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check . The same source with different mitigation settings can have a security-significant difference: **never bulk-suppress security compiler flag changes as noise**. MSVC COMDAT folding `/OPT:ICF` may merge functions by linker policy; L1 N:M identity and L2 should be separated.

Construct factorial controls with two versions each of GCC, Clang and MSVC/clang-cl, O0/O2/O3/LTO, matching and mismatched security flags, PDB/no PDB, exceptions enabled/disabled, build reproducibility and function ordering. Record the *actual compiler banner*, not a mutable `windows-latest` label as a version pin.

## 6. Targeted symbolic pilot — feasibility acceptance, **not** yet implemented

For a candidate pair already classified `review` with known x86-64 basic-block boundaries and resolved immediate types:

- Normalize the identical entry symbolic inputs (RCX/RDX/R8/R9, RSP, relevant memory), explicit ABI, and opaque external-call contracts.
- Prefer one or two limited instructions: `icmp ult/sle` boundary and `add/and` constant; require concrete counterexample (e.g. `x = 16` for `x<16` versus `x<=16`). A witness must be independently checked against the lifted instruction semantics; it is a **differing behavior under assumptions**, not vulnerability proof.
- Cap path count, blocks, wall clock, memory and solver time; persist solver/version, formula hash, symbol constraint policy and any limitations. Return `unknown` on timeout, unmodeled memory, unsupported opcode or indirect jump. Do not allow a solver result to overwrite other valid verdict/evidence or modify L1.
- Define value test: incremental false-benign detection on a blinded mutation set, at bounded p95 cost, without harmful sensitivity to toolchain. If no measured improvement over existing C2/C6/MAT-ANCHOR, **do not ship** the dependency.
- Proposed module boundary: optional `unified/experimental/solver` or a child process writing a versioned evidence atom, behind a configuration switch, never loaded by default Windows frozen alpha. Requires SPEC-31 contract amendment, new license manifest, tests and release review.

## 7. Integrator decision summary

**Now:** prefer proof-contract correction, semantic-mutation regression coverage, native PE target verification, explainable evidence UI and data provenance. **Next:** independently benchmark P-code/SSA observation on branch/constant changes. **Defer:** generalized whole-program SMT equivalence, speculative register-renaming cosmetic verdicts, solver-inferred vulnerability labels, interprocedural symbolic execution and any mandatory dependency which changes Windows packaging.

Source references above are direct primary documentation/papers. They justify *what to test*, not a claim that current PatchTrace has verified those capabilities in a native Windows alpha.
