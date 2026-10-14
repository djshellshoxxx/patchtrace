# Diaphora research: actionable features for PatchTrace
Date: 2026-10-14. Status: upstream source/code inspected; local IDA/Diaphora live execution NOT performed.
Target: Diaphora 3.4.3 (released 2026-10-11), PatchTrace 0.1.0. This document is technical research, NOT a claim that any feature is implemented.
Companions: docs/specs/diaphora-optional-engine.md; docs/plans/diaphora-integration.md.

## Sources and reproducibility
- Official README: https://github.com/joxeankoret/diaphora
- 3.4.3 release: https://github.com/joxeankoret/diaphora/releases/tag/3.4.3 (IDA 9.5 beta, updated trained model for scikit-learn >=1.4, fixes for non-Qt CLI/idat, matching hook and heuristics).
- Matching strategy: https://github.com/joxeankoret/diaphora/wiki/Matching-Strategy
- Historic heuristic descriptions (written in 2018; NOT current count): https://github.com/joxeankoret/diaphora/wiki/Heuristics-and-their-explanation
- Actual matching definitions: https://github.com/joxeankoret/diaphora/blob/master/diaphora_heuristics.py
- Export schema/indexes: https://github.com/joxeankoret/diaphora/blob/master/db_support/schema.py
- Diff engine and results serialization: https://github.com/joxeankoret/diaphora/blob/master/diaphora.py
- IDA exporter and automation: https://github.com/joxeankoret/diaphora/blob/master/diaphora_ida.py
- Vulnerability-pattern extension: https://github.com/joxeankoret/diaphora/blob/master/scripts/patch_diff_vulns.py
- Automation: https://github.com/joxeankoret/diaphora/wiki/How-can-I-automate-the-diffing-process%3F
- Export performance: https://github.com/joxeankoret/diaphora/wiki/Diaphora-takes-too-long-exporting%21
- Source license: https://github.com/joxeankoret/diaphora/blob/master/LICENSE
- PatchTrace current contracts: src/patchtrace/secondary/{contracts,registry,runs,scheduler,store,reconcile}.py and docs/specs/multi-engine-orchestration.md.
Pin exact upstream commit/tag, hashes, IDA version, available decompiler, Python and matcher profile during implementation. Docs below describe code inspected on upstream master around this research date; pinning 3.4.3 and checking differences is a PR acceptance gate.

## 1. Design summary and how Diaphora works
Diaphora is an IDA plugin (IDA >=7.4/Python 3; Python 3.11 last tested in README) with a Python/SQLite comparison backend. Export each analyzed program ONCE into a SQLite function database; SQL candidate queries then compare two exports in reliability/performance order. This architecture amortizes slow decompilation, CFG and fingerprint extraction over repeated comparisons. Non-SQL passes follow graph neighbors and brute-force plausible leftovers. It is NOT merely a raw-byte diff or interchangeable with BinDiff's matching scores.

The export SQLite schema exposes:
- functions: unique text address, rva and segment_rva, name and mangled name, byte and normalized function hashes, assembler and cleaned assembler, pseudocode and cleaned pseudocode, up to three fuzzy pseudocode hashes, pseudocode AST-derived prime representation, instruction/mnemonic sequences, called names, constants, prototype, number of CFG nodes/edges, indegree/outdegree, cyclomatic complexity, SCC count/product, loops, topological sort, switches, MD-Index, KGH hash, microcode/clean microcode/microcode prime product, source file, export_time.
- program: callgraph prime features, processor, md5sum.
- instructions, basic_blocks, bb_relations, bb_instructions, function_bblocks: granular code/CFG/assembly associations.
- callgraph and constants linked by function ID.
- compilation_units and compilation_unit_functions: related functions and source-unit inference.
- program_data: named types/structs/unions/enums and metadata.
- version: Diaphora export schema marker.
Caution: upstream data fields and names are source-specific, NOT a stable vendor API. Some fields absent when decompiler/microcode or summary mode is used.

The diff result database is a DIFFERENT schema. diaphora.py save_results() creates:
  config(main_db, diff_db, version, date)
  results(type, line, address, name, address2, name2, ratio, nodes1, nodes2, description)
  unmatched(type, line, address, name)
Result categories include best, partial, unreliable, multimatch; unmatched categories primary/secondary. A unique index on (address,address2) means a single database cannot represent all duplicates of the same endpoint pair as separate records. Result paths in config are sensitive and must not be exported in PatchTrace reports.
There is no intrinsic SHA-256 pair binding in the diff results. A trusted execution manifest or verified locally-associated export provenance is REQUIRED to associate it with PatchTrace's artifact pair.

## 2. Feature inventory: mechanisms, benefits, caveats, priority
Each recommendation describes an isolated optional PatchTrace capability, not a request to transplant Diaphora's AGPL code.

### F01 Ordered SQL matching fingerprints [P0]
Mechanism: cheap strong matches first: identical byte/function hash with RVA, sequence or structure guards; then CFG, constants, names, opcode distributions, pseudocode/AST, neighborhood and slower fuzzy passes. Stored heuristic name accompanies each result (description). Current source diaphora_heuristics.py defines categories Best/Partial and constraints; the historic wiki's "51 heuristics" is a January 2018 snapshot, NOT a verified present-day total.
Value: find functions after reordering, refactoring, relocation or stripped symbols and display WHY they matched. Proposed representation: heuristic identifier, phase, attributes used, upstream ratio, evidence source/version, constraints and presence mask.
Limits: collision/common-code/thunk/library duplicates, auto-names, compiler drift; do not treat a category named "Best" as P(correct)=1. Shared Ghidra/IDA code-derived attributes correlate.

### F02 Decompiler pseudocode equality/cleanup/fuzzy hashes [P0]
Mechanism: export Hex-Rays pseudocode, normalized pseudocode removing autogenerated identifiers, three fuzzy hashes (DeepToad family), AST prime-like structural token representation; compare hashes or whole pseudocode plus constants/names. Matching can work where bytes change but semantics remain similar.
Value: recover logical function identity across patched builds; rich old/new side-by-side code view; likely higher leverage than new byte-only heuristic.
Caveats: needs IDA decompiler for best results; output pseudocode depends on decompiler version/options, optimization, types; AST equality or high fuzzy similarity is *not* semantic equivalence. Report unavailable for no-decompiler export, never create fake pseudocode from disassembly. Distinguish exact, normalized and fuzzy matches.

### F03 Hex-Rays microcode [P1, capability gated]
Mechanism: export microcode, cleaned representation and prime-based descriptors; can show microcode differences in graphs. It is a Hex-Rays-specific intermediate representation, NOT interchangeable with Ghidra p-code.
Value: cross-check a changed conditional, operation or optimizer transformation where pseudocode differs.
Caveats: only with licensed supported IDA/Hex-Rays configurations; export can be expensive. Keep microcode evidence in a distinct view/type with explicit producer, IR dialect and version. Never merge two IRs without validated semantic mapping.

### F04 CFG topology, MD-Index and SCC fingerprints [P1]
Mechanism: graph node/edge counts, cyclomatic complexity, in/out degree, Tarjan/topological features, loops, SCC prime products, rare MD-Index, mnemonic sequence/product and KGH-style hashes constrain candidate pairs.
Value: match renamed and rebased functions and detect structural changes.
Caveats: weak small-function matches produce false positives; source config has small-function thresholds and same-CPU flags. Some graph formulas from papers are approximations/fingerprints rather than proofs. Preserve exact feature names and match reason, not unsupported reconstructed values.

### F05 Callgraph-neighborhood propagation [P1]
Mechanism: seed with best/high-signal pairs; look recursively at callers/callees of matching functions for new likely pairs. Additional compilation-unit affinity or address gap can narrow candidates.
Value: fill unmatched queue and reconstruct renamed/moved function relationships.
Caveats: one mistaken seed can propagate; bound iterations/depth, record each seed/edge, require nontrivial corroboration, return alternatives, retain manual corrections as hard constraints. Initial implementation should consume Diaphora's already-produced results rather than reconstruct its full graph search.

### F06 Compilation-unit matching [P1]
Mechanism: infer source/build units from functions, code ranges, pseudocode primes and helper CodeCut/IDAMagicStrings; compare related compilation-unit membership. Source comments and hashes may provide a name.
Value: isolate rebuild noise, locate changed modules and cluster a KB's changes at subsystem level.
Caveats: inferred grouping is probabilistic; LTO, function folding, PGO, unity builds and inlining may break assumptions; source-file labels can expose local user paths. Display "inferred unit" and evidence count; do not claim genuine original source file without verified debug symbols.

### F07 Vulnerability-fix heuristics [P0 for investigation, not proof]
Mechanism: scripts/patch_diff_vulns.py observes PARTIAL (ratio < 1) function matches and uses line diffs to look for changed signed/unsigned conditional jumps (e.g. jl versus jb), added size-check comparisons in 'if' pseudocode, and a list of interesting API/string substrings (copy/printf/alloc/free/ProbeForRead/Write/etc.). Upstream patterns are intentionally broad and may mark innocuous changes.
Value: possible boundary-check, signedness, validation and API-related patch candidate queue; align with PatchTrace's existing enrichment BND/INT/OVF/VAL/ERR/SIZE/SCRUB and CSAF/CVE interpretation. Diaphora detection becomes a separate derived provenance signal.
Caveats: not a vulnerability oracle, broad unsafe-function matches can be noisy, apparent added check may be a decompiler rendering artifact; architecture-specific branch comparison needs control-flow and operand context. Require verifiable old/new source snippets and signedness intent, separated from score. A CVE narrative can PRIORITIZE but must not manufacture code evidence. Never add raw Diaphora heuristic score to existing scores as though independent.

### F08 Diff presentation and generated pseudocode/assembly patches [P1]
Mechanism: code-format HTML/line diffs, pseudocode patches, assembly and microcode graphs. Separate source representations exist in export DB; diff results DB contains matching metadata.
Value: PatchTrace UI can let analyst choose "Ghidriff pseudocode", "Diaphora pseudocode", "assembly", "microcode" with provenance; anchor changed lines to actual function and artifact.
Caveats: NEVER blindly render upstream HTML/embedded scripts as rich content; sanitize/re-render as plaintext or app-authored highlighting. Do not promise a microcode graph when neither underlying export nor block references are present. Patch generation is a presentation derivative, not a new independent engine vote.

### F09 Manual matching and ambiguous candidates [P1]
Mechanism: GUI allows manual matches and multimatches/unmatched display. Diff result types partition best, partial, unreliable, multimatch. 
Value: show conflict, second-best endpoints and analyst-approved corrections, preserving Ghidriff primary and existing PatchTrace review service.
Caveats: Diaphora's manual match is not the same as a PatchTrace analyst correction; import proposals only. A duplicated pair or one-to-many inference is not automatically accepted. Source result table may omit some alternates; label coverage as available, not complete.

### F10 Importing symbols, comments and type definitions [P2]
Mechanism: IDA-aware port of names, comments, enums, structs, unions, typedefs, type libraries, pseudocode comments (see importer routines and program_data).
Value: optional analyst-assist for external IDA workflow, particularly for repeated versions.
Caveats: PatchTrace does NOT edit binaries or IDA databases in alpha; create reviewable export of candidate annotations and require explicit user confirmation before any outbound application. Do not modify Ghidriff's names or original user notes.

### F11 Scripting hooks and filters [P2 controlled]
Mechanism: upstream supports project-specific Python hooks before/after export, matching customization, on_match and completion; supports filtering and export subsets.
Value: allow rules for a KB family or project to focus on specific namespaces/modules/functions.
Caveats: arbitrary Python is executable. PatchTrace must NEVER run scripts supplied in a project/untrusted export. Prefer declarative bounded allowlisted profile fields; leave deliberate expert scripts out of the automatic feature and require explicit separate opt-in if ever added.

### F12 Batch mode, SQLite snapshots, resumability/performance [P0]
Mechanism: export expensive features once to SQLite; diff the exports in pure Python. Official automation wiki shows DIAPHORA_AUTO=1 and DIAPHORA_EXPORT_FILE for IDA export; command-line Python comparison of two exported DBs: python diaphora.py older.sqlite newer.sqlite -o results.diaphora. Initial export requires IDA/IdaT/Ida64 according to local version; no IDA needed for already-exported pure Python diff. Export can be summaries-only and optionally exclude decompiler/microcode. The exporter uses crash markers/resume logic.
Value: lowest-risk Path A is import existing .diaphora + paired .sqlite DBs; Path B uses supplied .sqlite exports then runs comparison; Path C (later) adds IDA-powered export.
Caveats: 3.4.0 release warns script mode is going away: re-test 3.4.3 IDA plugin/headless launch and do not assume historical '-S' invocations work forever. Multiple export modes change available evidence; cache key includes export mode and exact tool/decompiler versions.

### F13 Parallel work, SQL caps, ML [P2/research]
Upstream has parallel diff processing and knobs SQL_MAX_PROCESSED_ROWS (default 1,000,000) and SQL_TIMEOUT_LIMIT (default 300 s/heuristic), and a configurable CPU count. Slow heuristics disabled for sufficiently large databases (threshold source config ~4001 functions); >8000 can change microcode export behavior, >100000 summary-only guidance. Do not disable safety limits. Upstream experimental ridge/scikit-learn has changed across recent releases; 3.4.1 disabled use of trained models due to compatibility bugs, 3.4.3 re-enables with a retrained >=1.4 model. Treat as experimental, never ship trained weights without provenance and held-out evaluation.
PatchTrace existing scheduler caps parallel engines at two; nested parallelism must not oversubscribe cores/RAM. Per-heuristic timeout is not the same as whole-process deadline.

## 3. Honest novelty assessment
Diaphora's public README describes several capabilities as "unique," but feature overlap exists. Ghidriff already offers Ghidra pseudocode/function comparisons; BinDiff offers graph matching, propagated matches and analyst review; QBinDiff offers customizable graph-aware matching. The Diaphora-specific practical combination is *rich export-time fingerprints + explainable ordered SQL heuristics + Hex-Rays pseudocode/microcode + CU grouping + patch-relevant pattern hooks*. Do not advertise categorical exclusivity or duplicated evidence as independent proof.

Compared with current PatchTrace:
- Present already: Ghidriff baseline, independent optional rz-diff and BinDiff import, per-engine status/cache, reconciliation, evidence ranking/WIL/CVE, raw code/bytes and PE overview, analyst corrections.
- Missing: Diaphora exports/diff import, IDA/Hex-Rays-backed semantic views, CU cluster model, direct microcode representation, linked Diaphora heuristic provenance, optional Diaphora vulnerability signatures.
- Existing docs/specs/three-tool-evidence-adapters.md explicitly DEFERRED Diaphora as an extra whole matching engine until present multi-engine work is finished. This spec preserves that sequencing and makes import a low-risk research path, not a change in primary priority.

## 4. Diaphora output semantics to preserve
Upstream results 'type' is a match *bucket* (best/partial/unreliable/multimatch), 'ratio' is a heuristic similarity ratio not a calibrated probability, 'description' is the heuristic/match reason, 'nodes1/2' are graph sizes not counts of evidence, unmatched sides are one-sided categories. Diff output 'config.main_db/diff_db' paths are NOT trustworthy identity or ready for user-facing export.
Some function/label addresses are stored as text and may represent IDA EAs, not RVA. A database 'rva' column is available in exports. Map each side independently using validated image base / PE section evidence and architecture; do not guess base subtraction. If mapping cannot be proved, mark non-comparable; preserve external addresses for troubleshooting behind privacy control. Diaphora's 'program.md5sum' does not replace SHA-256 binding.
No trustworthy independent decompiler equivalence claim: two decompilers with different output may reflect toolchain differences, not binary changes.

## 5. License and operational assessment
Diaphora 2.x+ is AGPL-3.0-or-later, while PatchTrace's repository is MIT. Never copy, vendor, paste adapted heuristics or import Diaphora source into the PatchTrace MIT runtime without a deliberate compatibility/distribution and legal review. Proposed implementation independently reads an external DB or invokes user-installed Diaphora using a local subprocess; this design reduces coupling, but it does NOT automatically settle every AGPL-combination/legal question. Preserve notices for any shipped derivatives; seek licensing advice for distribution/hosting decisions.
IDA/Hex-Rays is independently licensed and not bundled. Users without IDA should be able to import previously exported results and use regular PatchTrace; never label missing IDA as core-app failure.

## 6. Security, reliability and empirical unknowns
- Untrusted SQLite: open read-only with SQLite query-only/immutable snapshot as appropriate; copy into a private bounded staging area; check magic/version/schema, quick_check; restrict file size/pages/rows/string lengths; do not execute SQL from project/export; never eval source text. Upstream diffing code is not a sanitizer.
- User-supplied SQLite may contain paths, symbols, comments and pseudocode with secrets: redact on exports by default and display snippets only with a deliberate privacy setting.
- External child: absolute executable allowlist, argv list, no shell, clean restricted env, private cwd, timeout, process-tree cancellation, bounded stdout/stderr; Python interpreter/IDA scripts from user configurable locations are trusted only after explicit opt-in.
- Fail closed on wrong pair/orientation and malformed schema. No committed base results overwritten; staged scratch removed on error.
- Accuracy: baseline high-precision mapping corpus and negative controls. Report incremental pairs recovered, false matches, true patched function recall, top-K triage, time, memory and missing-capability rate. Do not claim improvements without actual fixtures.

## 7. Research questions / live verification still required
1. Pin release 3.4.3 SHA and verify the exact headless IDA invocation on Windows 11 with relevant paid/free licenses.
2. Produce real export + diff DB fixtures; inspect 3.4.3 results and function table schemas with SQLite and confirm addresses/ratio formats.
3. Determine whether Python 3.12 running 3.4.3 diff-only works; upstream documents Python 3.11 as last tested; use an isolated compatible interpreter if needed.
4. Test different image bases, PDB/no-PDB, stripped symbols, no decompiler, missing microcode and high function counts.
5. Confirm archive paths generated by IDA cannot overwrite original input/other user's directories; confirm cancellation leaves originals unchanged.
6. Measure marginal benefit to PatchTrace's actual patched-function detection, not just raw function-match recall.
