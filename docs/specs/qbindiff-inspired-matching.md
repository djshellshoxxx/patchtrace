# SPEC-QB-01: Configurable graph-aware function matching
Status: proposed; research-backed design, not implemented.
Scope: optional additive analysis for PatchTrace's existing Windows x64, Python 3.12 and Ghidriff pipeline.

## Research and novelty assessment
QBinDiff models two programs as attributed call graphs, extracts function/instruction/operand features, constructs a weighted similarity matrix, applies anchors and user-defined postpasses, then aligns graphs using an approximate max-product/min-sum belief-propagation approach. The exact optimizer is sophisticated; reproduce the *useful behavior* with independent code and benchmark accuracy before attempting full numerical parity. Sources: https://diffing.quarkslab.com/qbindiff/doc/source/binary_diffing.html ; https://diffing.quarkslab.com/qbindiff/doc/source/features.html ; https://diffing.quarkslab.com/qbindiff/doc/source/api/differ.html ; https://blog.quarkslab.com/qbindiff-a-modular-diffing-toolkit.html ; https://github.com/quarkslab/qbindiff .

BinDiff already supports graph-based function matching, anchors/propagation and confidence. Diaphora supports customizable matching heuristics and manual matches. No feature below should be advertised as universally exclusive to QBinDiff. Strong differentiation is the combination of arbitrary pluggable feature extractors, externally refined pairwise scores, general attributed graph matching, and explicit content-vs-topology controls. Features should be reimplemented independently or integrated as an optional external licensed engine, not copied indiscriminately. Verify QBinDiff's exact license and transitives before redistribution.

## Goals
1. Independently rank candidate old/new functions using configurable weighted evidence without altering existing Ghidriff results.
2. Support a deterministic, bounded graph-aware reranker, with an optional experimental message-passing solver.
3. Explain *why* each match was proposed, expose counter-evidence and flag ambiguity; never treat scores as vulnerability likelihood.
4. Permit user-imposed confirmed matches, exclusions and constrained subgraph comparisons.
5. Make data-oriented matching available for patch analysis and compiler-drift cases.
6. Operate offline and preserve current projects, code panes, CLI, GUI and report output.

## Existing integration constraints
PatchTrace README describes PE AMD64, Ghidriff raw JSON normalization, SQLite projects, manual corrections, analysis workers, code panes and an offline backend setup. Python >=3.12; PySide6==6.12.0, pydantic==2.13.5. Existing run/import failure preserves committed results. Do not overwrite existing data or reinterpret Ghidriff confidences.

## Module architecture (suggested files, adjust to observed source tree)
- `src/patchtrace/matching/contracts.py`: versioned `ProgramGraph`, `FunctionNode`, `CallEdge`, `FeatureValue`, `CandidatePair`, `MatchProposal`, `MatchingProfile`, `MatchExplanation`, evidence provenance. Immutable typed data; identity includes artifact SHA-256, architecture, address, extractor version.
- `matching/adapters/ghidra_graph.py`: extract optional graph/feature manifests from *trusted* Ghidra analysis exports. Treat data as absent if Ghidriff JSON lacks required edges/instructions. Never synthesize call graphs or instructions from code hashes. Avoid a second Ghidra scan until demonstrably required.
- `matching/adapters/binexport.py` optional future source; explicit capability-gated support. Do not add BinExport or Quokka as hard dependencies.
- `matching/features/registry.py`: typed extractor protocol with `key`, `version`, `required_capabilities`, `extract(node, context)`, `weight`, `cost`; reject duplicate keys/nonfinite weights, log extractor provenance; never execute untrusted plugins by default.
- `matching/features/builtin.py`: basic block and instruction counts, parent/child degree, CFG density/cyclomatic complexity, normalized mnemonic histogram, import/library references, strings and constants, read/write counts, normalized p-code operations when present, referenced data names. Address/name/hash are optional weak or anchoring evidence; warn for compiler/relocation sensitivity. Weisfeiler-Lehman graph features experimental only, benchmark numerical stability.
- `matching/similarity.py`: per-feature typed distances (cosine, Canberra, Euclidean, Jaccard where applicable), missing-value policy, normalization, weighted aggregation and score decomposition. Do not compare categorical hashes as continuous numbers. Validate finite [0,1] output; produce per-feature contribution plus availability.
- `matching/candidates.py`: shortlist candidate pairs using exact anchors, hashes, imports, lightweight similarity and bounded top-K in both directions. Sparse edge-list/CSR representation; never allocate n*m dense arrays without a strict budget and explicit operator consent.
- `matching/refinement.py`: ordered passes with declared inputs/outputs that can boost/penalize/prune a score; immutable snapshots, deterministic order, hard anchor and exclusion invariants, diagnostics per pass. No arbitrary Python execution from project files.
- `matching/align.py`: deterministic one-to-one assignment baseline (greedy with stable tie-breaks or bounded maximum-weight matching per connected candidate component); enhance with topology-aware iterative message passing and damping, iteration/time/memory limits, early stopping and cancellation. No claims of mathematical equivalence to QBinDiff without independent verification.
- `matching/anchors.py`: enforce unique analyst anchors; reject contradictory anchor pairs, one-to-many conflicts, excluded edges and absent nodes; pre-existing user correction retains priority over automatic suggestions.
- `matching/explain.py`: rank contribution breakdowns, graph support, disagreements, ties, missing features and delta from Ghidriff; explain confidence separately from similarity.
- `matching/service.py`: single orchestrator with stable interface `propose_matches(graph_old,graph_new,profile,anchors,cancel)->ProposalRun`. Never persist until full validation.
- `matching/profiles.py`: safe, versioned built-in profiles: default, compiler-drift, data-oriented, obfuscated, firmware-subgraph, conservative-CVE; profile selection is advisory, not a deterministic bug diagnosis.

## Key research observations to implement carefully
QBinDiff features span function call-degree, import/library use, CFG block/edge structure, cyclomatic complexity, hashes, graph density/diameter/transitivity, instruction and p-code mnemonic counts, jumps, constants, strings, data references and memory-read/write behavior. Features are often fragile across compiler optimizations. QBinDiff provides custom similarity-matrix postpasses, anchoring and a content-vs-callgraph tradeoff parameter. Its optional graph normalization can produce partial matching. Higher sparsity improves resource use but may discard true matches. Weisfeiler-Lehman features are documented as potentially numerically unstable. The documented API supports generic graph alignment, not only executable programs. See upstream docs linked above.

## Algorithms and safeguards
Represent adjacency as a directed sparse graph. Given feature similarity S_ij and old/new adjacency A/B, maximize a bounded approximation of:
  alpha * sum(S_ij * X_ij) + (1-alpha) * sum(A_ik * B_jl * X_ij * X_kl)
subject to at-most-one old/new function matching; permit unmatched nodes. This expression is conceptual, not an exact QBinDiff transcription. Keep intermediate values finite; scale weights; avoid assigning high scores merely because a function is common. Anchors must be unique and have provenance. Track candidate pruning recall and unresolved candidate rate. Unmatched is an explicit valid result. Link score to an algorithm/version/profile; calibrate reported confidence on held-out labeled pairs rather than calling raw similarity 'probability'. Build candidate generation and scoring before implementing graph propagation.

## UX and persistence
Add optional Analysis > Match refinement profile; default 'Ghidriff only' retains existing behavior. Show Suggested Match, Ghidriff Match, and Analyst Correction as distinct evidence sources; never silently apply a suggestion. Per function: contributing features, graph-neighbor evidence, incompatible/missing capabilities, alternative candidates and rationale. Save proposals to additive versioned tables tied to artifact digests, run ID, profile fingerprint, extractor versions; do not mutate previous result tables until analyst explicitly accepts a correction. Export confidence explanations in JSON/HTML/Markdown with provenance. On mismatch/incomplete data disable gracefully.

## Acceptance tests
Unit: all distances, NaN/inf rejection, normalization, missing features, deterministic tie-break, contradictory anchors, one-to-one constraints, empty/singleton graphs, repeated imports, timeouts, cancellation and profile serialization.
Property: mapping injectivity, score bounds, invariant anchors, no mutation of committed prior results, candidate pruning never violates must-link.
Integration: existing Ghidriff-only golden fixture bit-for-bit unchanged; synthetic function renaming/reordering; Windows x64 compiled before/after fixtures with known identities; compiler optimization variation; same-function many call sites; split/inlining explicitly unresolved; malicious corrupted exports fail closed.
Performance: collect time, peak RSS, candidate recall@K, precision/recall/F1 of function mapping, coverage and false-positive match rate on a separately labeled benchmark. Compare with existing Ghidriff baseline and optional upstream QBinDiff/BinDiff where available. Set explicit resource limits before enabling by default.
Security: no network; no dynamic imports from project; hard input size/candidate count caps; supervised child process for costly solver; errors sanitize paths/tokens; no external target execution; offline operation.

## Delivery increments
P0 inventory actual adapters/schema/test fixtures and establish baseline. P1 feature contracts/registry + lightweight features. P2 sparse candidate generation + anchored scoring. P3 refinement passes + explainability. P4 opt-in GUI/report/proposals. P5 graph-aware solver experiment and accuracy benchmarks. P6 extended data-focused features, profiles and cross-backend exporters.
Definition of done: feature gates default off, benchmark improvement documented, regression suite green on Linux and Windows, native Windows Ghidriff comparison and frozen installer smoke test, rollback verified.
