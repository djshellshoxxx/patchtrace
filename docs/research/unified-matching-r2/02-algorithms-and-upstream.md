# R2.02 — Matching algorithms, upstream evidence, and representation learning

Research date: **2026-10-30**. PatchTrace baseline: **`a04f5a299a8d4afef023261e52e08d14678cf1e7`**. Scope: correspondence for adjacent Windows PE AMD64 patch pairs, with an offline, deterministic core; compare exact/normalized keys, Ghidriff/Ghidra VT, BinDiff, rz-diff, QBinDiff, and learned representations. This is research, not a contract change or a claim that an experimental technique is production ready.

Evidence labels throughout: **[U]** upstream source/document/paper read during this investigation; **[L]** local baseline source inspected; **[E]** a local microexperiment executed for this report; **[A]** our analysis or proposed experiment; **[?]** unresolved. A paper's evaluation is upstream evidence about its own setup, not measured PatchTrace accuracy. GitHub connector `sha` values below are **file/blob SHA-1s, not repository commit SHAs**. Moving-branch reads are identified as such; no invented repository pin is substituted for a missing one.

## 1. Decisions supported by the evidence

1. **Keep correspondence and change detection separate.** Equality after operand masking, mnemonic projection, data-flow abstraction, or learned embedding does not imply that a security-relevant edit is absent. This distinction is directly visible in Ghidra's exact-instructions documentation and in BSim's explicit tolerance of actual source changes; the local probe in §10 reproduces the masking case. [Ghidra exact correlators](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTracking/src/main/help/help/topics/VersionTrackingPlugin/VT_Correlators.html), [BSim overview](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/BSim/src/main/help/help/topics/BSim/BSimOverview.html). **[U,E,A]**
2. **Most classical recommendations are already implemented.** PatchTrace has the P01–P19 ladder, unique-both-sides drill-down, neighbour propagation, rarity filtering, call-target rehashing, reference vectors, block votes, duplicate groups, bounded MinHash candidates, integer assignment with rejection, and soft tier-C arbitration. Recommending that these be built again would misstate the baseline. The valuable next work is measurement of candidate loss, pass-specific precision, wrong-anchor propagation, and added/removed/split/merged cases. See §2 and §11. **[L,A]**
3. **QBinDiff is an optimization baseline, not a pretrained neural model.** Its belief-propagation solver combines function similarities and conserved call edges. It does not inherently require a training corpus or model weights. Its actual implementation still accepts a dense initial matrix and densifies residual assignment; a high sparsity setting does not make that initial allocation disappear. [Paper](https://arxiv.org/abs/2112.15337), [matcher source](https://github.com/quarkslab/qbindiff/blob/main/src/qbindiff/matcher/matcher.py). **[U]**
4. **Learned embeddings are plausible residual candidate generators or rerankers.** None of the reviewed embedding objectives proves historical identity or semantic equivalence. Function search quality, binary-wide injective mapping quality, and one-instruction patch recall are different outcomes. A learned candidate must retain its own provenance and must not suppress a raw/typed operand difference. §7–§9 explain the architectural and operational costs. **[A]**
5. **Prior notes require two corrections.** DeepBinDiff's released implementation performs token training on the two inputs and says it requires no pretrained model; its paper used a different, once-trained token setup. Asm2Vec is exposed in the authors' open Kam1n0 platform; a blanket statement that the original approach is unavailable/open-source-free is too strong. [DeepBinDiff README](https://github.com/yueduan/DeepBinDiff/blob/master/README.md), [paper §VII-E](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24311-paper.pdf), [Kam1n0 README](https://github.com/McGill-DMaS/Kam1n0-Community/blob/master2.x/README.md). **[U]**
6. **No speed or accuracy winner is established for PatchTrace's target.** The primary sources use different extraction tools, architectures, function filters, training data, hardware, and candidate pools. In particular, the Cisco/Talos measurement study disables inlining and filters functions with fewer than five blocks in Dataset-1. Those results cannot settle correspondence for tiny PE wrappers, ICF aliases, or compiler-generated helpers. [Measurement paper §4.1](https://www.usenix.org/system/files/sec22-marcelli.pdf). **[U,A]**

## 2. What the current repository already does

The relevant baseline contracts are [SPEC-31 matching](../../specs/unified-engine/04-matching-pipeline.md), [QBinDiff-inspired proposal](../../specs/qbindiff-inspired-matching.md), and the existing [literature note](../ue-matching-literature.md). Older research is retained as historical evidence: [BinDiff](../unified-engine/02-bindiff.md), [Ghidriff/Rizin](../unified-engine/03-ghidriff-rizin.md), [classical prior art](../unified-engine/04-structural-matching-prior-art.md). Assertions below are from current source, not merely those plans. **[L]**

| Baseline source | Implemented mechanism | Consequence for this research |
|---|---|---|
| `src/patchtrace/unified/ir/features.py`, `ir/operands.py` | Length-delimited 64-bit BLAKE2b instruction keys; sequence/multiset keys; positive-evidence operand classification; L1 masks located addresses, L2 also scalar/stack/memory fields; L3 uses SLEIGH's instruction mask | Do not propose generic address masking as new. Evaluate *which information each level destroys* and whether pairing evidence is incorrectly reused as unchanged evidence. |
| `ladder/passes.py` (`LADDER_VERSION='ladder/2'`) | Imports, exports, names, raw/normalized hashes, mnemonic keys, CFG/callgraph MD, rare strings/constants, import sets, P15 call-target substitution | Much of the BinDiff/VT feature ladder has already been adapted with stronger typing. Exact names have a body-size/mapped-callee guard. |
| `ladder/engine.py`, `state.py`, `propagate.py` | Ordered passes and drill-down, owned anchors, deterministic waves, implied votes/conflicts, bounded hubs/neighbours, soft-candidate conflicts | Test propagation risk and order invariants rather than replace it with an unbounded graph matcher. |
| `ladder/blocking.py` | Shared-token blocking; mnemonic 3-grams; 16 MinHash permutations in 4 bands of 4; top candidates per direction; bucket splitting/caps | Every residual solver inherits these recall limits. A sophisticated scorer cannot recover an edge never generated. |
| `ladder/residual.py` (`RESIDUAL_VERSION='residual/1'`) | P16 reference vectors, integer nano-nat weights and integer cosine, mutual best/margin; P17 rare block voting; P18 layout; P19 assignment | IDF-like weighting and reciprocal reference margins already exist in P16. A P19 rarity-weighted score would be a specific delta, not the first such weighting in the engine. |
| `ladder/assign.py` | Pure Python shortest-augmenting-path assignment; integer costs; dummy rejection columns; rectangular worst-case bound `O(rows² × columns)` | P19 already permits unmatched functions. Global assignment is optimal only for the supplied additive cost matrix, not for historical identity. |
| `ladder/groups.py` and facts/fusion modules | Duplicate/ICF/inline-outline hints and separate evidence/facts channels | Learned or block-level many-to-many evidence should enter as hypotheses/groups; do not force it into one-to-one identity. |

The live research gap is not algorithm inventory. It is whether these implemented choices meet their intended precision and recall on independently labelled real inputs, and where the candidate generator, extractor, or acceptance policy loses the true mapping. This report does not infer a pass's real precision from its tier name. **[L,A]**

## 3. Equality, normalized equality, identity, and similarity

Four questions must remain distinct:

| Question | What evidence can establish | What it cannot establish |
|---|---|---|
| Are the supplied byte ranges equal? | Exact comparison of verified byte ranges; a hash can index likely equals before comparison | Whether the ranges were correctly recovered as whole functions; which source function produced either range |
| Are normalized representations equal? | Equality under a stated extractor, normalization version, and information-removal policy | Equality of removed constants, offsets, registers, branch polarity, or targets |
| Did this old function become this new function? | A correspondence hypothesis supported by unique content, names, context, analyst anchors, or ground truth | Automatic proof from any single lossy fingerprint; uniqueness in a residual pool is only conditional uniqueness |
| Are these functions similar? | A metric, learned ranking, or graph objective under its own representation | A calibrated probability of historical identity, semantic equivalence, or a conclusion about vulnerability status |

**[A]** This is a logical distinction, not a claim that normalized matching is undesirable. Adjacent patch pairs need a matcher that survives address relocation while a change detector retains the operand edits that relocation normalization must not erase. Ghidra's help explicitly reports exact-instructions similarity 1.0 even when bytes differ. BSim's p-code/data-flow description intentionally tolerates storage changes, ordering, compiler transformations, and some true source changes. [VT correlators](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTracking/src/main/help/help/topics/VersionTrackingPlugin/VT_Correlators.html), [BSim overview](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/BSim/src/main/help/help/topics/BSim/BSimOverview.html). **[U]**

### 3.1 Exact keys and the normalization ladder

**[A]** Hash lookup is a useful first stage because key construction can be linear in input bytes/instructions. That is not the complexity of the entire matching pipeline. Sorting keys costs `O(n log n)` if used for deterministic traversal; sorting a mnemonic multiset costs `O(I log I)` per function under the current general-purpose implementation; graph preprocessing, recursive buckets, propagation, and residual scoring add work. Fixed-length dictionaries have expected constant lookup, not an adversarial worst-case proof.

**[L,A]** BLAKE2b-64 equality is a compact fingerprint, not collision-free canonical equality. Per-comparison random collision probability near `2^-64` does not describe a large collection's aggregate collision probability, nor representational collisions created by normalization. A content-key acceptance audit should separate (a) equal normalized content, (b) duplicate bodies from different functions, and (c) accidental hash collision. For especially consequential exact anchors, rechecking the normalized stream before acceptance is a defensible experiment if the existing reader budget allows it. It should not be advertised as fixing ICF or repeated templates, which can be truly byte-identical.

**[U,A]** Ghidra's `ExactInstructionsFunctionHasher` applies `InstructionPrototype.getInstructionMask()` to bytes. It is deliberately broader than PatchTrace L1's located-address masking: do not call both operations equivalent. A register or immediate field omitted by an opcode mask can carry the very edit under investigation. [Hasher source](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/match/ExactInstructionsFunctionHasher.java). PatchTrace's typed, located-field policy is already a useful improvement in specificity; its empirical advantage remains to be measured.

**[A]** Uniqueness helps precision but has two qualifications. First, an attribute can be unique in a small caller/callee pool while common globally. Second, early accepted pairs remove alternatives and can make a later key unique. The reported justification therefore needs pool scope, dependency anchors, and pass order. If an early anchor is wrong, monotone acceptance can propagate it. Existing provenance and separate evidence families should be used to measure this effect rather than interpret the number of agreeing downstream pairs as independent support.

## 4. Ghidriff, Ghidra Version Tracking, and BSim

### 4.1 Ghidriff is not the AutoVT workflow

**[U]** `VersionTrackingDiff` runs symbol matching and an ordered list of Ghidra `MatchFunctions`/hasher operations, subtracting matched address sets after each pass. Current source includes raw-byte, instruction-mask, structural graph, mnemonic, BSim, bulk instruction, call/signature, string, and switch correlators. Structural and bulk-block passes enable one-to-many matching. It then invokes implied and decompiler matching before final external-name handling. The order therefore affects what evidence remains available to later passes. [Current driver](https://github.com/clearbluejar/ghidriff/blob/main/ghidriff/version_tracking_diff.py), blob `06b181b83ddadf577c0da01fa04a4d4842be5839`.

**[U]** Ghidra VT is a broader framework: function *and data* correlators, duplicate matches, match acceptance state, reference-based correlators, and implied associations. The help describes correlators whose scores have different meanings, including fixed scores for exact matches and vector-based scores for references. A VT match record is evidence from a correlator; it is not a universal likelihood. [VT correlators](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTracking/src/main/help/help/topics/VersionTrackingPlugin/VT_Correlators.html). The current AutoVT script delegates to the AutoVT machinery; its existence must not be used to claim Ghidriff executes that machinery. [AutoVT script](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTracking/ghidra_scripts/AutoVersionTrackingScript.java).

**[U,A]** Current Ghidriff source already contains guards against nonexistent or non-entry function matches and a correctly separated `skip_types` list. Historical findings about released versions must stay attached to their old versions; the earlier 2026-10-14 report's `ghidriff 1.0.0` observations are not automatically facts about this moving `main`. No fresh Ghidra/Ghidriff execution was performed for R2.02, so this report does not revalidate old measured defects or declare them fixed. [Driver](https://github.com/clearbluejar/ghidriff/blob/main/ghidriff/version_tracking_diff.py), [engine](https://github.com/clearbluejar/ghidriff/blob/main/ghidriff/ghidra_diff_engine.py).

### 4.2 Reference evidence and implied matches

**[U]** VT reference correlators encode accepted data/function matches as features for referencing functions and add unique unmatched-reference features. The help describes logarithmic weighting based on feature incidence and cosine-like comparison. This supplies a principled reason to downweight popular shared references and penalize lost/new references. [Reference correlator help](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTracking/src/main/help/help/topics/VersionTrackingPlugin/VT_Correlators.html). **[L]** PatchTrace P16 already implements its own documented integer version; a proposal to add reference vectors is redundant.

**[U,A]** Ghidriff's implied matching uses an instruction correlation to suggest referenced functions, with thunk resolution. This depends on the correctness of the parent match and address/instruction recovery. It is not independent corroboration from a new disassembler. [Implied-match source](https://github.com/clearbluejar/ghidriff/blob/main/ghidriff/implied_matches.py). For PatchTrace, the more useful extension is a *dependency sensitivity evaluation*: remove or corrupt one accepted anchor and report the changed descendants, conflicts, and final false matches. Existing votes/conflicts and hub guards should remain the conservative baseline.

### 4.3 BSim as the nearest operational comparison for embeddings

**[U]** BSim features come from decompiler-generated p-code data flow, and indexed nearest-neighbour search admits partial feature overlap. Ghidra supports a local H2 database in addition to server technologies. This provides an offline comparison without first introducing a separate neural training pipeline. [BSim overview](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/BSim/src/main/help/help/topics/BSim/BSimOverview.html). **[?]** This report has not measured BSim's extraction cost, local query throughput, memory, or patch-pair precision; a vendor query-speed statement omits the preceding Ghidra/decompiler work and is not an end-to-end benchmark.

**[A]** BSim is particularly relevant because Ghidriff already invokes it. A new representation learner should be compared against BSim *on the same residual functions* and with extraction cost included, rather than claim novelty from using a function vector alone. BSim and a Ghidra-derived neural representation also share upstream failure modes such as function-boundary and decompilation errors. Their agreement must not be counted as two fully independent observations.

### 4.4 Operational fit

**[U,A]** Ghidriff source is GPLv3; Ghidra source files reviewed here carry Apache-2.0 notices. The repository's existing external-process boundary for Ghidriff is appropriate to retain. This is a packaging recommendation, not a legal conclusion that subprocess use alone settles all obligations. Review the actual distributed components and notices. [Ghidriff license](https://github.com/clearbluejar/ghidriff/blob/main/LICENSE), [Ghidra hasher notice](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/match/ExactInstructionsFunctionHasher.java). No model-weight redistribution is required by the reviewed classical VT workflow. Offline feasibility still depends on provisioned Ghidra/Java/Python dependencies and the selected symbol policy.

## 5. BinDiff

### 5.1 Algorithm and output

**[U]** The v8 concepts document describes global attribute matching, unique matches, recursive drill-down inside ambiguous buckets, matching callers/callees around fixed points, block matching, and call-reference matching. It explicitly classifies address/call sequences and content-free singleton propagation as weak techniques. It is a heuristic staged alignment, not exhaustive graph isomorphism and not a general globally optimal solver. [v8 concepts](https://github.com/google/bindiff/blob/v8/docs/concepts.md), [driver](https://github.com/google/bindiff/blob/v8/differ.cc).

**[U]** BinDiff preserves function, basic-block, and instruction correspondences in its database-writing path, including algorithm information. This is finer output than a function embedding alone. A high-level function score should not replace access to these subordinate correspondences. [v8 database writer](https://github.com/google/bindiff/blob/v8/database_writer.cc). **[A]** Those address pairs are still an alignment produced by heuristics, not proof that a particular operand is unchanged.

**[U,A]** The concepts document's confidence is an aggregation of algorithm confidence with sigmoid weighting; similarity aggregates structural/matching information and is affected by confidence. These are designed scores, not empirically calibrated probabilities. The document uses approximate factor weights and is not an executable numeric specification; use the pinned source/configuration for exact arithmetic. [Confidence/similarity documentation](https://github.com/google/bindiff/blob/v8/docs/concepts.md#confidencesimilarity). Do not average BinDiff confidence with Ghidriff text ratios, rz-diff byte similarity, or neural cosine.

### 5.2 Useful mechanisms versus already adopted work

**[U,L]** Unique-key drill-down and caller/callee propagation are already in PatchTrace. BinDiff's matched-block call-reference rule is useful precedent for local context, but PatchTrace has an explicit bounded call-site alignment/vote policy rather than blindly pairing residual calls in position. [BinDiff call-reference implementation](https://github.com/google/bindiff/blob/v8/match/basic_block_call_refs.cc), baseline `ladder/propagate.py`.

**[A]** Edge context is a potentially stronger discriminator than a single node histogram: a shared rare caller *and* rare callee, or two corroborating mapped neighbours, can distinguish common wrappers. But conserved topology is fragile under inlining, outlining, tail calls, CFG recovery failure, and new dispatch layers. Evaluate that discriminator within existing residual candidates, with hub/rarity control and explicit negative cases, before adding a new accepted pass.

**[L,?]** The existing BinDiff research documents v8 BinExport2 limitations, including unavailable operand-change classification and inert string steps. Those claims are retained as pinned historical evidence; this R2 subtask re-read the driver, concepts, call-reference matcher, database writer, and prime matcher, **not every reader/classifier path**. Do not silently generalize those old limitations to all future BinDiff releases. See [the earlier source-level analysis](../unified-engine/02-bindiff.md) for its exact file coverage and source paths.

### 5.3 Cost, determinism, licensing

**[A]** Hash/shape passes can be close to linear after feature extraction, but repeated drill-down and graph neighbourhood traversal depend on graph density, collisions, and pass ordering. There is no defensible single `O(n)` bound for complete BinDiff from its README. Determinism of a pinned exported graph and executable should be measured separately from reproducibility of IDA/Ghidra analysis and export.

**[U]** Current upstream README lists separate disassembler integration and distinguishes native core builds from the Java GUI's commercial yFiles dependency. The source is Apache-licensed. The fact that core source is open does not make all GUI build dependencies or disassembler licenses interchangeable. [Current README/build/license discussion](https://github.com/google/bindiff/blob/main/README.md). **[A]** Keep the already-supported CLI/import path as the operational baseline/oracle; a full GUI vendoring effort is unnecessary for matching research.

## 6. Rizin `rz-diff`

### 6.1 Read the pinned code, not a generic `radiff2` description

**[U]** In the inspected `v0.9.1` source, function and block similarity concatenate recovered raw bytes; equal-length equal buffers short-circuit, otherwise Levenshtein similarity is calculated. There is no located-address normalization in that similarity routine. [Pinned similarity implementation](https://github.com/rizinorg/rizin/blob/v0.9.1/librz/arch/similarity.c), blob `8544259e17a692bcb3c1d8858f104745cd0cba4c`. The official handbook distinguishes functions, graphs, bytes, and other object/text diff modes. [Handbook](https://book.rizin.re/src/tools/rz-diff/binary_diffing.html).

**[U]** The same pinned source contains `calc_similarity < threshold && calc_similarity <= max_similarity` in selection. A candidate above the threshold can therefore replace a higher-scoring previous candidate. Function names can cause early selection, and secondary candidates are not consumed to impose a global one-to-one assignment. This is observable source logic, independently of the old report's runtime examples. Do not describe this version as an argmax matching algorithm. [Selection implementation](https://github.com/rizinorg/rizin/blob/v0.9.1/librz/arch/similarity.c). **[?]** No newer release was installed or validated in this subtask; a development fix is not evidence about a shipped executable.

**[U]** Graph mode obtains two functions, invokes basic-block matching, and emits block/opcode information; function mode emits a different result shape. The whole-file distance code has a 1 MiB bound for certain distance modes. That bound must not be misreported as a universal cap on all function matching. [Pinned CLI source](https://github.com/rizinorg/rizin/blob/v0.9.1/librz/main/rz-diff.c), blob `3be455f898e91b906ed2d2307060f41c0833450e`.

### 6.2 Appropriate use

**[A]** Raw bytes can expose a scalar edit lost by broader normalized representations, but also respond strongly to relocation/layout. This makes rz-diff useful as a separately extracted observation or a targeted two-function/block comparison, with its selection limitations exposed. A raw similarity cutoff cannot by itself distinguish moved addresses from a security patch. Rizin-derived boundaries provide a different extractor perspective; they can also miss or merge functions, so disagreement must remain visible.

**[A]** A Levenshtein pair can take `O(L_a × L_b)` dynamic-programming work in the generic worst case; prefix/suffix shortcuts, equality checks, memory optimizations, and actual length distributions matter. If every old function scans every new function, the similarity stage has `n×m` comparisons. The resulting `O(sum over pairs L_a L_b)` expression is an analysis bound, not a measured runtime or a claim that every pair reaches the worst case. Blocking and selected-function use are preferable for large residuals.

**[U,A]** The reviewed Rizin C files declare LGPL-3.0-only in their SPDX headers. Treat distribution of a selected executable and its dependencies separately from copying implementation code. A subprocess adapter preserves the existing architecture but does not remove notice/source obligations for a bundled tool. No model training/weights are involved. [Similarity notice](https://github.com/rizinorg/rizin/blob/v0.9.1/librz/arch/similarity.c), [CLI notice](https://github.com/rizinorg/rizin/blob/v0.9.1/librz/main/rz-diff.c).

## 7. QBinDiff: network alignment without representation training

### 7.1 Objective and capabilities

**[U]** The ASE paper formulates function correspondence as network alignment over call graphs, considering both node content and conserved call edges, and uses max-product belief propagation to approximate a solution. The repository exposes user features, anchored matches, similarity refinement, and a content/graph tradeoff. [Paper](https://arxiv.org/abs/2112.15337), [repository](https://github.com/quarkslab/qbindiff), [similarity docs](https://diffing.quarkslab.com/qbindiff/doc/source/features.html). Calling this a machine-learning approach does not mean it uses a learned neural encoder or needs a GPU/training set.

**[A]** A useful conceptual objective is `alpha Σ s_ij x_ij + (1-alpha) Σ A_ik B_jl x_ij x_kl`, under injective matching constraints and any anchors. This expression explains why two individually weak candidates can reinforce each other if their call edges agree. It is not a line-for-line transcription of every normalization, regularizer, or acceptance rule in QBinDiff. The quadratic objective is different from PatchTrace P19's additive assignment, and neither objective certifies historical identity.

**[U]** Upstream similarity features operate on the exporter-provided function attributes; the CLI supports BinExport/Quokka/IDA loader choices and architecture modes. The generic aligner can handle other attributed graphs. The normal binary output is **function correspondence**, not learned instruction-level deltas. Writing a `.BinDiff` container does not prove that QBinDiff computed BinDiff's block/instruction alignment. [README](https://github.com/quarkslab/qbindiff/blob/main/README.md), [differ API](https://diffing.quarkslab.com/qbindiff/doc/source/api/differ.html).

### 7.2 Actual resource behaviour and rejection

**[U]** `Matcher` accepts `sim_matrix`, sorts/masks it to form CSR, constructs a squares matrix between candidate edges, runs belief propagation, and refines missing assignments with LAP. The source docstring states a squares construction cost in terms of sparse candidate count and average graph degree squared; this is an upstream characterization, not a general bound on every stage. [Matcher source](https://github.com/quarkslab/qbindiff/blob/main/src/qbindiff/matcher/matcher.py), blob `b6be1546b9c97735bd106b2c322ee60b607e03af`.

**[U,A]** Sparsification occurs *after* access to the initial dense similarity array. Residual refinement calls `.toarray()` and `solve_linear_assignment` allocates a square matrix padded to the larger side. Zero-score entries are assigned a very high cost, but the routine still returns an assignment for the smaller side; that is not the same as semantic rejection. At 60,000×60,000 entries, even one float32 array is 14.4 GB decimal before masks, sorting indices, graph matrices, or solver workspace. This number is arithmetic (`60,000² × 4`), not a measured QBinDiff peak RSS. [Source](https://github.com/quarkslab/qbindiff/blob/main/src/qbindiff/matcher/matcher.py).

**[U]** Upstream itself warns that graph alignment is memory-intensive, recommends caution above roughly 10,000 functions, and suggests very high sparsity for large inputs. It also says tuning is often necessary and does not claim to be faster than other differs. [README](https://github.com/quarkslab/qbindiff/blob/main/README.md), [sparsity discussion](https://diffing.quarkslab.com/qbindiff/doc/source/params.html). **[A]** Use it on a capped residual or curated experiment, with explicit resource limits and retention of unassigned/low-quality results. Do not import its full-assignment semantics into PatchTrace.

### 7.3 What to transfer

**[L,A]** PatchTrace already transfers the most operationally useful parts: custom features, exact anchors, blocked candidates, assignment, and rejection. The genuinely unimplemented experiment is *bounded topology-aware score refinement inside the candidate graph*. Start with one deterministic damped update from already accepted non-hub neighbours; compare against unchanged P19 and a simple rarity-weighted Jaccard score. Only investigate iterative belief propagation if that first update yields a measurable gain on development data.

**[A]** Topology can reward a coherent but wrong mapping of duplicated subsystems. Hub callees, missing indirect calls, new wrappers, and inlining alter graph conservation. Keep anchors fixed, limit contribution from common neighbours, log iterations, bound candidate/square counts, and abstain on ties. Raw floating-point convergence differences should not leak into an allegedly byte-identical core output; a separately fingerprinted optional engine is a safer experiment than redefining deterministic ladder semantics.

**[U]** Project metadata declares Apache-2.0 and lists NumPy/SciPy, native build components, Capstone, graph/LSH packages, exporter wrappers, and platform-specific LAP packages. Dependency licenses and binary availability must be checked separately. No pretrained weights are inherent to the reviewed solver. [Project metadata](https://github.com/quarkslab/qbindiff/blob/main/pyproject.toml), blob `187d2682b46c3b430bb958fcf25845873dd4ada9`.

## 8. Representation-learning methods

### 8.1 DeepBinDiff: program-wide block embeddings

**[U]** The NDSS 2020 paper combines normalized opcode/operand token representations with interprocedural CFG context. It merges the two graphs, uses TADW for block embeddings, then a k-hop greedy matching procedure. Its stated target is unpacked stripped binaries on the same architecture; x86 is implemented and cross-architecture IR support is future work. This is **basic-block correspondence across a binary**, which can express movement/inlining patterns more naturally than function-only nearest neighbours. [Paper §§II–VI](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24311-paper.pdf).

**[U]** The released repository differs operationally: it uses angr, requires TensorFlow 1.14–<2, gensim/networkx/lapjv, reports CPU-only use, trains token embeddings on the two inputs on the fly, and prints block-index pairs mapped through `output/nodeIndexToCode`. It explicitly says no pretrained model is required. [Official README](https://github.com/yueduan/DeepBinDiff/blob/master/README.md). This corrects an overly broad reading of “needs a trained pipeline” in the old note.

**[U]** The paper's evaluation instead reports a once-trained token model, with approximately 16 hours of training in that setup. It reports average graph preprocessing of 8.2 seconds using IDA and average TADW embedding generation of 591 seconds per binary diff; those are historical component timings from its dataset and implementation, not desktop PE timing targets. The released README's on-the-fly training cannot be assumed to have that same cost. [Paper §VII-E](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24311-paper.pdf).

**[A]** The attractive idea is context-rich **block candidates**, not adoption of an old ML stack wholesale. Matrix factorization, graph merging, per-pair training, stochastic walks, and block recovery make deterministic offline deployment expensive to validate. It also normalizes constants/registers, so matching blocks cannot establish that an operand edit is cosmetic. Benchmark against current P17 block votes and facts alignment, and count false block matches from boilerplate. BSD-3-Clause code licensing is clear; the accompanying binaries/dataset still need their own provenance/redistribution inventory. [Code license](https://github.com/yueduan/DeepBinDiff/blob/master/LICENSE).

### 8.2 Gemini: attributed-CFG graph embeddings

**[U]** Gemini learns a function vector from an attributed CFG using a structure2vec-style recursive node update and aggregation. A Siamese training setup makes functions with matching labels close. It supports cross-platform similarity through the chosen features/training data; it emits a function similarity representation rather than an instruction map. [Paper](https://arxiv.org/pdf/1708.06525), [model implementation](https://github.com/xiaojunxu/dnn-binary-code-similarity/blob/master/graphnnSiamese.py).

**[U]** The original public implementation uses Python 2.7 and TensorFlow 1.4; it includes training/evaluation code, data, and a saved-model directory. Source is BSD-3-Clause. [README](https://github.com/xiaojunxu/dnn-binary-code-similarity/blob/master/README.md), [license](https://github.com/xiaojunxu/dnn-binary-code-similarity/blob/master/LICENSE). The paper's “30 minutes” training statement is for an effective five-epoch model in its setup; it separately says best performance uses substantially longer training, below ten hours. Do not turn the short headline into a universal training budget. [Paper §4.4](https://arxiv.org/pdf/1708.06525).

**[A]** CFG message passing can use existing PatchTrace graph features, but a Python2/TF1 prototype is an experimental dependency migration project, not a drop-in Windows component. A small GNN with opcode histograms is a fairer controlled experiment than assuming hand-engineered Gemini features are optimal. Graph aggregation can conflate locally similar structures and is exposed to extractor CFG errors. Cross-platform claims need the actual checkpoint/training support; they are not proof that any x64 checkpoint generalizes to MSVC PE.

### 8.3 SAFE and SAFEtorch: sequence embeddings

**[U]** SAFE maps normalized assembly instructions to instruction vectors, models their sequence with a bidirectional GRU, then applies self-attention and projection to obtain a function embedding. This avoids requiring a CFG for the neural encoding. The paper's prototype truncates functions at 150 instructions and trains separate instruction models for ARM and AMD64; a long function's omitted tail is an actual information limit. [Paper §§4–5](https://arxiv.org/pdf/1811.05296).

**[U]** The original README downloads both an instruction-to-vector model and a frozen AMD64 TensorFlow function model; it relies on radare2 for the quickstart. Inference therefore requires provisioning model *and* vocabulary/embedding artifacts, even though no local retraining is necessary for that checkpoint. [Original README](https://github.com/gadiluna/SAFE/blob/master/README.md). SAFEtorch provides a PyTorch implementation, model archive, and function-embedding example; it states x86 and ARM support and uses an MIT license. [SAFEtorch README](https://github.com/facebookresearch/SAFEtorch/blob/main/README.md), [license](https://github.com/facebookresearch/SAFEtorch/blob/main/LICENSE).

**[U,A]** Licensing must be recorded precisely: original SAFE's root `LICENSE` file contains only a copyright notice, but `neural_network/SAFEEmbedder.py` explicitly declares GPL3, and the Cisco derivative identifies its imported SAFE source as GPLv3. This is not evidence that original SAFE is permissively licensed. SAFEtorch's own MIT source license is clearer, but the reviewed model download has no separately verified weight/dataset terms or checksum manifest here. [Original license](https://github.com/gadiluna/SAFE/blob/master/LICENSE), [source header](https://github.com/gadiluna/SAFE/blob/master/neural_network/SAFEEmbedder.py), [Cisco notices](https://github.com/Cisco-Talos/binary_function_similarity/blob/main/README.md).

**[A]** SAFEtorch is a reasonable low-complexity neural baseline after package/model provenance checks, especially for residual function candidate ranking. It is less suitable as a final identity authority: sequence truncation, OOV vocabulary, constant normalization, common prologues, and changed block order all matter. A patch located after the sequence limit could have no influence on its vector; it must still be inspected by the ordinary facts channels.

### 8.4 Asm2Vec: learned function vectors with iterative query inference

**[U]** Asm2Vec extends paragraph-vector-style learning with assembly operations/operands and sampled instruction sequences. It learns token and repository-function vectors without supervised pair labels, then estimates a new query's function vector while holding learned token vectors fixed; cosine supplies search ranking. The paper explicitly observes that a query can rank its own repository function first without cosine 1, because the query vector is inferred while the stored vector was trained. This is unusually direct evidence that vector similarity is not byte identity. [Author-hosted paper §§4–5](https://dmas.lab.mcgill.ca/fung/pub/DFC19sp.pdf).

**[U]** The authors' Kam1n0 v2 platform publicly lists Asm2Vec applications and is Apache-2.0 at the platform level. The authors' presentation lists same-processor-family and interpretability/static-recovery limitations. This updates the old “original not open” shorthand; it does **not** prove exact equivalence between every public release and the 2019 experimental implementation. [Kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community/blob/master2.x/README.md), [platform license](https://github.com/McGill-DMaS/Kam1n0-Community/blob/master2.x/LICENSE.txt), [author slides](https://www.ieee-security.org/TC/SP2019/SP19-Slides-pdfs/honghui_ding_-_05-Steven_Ding-Asm2Vec_Boosting_Static_Representation_Robustness_for_Binary_Clone_Search_against_Code_Obfuscation_and_Compiler_Optimization_.pdf).

**[U]** Cisco's independent reproduction documents random-walk preprocessing, a modified Gensim 3.8 implementation, separate training and inference modes, and inference epochs that update only function weights. It is an auditable research implementation, with Gensim's LGPL-2.1 dependency distinguished from the repository's MIT wrapper. [Implementation notes](https://github.com/Cisco-Talos/binary_function_similarity/blob/main/Models/Asm2vec/README.md), [license inventory](https://github.com/Cisco-Talos/binary_function_similarity/blob/main/README.md).

**[A]** Advantages are unsupervised corpus learning and a CPU-friendly experimental route. Costs are per-query iterative optimization, vocabulary dependence, stochastic walks, and potential drift when the corpus changes. Cache keys need corpus/model and inference settings, not only binary hash. It is a candidate-search baseline, not a whole-binary one-to-one matcher; a postprocessing assignment cannot transform a vague clone score into historical truth.

### 8.5 jTrans: jump-aware Transformer plus contrastive fine-tuning

**[U]** jTrans injects direct-jump information into a BERT-style Transformer by tying jump-target token and position representations. Pretraining combines masked language modelling and jump-target prediction; supervised contrastive fine-tuning brings positive functions together and separates negatives. It represents individual functions and uses cosine for similarity. Direct jumps are covered; indirect-jump target recovery is explicitly outside the paper's scope. [Paper §§4,7](https://arxiv.org/pdf/2205.12713).

**[U]** The official repository provides code and externally hosted model/data archives. Its documented prerequisites are Linux, Python 3.8+, PyTorch/CUDA, and IDA Pro for preprocessing; it explicitly does not officially support Windows or macOS. Code is MIT. [README](https://github.com/vul337/jTrans/blob/main/README.md), [license](https://github.com/vul337/jTrans/blob/main/LICENSE). BinaryCorp is sourced from Linux projects/builds; the paper's reported 10,000-candidate retrieval evaluation is useful scale evidence, not adjacent MSVC patch-pair validation. [Paper](https://arxiv.org/pdf/2205.12713).

**[A]** This is a more relevant contrastive/Transformer reference than treating “Transformer” as a stand-alone matching algorithm. Contrastive *loss* determines what should be invariant; the architecture alone does not guarantee robustness. Compiler variants of one source function are sensible positives for identity retrieval, but vulnerable/fixed revisions can also become close, which is useful for correspondence and dangerous for change suppression. Start as an optional external residual reranker. Weight/data licensing, archive digests, tokenizer compatibility, CPU latency, and Ghidra-to-IDA preprocessing equivalence remain unresolved here.

### 8.6 TREX: training from traces, static inference

**[U]** TREX learns approximate execution semantics from forced-execution traces with masked-modality pretraining, then fine-tunes for function similarity. At inference it uses static instructions and does not execute the target function. Its reported architecture coverage includes x86/x64, ARM, and MIPS. [Author-hosted paper §§1–2](https://www.cs.columbia.edu/~suman/docs/similarity.pdf). This distinction prevents two errors: describing it as purely static *training*, or assuming it must execute every analysis target.

**[U]** The public implementation uses PyTorch, recommends a GPU environment, links pretrained parameters/datasets, and includes separate pretraining and fine-tuning preparation scripts; source is MIT. [README](https://github.com/CUMLSec/trex/blob/main/README.md), [license](https://github.com/CUMLSec/trex/blob/main/LICENSE). **[A]** Provisioned weights could support offline static inference, but reproducing the forced-execution training pipeline is outside PatchTrace's no-target-execution policy. Do not run it on user binaries to create training traces. Any evaluation must use already authorized datasets/features and separately reviewed preprocessing.

### 8.7 GNN encoders versus pairwise graph matching networks

**[U]** The Cisco/Talos measurement compares reusable graph embeddings with Graph Matching Networks whose representations depend on *both input graphs*. It finds strong results for graph models using simple opcode features, while emphasizing reproducibility and differing cost profiles. A pairwise GMN can score a pair well but cannot be assumed to provide one reusable vector per function for a global nearest-neighbour index. [Paper §§3–5](https://www.usenix.org/system/files/sec22-marcelli.pdf), [released implementations and license notes](https://github.com/Cisco-Talos/binary_function_similarity).

**[A]** This suggests a two-stage learned experiment: reusable embedding retrieval for candidate recall, then a pairwise graph reranker for a small shortlist. Its score must still pass explicit abstention/assignment policy. This is a proposed architecture, not demonstrated improvement; the current deterministic token/MinHash generator is the required baseline.

## 9. Cross-method operational comparison

### 9.1 Granularity and practical role

| Method | Native evidence/output | Training/weights needed | Sensible PatchTrace role | Principal failure class [A] |
|---|---|---|---|---|
| Exact raw/typed normalized keys | Function or BB equality under declared representation | None | Main conservative ladder; raw/typed facts retain edit evidence | Duplicate bodies, boundary mistakes, representation collisions |
| Ghidriff/VT | Function/data associations and correlator provenance; decompiler/text diffs in Ghidriff | No external neural checkpoint for classical correlators | Existing engine and source evidence | Shared Ghidra extraction, early weak match, nonexclusive associations |
| BSim | Function feature neighbours, data-flow similarity | Ghidra feature/weight configuration; no new neural training requirement asserted | Existing semantic-similarity comparison | Decompiler failure, small similar functions, true edits normalized away |
| BinDiff | Function, BB, instruction correspondence and algorithm scores | None | Existing oracle/secondary result | Weak tail, compiler structural changes, shared exporter dependencies |
| rz-diff | Raw-byte function score; graph mode BB pairs/opcodes | None | Separate extraction/targeted comparison | Address noise, all-pairs cost, pinned selection/nonexclusive behaviour |
| QBinDiff | Function network alignment | No learned weights inherent | Capped graph-alignment experiment | Dense allocation, forced residual assignment, graph symmetry/hubs |
| DeepBinDiff release | Binary-wide BB pairs | On-the-fly training, no pretrained model | Research block-candidate experiment | Per-pair cost, stochastic context, CFG recovery, normalization |
| Gemini/GNN | Function vector from attributed CFG | Trained encoder | Residual retrieval baseline | CFG/feature distribution shift and pooling collisions |
| SAFE/SAFEtorch | Function vector from normalized instruction sequence | Token vocabulary/i2v and function weights | Simple neural retrieval baseline | Truncation/OOV, instruction ordering, small/template functions |
| Asm2Vec | Learned/inferred function vector | Corpus training; iterative query inference | Unsupervised clone-search baseline | Corpus drift, stochastic inference, family-specific assembly |
| jTrans | Function vector with direct-jump-aware attention | Pretrained/fine-tuned checkpoint/tokenizer | Optional contrastive Transformer reranker | Domain shift, token budget, indirect jumps, Linux/IDA assumptions |
| TREX | Function embedding with trace-trained knowledge | Pretrained/fine-tuned weights | Optional static-inference experiment | Training provenance, domain shift, resource and preprocessing burden |
| Pairwise GMN | Pair-dependent graph similarity | Trained model | Shortlist reranking only | Per-pair cost; no globally cacheable embedding assumption |

The upstream facts underlying this table are cited in §§4–8; “role” and failure predictions are our synthesis. No row establishes deployed compatibility or comparative accuracy on PatchTrace's corpus. **[A]**

### 9.2 Complexity: compare stages, not slogans

Let `n,m` be function counts, `B,E` block/graph size, `L` sequence length, `d` embedding width, `K` retained candidates, and `T` iterations. **[A]**

| Stage | Qualified cost analysis | What must be measured |
|---|---|---|
| Build exact byte/instruction keys | `O(total bytes/instructions)` for streaming keys; sorted deterministic bookkeeping adds sorting | Extractor/IO time, hashing, peak memory, duplicate bucket sizes |
| Multiset mnemonic key | General sort-based implementation `O(I log I)`; a bounded-vocabulary counter can differ | Whether computation is material beside extraction |
| Generic raw edit distance | Worst-case `O(L_a L_b)` per pair; equal/prefix/suffix shortcuts change actual work | Number of expensive pairs, lengths, allocation/reads |
| Existing blocked assignment | Per component roughly cubic for balanced dimensions; actual implementation `O(rows² × columns)` | Component size distribution, dummy columns, deadline/cap abstentions |
| Sparse topology refinement | Depends on retained candidate edges and candidate-edge “squares,” with iterations multiplying work | Candidate/square counts, high-degree tails, convergence and tie stability |
| Reusable embedding encoder | Depends on model; GNN roughly repeated edge aggregation plus dense layers; GRU sequence work; dense attention includes an `L²` attention term | Extraction, loading/warmup, CPU/GPU batch throughput, long-input policy |
| Search embedding matrix | Exhaustive cosine is `O(nmd)`; vector caching does not remove all-pairs search | ANN index build/query cost and independently measured recall |
| Pairwise reranker | A model invocation per candidate pair rather than a single vector per function | Total candidate pairs, batching, resource cap behaviour |

These are analytic descriptions under their stated representations, not formal bounds on complete upstream tools. Approximate search may improve speed while dropping the true candidate; random seeds, index implementation, and hardware also affect reproducibility. The correct budget includes decoding, feature extraction, model load, inference, retrieval, assignment, and evidence reconstruction. **[A]**

### 9.3 Licenses, models, and corpora are separate artifacts

| Component | Code evidence verified | Weights/corpus status in this investigation |
|---|---|---|
| Ghidriff / Ghidra | GPLv3 / reviewed Ghidra files Apache-2.0 | No separate learned weights required for classical VT; symbol/source/tool dependencies remain separately provisioned |
| BinDiff | Apache license in upstream README; GUI yFiles is commercial | No training weights; exporter/disassembler and GUI dependency terms separate |
| Rizin files read | SPDX LGPL-3.0-only | No training weights |
| QBinDiff | Apache-2.0 project metadata; some dependencies have their own notices | No learned weights required; do not treat dependency graph as a single Apache artifact |
| DeepBinDiff | BSD-3-Clause | Release trains on pair; supplied experimental binaries/corpora need an inventory |
| Gemini original implementation | BSD-3-Clause | Saved model/data exist in repo; no separately validated corpus/weight provenance manifest |
| SAFE original | GPL3 file header; root license file is incomplete as a license grant | Model download exists; no independently verified archive terms/digests here |
| SAFEtorch | MIT | External model archive; code license alone is not a documented grant for every training binary/model asset |
| Asm2Vec/Kam1n0 | Platform Apache-2.0; Cisco reproduction MIT with LGPL Gensim dependency | Implementation equivalence and chosen training repository require explicit records |
| jTrans | MIT source | External BinaryCorp and model archives; per-project binary licenses and weight terms not verified |
| TREX | MIT source | Externally linked weights/traces/data; terms/digests not verified |
| Cisco reproduction suite | MIT top level, with explicit GPL/Apache/LGPL/CC-BY-NC-SA exceptions | Do not vendor whole suite under its top-level label; binaries have a separate LICENSES directory |

License URLs accompany each component in §§4–8. **[A]** Offline feasibility means a fully provisioned, hash-pinned runtime can process local features without network. It does not imply a right to redistribute every checkpoint/corpus, or that an upstream download script is offline. A future model bundle needs architecture coverage, tokenizer/normalizer version, exporter fingerprint, checkpoint digest, dependency notices, local-only execution, memory/time limits, and a documented invalid/missing-model fallback. This is an engineering acceptance list for an actual proposed model, not a new permission gate for this research.

## 10. Small reproducible experiments in this subtask

Only importable pure Python functions and hand-constructed bytes/matrices were exercised. No target was executed, no external runtime/model installed, and no corpus or locked evaluation was accessed. These observations are **not an accuracy benchmark**. Command run at the stated baseline: `PYTHONPATH=src python -` with this input:

```python
from patchtrace.unified.ir.features import KeyStream, sequence_key, multiset_key
from patchtrace.unified.ir.operands import (
    OperandFacts, VK_SCALAR, STATE_LOCATED, mask_instruction,
)
from patchtrace.unified.ladder.assign import assign_with_rejection

old, new = bytes.fromhex('83 ff 40'), bytes.fromhex('83 ff 41')
def key(raw):
    stream = KeyStream()
    stream.add(raw)
    return stream.value()
def facts(value):
    return OperandFacts(VK_SCALAR, value, 2, 1, STATE_LOCATED, ())
for level in (1, 2):
    a = mask_instruction(old, [facts(64)], level)
    b = mask_instruction(new, [facts(65)], level)
    print(level, a.hex(), b.hex(), key(a) == key(b))
a, b = ['MOV', 'CMP', 'JNZ', 'RET'], ['CMP', 'MOV', 'JNZ', 'RET']
print(sequence_key(a) == sequence_key(b), multiset_key(a) == multiset_key(b))
print(assign_with_rejection([[900, 800], [850, 0]], floor=600))
for j in (0.2, 0.5, 0.8, 0.9):
    print(j, 1 - (1 - j**4)**4)
```

Observed output/effect **[E]**:

| Probe | Observation | Interpretation [A] |
|---|---|---|
| L1 masking of `83 ff 40` versus `83 ff 41` with supplied scalar facts | `83ff40` versus `83ff41`; keys unequal | Located scalar difference is retained by the current L1 policy |
| L2 masking of the same bytes/facts | Both `83ff00`; keys equal | Lossy equality is expected and useful for pairing; it cannot justify “unchanged” |
| Reordered mnemonic lists | Sequence keys unequal; multiset keys equal | Histogram equality removes order; it is not proof of semantic equivalence. No claim that these lists are valid whole functions is needed |
| Rejection assignment | `[1, 0]` | Global sum prefers the 800/850 edges over taking 900 then rejecting the second row. An optimal sum can choose a row's second-best candidate; acceptance margins are a separate policy |
| Ideal independent MinHash, 4×4 bands, Jaccard .2/.5/.8/.9 | .0063846564 / .2275238037 / .8784974493 / .9860128670 | This is a calculation under ideal MinHash independence, **not measured recall of PatchTrace's concrete hash family or combined blocker** |

The ideal band formula is `P(at least one band collision)=1-(1-J^r)^b`, derived by requiring all `r` rows of a band to collide, then taking the complement of no collision in `b` independent bands. At `J=.5`, the MinHash route alone is therefore far from certain. PatchTrace also admits shared-reference/string/import candidates and caps candidates/buckets, so actual combined recall can be higher *or* cap-limited. Measure each route and its union rather than select bands from this calculation alone. **[A]**

## 11. Improvements justified for evaluation, with explicit deltas

These are ordered experiments, **not permission to change the persisted contracts or release policy**. The parent R2 work owns actual benchmark execution/integration. All acceptance criteria must use development data until the evaluation protocol permits its final holdout.

| Priority / experiment | Specific difference from current code | Why it follows from research | Required evidence before adoption |
|---|---|---|---|
| P0: candidate-loss accounting | Add research-side tracing of truth edges before/after token admission, MinHash, size split, bucket cap, directional top-K, and residual eligibility | Existing top-K/LSH is a recall bottleneck; no solver can restore pruned edges | Per-generator and union recall, cap-abstention counts, timing/memory; separate matched/unmatched and tiny/ICF strata |
| P0: per-pass identity/materiality audit | Evaluate pairing correctness and edit visibility separately for P04/P05 versus P06–P10 and residuals | VT/BSim/learned abstractions deliberately discard change information | Pair precision plus constant/register/target/branch-edit recall; explicitly count false cosmetic suppression |
| P1: rarity-weighted P19 score | Replace only plain token-set Jaccard in the experimental P19 scorer with a deterministic rarity-weighted variant; P16 already has weights | Common boilerplate should not outweigh a rare reference; QBinDiff motivates feature control | Paired ablation on identical candidates; calibration/precision and abstention effects; no use of a raw score as probability |
| P1: topology from trusted neighbours | One bounded, damped score term from existing non-hub accepted neighbours, within current candidates | Network-alignment evidence can resolve locally ambiguous near-clones | Gain beyond rarity alone; poisoned-anchor and symmetric-subsystem negative controls; deterministic output/resource bound |
| P1: rejection/margin audit | Compare assignment objective gain with reciprocal alternatives and dummy rejection; do not remove current rejection | QBinDiff residual LAP and the toy example expose forced/second-choice mapping risks | Added/removed functions, uneven sides, equal candidates, false identity versus abstention; report both coverage and false matches |
| P2: BSim versus simple learned residual retrieval | Compare existing BSim and one explicitly provisioned SAFEtorch or simple graph encoder on the *same residual truth set* | BSim already supplies an offline semantic similarity baseline | Candidate recall@K, accepted precision, extraction/model startup and CPU throughput, missing-model behaviour, license/provenance completeness |
| P2: jTrans/GMN reranking | Score a bounded shortlist as separate optional evidence, preserving main ladder decisions | Contrastive/jump/context features can help under compiler drift, pairwise models cost more | Ghidra/IDA preprocessing sensitivity, small-function and near-clone negatives, out-of-domain MSVC results, tail/truncation coverage |
| P3: DeepBinDiff-style block context | Experimental block candidates or one graph-context feature, benchmarked against current P17 | Whole-program BB context can survive function reorganization | Correct block edges and grouping versus false boilerplate matches, pair-training/runtime budget, deterministic repeatability |

**[A]** Do not promote a method because it finds more pairs. A forced incorrect mapping can hide an actually added function and simultaneously erase a removed function. Report unmatched coverage, competing hypotheses, and wrong-pair rate; evaluate identities and N:M containment separately. Correctness on one-to-one compiler variants does not establish behaviour on an inlined old function, one-to-many clones, identical thunks, or folded COMDAT aliases.

**[A]** For learning experiments, partition by source lineage/project before fitting model/thresholds, deduplicate exact and normalized clones across splits, and retain compiler/optimization/architecture metadata. Positives labelled by symbols alone need alias/ICF adjudication. Include hard negatives that share boilerplate or a similar name but differ in checks/targets. The Cisco study's controlled filters and jTrans's pool-size experiments are reasons to document these choices, not substitute benchmarks. [Cisco paper](https://www.usenix.org/system/files/sec22-marcelli.pdf), [jTrans paper](https://arxiv.org/pdf/2205.12713).

**[A]** Deterministic core acceptance requires more than `seed=0`: normalize traversal order; fix tokenization, vocabulary, model/checkpoint, device/runtime, precision and BLAS/thread settings; disable training/dropout at inference; record truncation/OOV/missing-feature rates; define stable ties and abstention bands. GPU/parallel floating-point output may still differ across platforms. Keep model evidence versioned and optional until repeat runs and cross-platform comparisons demonstrate the intended reproducibility. Quantization can stabilize score representation but cannot retroactively make different near-tie rankings equivalent.

## 12. Source ledger and unresolved evidence

The following are selected exact **file-content identities returned by the GitHub connector** on 2026-10-30. Branch/tag is part of the observation. These values allow later content verification, but a blob SHA must not be passed off as a repository checkout SHA.

| Repository / ref / path | Blob SHA-1 |
|---|---|
| `clearbluejar/ghidriff` `main` `ghidriff/version_tracking_diff.py` | `06b181b83ddadf577c0da01fa04a4d4842be5839` |
| same, `ghidriff/ghidra_diff_engine.py` | `4c6f5c975571b067ccc223288c78b2b11280d06c` |
| same, `ghidriff/implied_matches.py` | `41e5b04883a87743f6010c178470e2f11d32d2a9` |
| `NationalSecurityAgency/ghidra` `master` `.../VT_Correlators.html` | `27d94971a20d3644cc4e6538ceeaa794ff482a0a` |
| same, `.../ExactInstructionsFunctionHasher.java` | `309680b2ecfef1c7871ced655f6e52477895e373` |
| same, `.../BSim/BSimOverview.html` | `84efd801764e4e5c9e81ed30dcad818898bab3d0` |
| `google/bindiff` `v8` `docs/concepts.md` | `41888698b0433fc0b0026ea14161f05c5dfca6cf` |
| same, `differ.cc` | `c87bc1801fe4aa2c141674ddaf9b142e91ca8afc` |
| same, `database_writer.cc` | `7d2357d68683e8812fffaac1108016fa51c9a8d9` |
| same, `match/basic_block_call_refs.cc` | `6c5639ff2ed89b6511cd1e13f4ab0e019bd5d399` |
| `google/bindiff` `main` `README.md` | `50a88546db4598ee21f156a986f20c53547c5298` |
| `rizinorg/rizin` `v0.9.1` `librz/arch/similarity.c` | `8544259e17a692bcb3c1d8858f104745cd0cba4c` |
| same, `librz/main/rz-diff.c` | `3be455f898e91b906ed2d2307060f41c0833450e` |
| `quarkslab/qbindiff` `main` `src/qbindiff/matcher/matcher.py` | `b6be1546b9c97735bd106b2c322ee60b607e03af` |
| same, `pyproject.toml` | `187d2682b46c3b430bb958fcf25845873dd4ada9` |
| `yueduan/DeepBinDiff` `master` `README.md` / `LICENSE` | `fc0ed9be3b55aa2f76ca325008370ddc68529225` / `a0aab531f734fb3f2653f0fb5b2fb0be1b850f9d` |
| `gadiluna/SAFE` `master` `README.md` / `LICENSE` | `2a66b1b76f7eb2dc4cafe36218c88c64e6c0dced` / `8a914fa8590be854b2ee427bdbeb7d3c082b6433` |
| same, `neural_network/SAFEEmbedder.py` | `92e377c947b572da3d98b574c23bfdfe9099e8ed` |
| `facebookresearch/SAFEtorch` `main` `README.md` / `LICENSE` | `c41826636b9a1af04285d4d75a6cc9936196faa0` / `b96dcb0480a0b0be0727976e5202a1e7b23edc3f` |
| `xiaojunxu/dnn-binary-code-similarity` `master` `README.md` / `LICENSE` | `7b84108a4a1625b0ce95f645b7b55b467865d944` / `30e9e08a02ba34cda4d4aa081d0cff2f1ef2168f` |
| same, `graphnnSiamese.py` | `98bbc5ff6b006cdfc236369d33ed0ce6bf37ad04` |
| `McGill-DMaS/Kam1n0-Community` `master2.x` `README.md` / `LICENSE.txt` | `68462f39647d501e6e900025e7d63e582d3b0001` / `b9ae747ebcfab1295c79541c9b9f3a6ef419711e` |
| `vul337/jTrans` `main` `README.md` / `LICENSE` | `2676e36eafb121f1d240656f2e60aa5b7f00da58` / `9364b0a13feb2c1f0ce365979a2341e267fd4913` |
| `CUMLSec/trex` `main` `README.md` / `LICENSE` | `59fd894fbc72709c57e195111ea9ab43cac41c16` / `a58f3e7dc20883c44420768c7fce6ad3205b606d` |
| `Cisco-Talos/binary_function_similarity` `main` `README.md` | `991b4dfabe6e5ae07d6446ccf9678c4a805c41e6` |
| same, `Models/Asm2vec/README.md` | `633f3c7d856c39dd5d4c919a2158e7132b65c014` |

Primary papers/documents, with exact versions when visible:

- DeepBinDiff, NDSS 2020, DOI `10.14722/ndss.2020.24311`: [publisher PDF](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24311-paper.pdf).
- QBinDiff, ASE 2021: [arXiv `2112.15337v1`](https://arxiv.org/abs/2112.15337v1); [upstream parameters](https://diffing.quarkslab.com/qbindiff/doc/source/params.html), [similarity/features](https://diffing.quarkslab.com/qbindiff/doc/source/features.html), [differ API](https://diffing.quarkslab.com/qbindiff/doc/source/api/differ.html).
- SAFE, DIMVA 2019: [arXiv `1811.05296v4`](https://arxiv.org/abs/1811.05296v4), [PDF](https://arxiv.org/pdf/1811.05296).
- Gemini, CCS 2017: [arXiv `1708.06525v4`](https://arxiv.org/abs/1708.06525v4), [PDF](https://arxiv.org/pdf/1708.06525).
- Asm2Vec, IEEE S&P 2019: [author-hosted paper](https://dmas.lab.mcgill.ca/fung/pub/DFC19sp.pdf), [publisher record](https://ieeexplore.ieee.org/document/8835340/), [author presentation](https://www.ieee-security.org/TC/SP2019/SP19-Slides-pdfs/honghui_ding_-_05-Steven_Ding-Asm2Vec_Boosting_Static_Representation_Robustness_for_Binary_Clone_Search_against_Code_Obfuscation_and_Compiler_Optimization_.pdf).
- jTrans, ISSTA 2022, DOI `10.1145/3533767.3534367`: [arXiv `2205.12713v1`](https://arxiv.org/abs/2205.12713v1), [PDF](https://arxiv.org/pdf/2205.12713).
- TREX extended paper: [author-hosted PDF](https://www.cs.columbia.edu/~suman/docs/similarity.pdf); use the paper's exact version when reproducing numbers rather than mixing the earlier “Micro-Traces” title and extended results.
- Marcelli et al., USENIX Security 2022: [publisher page](https://www.usenix.org/conference/usenixsecurity22/presentation/marcelli), [paper](https://www.usenix.org/system/files/sec22-marcelli.pdf), [artifact repository](https://github.com/Cisco-Talos/binary_function_similarity).
- [Rizin official handbook](https://book.rizin.re/src/tools/rz-diff/binary_diffing.html).

**Unresolved [?:]** no repository-wide SHA was obtained for the moving-branch upstream reads; no external ML model was downloaded or executed; no proposed model's complete weight/corpus rights were established; no Windows embedding packaging/inference test ran; no new full BinDiff/Ghidriff/rz-diff runtime comparison was performed in this subtask; no target-specific accuracy or confidence interval follows from this literature review. These are explicit limits, not silent failures or evidence against any method.
