# R2 graph, residual assignment and scaling review

Date: 2026-10-30. Production baseline: `a04f5a299a8d4afef023261e52e08d14678cf1e7`.
Baseline experiments and reproducer: commit `79537ae`. These are synthetic algorithm experiments, not an independent corpus evaluation or evidence of real Windows matching accuracy. No target binary, Ghidra process, neural model or locked test set was executed.

## Findings and decisions

The implemented ladder already contains global structural keys, call-graph propagation, inverted-index candidate blocking and rejection-aware assignment. The earlier proposed `matching/*.py` architecture in SPEC-QB-01 is not the current implementation: SPEC-31 and `src/patchtrace/unified/ladder/` are authoritative for what ships. Neither a WL feature, a KOKA fingerprint, whole-graph belief propagation nor a sparse/min-cost-flow assignment backend is implemented in this path.

The exact path completed 100,000 functions per side in 3.430 s of ladder time and 250.6 MiB process peak RSS. A separately forced all-residual fixture completed 100,000 in 31.064 s and 1,116.1 MiB; this fixture's rare strings let P16 resolve every twin, so **it does not establish 100k LAP performance**. P19's actual solver was exercised on bounded ambiguous components and separately on matrices no larger than the production 200-row cap. A common-token-only 100k fixture emitted zero candidates because large buckets abstained, demonstrating the resource/recall tradeoff rather than high recall on difficult data.

Two concrete issues emerged. First, distinct, strongly connected CFGs have exactly equal production MD keys and produce a P10 tier-B ladder pair with no body evidence. This is a structural fingerprint collision, not a demonstrated final unified automatic match; fusion can retain a single structural opinion as tentative. Second, loop counting performed quadratic immediate-dominator ancestor walks even on an acyclic chain. The latter received a narrow semantics-preserving optimization after the baseline was committed and the root assigned `cfg.py` ownership. No ladder thresholds or match acceptance rules changed in this slice.

## Implemented mechanics versus research proposals

| Mechanism | Baseline implementation and limits | Research interpretation |
|---|---|---|
| Exact ladder | P01 imports, P02 exports, P03 trusted names; P04/P05 exact/masked hashes; P06-P09 progressively weaker body keys | Dictionary joins with uniqueness among unmatched pools; ambiguous buckets drill down through later keys in the same stage. Already implemented. |
| CFG structural key | P10 uses `(md_td, md_bu, n_bb, n_edge)` for content-eligible functions with at least 5 blocks | A compact necessary-condition heuristic, not a proof of isomorphism or identity. Loop count is not part of this key. |
| Call-graph structural key | P11 computes incident-edge MD at each vertex in forward/reverse graph orientations | Uses call sites, including repeated and self calls, for degrees/MD; neighbor propagation uses distinct non-self adjacency. Do not conflate the two graph representations. |
| Dominators | `ir/cfg.py::dominators` uses reverse-postorder iterative immediate dominators for reachable blocks | Implemented for ingest loop count; no dominator-tree matching pass exists. Its algorithm remains unchanged by the optimization below. |
| Propagation | After each stage, deterministic waves propose matches among unmatched callers/callees, resolve competing proposals, cast call-site votes, and propagate through thunks | Uses accepted matches as anchors; hubs with fan-in >64 are excluded as neighbors/voters; neighborhoods are truncated to 64 ascending FIDs. A/B accepts seed later waves; C remains soft until finalization. |
| Call-site votes | Ordered sites use unique imported/matched tokens to delimit positional gaps; equal-length compatible gaps vote; at least 2 conflict-free anchor votes give B | This is not CFG basic-block isomorphism or whole-callgraph optimization. The site limit is 512. |
| P12-P15 | String/import/constant sets with rarity/size guards; P15 rehashes using already matched call targets, up to 8 waves | Existing context-based refinement. Independent support is not implied merely by several pass names: evidence dependencies still matter in fusion. |
| P16 | Reference-vector cosine with confidence and margins in both directions, blocked candidate pairs only | Decimal logarithms, integer square roots and integer comparisons avoid ordinary float-score tie drift. Two feature types yield B; single-type results are soft C. |
| P17/P18 | Rare basic-block votes; bounded layout gaps between monotone accepted anchors | Soft C proposals, followed by final conflict checks. P18 is a positional heuristic and requires realistic reorder stress. |
| P19 | Jaccard similarity over blocking tokens; connected components above floor; dense integer shortest-augmenting-path assignment with reject columns | Already built. At most 200 functions per side per component; 30 s total LAP clock; score floor 600/1000 and two-sided margin 50/1000. Output remains soft C. |
| WL / KOKA | No executable pass in the unified source tree | Research candidates only. SPEC-QB-01's optional feature registry and global configurable optimizer are still proposed. |
| Sparse LAP / min-cost flow | No alternate backend in current `ladder/assign.py` | Possible bounded experiments, not a prerequisite justified by these measurements. |

Local primary evidence: `ladder/{engine,passes,propagate,blocking,residual,assign}.py`, `ir/{cfg,mdindex,ingest,features}.py`, `limits.py`, SPEC-31/04 and SPEC-QB-01. The actual default values are **20** candidates per direction, **300** blocking bucket members per side and **200** assignment rows/columns per side. The older research note's illustrative “k <= 300” is not the current assignment cap.

BinDiff's upstream concepts describe global uniqueness, drill-down, subsequent matching within caller/callee neighborhoods and function-reference propagation [S1]. That supports the ladder's ancestry; it does not provide PatchTrace accuracy evidence. QBinDiff's paper instead formulates content plus call-graph alignment as network alignment and uses max-product belief propagation [S2]. Current QBinDiff documentation also warns that workloads above 10,000 functions may exhaust memory [S3]. Transplanting a whole-image dense optimizer would discard the existing bounded-residual architecture without evidence of a compensating benefit.

## Candidate blocking, rejection and cost model

`blocking.py` builds tokens from matched callers/callees, import identities, rare strings/constants and, when a mnemonic source exists, four MinHash bands of four rows over mnemonic trigrams. Padding mnemonics `nop`/`int3` are removed for MinHash. A candidate requires at least two non-size tokens or a shared band. Size and block-count buckets contribute ranking but cannot generate a candidate alone. Oversized token buckets split first by instruction-count log2 bucket, then block-count log2 bucket; a still oversized bucket abstains.

Both directions rank top-20 candidates, then the union is retained so every function sees incoming rivals during margin tests. Thus **20 is not a bound on each final vertex degree**. The safe total bound is `K * (n_old + n_new)`, not `K * min(n_old, n_new)`. Shared bucket-member enumeration can be much larger than emitted candidate count, and MinHash work depends on shingle volume as well as function count. “Linear in functions” requires bounded per-function input/features and bucket caps; it is not a universal bound independent of function size.

P19 forms candidate connected components using only edges with similarity at least 600. Components over 200 members on either side abstain before a dense matrix is allocated. For an `r x c` matrix, rejection adds **r dummy columns**; every row can use a reject column at cost `1000 - floor`. Although the docstring says each row owns a dummy, the implemented dummies are identical shared columns; their number makes the two formulations equivalent. Real edge cost is `1000 - similarity`. The objective is therefore to maximize the total `similarity - floor` of selected real edges, permitting unmatched rows. A tie at the floor can be assigned, but the later 50-point margin check still applies. Candidate absence is represented by similarity zero inside the component, which costs more than rejection under the current floor.

The solver's measured work depends sharply on shape. It scans all real plus reject columns on each Dijkstra expansion: worst case `O(r^2(c+r))`, dense storage `O(r(c+r))`, bounded at the component level. Equal-cost matrices force many more expansions than strong diagonal matrices:

| Rows, real columns | Strong diagonal wall s / column scans | Equal-score wall s / column scans |
|---:|---:|---:|
| 20 | 0.000150 / 800 | 0.000634 / 8,400 |
| 50 | 0.000663 / 5,000 | 0.008937 / 127,500 |
| 100 | 0.002484 / 20,000 | 0.062781 / 1,010,000 |
| 200 | 0.010786 / 80,000 | 0.572721 / 8,040,000 |

Raw files: `results/graph-assignment-{20,50,100,200}.json`. Each solves twice in a fresh process, at floor 600, with diagonal 1000/off-diagonal 700 or every entry 1000. Identity wins ties deterministically. This table measures solver cost; equal scores would fail the ladder's later margin checks and do not justify accepted matches. No dense matrix at 1k, 10k, 50k or 100k was constructed.

Alternatives deserve distinct evaluation. SciPy's dense solver uses a modified Jonker-Volgenant algorithm [S4]. Its sparse LAPJVsp interface can use an edge graph, but requires a full matching of the smaller side, treats missing/zero edges specially and warns that tied outputs may vary across versions [S5]. To preserve PatchTrace rejection semantics, add one private reject edge per old row and keep a nonzero cost shift on every edge, including rejection; adding rejection only after solving a forced full real match is incorrect. A min-cost-flow representation can use unit source→old edges, unit old→new candidate edges, unit new→sink edges and unit old→sink reject edges, with total supply equal to the number of old rows [S6]. This is sparse and expressive, but introduces implementation/dependency and deterministic-tie obligations. None was installed or timed here. First measure real residual component distributions and candidate recall; a faster optimizer cannot recover a true pair pruned before assignment.

## Scale experiments

Environment: Linux 6.18.57 x86_64, glibc 2.39, Python 3.12.14, AMD EPYC 9V74 virtual host exposing 9 logical CPUs. Experiments are single-process/single-thread Python. CPU time uses `time.process_time`; wall time uses `time.perf_counter`. Peak RSS is Linux `resource.getrusage(RUSAGE_SELF).ru_maxrss / 1024`, in MiB, across the fresh child process lifetime including imports and fixture creation. It is not incremental solver allocation, Java heap, Windows RSS or tracemalloc. Timing is one local observation per shape/size, without CPU isolation or confidence intervals; other work could run on the shared host. CPU/wall values are both retained in raw JSON and agree closely in these runs.

`tools/research/r2_graph_benchmark.py` reuses `tests/unified_ir_builder.py` and `tests/unified_residual_support.py`. It does not create a second corpus/labeling framework. Root owns the whole-engine benchmark and release/gate assessment; these runs isolate algorithm shapes not covered by a single aggregate ladder time.

**Fast exact path.** Precomputed synthetic keys are unique on both sides; no calls, names or strings. All functions exceed tiny gates. This deliberately measures loading the function columns and matching P04, not instruction decoding, hashing, realistic graph propagation or ingestion. Hashes/rows are shared between fixture sides, reducing fixture memory relative to independently loaded real inputs. Full ladder table including P16-P19 runs, but residual pools are empty.

| Functions per side | Side construction wall s | Ladder wall s | Ladder CPU s | Whole experiment wall s | Peak MiB | Correct P04 pairs |
|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 0.0064 | 0.0161 | 0.0161 | 0.0251 | 29.2 | 1,000 |
| 10,000 | 0.0717 | 0.1843 | 0.1843 | 0.2791 | 51.4 | 10,000 |
| 50,000 | 0.5297 | 1.3027 | 1.3024 | 1.9729 | 141.3 | 50,000 |
| 100,000 | 1.4276 | 3.4303 | 3.4287 | 5.1357 | 250.6 | 100,000 |

**All-residual, selective twin tokens.** Existing `dense_world` shuffles the newer functions, changes all six body hashes, supplies three of ten common imports plus two unique twin strings, and `DenseMnemonics` mutates about 10% of each twin's mnemonic stream. Only P16-P19 are enabled, guaranteeing no earlier exact-key consumption. The private twin strings are intentionally an easy identity signal; mnemonic streams are generated from fixture truth. These results are not evidence of independent feature extraction quality.

| Functions per side | Ladder wall s | Ladder CPU s | Total wall s | Peak MiB | P16 candidates evaluated | Bucket-member visits | Block-cap abstentions |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 0.4452 | 0.4451 | 0.4865 | 53.4 | 26,068 | 1,074,550 | 0 |
| 10,000 | 4.5872 | 4.5866 | 5.1519 | 221.5 | 237,253 | 6,641,354 | 20 |
| 50,000 | 14.5634 | 14.5592 | 17.5611 | 608.7 | 224,090 | 5,638,272 | 160 |
| 100,000 | 31.0642 | 31.0503 | 36.8593 | 1,116.1 | 278,041 | 4,476,990 | 210 |

Every run completed and returned exactly n correct P16:B pairs, with no assignment-time-cap. P19's hook ran but no LAP buckets were solved: P16 consumed the eligible pool. Candidate counts decrease between some scales because additional common buckets cross abstention thresholds, while unique twin strings survive. Increasing n is not a constant candidate-shape stress test. The 100k RSS is below the 1.5 GiB worker limit, but leaves limited room for other concurrent pipeline structures; no whole-worker memory acceptance claim follows.

**Common-only blocking stress.** Remove the unique strings, provide no mnemonic source, and set identical instruction/block-count buckets. Common imports remain. This run measures `block()` directly, not all residual matching. At 1k some imports still fit the 300-member cap; at larger sizes all ten buckets abstain.

| Functions per side | Blocking wall s | Blocking CPU s | Candidates | Enumerated members | Abstained buckets | Process peak MiB |
|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 0.1167 | 0.1167 | 16,572 | 849,342 | 5 | 34.9 |
| 10,000 | 0.1492 | 0.1492 | 0 | 0 | 10 | 72.4 |
| 50,000 | 0.7822 | 0.7816 | 0 | 0 | 10 | 256.6 |
| 100,000 | 1.7798 | 1.7764 | 0 | 0 | 10 | 484.7 |

This is safe resource behavior with deliberate recall loss: all true twins exist, but no candidate survives at the three larger sizes. These functions must remain unresolved. Bounds are a correctness/UX issue as well as a performance issue, so retain cap diagnostics in reports.

**Actual ambiguous P19 components.** On the same common-only family at n=200 and n=300, run all four residual passes. The two-sided candidate union produced 5,727 and 9,321 candidates respectively. At 200, P19 solved one LAP component and marked 158 candidates ambiguous, accepting zero P19 pairs. P16 finalized 42 correct C pairs. At 300, P19 abstained on one oversized component and accepted zero; P16 finalized 26 correct C pairs. Thus solver invocation, margin rejection and component-cap abstention are all observed, with no fabricated 100k assignment claim. Some import triples are unique at these small scales and account for P16's C pairs.

## Per-pass ablations on an existing generated fixture

Use `generate_pair(1000, seed=1, changed=0.5, shifted=0.2, duplicates=0.01)` plus existing `GeneratedMnemonics`. Truth has **992 pairs**, with additions/deletions and reordered functions. Baseline finds 985 correct pairs, zero wrong; recall against this generator's truth is 985/992, not real-binary accuracy. The baseline's source counts are P03 206, P04 225, P05 155, P06 95, P09 178, P10 37, P11 2, P16 1, P18 20, P19 1 and PV 65. P16/P18/P19 and six PV pairs are C; 59 PV pairs are B. P19 actually evaluates 25 candidates and solves one component here.

| Removed pass/mechanism | Final correct pairs | Change versus 985 | Interpretation on this fixture |
|---|---:|---:|---|
| P01 | 985 | 0 | No eligible external-import anchors in this generator. |
| P02 | 985 | 0 | No export map supplied; does not test export quality. |
| P03 | 982 | -3 | Other passes absorb most named anchors. |
| P04 | 985 | 0 | P05 absorbs all 225 P04 pairs. |
| P05 | 982 | -3 | Weaker body/structural passes recover most pairs; P15 adds one. |
| P06 | 985 | 0 | P07 absorbs 95 pairs. |
| P07 | 985 | 0 | No baseline exclusive yield. |
| P08 | 985 | 0 | No baseline exclusive yield. |
| P09 | 985 | 0 | P10 absorbs much of the loss; provenance shifts sharply. |
| P10 | 984 | -1 | P16/P19/PV recover 36 of 37 baseline P10 pairs in aggregate. |
| P11 | 985 | 0 | PV rises by two. |
| P12 | 985 | 0 | No exclusive yield in this fixture. |
| P13 | 985 | 0 | No exclusive yield in this fixture. |
| P14 | 985 | 0 | No exclusive yield in this fixture. |
| P15 | 985 | 0 | No baseline exclusive yield. |
| P16 | 985 | 0 | P18 rises by one. |
| P17 | 985 | 0 | Generator lacks explicit block-vote evidence. |
| P18 | 977 | -8 | PV recovers some lost layout proposals. |
| P19 | 985 | 0 | PV rises by one. |
| All propagation waves | 956 | -29 | P16/layout/rehash grow, but do not recover everything. |
| P16-P19 together | 976 | -9 | PV rises from 65 to 78; final C conflict set changes. |
| P10 and P11 together | 984 | -1 | Aggregate graph-only incremental yield is small here. |

All 23 runs have zero wrong pairs and complete status; raw `graph-ablation-00..22.json` retain pass/tier counts, candidates, hook times and limits. Leave-one-out results are not independent causal contributions: earlier accepts shrink later pools, drill-down changes, propagation changes, and C proposals compete at finalization. In particular, zero leave-one-out count loss does not show a pass can safely be removed. These counts support **keeping the simple bounded graph architecture while collecting real per-pass evidence**, not adding global belief propagation or promoting layout matches.

## Concrete structural ambiguity and determinism

`--mode collision` constructs two graphs on six vertices:

* G1: `i → (i+1)%6` and `i → (i-1)%6`.
* G2: `i → (i+1)%6` and `i → (i+2)%6`.

Both are strongly connected with twelve edges and uniform in/outdegree two. They are not isomorphic: every G1 edge has a reciprocal partner; no G2 edge does. The production MD implementation intentionally has no zero-in-degree or zero-out-degree roots in either graph, so levels remain zero and every edge contributes the same term. Both top/down keys are exactly **747376367166**. A single content-eligible function per side, with six distinct body keys and these equal MD/count fields, is paired by P10 as B/E-CFG. The reproducer uses production `flow_graph_md`, not the test generator's stand-in MD routine; JSON includes the edge lists and full pair provenance.

This is not a random 64-bit digest collision. Increasing hash width cannot fix an information-losing structural invariant. Uniqueness within the two current pools is compatible with an accidental shared fingerprint. No production acceptance change is made: a graph-only B opinion must be assessed by fusion and realistic negative cases before policy changes. A plain degree-initialized 1-WL pass would also fail to separate these two uniformly regular directed graphs: every vertex has the same color and the same incoming/outgoing color multisets at every round. This follows directly from the refinement rule [S7]; WL is not a universal collision cure. Instruction/block labels or matched context may help but need measurement.

Three fresh processes each for the generated and all-residual 1k fixtures, with `PYTHONHASHSEED=1`, `321`, and `random`, produced identical serialized pair/provenance hashes within each family: generated `58890a6a9bef903378734dd6e819e07ed059a44cf761ccc2ff9ae8ca868f7d22`; residual `f9681bea4ed6bbe041e89b93268a6398deb4d7eaae876869b9db3173c75ee05c`. This checks hash-seed stability on Linux, not Windows or cross-version floating-point MD parity. Existing row-order/mirror property tests remain relevant.

Arithmetic determinism is conditional on bounded work completing. P19's 30-second clock may abstain on a prefix of components depending on host speed; a whole-ladder deadline can return partial results. These are specified resource exits, so the blanket “pure content determines identical results across machines” statement needs to be read with that condition. No actual hardware-dependent mismatch was observed in these runs.

## Verified loop-count performance repair

Before the repair, `count_back_edges` computed immediate dominators and then walked from each edge's source all the way toward the root until it found the target. A forward chain has no back edges, yet its ancestry queries visit `n(n-1)/2` vertices. The red operation-count regression monkeypatches only the already-computed dominator vector for a 512-block chain: **262,144 indexed accesses**, versus a deliberately loose linear bound of `12 * (V+E) = 12,276`. The other 61 semantic/oracle tests passed before the repair; this guard failed, establishing the regression before implementation.

The repair leaves `dominators` unchanged, builds its tree, assigns DFS entry/subtree-end intervals iteratively, and tests domination in constant time by interval containment. Unreachable nodes retain sentinel intervals; nonzero/invalid entries, self loops and repeated edges preserve existing behavior. This reduces the work **after dominator construction** to O(V+E), with O(V) auxiliary storage; it does not claim that iterative dominator construction itself is linear for all graphs. Cooper–Harvey–Kennedy discuss why the simpler iterative dominator algorithm can be effective on ordinary compiler CFGs despite weaker worst-case asymptotics [S8].

| Chain blocks | Before loop count wall s | After loop count wall s | After CPU s | After process peak MiB |
|---:|---:|---:|---:|---:|
| 1,000 | 0.015860 | 0.001763 | 0.001764 | 27.5 |
| 2,000 | 0.064223 | 0.002237 | 0.002238 | 27.7 |
| 5,000 | 0.386845 | 0.006568 | 0.006571 | 28.7 |
| 10,000 | 1.552340 | 0.027999 | 0.027926 | 31.0 |
| 50,000 | Not run: quadratic baseline intentionally bounded | 0.110009 | 0.109706 | 49.3 |
| 100,000 | Not run: quadratic baseline intentionally bounded | 0.219195 | 0.219196 | 71.6 |

Every chain result is zero back edges. At 10k the observed loop-count speedup is about 55x; do not extrapolate that ratio to ordinary small CFGs. Baseline raw `graph-cfg-*.json` remains committed unchanged; optimized files use `graph-cfg-optimized-*.json`. The raw field `ancestor_visits_derived` is the old walk's analytical reference count, not a measured count for the optimized implementation. No 100k quadratic baseline was attempted. Ingest previously called loop counting within one function without an inner budget check, so removing this avoidable long-chain scan also reduces a source of cancellation latency; it does not prove all ingest inner work is bounded in latency.

The new independent oracle removes each vertex and checks reachability from the chosen entry, using the definition of dominance rather than another dominator-tree implementation. Sixty seeded random families include sparse/dense graphs, chains, loops, duplicates, unreachable regions and nonzero/invalid entries. The tests also check explicit self-loop/duplicate behavior and the operation bound. Existing graph and ingest/record/reader/fact/ladder-port tests provide integration coverage. This changes no persisted field values by design, and no schema or IR key version changes are warranted by this optimization.

## Reproduction and validation

The script is Linux-only because of the `resource` RSS method. From the repository root:

```bash
PY=/workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python
"$PY" tools/research/r2_graph_benchmark.py --mode exact --n 100000 --output /tmp/graph-exact.json
"$PY" tools/research/r2_graph_benchmark.py --mode residual --n 100000 --output /tmp/graph-residual.json
"$PY" tools/research/r2_graph_benchmark.py --mode common --n 100000 --output /tmp/graph-common.json
"$PY" tools/research/r2_graph_benchmark.py --mode ambiguous --n 200 --output /tmp/graph-ambiguous.json
"$PY" tools/research/r2_graph_benchmark.py --mode assignment --n 200 --output /tmp/graph-assignment.json
"$PY" tools/research/r2_graph_benchmark.py --mode generated --n 1000 --omit P10 --output /tmp/graph-ablation.json
PYTHONHASHSEED=321 "$PY" tools/research/r2_graph_benchmark.py --mode residual --n 1000
"$PY" tools/research/r2_graph_benchmark.py --mode collision
"$PY" tools/research/r2_graph_benchmark.py --mode cfg --n 10000
```

The scale loops used exact/residual/common sizes `1000,10000,50000,100000`, each launched by a fresh `subprocess.run` with `timeout=240`. CFG baseline sizes were `1000,2000,5000,10000`; optimized adds `50000,100000`. Assignment sizes were `20,50,100,200`, capped by the script. Ablation cases were the empty omission followed by P01..P19, `propagation`, `P16,P17,P18,P19`, `P10,P11`; file number is that list index. `--omit propagation` replaces the engine's propagation callback in that experiment process only. It does not modify production on disk.

Focused baseline command passed **110 tests** in 10.11 s:

```bash
PYTHONPATH=src QT_QPA_PLATFORM=offscreen "$PY" -m pytest -q \
  tests/test_unified_ir_graph.py tests/test_unified_ladder_assign.py \
  tests/test_unified_ladder_blocking.py tests/test_unified_ladder_propagate.py \
  tests/test_unified_ladder_residual_table.py
```

The pre-fix red run was `61 passed, 1 failed`; the post-fix graph/ingest run was **125 passed** in 1.04 s. Ruff passed for the research script, `cfg.py` and the new test. The root owns full-repository validation and platform gates; these focused counts do not replace them. Suggested `docs/modules.md` index entry for root: `research.r2.graph | tools/research/r2_graph_benchmark.py | bounded Linux synthetic ladder/blocking/LAP/CFG measurements reusing existing fixture generators; no shipping dependency | tests/unified_ir_builder.py, tests/unified_residual_support.py, unified ladder/IR | raw graph-*.json and this note`. Root also owns shared tracker updates.

## Research handoff and remaining evidence

Retain the current exact→propagation→bounded-residue architecture. Measure candidate recall and residual component sizes on R1's approved real fixtures before considering a sparse solver. Add cap-abstention and remaining-pool counts to human-readable research reports: a fast empty candidate graph can conceal total recall loss. Preserve distinct support classes in fusion; adding several graph fingerprints cannot manufacture independent corroboration. Keep the MD collision as a negative structural fixture and assess its final fusion disposition separately.

If a WL experiment becomes justified, use fixed integer/hash labels, separate incoming/outgoing neighborhoods and semantic block labels; pin feature/version/iteration count in cache identity, bound rounds and memory, and test compiler/inlining/ICF families separately. The JMLR WL paper gives an efficient labeled-graph feature method [S7]; it does not establish binary-match precision. NetworkX documents changed directed/unlabeled graph hashes in v3.5 and warns that hash-string similarity is not graph similarity [S9]. QBinDiff's current WL API exposes custom labels and optional iteration limits, and its BOWLSH documentation warns that hyperplane storage is not deallocated [S10]. Neither an unrestricted refinement loop nor that particular LSH machinery is needed for an initial integer-labeled experiment. The earlier SANER/KOKA paper URL currently redirects to a resources landing page, so its original evaluation tables were not recovered here and are not used to justify an accuracy claim.

Remaining gaps: real Windows per-pass accuracy, uncertain/negative pairs, realistic compiler drift and reordering, Ghidra extraction effects, end-to-end fusion acceptance, Windows memory/timing and cross-platform MD parity. R2's synthetic results establish cost shapes and a narrow ingest repair; they do not close those gates.

## Primary sources inspected

All URLs retrieved 2026-10-30. Documentation URLs are mutable; the implemented MD provenance remains the repository's pinned BinDiff v8 record `aecc14dcc2e0f06a0f8957dc465a9073215b5920`, not a new upstream parity run.

* **S1** Google BinDiff, *Understanding BinDiff*, uniqueness/drill-down/neighborhood matching and MD descriptions: https://github.com/google/bindiff/blob/main/docs/concepts.md .
* **S2** Mengin and Rossi, *Binary Diffing as a Network Alignment Problem via Belief Propagation*, ASE 2021, abstract/method formulation inspected: https://arxiv.org/abs/2112.15337 . No evaluation table transcribed.
* **S3** QBinDiff introduction, experimental scope, content/topology tradeoff and memory warning: https://diffing.quarkslab.com/qbindiff/doc/source/intro.html .
* **S4** SciPy dense assignment API, modified Jonker-Volgenant and rectangular matching: https://docs.scipy.org/doc/scipy/reference/generated/scipy.optimize.linear_sum_assignment.html .
* **S5** SciPy sparse LAPJVsp API, full matching, absent/zero edges and tied-output warning: https://docs.scipy.org/doc/scipy/reference/generated/scipy.sparse.csgraph.min_weight_full_bipartite_matching.html .
* **S6** Google OR-Tools, assignment as minimum-cost flow: https://developers.google.com/optimization/flow/assignment_min_cost_flow . Flow/reject construction above is this report's derivation, not a copied upstream rejection example.
* **S7** Shervashidze et al., *Weisfeiler-Lehman Graph Kernels*, JMLR 12 (2011), 2539-2561: https://jmlr.org/papers/v12/shervashidze11a.html and https://www.jmlr.org/papers/volume12/shervashidze11a/shervashidze11a.pdf .
* **S8** Cooper, Harvey and Kennedy, *A Simple, Fast Dominance Algorithm*: https://www.clear.rice.edu/comp512/Lectures/Papers/TR06-33870-Dom.pdf .
* **S9** NetworkX WL graph-hash API, directed/hash-version warning: https://networkx.org/documentation/stable/reference/algorithms/generated/networkx.algorithms.graph_hashing.weisfeiler_lehman_graph_hash.html .
* **S10** QBinDiff WL/BOWLSH API: https://diffing.quarkslab.com/qbindiff/doc/source/api/features.html ; similarity feature/matrix model: https://diffing.quarkslab.com/qbindiff/doc/source/features.html .
