# R1 pilot results and failure analysis

Research date: 2026-10-30 UTC. All experiments are development observations.
The protocol was written before scoring; original labels and unsuccessful runs
are retained. No target DLL or EXE was executed. This report distinguishes a
running analysis process, observed coverage, accepted truth and general accuracy.

## What was actually built and reviewed

The authored suite contains 21 source functions per version, 22 union identities,
16 deliberate semantic edits, three unchanged controls, one cosmetic edit and
one added/one removed interface. The common input domains and source witnesses
are in the [suite README](../../../corpus/ours/r1-pilot/defined/README.md).
The [independent source and binary review](results/source-and-binary-review.md)
records exact source hashes, PDB/DWARF ranges, debug-to-engine byte equality and
the compiled instruction changes. Its reviewer was another automated agent,
separate from the author, not a human adjudicator or a formal verifier.

The build matrix uses stock profiles and flags:

| Profile | Compiler | Optimizations built | Name visibility of stripped engine input |
|---|---|---|---|
| `msvc-free` | Clang 18.1.3, MSVC target ABI; LLD 18.1.3 | O0, O1, O2, O3, Os | No COFF symbols or exports; no entry point or `.pdata` in the reviewed O2 image |
| `mingw-gcc` | GCC 13-win32 | O0, O1, O2, O3, Os | No COFF symbols, but 21 source-function names remain in PE exports |
| `mingw-clang` | Clang/LLD 18.1.3, GNU Windows target | O0, O1, O2, O3, Os | No COFF symbols, but 21 source-function names remain in PE exports |

These are **three profiles and two compiler families**, not three vendor
compilers or a compiler-version study. Microsoft `cl.exe` was unavailable on
this Linux host. No extra exports, unwind tables, discovery seeds or relaxed
engine filters were injected to improve the hidden-name result.

The first matrix built ten configurations and recorded five linker failures.
Installing the distribution's `lld` package supplied the generic linker command
required by the existing Clang/MinGW recipe. The five retries then succeeded.
The [initial receipt](results/build-matrix.json),
[dependency retry](results/build-matrix-clang-retry.json),
[receipt-preservation rebuild](results/build-matrix-provenance-rebuild.json) and
[final matrix](results/build-matrix-final.json) preserve that sequence. Later
provenance repairs are described below; the first receipts are not silently
replaced with the successful interpretation.

Independent O2 review of the freestanding and MinGW GCC configurations verified
all sixteen changed raw bodies, three unchanged raw-identical bodies and one
cosmetic raw-identical body. Four identities were excluded from definitive
correspondence scoring **before reading the matching outputs**: the old
`r1_integer_constant` body is equivalent to `r1_primary`, and the bounds-added
and bounds-removed functions exchange equivalent bodies across versions. The
review selection therefore contains 18 accepted records: **16 paired identities
(13 changed and three negative controls), plus two one-sided identities**.
The four ambiguous records remain present and counted. Original factory labels
remain untouched; the review is an exact-digest overlay.

## Matching and change observations

The primary baseline is pinned Ghidriff commit
`4f5d895fcbb1eacd65efd81145922c15bb7e741d` (distribution 1.0.0), Ghidra 12.0.4 and
Java 21. Rizin is the verified 0.9.1 static release. Unified consumes the actual
completed primary run and identity-bound GZF extraction. Full tool and archive
identities appear in [environment.json](results/environment.json).

### Independently reviewed authored O2 cases

| Input condition and engine | Correct accepted paired identities | Wrong accepted edges | Accepted material changes flagged | Unknown change on correctly matched material pairs |
|---|---:|---:|---:|---:|
| Freestanding Clang, Ghidriff | 0 / 16 | 0 | 0 / 13 | 0; all 13 are unmatched |
| Freestanding Clang, unified | 0 / 16 | 0 | 0 / 13 | 0; all 13 are unmatched |
| Freestanding Clang, rz-diff | Failed: no functions found | Not scored | Not scored | Not scored |
| MinGW GCC with exports, Ghidriff | 16 / 16 | 0 | 6 / 13 | 7 |
| MinGW GCC with exports, unified | 16 / 16 | 0 | 11 / 13 | 2 |
| MinGW GCC with exports, rz-diff | 0 / 16 | 0 | 0 / 13 | 0; all 13 are unmatched |

Evidence: [hidden input receipt](results/pilot-msvc-free-o2.json),
[visible-export receipt](results/pilot-mingw-gcc-o2.json) and its
[independent repeat](results/pilot-mingw-gcc-o2-repeat.json).

For the visible-export Ghidriff and unified populations, correspondence
precision/recall/F1 are each 16/16, 16/16 and 1.0. These are descriptive results
for one small development fixture. The explicit material-detection recalls are
6/13 (46.15%) and 11/13 (84.62%). The two accepted unified abstentions are
`r1_signedness` and `r1_call_target`. No correctly matched accepted negative
control was called material in that configuration.

These engine signals have different meanings. Ghidriff `modified` is a generic
engine change signal, including metadata changes; it is not a semantic-materiality
proof. Unified `material` is a stronger classification. The experiment measures
those signals against the same reviewed cases, but is not a controlled ablation
that attributes improvement to an independent evidence channel.

The hidden-name result is a discovery failure, not evidence that source semantics
were unchanged. Ghidriff and unified completed with zero functions/rows. Rizin
returned exit zero with empty stdout and `No functions found in file0` on stderr;
the production adapter correctly rejected the empty result. A process exit code
alone would have falsely implied success. The bounded
[rz-diff diagnostic](results/rzdiff-hidden-diagnostic.json) preserves this fact.

The visible-export rz-diff run completed with 31 image correspondences, all
outside the labelled project population. It is not a zero-function run, and its
absence of project coverage is not scored as correct unchanged output. Neither
Ghidriff nor unified produced an explicit accepted one-sided observation for the
tiny added/removed interfaces; their two endpoints remain unmatched. Correct
paired identity accuracy must not hide that gap.

### Per-mutation interpretation

The complete function-by-function observations are in
[per-function-observations.json](results/per-function-observations.json).
For the accepted thirteen material changes:

| Authored change | Ghidriff explicit change | Unified materiality signal |
|---|---|---|
| Comparison operator | Unknown | Material |
| Branch inversion | Unknown | Material |
| Pointer offset | Unknown | Material |
| Array index | Flagged | Material |
| Overflow guard | Flagged | Material |
| Signedness | Unknown | Review/unknown |
| Allocation size | Unknown | Material |
| Loop boundary | Flagged | Material |
| Callback target/slot | Unknown | Review/unknown |
| Error handling | Flagged | Material |
| Null validation | Flagged | Material |
| Structure field | Flagged | Material |
| Security flag | Unknown | Material |

The constant and two bounds mutants remain in the raw observations but are
excluded by the predeclared correspondence ambiguity selection. The benchmark
does not rewrite their source lineage to whichever correspondence an engine
prefers. No threshold or matching heuristic was tuned using this table.

## Real security patch pilot: cJSON

The existing recipe fetched and licence-verified cJSON commits
`cb8693b058ba302f4829ec6d03f609ac6f848546` (1.7.16) and
`87d8f0961a01bf09bef98ff89bae9fdec42181ee` (1.7.17), then built both with MinGW
GCC O2. The [cJSON review](results/cjson-review.md) verifies the MIT licence,
all 99 recorded source inputs per side, source deltas, DWARF ranges, stripped
range bytes and compiled guards for `cJSON_SetValuestring` and
`cJSON_InsertItemInArray`. The pinned upstream changelog associates them with
CVE-2023-50472 and CVE-2023-50471. This local guard-survival acceptance does not
establish exploitability, complete affected-version ranges or safety for every
possible input. The reviewer disclosed prior exposure to the engine's two
modified RVA pairs; this is **unblinded**, with predictions excluded from oracle
construction.

Both stripped DLLs retain **92 named exports**, including both selected
functions. A setting named `hidden` disables debug symbols; it does not remove
the PE export table. The result is export-name-visible.

Ghidriff's raw table contained 268 address correspondences: 221 image edges and
47 validated external edges. External addresses cannot be subtracted from the
PE image base and were explicitly counted outside the image-scoring scope.
Of the 221 image observations, two carried explicit changes and 219 had unknown
change verdicts. The original exploratory factory-label result is preserved in
[pilot-cjson-o2.json](results/pilot-cjson-o2.json), not promoted wholesale.

Only the two statically reviewed security functions enter the
[reviewed result](results/pilot-cjson-reviewed.json). Ghidriff and unified both
observed the two correct correspondences and flagged both changes. Rz-diff
produced no accepted correspondence for either function. **The other 111 label
records are unresolved under this review.** There are no accepted negative
controls, so this subset cannot estimate false-positive rates. In particular,
`cJSON_Version` changes through a header macro even though its function span is
unchanged; its earlier ambiguity is preserved. Reporting this as perfect
whole-library accuracy would be incorrect.

## Deterministic controls and compiler noise

The [control build report](results/controls-and-structure.md) records independent
freestanding O2 rebuilds with identical engine, debug-image and PDB hashes and
21 identical project bodies. The single translation unit cannot exercise the
factory's object-link reordering; that layout condition is not applicable, not
passed. Four actual same-source compiler/optimization comparisons were built:
Clang O0/O2, Clang O2/Os, Clang/GCC O2, and GCC/MinGW Clang O2. The latter had a
preserved linker failure followed by a successful dependency repair.

The product backend intentionally shortcuts identical hashes. A separate
[direct native A/A experiment](results/native-aa-control.md) invoked pinned
Ghidriff with `--force-diff`, unchanged default filters, disabled debug-symbol
loading and visible MinGW exports. Identical bytes with the same basename first
triggered a ProgramDB transaction failure; distinct basenames succeeded in two
fresh analysis directories. Both runs observed 53 image correspondences,
including **all 21 construction-known project RVA pairs**, plus 32 unscored image
pairs and 22 explicitly excluded external edges. Observation digests matched;
full raw JSON hashes differed. Every observed change verdict remained unknown.
This establishes scoped correspondence repeatability, not negative-change
classification or hidden-name generality.

The [GCC/Clang same-source run](results/pilot-compiler-noise.json) is exploratory,
without a separate complete binary-semantics admission audit. Ghidriff observed
all 21 source-correspondence candidates and marked all as modified, including
compiler metadata differences. Unified matched all 21, called three material
and left eighteen for review. Rz-diff again observed only unlabelled runtime
pairs. The three material flags are research failure candidates, not a
population false-positive estimate. The
[failure-analysis addendum](results/failure-analysis-addendum.md) preserves exact
IR/fact evidence for `r1_comparison`, `r1_bounds_removed` and `r1_loop_bound`.

One concrete evidence defect was found: the existing store detector can treat
conditional branch operands as memory stores. On the recorded bounds example,
this gives added branch blocks an effect anchor. This is recorded for a separate
production correctness change; R1 does not tune or modify matching algorithms.

## Structural evidence and representation limits

The existing LLVM loop-extraction machinery really transformed the reviewed
source: 21 IR definitions became 22, and `r1_loop_bound.extracted` survived in a
Windows COFF object. The [recorded command and hashes](results/controls-and-structure.json)
establish actual outlining, not a mocked structural case. This was not a linked
PE/unified acceptance run. The current `/1` label contract has unique endpoints;
it cannot faithfully score a general parent-plus-helper hyperedge. That case
must remain a structural research fixture until an explicit one-to-many contract
and evaluator exist. It is not forced into a false one-to-one answer.

## Build-provenance defects repaired by the experiment

Two reproducible defects were independent of matching algorithms:

1. Different recipes can emit identical debug artifacts. The old
   `images/<debug_sha>/build.json` silently retained only the last recipe. Every
   complete receipt is now also retained under `builds/<receipt_sha>.json`, with
   immutable content-addressed publication and tamper checks. The legacy file
   remains a last-build view. Actual rebuilds recovered the missing receipts.
2. `Session.side` cached by debug hash even though `SideData` contains build
   provenance. Two freestanding O3 endpoints and one MinGW Clang O3 endpoint
   consequently carried O2 metadata. Its key now binds the full build
   specification, debug hash, recipe/source digests and resolved source root.
   The final matrix was rebuilt and checked against every requested cell.

The earlier receipts preserve the failures; they are not authoritative final
configuration metadata. The repair changes provenance/cache scope, not function
truth or emitted machine bytes. [Immutable build receipts](results/build-receipts/)
contain full compiler/linker argv templates, actual versions, source input hashes,
recipe/source digests and output hashes.

## Metrics, partitions and performance scope

The new additive metrics grant credit only to actual observations. A missing
Ghidriff modified row never supplies a free unchanged match. Identity can be
observed while the change verdict is unknown. Unified tentative, contested,
candidate and structural rows remain abstentions. Material detection uses **all
accepted material truth pairs**, including missed correspondences. Undefined
denominators are JSON null. Correspondence FPR remains null because no verified
negative candidate-edge universe was specified; false discovery rate is a
different quantity.

The [partition audit](results/partition-audit.json) records all published pilot
cases as development. A deliberately invalid assignment of one compiler variant
to validation is detected through six shared-identity keys. An all-development
pass is not held-out validation, and exact-key leakage checks do not certify the
absence of near duplicates or vendored fragments. No locked test or calibration
threshold was selected or consumed.

Wall times are local observations on a shared host. The first visible-export
GCC run took 24.728 s for primary analysis, 24.723 s for extraction/unified work
and 0.306 s for rz-diff. Its warm unified cache lookup took 0.0106 s. A separate
cold run reproduced observations, metric counts and unified row digest; times
were 30.672 s, 33.181 s and 0.216 s. The cJSON primary run took 39.821 s;
its first unified extraction/analysis took 29.868 s and rz-diff 2.384 s. Workloads
and scopes differ, so these are not controlled engine-speed rankings.

A fresh [resource-profiling run](results/profiled-resources.json) completed in
49.913 s and measured **1,117,360,128 bytes** as Linux's largest completed-child
peak RSS. This is not maximum simultaneous process-tree memory: the
[Linux getrusage definition](https://man7.org/linux/man-pages/man2/getrusage.2.html)
explicitly distinguishes those quantities. Its full pilot receipt is preserved
as [pilot-mingw-gcc-o2-profiled.json](results/pilot-mingw-gcc-o2-profiled.json).
Process-tree peak, controlled throughput scaling and a broad size/function-count
study remain unavailable. Raw timestamps/project metadata need not be byte
deterministic when the observed correspondences are.

See [limitations](06-limitations-and-open-questions.md), the
[executable handoff](07-handoff-and-reproduction.md), `docs/qa.md` and
`tasks/todo.md` for validation status and outstanding gates. None of these
measurements is a release-acceptance or general calibrated-probability claim.
