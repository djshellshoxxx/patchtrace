# R1 limitations and next research questions

This register describes the limits of the observed evidence, not optional
disclaimers appended to an accuracy claim. The [results report](05-results-and-failure-analysis.md)
and its linked receipts are the evidence for the current status. No percentage
of overall project completion is asserted.

## Research questions and what can be answered now

| R1 question | Current evidence | Remaining requirement |
|---|---|---|
| Same-function identity across versions | Reviewed MinGW O2 fixture: 16 accepted paired identities recovered by Ghidriff/unified; hidden-name case exposes discovery failure; two selected cJSON security identities observed | Broader independently labelled projects and an export-name-hidden condition with discoverable function boundaries |
| Compiler/optimization effects | Fifteen actual build cells across three profiles/two compiler families; four same-source build comparisons; one genuine GCC/Clang engine comparison | Multiple compiler versions, true MSVC, separately admitted labels for every scored configuration, representative optimization and LTO studies |
| Constants, branches, checks and memory edits | Sixteen authored mutations survive in independently inspected O2 artifacts; thirteen enter strict material-detection scoring after ambiguity exclusions | More than one function/template per class, compound patches, less distinctive code and larger real patch sets |
| Material changes versus compiler noise | Three unchanged controls and one cosmetic control; exploratory cross-compiler control reveals three material flags and eighteen abstentions | Independent equivalence evidence beyond the reviewed domains, broad negative controls and accepted false-positive populations |
| Added/removed/split/merged/inlined/outlined functions | Two authored one-sided interfaces remain unobserved by the scored baseline; actual LLVM outlining adds a compiled helper | A range/group relationship contract and scorer; linked PE structural fixtures; inlining, folding, split/merge and elimination coverage |
| Incorrect correspondences | Explicit TP/FP/FN and FDR implemented; no incorrect accepted paired edge in the tiny visible-name subset | A substantial verified negative candidate universe, diverse ambiguous cases and held-out error estimates; FPR remains undefined |
| Independent engine evidence | Genuine Ghidriff, rz-diff and unified runs; provenance retained | BinDiff/BinExport provisioning, ablations and correlation analysis; Ghidra-derived channels are not independent replications |
| Benefit from technique combinations | Eleven accepted material changes flagged by unified versus six generic Ghidriff change signals on one fixture | Preregistered ablations with common decision semantics, fixed engine settings and separate locked evaluation |
| Scaling and performance | Wall time, sizes, counts, scoped repeatability, warm cache, one completed-child RSS profile | Process-tree peak, concurrent load control, cache-hit definitions across engines and many size/function-count strata |
| Determinism and robustness | Repeated builds, repeated native observations, immutable snapshots, explicit failed launches, malformed/ownership unit coverage | Native Windows reproduction with identical artifacts, cancellation/resource stress on the final corpus, broad partial-engine-failure campaigns |

## Why the current scores are not general accuracy estimates

The authored functions share a single source/template lineage. Repeated compiler
builds are correlated observations, not independent projects. Names survive in
the successful MinGW inputs. The fully name-hidden freestanding configuration
provides poor discovery cues and yielded no discovered functions. Pooling these
conditions into one accuracy number would hide the principal finding.

Four authored identities are excluded because of intrinsic duplicate-body
ambiguity identified before scoring. The original lineage is retained, but a
one-to-one engine cannot always infer that lineage from code alone. Those
exclusions reduce the material denominator from sixteen to thirteen. They must
be reported wherever the 11/13 result is used.

The cJSON acceptance is deliberately narrow and unblinded. Two compiled security
checks were inspected; 111 other candidate records were not admitted. Its two
positive results supply no negative-control estimate and no claim of complete
library coverage. The version-macro counterexample shows why unchanged source
spans cannot supply automatic negative labels.

Empty observations do not establish unchanged behavior. Conversely, a generic
Ghidriff modified record can represent signature, address or reference-count
metadata. Unknowns, unmatched endpoints, candidate decisions and unavailable
engines have different meanings and must remain separate. No confidence value
has been calibrated or presented as a probability.

## Ground-truth representation and promotion

The current contract can record source identity, paired/one-sided RVAs, body
facts, ambiguous labels, recipe/artifact hashes and review overlays. It cannot
express arbitrary one-to-many function realizations or shared code ranges
without loss. PDB/DWARF ranges are candidate provenance evidence; compiler
optimization, aliases, inlining and missing debug records can break naïve joins.

The pilot's independent source/binary reviewer is an automated agent. That is
stronger process separation than checking authored labels against the same
factory, but is not a human review or formal proof. Future accepted datasets
should record reviewer competence, adjudication disagreements, sampling method
and uncertain evidence. A second reviewer should inspect real security labels
without seeing engine predictions when possible.

Legacy masked body equality is not semantic equivalence. A changed referenced
object, literal or call target can be erased by coarse address masking. R1 did
not rewrite historical label semantics or claim a comprehensive relocation-aware
proof. The accepted O2 mutations use source witnesses plus actual disassembly
and bound raw bytes instead.

## Partitions and leakage

All pilot cases remain `dev`; there is no training, validation or locked-test
performance claim. Compiler variants, repeated builds, template variants and
shared source projects must remain grouped. The provided audit detects supplied
project/lineage, source revision, engine/debug/PDB artifact and mutation-template
intersections. Its deliberate negative control demonstrates rejection of one
split compiler variant.

The audit does not discover semantic near duplicates, copied snippets, vendored
dependencies or unrecorded shared templates. It cannot certify that a pretrained
model never saw public code. A future partition manifest needs a project-family
and vendored-fragment audit before calibration. Do not create independence by
renaming a project or splitting optimization levels across roles.

## Coverage goals: actual versus catalogued

The [candidate audit](03-real-world-patch-candidates.md) documents 102 distinct
commit edges, 35 security cards, 26 project labels representing 25 upstream
repositories, 16 recipe projects and 98 source/license pins. Split card files
mirror consolidated inventories and must not be counted twice. A project label
is not an independently built or reviewed project.

This session's real security pilot is **one project and one release pair**, with
two accepted function-level check changes. It is not a newly validated
14-project/15-vulnerability corpus. Six Tier R projects have three connected
selected edges; combining found cards can provide additional selected chains,
but selected chains do not prove consecutive upstream releases. The full pin
ledger and cheapest missing-edge work are already in the candidate audit.

The Brotli and miniz security associations remain quarantined from accepted
security-function scoring. Respect existing project exclusions, including the
PostgreSQL ownership exclusion. Do not silently replace an unavailable source
pair with a synthetic example or count a historical prose build claim as a new
reproduction.

## Tool and platform blockers

True MSVC is unavailable on this POSIX host. The `msvc-free` profile is Clang
targeting the Microsoft ABI; it must never be reported as a Microsoft compiler
run. Windows native engine determinism remains unverified even if unrelated
Windows unit CI succeeds. No packaging changes were made, so this research does
not create or validate a new standalone executable.

BinDiff was not run. The repository's pinned BinDiff configuration remains
unverified and no accepted BinExport inputs were provisioned for this pilot.
The blocker is explicit; it is not a zero score or evidence that BinDiff is
incompatible. No trust flag or licensing assertion was changed to bypass it.

The initial full test invocation was restricted from opening local sockets. Its
interrupted failure counts are retained as an invalid acceptance environment;
the subsequent localhost-enabled run is reported separately in QA. A separate
test-only venv interpreter fix preserves the selected interpreter instead of
dereferencing its symlink into an interpreter without installed dependencies.

The PR's Sonar check reported 3.9% new-code duplication against a 3% limit at
checkpoint `a02a1774a1617441072f4a8770348cc22038eeac`. Public Sonar component and
duplication APIs returned CloudFront HTTP 403, so exact file/block attribution
was unavailable. This specific PR failure is not attributed to the unrelated
main-branch failure. No threshold or analysis exclusion was changed. Final-head
CI/review status is recorded in the handoff; a draft PR is not merged acceptance.

## Priority follow-ups with concrete acceptance conditions

1. **Repair conditional-branch store evidence in a separate production change.**
   Reproduce the exact JNC counterexample and add regression coverage for all
   conditional branches versus genuine stores. Coordinate ownership, update the
   fact semantics specification, and preserve R1's pre-fix results. Repeat the
   compiler control and held-out cases after the correction; do not tune anchors
   merely to make this fixture pass.
2. **Close provenance/CI integration.** Verify final matrix metadata and all
   immutable receipt links, inspect final Linux/Windows/native checks and the
   PR-specific Sonar components, and obtain required independent review. Review
   any conflict with the coordinator's QA/task-log branch without discarding
   either handoff.
3. **Design a discovery-controlled hidden-name cohort.** State which PE metadata
   remains visible; compare boundary discovery independently from correspondence
   over fixed discovered boundaries. Avoid feeding oracle PDB identities into a
   purportedly blind matcher. Preserve the zero-discovery case as a diagnostic.
4. **Extend structural truth deliberately.** Define group/range identity and
   ambiguity invariants before serializing one-to-many realizations. Use the
   compiled loop-extraction helper as the first real fixture, then add ICF,
   inlining and elimination. Do not retrofit those cases into unique-RVA labels.
5. **Expand real cases before calibration.** Select the small recipe-backed
   chains in the candidate ledger, verify upstream adjacency and licenses, build
   exact pins, and independently admit function subsets. Establish project-level
   partitions and negative controls before selecting any thresholds.
6. **Run controlled ablations and platform repetitions.** Include genuine
   BinDiff once provisioned, record engine failures and shared dependencies, and
   compare identical artifact hashes across Linux/Windows. Add representative
   binary-size strata and process-tree memory sampling with a documented method.

R1's research and pilot artifacts are usable inputs to those tasks. The larger
coverage and merge/release gates are not represented as complete.
