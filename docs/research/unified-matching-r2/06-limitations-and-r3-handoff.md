# R2 limitations register and R3 semantic-change handoff

Date: 2026-10-30 UTC. Baseline `a04f5a299a8d4afef023261e52e08d14678cf1e7`.
Delivery branch `codex/r2-unified-matching-research-20261030`,
[draft PR #131](https://github.com/djshellshoxxx/patchtrace/pull/131).
This register separates completed investigation/repairs from acceptance claims
that the current evidence cannot support. The latest test/CI status belongs to
[report 05](05-baseline-and-validation.md) and the PR, not an old green badge.

## Decisions supported by the research

Retain the existing staged ladder, bounded candidate generation and rejection-aware
residual assignment. The implementation already contains P16–P19; replacing it
with a dense whole-image solver would add cost without a demonstrated benefit.
Keep ordinal confidence, explicit analyst authority, Ghidriff as the primary
comparison source, derived unified output, immutable raw records and L1/L2
separation. The source inventory and ablations provide no basis for changing
default thresholds or pass ordering on a single generated fixture.

Ship the narrow repairs through normal review/gates: stable native atom ordering,
complete B+B support witnesses under caps, explicit manual-group explanation,
IR-only unmatched preservation, classified failure for impossible evidence caps,
and linear dominator-ancestry queries after immediate dominators. Result cache
policy is `matching/2`; wire/engine contract stays `ude/1`. Do not adopt neural
embeddings as a default dependency, reinterpret native scores as probabilities,
globally swap rz-diff endpoints, or infer added/removed functions from a missing
correspondence. These are decisions based on the observed scope, not permanent
rejection of alternative research directions.

## Acceptance checklist

| R2 criterion | Evidence available | Status / remaining condition |
|---|---|---|
| Current implementation inventoried | Source map, per-engine profiles, P00–P19 mechanics, inactive P02 and missing Diaphora integration | Documented; source presence is separated from operational verification |
| Established techniques evaluated | Primary papers/docs/code, complexity, licenses, applicability and proposed experiments | Research review complete for the scoped methods; no empirical ranking of unexecuted models |
| Existing engines have measured baseline results | Synthetic ladder, native Ghidra/Ghidriff/rz-diff, exact baseline CI | Partial; no representative complete-engine benchmark or native BinDiff result |
| Ladder stages evaluated individually | Twenty-three generated-fixture ablations and actual residual/assignment probes | Partial; no per-compiler/per-project native incremental contribution estimate |
| Conflicts deterministic and tested | Existing properties plus new seed, witness, cap and manual regressions | Focused local evidence passes; current-head Windows/cross-platform gate required |
| Important false-match categories covered | Seventeen-category taxonomy, existing invariants and new executable defects | Important concrete defects covered; prevalence and unrepresented compiler transformations unknown |
| Improvements measured before/after | Atom serialization, witness retention, native helper coverage, access-count and timing evidence | Supported within each stated experiment; no claimed global accuracy gain |
| No demonstrated high-impact regression | Focused tests and independent production review | Full-suite/CI outcome remains mandatory; an unchecked head is not accepted |
| Explanations preserve provenance | Existing contracts plus witness/manual/leftover repairs | Improved; bounded omitted evidence and full relation provenance gaps remain |
| Performance limits documented | 1k/10k/50k/100k synthetic shapes, bounded 200-row LAP and memory | Documented; whole-pipeline real-program scale remains open |
| Required tests and CI pass | Exact results in report 05 | Open until current-head required checks and unresolved findings are addressed |
| Results committed to GitHub | Meaningful research/implementation checkpoint on PR #131 | Published; draft is not a merge or release claim |

**Real-world accuracy acceptance remains open.** A reviewed two-function cJSON
development selection can add real-source evidence, but one release transition,
one compiler configuration, export-visible functions and unblinded review cannot
stand in for held-out project lineages. No locked test set was consumed or used
to choose thresholds in this work.

## Prioritized limitations and executable next work

| ID / priority | Finding and consequence | Next bounded action | Owner / evidence needed to close |
|---|---|---|---|
| R2-L01 / P0 | Real-world ground truth and complete native outputs are insufficient for precision/recall acceptance | Finish R1 label admission, pin development/validation/locked lineage roles, then run the existing unified evaluators on unchanged defaults | R1 corpus owner plus R2 evaluator; independently admitted labels and exact denominators |
| R2-L02 / P0 | Advisory live gates wrote zero outcomes; A/A `identical` backend status is incompatible with the harness's completed-run requirement | Reproduce the smallest A/A case, preserve failure logs, repair only the harness/retention path with a regression, rerun G-U1–G-U8 | R1/live-gate owner; genuine Ghidriff/IR records, no fabricated primary run or omission credit |
| R2-L03 / P0 | rizin 0.9.1 singleton path reverses sides while ordinary multi-function paths do not | Preserve the 1→1, 1→2, 2→1 and 2→2 probes; obtain reliable producer orientation/count metadata or fail closed when ownership cannot be established | Secondary adapter/upstream owner; pinned native regression, same-address ambiguity cases, preserved raw output and versioned cache policy |
| R2-L04 / P0 | Current-head security/review/Windows gates are incomplete or failing at the first implementation checkpoint | Retrieve exact findings through supported interfaces; repair demonstrated issues; rerun and inspect each required job at the new SHA | Integration owner; no suppression, skipped review or baseline pass counted as approval |
| R2-L05 / P1 | Ladder groups are counted but not persisted; existing exclusive group semantics cannot express an inlined helper overlapping its host's 1:1 relation | Specify typed relation membership, explicit candidate edges, containment regions and separate exclusivity rules before migration | Unified contract owner; additive schema/migration plan and split/merge/inline/outline tests |
| R2-L06 / P1 | Native split/merge examples generate no automatic group at all | Distinguish group-generation recall from adapter loss; add bounded reviewed block/region coverage examples through the R1 corpus | R1 + matching owner; no Cartesian-product truth or forced 1:1 fallback |
| R2-L07 / P1 | P02 export-key algorithm is tested but production never passes export maps | Use the existing bounded PE export table over verified bytes, define aliases/ordinals/forwarders/data exports/truncation, carry identity-bound maps to the worker | Unified/PE owner; compute/persistence regression proving P02 rather than P03, and policy digest update |
| R2-L08 / P1 | Candidate caps can erase all true pairs in common-token stress; no optimizer can recover an absent edge | Measure true-pair coverage after each block/filter/top-K stage, bucket-size distributions and pruning reason counts on admitted development data | Matching/performance owner; coverage and runtime side by side, with adversarial repeated-library controls |
| R2-L09 / P1 | D-tag components are conservative dependency assumptions, not empirically validated statistical independence | Estimate conditional error agreement by source, class, lineage and extraction mode; retain conservative joins until held-out evidence supports an amendment | Calibration owner; no probability interpretation from raw agreement rates |
| R2-L10 / P1 | Native BinDiff and flow-MD oracle parity remain unverified here | Use the repository's pinned BinExport/BinDiff pipeline and existing parity check on bounded reviewed inputs | Native-tool owner; exporter/architecture/tool hashes, actual outputs and failure status |
| R2-L11 / P1 | Row caps preserve essential witness/opposition but omit the rest with a count only | Design a bounded omitted-by-source/class/endpoint summary or immutable raw-record references without increasing automatic confidence | Explainability/contract owner; old manifests readable, actual missing detail represented honestly |
| R2-L12 / P2 | Whole-pipeline memory, SQLite access, facts and GUI costs differ from pure ladder measurements | Profile extraction, ingest, read-model construction, matching, facts, write, filter/sort and UI separately on the same pinned large inputs | Performance/UI owner; cold/warm cache definitions and process-tree RSS |
| R2-L13 / P2 | Diaphora Mode A imports separately; registry metadata does not make unified atom generation operational | Add a dedicated adapter consuming its existing validated contract/trust policy, with source selection and worker integration | Diaphora/unified owner; optional native fixture only where IDA/Hex-Rays rights and runtime are available |
| R2-L14 / P2 | Learned methods have no measured marginal value here; weights/corpus rights and offline packaging are unresolved | Run optional frozen-model retrieval experiments after establishing exact baselines and candidate recall | Research owner; checkpoint/hash/license, training overlap audit, deterministic ties, Windows CPU latency/memory |
| R2-L15 / P2 | Some normalized fingerprints collide or erase scalar/control-flow distinctions | Maintain exact-body and semantic-delta channels separately; add adversarial constant, branch, data-target and repeated-CFG cases | Matching + R3 owner; no relaxed normalization used as unchanged proof |

The source-level P02 gap requires more than adding `exports=` to one call. A
name-only export list cannot establish an RVA; a PE data export is not a function;
several aliases can share one entry; ordinal reuse does not guarantee source
identity; a truncated parser cannot claim complete coverage. The existing table
parser is a reusable starting point, not an already wired matching input.

For rizin, artifact hashes authenticate which files were supplied, not which side
the native serializer assigned to each address. PE bounds alone are insufficient:
the reversed addresses in the probe are valid image RVAs on both sides. Reversing
whichever orientation appears to fit more names is a heuristic and may be wrong
on repeated/reused names. Any future repair must retain the original native
record and make the normalization decision inspectable. [Source proof and
regression design](07-native-rizin-findings.md).

## Native evaluation protocol after R1 admission

Reuse the existing Tier R factory, labels, outcomes and evaluator contracts.
Do not create a second benchmark corpus or relabel the same source lineage as
independent train/test data. Start with a small admitted development panel:
identical bytes, identical-source rebuild, compiler change, O0/O2/O3, debug stripping
with export visibility separately recorded, reordered functions, rebasing,
constant-only changes, branch inversion, bounds checks and explicit boundary
transformations. Add real release pairs with upstream/source/binary provenance.

Freeze the original default ladder before comparisons. Run primary-only,
ladder-only and each available secondary combination on exactly the same artifact
pair and extraction content, retaining failed/unavailable runs. Evaluate final
accepted one-to-one rows separately from tentative/contested/candidate rows and
from relation groups. Report eligible truth counts, correct/wrong/unknown
predictions, misses, per-side unmatched functions, relation ambiguity, high-tier
errors, candidate coverage, wall time, process-tree peak RSS and raw/config hashes.
Use macro averages across project lineages as well as micro counts; one large
project must not hide a small project's high-impact mistakes. Bootstrap by
lineage only when there are enough independent lineages to make that meaningful.

A pass-order experiment must freeze the candidate data and establish a reason to
expect improvement. Compare both the accepted set and the high-impact false-match
set, including downstream propagation of a mistaken anchor. A recall gain does
not justify an increase in incorrect A/manual-like automatic outcomes. Inspect
which true pair was removed by blocking before comparing solvers; otherwise a
solver change is being blamed for an upstream recall limit it cannot fix.

Repeat exact inputs with different hash seeds, then the same tool/runtime pins on
Linux and Windows. Compare canonical result content rather than timestamps or
wall-time fields. Mirror the pair direction and use chain-consistency experiments
as additional checks, not ground-truth substitutes. Reusing a warm sidecar is a
different performance condition from cold extraction and must be labelled.

Select thresholds only on development data with a written objective and an
explicit abstention policy. Validation can choose among preregistered designs;
locked evaluation is a final look after the decision, with receipts and the
existing calibration owner controlling access. A failed or incomplete locked run
must not become an excuse to tune and rerun without recording the protocol breach.

## R3 input contract

R3 is already active in [PR #129](https://github.com/djshellshoxxx/patchtrace/pull/129)
at the later ownership checkpoint. Its separate COS-PSEUDO blocker/EH repair and
proof-version increment are not included in this R2 branch. Preserve both its
proof version and R2's matching-policy version when integrating. Likewise use
[R5 #132](https://github.com/djshellshoxxx/patchtrace/pull/132) for calibration
coordination and [R6 #133](https://github.com/djshellshoxxx/patchtrace/pull/133) for
the final integration ledger. This handoff supplies evidence and remaining
questions to those workstreams rather than creating a competing implementation.

R3 studies semantic change conditional on explicitly qualified correspondence.
It should consume the persisted unified manifest/rows/facts and original source
references, rather than rerunning L1 from display names. For every inspected pair
or group retain:

- Ordered artifact SHA-256s, entry RVAs and source-specific function identifiers;
  extraction content digests, tool versions and extent/architecture information.
- Unified result ID, `matching/2` configuration identity, source file digests/run
  references, exact L1 decision, supporting atom indexes, conflicts and manual
  intervention.
- Raw/normalized instruction or block differences, data/import/call references,
  proof scope, explicit unavailable channels and any resource/coverage limit.
- Ground-truth admission and lineage role for evaluation data, including visible
  exports/debug symbols and whether a reviewer saw predictions before labelling.

The current contracts already carry much of this information, but not a complete
per-row source-availability matrix, typed relation/containment record or every
truncated alternative. R3 must not silently invent those fields from a display
summary. A source's native ratio retains its own unit and provenance.

### R3 first experiments

1. **Constant and condition sensitivity.** Reuse the native `MOV 0x11→0x12` and
   `JC→JNC` examples. Verify that correspondence survives while explicit deltas
   survive too. Their current `review` verdict is appropriate evidence to examine,
   not a declaration of exploitable behavior. Add pointers/data-table target
   changes that broad address masks could erase.
2. **Header/global dependency changes.** R1's cJSON review identifies a changed
   version macro affecting an otherwise unchanged function definition. Treat
   source-span equality and body equality as scoped observations; track relevant
   data, imported behavior, hooks and called-function changes separately.
3. **Compiler-only controls.** Use admitted same-source rebuild and optimization
   variants. Match identity and semantic equivalence are different labels. A
   compiler can inline/remove boundaries or exploit undefined behavior; require
   source-domain assumptions rather than declaring every same-source build equal.
4. **Transformation uncertainty.** On split/merge/inline/outline examples, compare
   covered regions and unexplained residuals. Do not feed an arbitrary flattened
   function pair to a semantic classifier and treat its disagreement as a patch.
5. **Disagreement and absence.** Preserve primary Ghidriff omission alongside
   explicit IR deltas. Missing decompilation is unavailable, not unchanged; a
   weak conflicting secondary endpoint is not a reliable new semantic identity.

Report two semantic metrics: change classification **conditional on independently
correct correspondence**, and unconditional patch detection that requires both a
correct correspondence and an explicit correct change verdict. If only the first
is shown, missed matches disappear from the denominator. Include abstention and
unknown coverage in both. Scope security associations to the upstream/source
evidence; a changed bounds check is not by itself a verified vulnerability,
exploitability result or formal semantic proof.

Do not allow a confident-looking L2 verdict to feed back silently into L1. Any
future feedback mechanism needs an explicit amended contract, separately measured
error propagation and its own cached policy version. Keep the baseline primary
records intact so disagreements can be revisited without rewriting history.

## Integration and reproducibility handoff

The repository notes and bounded JSON records are the durable research evidence.
Native tools, target binaries, GZFs, working projects and SQLite sidecars are local
research inputs/temporary artifacts and are not bundled into the PR. Every native
record includes artifact hashes and tool/version observations. The authored PE
examples can be regenerated using the existing fixture helpers; the real-source
pilot requires its R1 source/build receipts and admitted selection.

The shell's configured network route was unavailable for direct git transport.
Publication therefore used the GitHub connector to build a tree, verified that
its SHA exactly matched the local committed tree, created a commit with the
existing remote parent and updated the branch with an expected-head lease and
`force=false`. Local/remote commit metadata differs; tree equivalence is the
source-content check. No active worker branch was overwritten.

Before merging, re-read current main and open contributor work, integrate any
new conflict without discarding unique changes, inspect current-head Linux,
Windows and native checks, resolve concrete review findings, and honor the
repository's independent review requirements. Do not convert an inaccessible
annotation, skipped bot review, failed optional tool, unavailable dataset or
advisory green badge into a passing result. Release packaging, deployment and
default-on rollout remain separate actions with their own gates.
