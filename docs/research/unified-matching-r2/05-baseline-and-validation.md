# R2 measured baseline and implementation validation

Research date: 2026-10-30 UTC. Production baseline:
`a04f5a299a8d4afef023261e52e08d14678cf1e7`. The first published implementation
checkpoint is [c704a39](https://github.com/djshellshoxxx/patchtrace/commit/c704a39c8ece56c3215c1d765d79e7f4780ddcbd),
whose tree `077d4c84739987654092b895c4765e30ee11f0be` exactly equals local
commit `c91a35da90b542ee4e09e0557ff8366100d3531c`. Later notes and replay data do
not retroactively turn an earlier run into validation of a later source tree.

## What the measurements establish

There is useful executable evidence for the matching machinery, several concrete
defects, and six narrow repairs. There is **no representative real-world accuracy
estimate** for the complete unified system. The available evidence has four
different units of observation, which must not be combined into one accuracy score:

| Evidence layer | Observation unit | Measured here | What remains unmeasured |
|---|---|---|---|
| Pure algorithm fixtures | Generated function keys/graphs and constructed truth pairs | Pass ablations, deterministic results, caps, assignment work, CFG equivalence and scale | Real decoding, optimization diversity, extractor omissions and project-lineage generalization |
| Native extraction on authored PE files | Real Ghidra extraction of small synthetic x64 DLLs | Twelve extractions, six ladder/fusion/facts computations, replay under the new policy | Stripped or independently compiled real programs, compiler/version/optimization stratification |
| Native external matcher probes | Actual Ghidriff or rz-diff process and recorded output | One Ghidriff comparison; 22 rz-diff attempts plus five diagnostics | Broad native precision/recall, BinDiff comparison, multi-engine marginal value |
| Repository tests and CI | Explicit tests/jobs at a particular tree | Focused regression/property/store checks; baseline CI; current-head status below | A green advisory badge is not a passed corpus gate |

Primary experimental artifacts are the JSON files in [results](results/).
[Graph and residual measurements](03-graph-residual-performance.md) provide the
full per-size/per-pass tables; [fusion and false matches](04-fusion-identity-false-matches.md)
provides the exact counterexamples and evidence interpretation.

## Accuracy accounting and exclusions

For a specified set of eligible one-to-one relations, let `TP` be correctly
predicted pairs, `FP` be predicted pairs known to be incorrect, and `FN` be eligible
truth pairs not predicted. Precision is `TP/(TP+FP)`, recall is `TP/(TP+FN)`, and
F1 is `2TP/(2TP+FP+FN)`, only when their denominators are nonzero. These definitions
must be attached to the decision policy being scored: ladder pairs, final
`matched` rows, or an explicitly defined accepted subset are different outputs.

Unknown endpoint ownership is not automatically FP, and an unavailable engine run
is not a successful empty prediction. Report those separately. N:M/containment
truth must be evaluated under an appropriate relation metric, not flattened into
arbitrary one-to-one pairs. False-positive rate needs an explicit negative
population (`FP/(FP+TN)`); the astronomical set of every unrelated cross-product
pair is not a useful implicit denominator. No true-negative population was sampled
in these probes, so FPR is unavailable. Neither native similarity nor an ordinal
evidence tier supplies a calibrated error probability.

### Existing generated 1,000-function fixture

`generate_pair(1000, seed=1, changed=0.5, shifted=0.2, duplicates=0.01)` supplies
992 eligible twin pairs. With the full implemented ladder, the recorded output is
985 correct pairs, zero incorrect pairs and seven missed truth pairs. Therefore
the **fixture-level ladder** precision is 985/985 = 1, recall is 985/992 =
0.99294355, F1 is 1970/1977 = 0.99645928, and missed-truth fraction is 7/992 =
0.00705645. These are descriptive results for this generator/seed, not confidence
bounds or a claim of 100% production precision. The output includes 28 tier-C soft
pairs, so it is explicitly not the final automatically accepted unified subset.
Source: [graph-ablation-00.json](results/graph-ablation-00.json).

The baseline distribution is P03 206, P04 225, P05 155, P06 95, P09 178, P10 37,
P11 2, P16 1, P18 20, P19 1 and propagation 65. The 23 ablation variants include
individual pass removal and removal of broader mechanisms. Removing propagation
reduces correct pairs from 985 to 956; removing P18 yields 977; removing all
residual passes yields 976. Removing an earlier pass can move its pairs into a
later pass, so attribution counts are not causal marginal contributions. Several
passes have no unique benefit on this fixture; that is not evidence that those
passes are useless on real data. No ordering or thresholds were changed based on
this single development fixture. Full denominators, alternate attributions and
timings are in [the ablation table](03-graph-residual-performance.md#per-pass-ablations-on-an-existing-generated-fixture).

An independent graph counterexample creates two nonisomorphic strongly connected
six-node/twelve-edge CFGs with the same production MD key. P10 emits B/E-CFG
evidence. This establishes that MD equality is not an isomorphism or semantic
identity proof. It does **not** demonstrate a final automatic false match: a
single structural B opinion remains tentative under the component/class fusion
rule. [Raw collision](results/graph-collision.json).

## Native Ghidra and Ghidriff results

The native experiment reused the repository's existing authored PE fixtures.
Ghidra 12.0.4 (revision `e40ed13014025f82488b1f8f7bca566894ac376b`), OpenJDK
21.0.12, ghidriff 1.0.0, pyghidra 3.0.2 and JPype1 1.5.2 were available. The
tools were invoked as static analyzers; the target DLLs were never executed.
The fixture files expose export names, so these are **symbol-assisted integration
experiments**, primarily P03, not stripped-function accuracy experiments.

All 12 side extractions and ingests succeeded. Existing `Side` timing records
approximately 9.1–10.8 seconds per side, rounded to one decimal by that helper.
All six baseline ladder→fusion→facts computations completed. `sources=()` excludes
primary/secondary atoms in these six cases; the real Ghidriff comparison below is
a separate experiment, not an unseen additional corroborating source.

| Constructed change | Functions old/new | Baseline unified output | Replay after R2 |
|---|---:|---|---|
| Constant changed | 1 / 1 | One P03:A matched row; `review`; explicit scalar delta | Same correspondence and materiality |
| Branch condition changed | 1 / 1 | One P03:A matched row; `review`; explicit JC→JNC delta | Same |
| Added check | 1 / 1 | One P03:C candidate; zero accepted pairs; `material` | Same |
| Function moved | 1 / 1 | One matched row, `unchanged`, UNCH/1 | Same |
| Function split | 1 / 3 | Entry pair matched/material; helper observations absent | Entry pair plus two `newer-only` W/E-UNKNOWN helper rows |
| Functions merged | 3 / 1 | Entry pair matched/material; helper observations absent | Entry pair plus two `older-only` W/E-UNKNOWN helper rows |

Sources: [native-ghidra.json](results/native-ghidra.json),
[native-ghidra-current.json](results/native-ghidra-current.json).
The added/removed wording is deliberately absent from the new helper rows. Their
recorded reason is `tiny`, step `unmatched-tiny`, materiality `not-applicable`.
This fixes lost observations, not automatic split/merge recognition. Direct
inspection of all six replayed correspondences found **zero generated groups**.
No `ladder-groups-not-shown` limitation appears in these particular examples
because there was no group to omit. Other nonempty ladder groups still require a
representation/persistence amendment, as described in the identity report.

The replay opened the original DLLs and verified sidecars read-only and reused
their exact IR content digests. Artifact, SQLite and manifest hashes were equal
before and after. Every configuration digest and result ID changed under
`matching/2`, while the ProgramIR digests remained equal. The report records both
production HEAD/tree and individual source hashes; those production hashes did
not change during the replay. No extraction or primary analysis was repeated.

### Native primary matcher discrepancy

Ghidriff completed the constant-change comparison in 12.451381941 seconds wall
time, with 0.729900837 seconds reported for its native diff stage. It produced one
`SymbolsHash` pair but `functions.modified=[]` and
`matched_funcs_with_code_changes_len=0`. The constructed instruction changed
`MOV RAX,0x11` to `MOV RAX,0x12`. On the same bytes the native IR facts preserve
that scalar delta and yield `review`.

This is an observed modified-function coverage discrepancy in one deliberately
small example, not proof of a security fix, general Ghidriff recall, or semantic
inequivalence. It motivates keeping L1 correspondence separate from L2 change
evidence and retaining the primary raw output even when derived facts disagree.
The native Ghidriff document SHA-256 is
`1cfe2b85b80e54860b3c4e315bba6edb6d9ff5f817fd8d38fb86f3373796b629`;
the complete small document and captured events are in `native-ghidra.json`.
No decompiler-on-demand or BinDiff facts were requested for these runs, so missing
C6–C8 evidence is not a negative vote.

## Real-source cJSON development probe

During R2, R1 made a bounded cJSON 1.7.16→1.7.17 O2 development selection
available. R2 copied only the exact hash-verified engine DLLs, created private
working/cache directories and performed fresh native extraction. The R1 source,
debug/binary review and original labels stayed read-only. Matching consumed no
oracle labels; the admitted selection was used for reporting after execution.
Both DLLs still expose 92 named exports. The independent source/DWARF/binary
review admitted two positive source-lineage/compiled-guard records, left 111
other records unaccepted, and disclosed prior exposure to engine predictions.
This is an unblinded development probe, not a held-out accuracy test.

Ghidra 12.0.4 extracted 262 functions per side. Ladder-only output contains 249
matched rows, one tentative row, five candidates and seven one-sided observations
on each side. Both admitted functions, `cJSON_SetValuestring` (`0x2b80→0x2b80`)
and `cJSON_InsertItemInArray` (`0x3ab0→0x3ac0`), are matched via P03:A and have
explicit `material` verdicts. Adding actual native rz-diff evidence preserves both
results. Rz-diff produced 169 parsed records but proposed neither admitted pair;
the combined result adds nine contested rows elsewhere, whose correctness is
unreviewed. Do not count the other 111 records or runtime/import/thunk rows as
known true or false predictions.

Older/newer extraction plus ingest took 33.250/33.141 seconds, ladder-only
compute/write/deep verification 0.937 seconds, native rz-diff 2.567 seconds, and
combined compute/write/deep verification 1.146 seconds. Whole probe wall time was
71.373 seconds; process-tree peak RSS is unavailable. Both result stores passed
deep verification. C3 supplied the second change channel for the admitted pairs;
C6 was unavailable. Instruction alignment contains compiler/register/CFG noise,
so this does not certify every displayed delta as the reviewed source guard.

This is **two of two selected positive identities recovered with explicit material
verdicts**, not broad precision/recall, F1, FPR or negative-control specificity.
See [report 08](08-native-cjson-development.md) and
[the full receipt](results/native-cjson.json), including native stdout, all parsed
records/derived rows/facts, artifact hashes, producing source hashes and R1 review
provenance. No primary Ghidriff output was fabricated or rerun in this probe.

## Native rz-diff results

The exact repository-pinned rizin 0.9.1 archive and executable were verified. The
probe used the production environment, registry, scheduler and strict parser;
the original 22 attempts took 7.624 seconds. Twenty runs exited natively with code
zero but no stdout and `No functions found in file0` on stderr. Their parser
outcome is correctly failed (`PT-SECONDARY-INPUT`), not a valid empty match set.

| Initial-run accounting | Count |
|---|---:|
| Failed production parser runs | 20 |
| Parsed production runs | 2 |
| Known correct / known incorrect eligible predicted pairs | 0 / 0 |
| Unknown-address proposals | 2 |
| Eligible truth pairs across all attempts | 18 |
| Eligible truth pairs unscored because the run failed | 14 |
| Eligible truth pairs missed in the two parsed runs | 4 |
| Excluded inline/split/merge relations | 6 |

Precision is undefined for the known-prediction subset, not zero or one. Combining
failed runs with successful empty predictions would manufacture an engine recall
estimate. The record therefore preserves the failure count and relation coverage
separately. [Raw output and diagnostics](results/native-rizin.json).

The two parsed address-shift cases exposed conditional reversal of old/new
addresses when the first input has exactly one recovered function. Five extra
native diagnostics and the pinned v0.9.1 source establish the mechanism. Ordinary
multi-function runs preserve the normal direction, so always swapping addresses
would create a new defect. The parser does not possess enough metadata to infer
the recovered first-input function count generally. No speculative correction was
made. Tier W prevents this source from independently accepting a correspondence,
but wrong endpoint references, names and weak contests remain an integration
concern. See [the dedicated investigation](07-native-rizin-findings.md).

## Performance before and after

Repeated immediate-dominator parent walks made back-edge counting quadratic on a
long acyclic chain, despite returning zero loops. R2 builds dominator-tree entry/
exit intervals with an iterative traversal and answers each ancestry query in
constant time. The immediate-dominator algorithm itself is unchanged. After its
result exists, interval construction and edge queries take O(B+E) time and O(B)
extra storage. This is a bound on that phase, not the entire extractor.

| Chain nodes | Before wall seconds | After wall seconds |
|---:|---:|---:|
| 1,000 | 0.015860 | 0.001763 |
| 2,000 | 0.064223 | 0.002237 |
| 5,000 | 0.386845 | 0.006568 |
| 10,000 | 1.552340 | 0.027999 |
| 100,000 | Not run; no extrapolated measurement | 0.219195 |

The 10k observation is approximately 55× faster. This is a single-process local
microbenchmark, not a claimed 55× whole-program extraction speedup. Regression
tests count parent accesses instead of asserting a machine-dependent wall-time
threshold. An independent vertex-removal reachability oracle covers graph
semantics, including self edges, duplicate edges, invalid entry, nonzero entry and
unreachable nodes. An additional review executed 2,832 before/after/oracle
comparisons, including exhaustive graphs through three vertices and random larger
graphs, with no discrepancy. [Detailed methodology and raw results](03-graph-residual-performance.md).

At 100k functions per side the exact-key fixture takes 3.430 seconds of ladder time
and 250.6 MiB peak process RSS. The selective residual fixture takes 31.064 seconds
and 1,116.1 MiB. P16 resolves every true twin in the latter; it does not measure a
100k-node assignment matrix. The common-token-only fixture abstains on oversized
buckets and emits no candidates at 10k, 50k and 100k. These measurements expose
the intended resource/recall tradeoff. True-pair candidate recall on a real corpus
remains a prerequisite to solver optimization. Whole-worker, Java, GUI and
sidecar memory must not be inferred from these Python process high-water marks.

## Changes justified by counterexamples

| Defect | Reproducer before implementation | Corrected behavior |
|---|---|---|
| Native atom order depended on hash iteration | Eight otherwise identical atoms across four PYTHONHASHSEED values produced four serializations | Canonical native tuple tie-break; one stable ordering |
| Evidence cap could erase the B+B class witness | Over 64 atoms retained only E-BODY although acceptance used E-DATA in another component | Preserve an actual different-component/different-class witness and point support indexes at it |
| Manual groups described as automatic agreement | Split, merge and ambiguous manual cases failed explanation assertions | Explicit analyst-correction language |
| IR-only unmatched functions disappeared | Real ingested sidecars plus compute/write/deep-verify/read yielded no rows | One-sided W/E-UNKNOWN observations with verified fid/RVA and original reason |
| Too-small custom atom cap produced an incoherent contested row | Two support witnesses plus one opposition with cap two | Classified `PT-UNIFIED-LIMIT` / `atoms-cap`, before publishing incomplete results |
| CFG back-edge count repeated ancestor walks | A 512-node access-count regression observed 262,144 parent reads | Iterative intervals and linear query work after immediate-dominator computation |

Matching changes also require cache invalidation. `matching/2` is included in the
pass-policy digest and hence the configuration/result identity. A proposed
`ude/2` engine label was rejected during integration because the persisted contract
is literally `ude/1`; changing it would have required a migration. Two new tests
compare the exact pre-R2 digest payload and verify future policy changes alter
result configuration. Existing result schemas, wire `ude/1` and IR keys stay
compatible. This is implementation versioning, not a newly trained confidence
model. [Cache regression](../../../tests/test_r2_cache_version.py).

The obsolete wire test that expected an unmatched gap function to disappear was
updated to assert both anchors and both one-sided gap observations. It does not
hide an unexpected failure: preservation of those functions is the intended
behavior and is separately exercised through persistence. A subprocess regression
was also made to select this checkout's absolute `src` path, because the reused
Python environment has an editable installation pointing at the separate R1
checkout. The initial child-process mismatch was diagnosed and rerun; it is not
counted as a passing R2 result.

## Test and review record

### Research-tool filesystem findings

The first implementation checkpoint's SonarCloud check failed with six path
handling annotations in the research scripts. The GitHub connector did not expose
the annotations endpoint; an approved public GitHub GET subsequently retrieved
the exact file/line/title records, preserved in
[integration-checkpoint.json](results/integration-checkpoint.json). The Sonar
issue-detail API returned HTTP 403. No finding was suppressed or marked approved.

Two real regressions confirmed that the original graph CLI could overwrite an
arbitrary output path and follow a report symlink outside the checkout. A shared
report writer now confines destinations to this checkout's R2 results directory,
rejects traversal/symlink/nonregular targets, refuses existing files by default,
and publishes complete JSON atomically. Only checkpoints belonging to the same
invocation or the explicitly requested Rizin append operation may update a report.
Eight focused path/publication tests pass, including interrupted publication,
racing destination creation and preservation by the Rizin error path. This helper
assumes a stable caller-controlled checkout and is not advertised as a hostile
concurrent-filesystem sandbox.

A separate source review found that Ghidra probe work roots could be reused and
replay case names could escape intended paths. New private work roots reject
existing files/directories and live/dangling symlinks; case kinds are validated
before joins. The initial 22-case regression run was 15 failed/7 passed before
the fix and 22 passed afterward. Those are real filesystem/preflight tests that
stop before native work, not extra native acceptance runs. The later integration
applies the shared output policy to all research runners.

External archive/executable paths remain explicit caller-selected inputs. Rizin
checks that they resolve to bounded regular files, then verifies the pinned
archive digest and equality with its exact executable member before execution.
Reading an explicitly selected file for verification is distinct from a report
write escaping its intended destination. The current-head analysis must determine
the remaining gate status; these changes do not retroactively make the failed
checkpoint green.

The local runtime is Python 3.12.14, pytest 9.2.0, Hypothesis 6.170.14, Ruff
0.17.3 and PySide6 6.12.0. The interpreter is
`/workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python`, used read-only. The R2
checkout is `/workspace/scratch/9b177a4979cd/patchtrace-r2`.

| Check | Result and scope |
|---|---|
| Unmodified focused baseline (`test_unified_*.py`, `test_secondary*.py`, `test_bindiff_*.py`) | 2,509 passed, 1 pre-existing xfailed; 258.99 s |
| Integrated R2 + keys/wire/fusion/CFG selection | 203 passed; 3.99 s |
| Expanded integrated selection after all research-tool safety changes | 248 passed; 5.72 s; copied validation interpreter with existing read-only dependencies |
| Independent integrated cache/leftover/cap/wire review selection | 19 passed; 3.96 s |
| Independent B+B predicate comparison | 10,000 seeded cases agree with exhaustive eligible-pair predicate |
| Independent graph semantic comparison | 2,832 cases agree before/after/oracle |
| Ruff / whitespace at implementation checkpoint | All checks passed / clean |
| Full local Linux suite | Running at this checkpoint; final outcome is recorded before handoff |
| Current-head cross-platform/native CI | Pending at checkpoint; baseline results are in report 00 |

### Full-run environment diagnosis and recovery

The ongoing full run's identified 56 failing/error IDs were rerun unchanged on a
detached exact baseline and current R2. Both produced **47 failed, 9 errors**
(2.13 s baseline, 1.70 s R2), with identical short-summary node IDs. Fifty-five
cases fail at `socket.socket` construction with `PermissionError: [Errno 1]
Operation not permitted`, before application transport/consent logic. The other
test resolves `sys.executable` through a venv symlink to the base interpreter,
which lacks `google.protobuf`, and obtains `protobuf_missing` instead of its
expected `protobuf_not_upb`.

An isolated scratch validation venv uses a copied interpreter, the same read-only
base packages, and a path to the original venv dependencies. It neither installs
new dependencies nor alters R1's environment. Its resolved interpreter remains
inside its venv and imports protobuf 7.36.2. Tool-approved execution supplies the
local socket access required by those tests; no network-policy bypass, test skip,
test rewrite or proxy change was used. **All 56 selected tests then pass in
30.43 seconds.** A first setup attempt was stopped by a missing base
`typing_extensions` dependency; matching the original runtime's read-only system
package setting fixed setup before the successful run. This setup failure is not
counted as a test pass.

The copied interpreter is
`/workspace/scratch/9b177a4979cd/r2-validation-venv/bin/python`. The final expanded
248-test integration selection also passes with it. The original full run and
its final count remain separate evidence; a repaired rerun of selected failures
must not be described as an independently green complete-suite invocation.

The existing strict xfail concerning support display for two same-class components
remains explicit. It is not reported as a pass, and no confidence policy was
weakened to remove it. Independent review found no concrete correctness defect
in the integrated cache, leftover, cap or default acceptance changes; this review
does not substitute for Windows, native corpus or complete group acceptance.

Exact focused integration command, from the R2 checkout:

```bash
PYTHONPATH=/workspace/scratch/9b177a4979cd/patchtrace-r2/src:/workspace/scratch/9b177a4979cd/patchtrace-r2/tests \
QT_QPA_PLATFORM=offscreen \
/workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python -m pytest -q \
  tests/test_r2_*.py tests/test_unified_keys.py tests/test_unified_wire_compute.py \
  tests/test_unified_fusion.py tests/test_unified_ir_graph.py

PYTHONPATH=/workspace/scratch/9b177a4979cd/patchtrace-r2/src:/workspace/scratch/9b177a4979cd/patchtrace-r2/tests \
QT_QPA_PLATFORM=offscreen \
/workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python -m pytest -q

/workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python -m ruff check src tests tools
git diff --check
```

Native reproduction commands, tool hashes, fixture hashes and complete small
outputs are in the native JSON records and the `--help` of
`tools/research/r2_ghidra_probe.py`, `r2_ghidra_replay.py` and `r2_rizin_probe.py`.
The replay depends on preserved IR; after temporary files disappear, reproduce
the first native probe before replaying. The JSON remains the durable record;
the repository does not commit tool distributions, target DLLs, GZFs or private
Tier W data.

## Current acceptance boundary

The repository's baseline advisory unified run reported success overall while
27 jobs failed and the actual G-U1–G-U8 gate report was NOT READY. It measured zero
matched rows. The first R2 implementation checkpoint has CI in progress and a
failing SonarCloud new-code security rating; exact path annotations were retrieved
and concrete report/work-directory defects repaired in later commits. A later
head requires its own analysis and is not waived through the old gate. CodeRabbit skipped automatic
review because the PR is draft. These observations are not approvals.

No held-out lineage evaluation, calibrated probability claim, native BinDiff
acceptance, automatic N:M completion, Windows package release or default-on
change is claimed. [The limitations register and R3 handoff](06-limitations-and-r3-handoff.md)
turn the remaining questions into concrete next experiments and ownership.
