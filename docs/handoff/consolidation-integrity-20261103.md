# Consolidation continuation — November 2, 2026 (Pacific)

The `20261103` receipt identifiers below use UTC. This continues the existing
consolidation; it is not release completion. Historical evidence remains bound
to its original source and environment.

## Main has advanced

Reviewed backup repair [#162](https://github.com/djshellshoxxx/patchtrace/pull/162)
was merged normally after fresh head/base/review checks. Main is now
`1b81740612e65df55e220ff6e42a4816756ec2ad`, tree
`61ddda8e5b94e4eaaeb13e9939625740d1124067`. Its parents are prior main
`ce8c65bf41541cf6adb52289d2a530ce2817a53a` and reviewed head
`f1a55c4cf21ddb0dea243bd417b74f86caaed142`.

All 24 reviewed-head checks completed: 22 success and two intended skips.
QA/package/Qt workflow `41540958514` and both native workflows completed
successfully. Snyk succeeded, no review threads existed, and the sole COMMENTED
review was a nonblocking missing-test suggestion. The resulting main tree
equals the reviewed head tree. No protection bypass or force update was used.
The two-observation fingerprint still does not claim an atomic snapshot.

The combined parent [#163](https://github.com/djshellshoxxx/patchtrace/pull/163)
remains a draft at `6e82fd70f315b99c6798a42c9061a1424a02933e`, tree
`2e7cd8e258821f50d776ca3b3a4caef594e2a417`. Its source already contained this
backup repair. At the latest inspected checkpoint, full Linux and Windows QA
passed; two Qt legs were still running and downstream package/smoke jobs had
not completed. The six failures remained the existing Sonar and Rizin/corpus
gates. Do not transfer these results to this later source tree.

## Reviewed integrity slices assembled

| Slice | Frozen author identity | Integrated behavior and evidence |
|---|---|---|
| Tier R provenance | `294bccc4886261376fa9cb61c0197c52f3fba315`, tree `91aa77f1a23bce2a56a27e2e325a5ab69c3365ac` | Complete content-addressed build receipts, build/source-bound SideData cache reuse, and unchecked ambiguous declared-unchanged controls. All three production files match preserved #128 blobs. Author 21 focused passes; independent source/caller review and two additional destination-type controls approved the bounded slice. |
| Saved rules integrity | `2fe7a2bff2caa1f95a0c858ec58b0a9121049951`, tree `b341d7169b61a604172ab38133c0ddef43121bbd` | Seven final #146 source/test/specification blobs preserved exactly: identity-aware cached grids, refusal before invalid export output, corrupt-sidecar skipping, and bounded POSIX acquisition. Author 420 focused passes; independent review verified source, actual callers and raw logs. |
| Backup refusal coverage | `c35dceb319e960a462748cbe17b03c05e0766255`, tree `afb1b5d366d5e9c4a6fb299bc5c840ef304aba98` | Test-only followup to the bot suggestion: a failed second byte observation revokes cached trust, preserves backup bytes and requires full re-verification before trust returns. Seventeen focused passes; independent review approved. |

Author commits are local review identities, not fabricated remote ancestry.
Root imported the reviewed patches into a separate integration checkout and
verified the exact source/test/specification blobs against both author trees.
Existing callgraph budgets, saved investigation scope, extraction isolation,
forced-identical controls, redaction, schemas and tool pins were preserved.

The assembled source was frozen at local commit
`a9b9d987a5f57a431a20b1895cb641b9d3f60de6`, tree
`d20bede6222093d00d054b528d738468f306f257`. This includes the earlier evidence
tree corresponding to published `44c320e37b84a38259f13fa8f0f444b542b96f2c`.
Later receipt/tracker changes do not alter the tested code or tests.

## Combined validation

The twelve selected test modules/nodes cover the six rules compatibility files,
three Tier R integrity regressions, the existing synthetic compiler-wrapper
integration control, and two backup integrity files:

**459 passed, zero failures/errors/skips in 14.06 seconds.** Whole-repository
`python -m ruff check src tests tools` and `git diff --check` passed. No wire
contract/schema changed. Synthetic fixtures and fake compiler scripts are
wiring evidence; no compared target or live comparison engine was executed.

See [focused receipt](../qa/consolidation-integrity-focused-20261103.json) and
[raw logs/JUnit](../qa/consolidation-integrity-focused-20261103.tar.gz),
[rules/backup independent review](../qa/consolidation-rules-integrity-independent-20261103.md),
[data-integrity independent review](../qa/consolidation-data-integrity-independent-20261103.md),
and [fresh CI review](../qa/consolidation-ci-review-20261103.md).

A new full-source run and exact published-head hosted gates remain required.
The earlier 19,154-pass run and its successful targeted environment followups
remain preserved separately; they do not qualify these later changes.

## Publication and ownership

Publish this as a focused followup to #163, retaining the actual evidence parent
`44c320e37b84a38259f13fa8f0f444b542b96f2c`, current main merge
`1b81740612e65df55e220ff6e42a4816756ec2ad`, protocol merge
`dfe8f421db390ccd3158393a60205fa5dd25df0b`, and replay/schema merge
`874e9a267fdc589a796ce573f2958e1aa84ea0f6`. The latter merge trees equal the
reviewed source already included in #163. The parent candidate head must remain
unchanged while its current checks finish. No #128 or #126 ancestry claim is
created by selectively preserving their fixes.

Root remains integration/publication and validation owner. Both bounded authors
and their independent reviewers have finished; no unfinished helper-owned edit
is outstanding. Original source branches and prior failed evidence remain.
Final publication SHA/tree and running-job identities belong in the PR and the
next result receipt; do not invent them in this pre-publication checkpoint.

## Explicit remaining work

- Sonar's combined-candidate detail is still inaccessible through the available
  connector. The C security rating where A is required remains unresolved;
  no path/rule/dataflow or false-positive disposition was invented.
- Rizin orientation quarantine and dependent corpus failures remain. BinDiff
  verification/exporter compatibility and packaged native/full offline bundle
  acceptance remain separate gates. No native acceptance is inferred here.
- #128/#145/#150 still contain the broader research tools/archive and anchored
  research publisher with completed matrix/pilot receipt recovery. The new
  build helper is self-contained, exclusive and complete-before-publication,
  but does not claim parent anchoring, power-loss durability or native Windows
  filesystem acceptance. The mutable compatibility view remains direct-write.
- The seven #146 rule paths are preserved in this proposed candidate. #126's
  separate named-superseded diagnostic disposition remains; saved scope must
  not be regressed to global revision suppression. The proposal evidence
  loader remains unset. No full rule-authoring workflow is claimed.
- Native Windows device races, human desktop/accessibility acceptance and the
  final public-release decision remain open. No final release is authorized by
  this checkpoint; no adopted work was silently removed from final scope.

Continue from [the release critical path](../qa/consolidation-release-critical-path-20261102.md)
and [research agenda](../research/patchtrace-improvement-research-20261102.md),
updating dated observations after new evidence. Historical PR counts are not a
completion percentage, and selective preservation does not justify premature
PR closure.
