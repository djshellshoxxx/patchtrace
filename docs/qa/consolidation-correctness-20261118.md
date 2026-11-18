# Consolidation correctness follow-up — 2026-11-18

## Scope and independent review

PR [302](https://github.com/djshellshoxxx/patchtrace/pull/302) remains the
continuation of #301 and preserves its full ancestry, including #297. Its first
published head was `f7e075480999e2f5a3681ddd429dca0fd9cac986`. Before merging,
a concurrent contributor opened [PR 304](https://github.com/djshellshoxxx/patchtrace/pull/304)
at `bb4277aed685d485b57ffe7a718e70bab3e34467`, descended directly from that
head. Review reproduced additional correctness failures. The continuation ports
the six narrow repairs below and adds independently checked follow-ups.

| Exact PR 304 source commit | Continuation REST commit | Scope |
|---|---|---|
| `de3d8bb752af384d7d0d9a47ff5ba077f96ec5fe` | `ed04746a110d800b73bf5824c82f454398154ec0` | fix(release): reject unsafe Windows ZIP path identities |
| `485d9c0896cca1ac63e68f3e64205a754bdd15d4` | `8bd9e6d9a5798d8cedffdd970fab7164f09612d8` | fix(kb): preserve uncertainty in chronology and fix boundaries |
| `bd994c07e3c626c3430b4707f99628079474f1aa` | `609545ad0883cdf743bf81533790ea69c850e048` | fix(accuracy): block scoring after unattributed advisory rejection |
| `07a335731839cc2bca40f207a5cb79228823857d` | `a56c20111853d499d90ff28588b883e187d8a0f3` | fix(kb): validate calendar evidence before establishing chronology |
| `aad3489bba2e6cd41fdaad486ce20c782d8be96c` | `7eb701825b58e2b4afaab8ecb6736e3ef4e8fb28` | fix(kb): validate direct lineage builds and sibling mappings |
| `11e88b634af70a40f6860e0abb843b3f627ad5cc` | `b244369c296bceb13ce6e0d716f99e078d440f13` | fix(kb): isolate index lineage by selected architecture |

These are selective ports, not a wholesale merge of #304. Its release-hold
marker/policy change is outside this task and is not adopted. Existing automatic
prerelease behavior is preserved. Its separate `.tsp` support, research winpairs
publication/native controls and source-corpus receipts remain in open #304.
Those receipts were checked against their committed digests and recorded
semantics; that check is not a new raw-source replay or a new L1/L2/L3 result.
The new concurrent #305 and #306 remain separate open work and retain their
branches. No branch has been deleted, archived, force-pushed or rewritten.

The independent freshness check completed at 2026-11-18T09:04:54Z: authenticated
branch pages contained 100/100/100/6 entries, matching the Git advertisement;
there were **306 branch heads including main, or 305 topics**, and **53 open
PRs**. All 300 original topic tips and all 48 original open PR head/base pairs
were unchanged. The five additions were #302–#306. All 18 planned closure-source
heads remained unchanged; closures are still conditional on qualified main.

PR #305 at `16ab88b0626ef05700c4199e926103932312e5c7` adds five guard-test
files, with no production change. PR #306 at
`f6ef1528c15b2281ee7b6f32625d02a5211c926d` repairs advisory-anchor circularity
in a production file whose blob is identical in starting main, #301, original
#302 and this candidate. It is independently tracked pre-existing scope.
The retained #168 draft still has separate SonarCloud/cancelled-check evidence;
that result does not qualify or fail the successor.

## Reproductions and final behavior

The independent release/L1 reviewer reproduced 63 failures and 11 passes for
the borrowed chronology/architecture controls on the original #302 source, and
three failures with one positive control for L1 rejection. The independent core
reviewer used a larger overlapping four-module set: 78 failures and 95 passes
on the original source, then 173 passes on the six-port candidate. These counts
overlap and must not be summed.

The first Windows ZIP port mistook Python's ordinary separator normalization
for NUL truncation. A valid authored ZIP with a raw backslash member failed when
read with Windows separator settings. The follow-up checks the actual NUL
condition, preserves the existing rejection and collision controls, and accepts
the benign separator case. The complete independent ZIP/L1 selection passed
238 tests after that fix. Native Windows qualification remains a separate gate.

Seven independent chronology/selection counterexamples failed on both the old
head and the initial six-port candidate; two positive controls passed. They
covered masked missing builds at one instant, cross-family equal-instant
ordering, hash-selected variants, KB-sort-dependent certainty, unavailable
variants and truncated alternatives. A further lead-authored probe reproduced
automatic selection and a supported fix boundary for competing older variants.
The first repair fixed those boundary and selection claims, but independent
review then found four failures affecting change/last-change provenance at an
ambiguous earlier position.

The final core implementation at
`bce67e93548ae100f3922a265aa2cba0a544e29f`, tree
`dc1f6c0a3133692b2e214cd0f0907b2911dfd404`, now:

- Orders valid UTC instants; equal instants require numeric builds from the same
  family. Display order cannot supply missing chronology.
- Keeps observations unordered against either endpoint in the confounding
  window and withholds a supported fix boundary.
- Uses established earlier rows for each target variant. A direct tied proposal
  still has `ORDER_UNVERIFIED`, incompatible lineage and grade X.
- Withholds change/last-change claims when competing predecessor observations
  disagree about whether the target bytes were already present. Established
  reversions remain valid.
- Carries full-source ambiguity into JSON and human output before filtering or
  truncation. Plan/acquire require an explicit pair choice, even when only one
  alternative is downloadable. Explicit choice does not remove hard blocks.
- Bounds enumeration before evaluating omitted targets. The 1–1,000 pair limit
  and 1,000,000 row-times-target work budget preserve visible truncation.
  Incomplete enumeration with no evaluated proposal reports `INDEX_GAP`.
  Chronology facts for repeated scans are calculated once and held only within
  that resolution; total timestamp parsing remains linear.

The earlier architecture regression expected one target variant to be treated
as another's predecessor. It now checks both alternatives against the established
older build, retains explicit-choice requirements and separately verifies the
direct tied comparison is blocked. No failing behavior was converted to a skip,
xfail or success.

## Exact verification

Independent final detached review: **239 passed in 2.35 s**, comprising the 225
affected project cases and 14 independently authored controls. Whole-tree Ruff
and comparison whitespace checks passed. The independent reviewer approved the
certainty, selection and work-budget changes at the exact code/tree above.

Lead affected integration command on that code:

```bash
QT_QPA_PLATFORM=offscreen PYTHONPATH=src:tests python -m pytest -q \
  tests/test_kbc_lineage*.py tests/test_kbc_resolver*.py \
  tests/test_kbc_pairs_index.py tests/test_kbc_acquire_cli.py
```

Result: **225 passed in 2.15 s**. This includes CLI listing, implicit plan/acquire
refusal, explicit planning and existing acquisition/consent regressions.

At `5ad21c39`, the separate verifier, L1 runner and KBC schema selection passed
**242 tests in 1.37 s**; those tested files remain unchanged through `bce67e93`.
KBC schema regeneration produced no drift, and whole-tree
Ruff and `git diff --check` passed. These results overlap the independent review
and are not an additive coverage total.

The work-budget test file borrowed onto pre-budget `6bf5d900` failed all ten
cases: eight behavioral failures and two absent-interface failures. An isolated
copy supplying the new constant to the old module confirmed both of those
remaining cases also failed behaviorally. In particular, a seven-pair limit
attempted an eighth proposal; 101 input rows caused 110,502 timestamp parses.
On the final implementation, independent instrumentation counted 323, 1,523 and
15,023 timestamp parses for 100, 500 and 5,000 variants with a ten-pair limit.
Lead synthetic timings were approximately 0.003, 0.013 and 0.129 seconds for
100, 500 and 5,000 variants. These are local measurements, not universal timing
guarantees or live vendor acceptance.

The earlier broad selection on the six-port candidate passed **1,499 tests**.
A later combined invocation of all KBC modules plus verifier/L1 on the first
follow-up ended with **exit 137 and no result summary**. It is not counted as
passing and its cause was not established. The smaller affected selections above
completed normally. Hosted full-suite gates are required on the new published
head; the old head's successful runs do not qualify this changed tree.

## Historical hosted qualification and open gates

The original #302 head `f7e07548` was tested through generated merge
`5b3bf738f2189e08e33b91fdfbed5b093609034a` over main
`9c411ca3d7b47f950be5f0c6f01b3c54184554c6`.
Its [QA/packaging run](https://github.com/djshellshoxxx/patchtrace/actions/runs/44251907224)
reported Linux **22,551 passed, 48 skipped, 6 xfailed** and Windows
**22,474 passed, 126 skipped, 5 xfailed**. Windows portable/frozen/installer
checks, all five Qt repeat legs, Linux package and both Ubuntu smoke legs
completed successfully; the seven original-head workflows subsequently passed.
Release/release-gate and the advisory MSVC job had their intentional skips.

That evidence remains attributed to the old head. The updated successor needs
its own current-head/base CI and merge decision. No merge or supersession closure
is claimed by this record. Main was still `9c411ca3` at the freshness check.
PW-01 remains in separate [PR 303](https://github.com/djshellshoxxx/patchtrace/pull/303)
and must incorporate the repaired predecessor before final qualification.

Manual Windows desktop/accessibility, clean-machine release, the targeted RB-01
live rerun, the owner's timeout-pair acceptance and separate L1/L2/L3 accuracy
gates remain open. A pre-existing mixture of Windows 10 index key aliases is
tracked separately; this follow-up does not claim to solve it. The two existing
strings-export issues remain separately tracked. No target binary or
package-supplied program was executed.

## Publication identity

The authenticated REST Git-data interface creates a new descendant chain with
the same complete trees as the local continuation. It does not rewrite the
original PR 304 commits or either existing remote branch. Source commit messages
retain the source author's original implementation/tree labels; the appended
continuation labels and this table identify the actual selective trees.

| Local continuation commit | Corresponding REST commit | Exact shared tree |
|---|---|---|
| `836f371db79527e66cb2bc9107651bf7ee241102` | `ed04746a110d800b73bf5824c82f454398154ec0` | `5e162549e6f793be2b45e0bca6f5902647fc0af0` |
| `0f8f234dc3017b26cc05342f92b323466ad48606` | `8bd9e6d9a5798d8cedffdd970fab7164f09612d8` | `bf6cd6f2cf308236f6c4d4b2c5d8c47fc61dea0f` |
| `ee41e77703af1340ecb47b143ac36ea047930d02` | `609545ad0883cdf743bf81533790ea69c850e048` | `40c1f12d3a0798c4d9be477ef34e50cca14dc909` |
| `532bd49a7566db2035d3ac9670fcd4d83208d53a` | `a56c20111853d499d90ff28588b883e187d8a0f3` | `ecdf8394c80e29ecce9d0f4f490fb8f4ebc50f58` |
| `2d0be71b64277a83ac45d1f457f4b77831fcd639` | `7eb701825b58e2b4afaab8ecb6736e3ef4e8fb28` | `2e9e33c0d1db3c877ed9a81176220e4889d644e3` |
| `c3131ebf0844ddaafe9d5d70e0301df07d177d1f` | `b244369c296bceb13ce6e0d716f99e078d440f13` | `58bc87b65d86eec9a5940e9436e1b63a6c7c36e5` |
| `c36a1725554ea96ab2029329e58947e6553b20df` | `b962facc70a4ed032b82afa9cebd217e25373a06` | `75d99f89e78f61b04656ba06bf105839ff9e7ab8` |
| `5ad21c39248563a2d56377b31b753c9eeae3a03a` | `fbc164d401b103237fad2fbb633dc2d124afb2b7` | `43968cdda9940c20ca5e4ede0a5c360a940e6c5a` |
| `6bf5d9003df13e639bbfd624c632cb26f19fdba8` | `154f030c7d170ebc757f8b1aa338c9f572f2133e` | `81a7f04868fd54616f3b92e8ea3e4dde3e16c27b` |
| `bce67e93548ae100f3922a265aa2cba0a544e29f` | `7d80aee7b92eb9fe83c818cdfec7527f19efc252` | `dc1f6c0a3133692b2e214cd0f0907b2911dfd404` |

The final documentation commit follows these objects. Branch publication uses
an expected-head fast-forward guard against `f7e07548`, followed by a fetched
tree comparison. Exact final PR head, base and tested merge identities belong in
the current PR and final integration record.
