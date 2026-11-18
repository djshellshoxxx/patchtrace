# Advisory anchor integration and preserved qualification

## Decision and exact source

The reviewed consolidation continues published #304
`f69614fa6b5bb9d25d4233b06a4c4ce179964a52`. It preserves actual #305
`16ab88b0626ef05700c4199e926103932312e5c7` and #306
`f6ef1528c15b2281ee7b6f32625d02a5211c926d` as merge parents, then repairs two
independently reproduced compatibility defects. No remote branch is deleted or
rewritten; none of these PRs is claimed integrated into main by this record.

The production/test repair was frozen at local commit
`b9fac06b0d9a487acff65fa51c4a98ce53943ab2`, published as
`2306de3a5141d31dcc2e374a2d25e5b5803a3ae7`, with identical tree
`4508e191f09d815ba15a81458739abd4f0b8295f`. The final documentation commit adds
this record and the exact evidence payloads; it changes no production or test
files. The [publication mappings](search-anchor-integration-20261118/publication-code-mappings.json)
pin each local and remote parent/tree pair.

## Findings and resulting behavior

The #306 circularity repair is necessary: an advisory-derived module, feature,
component or API value could previously match the indexed advisory or an analyst
note and appear to be binary evidence. The closed binary-kind union now survives
both changed and indexed scopes. String and PDB anchors retain their narrower
kind restrictions. A match remains a search hint; no vulnerability attribution
or new accuracy claim follows from it.

The original #306 implementation added 106 generated filter characters to the
256-character query budget. A valid 160-character CSAF-derived component found
in changed code became unsearchable; the largest plain changed-scope value fell
from 240 to 134. The repair retains normal bounded parsing, then reconstructs a
validated typed plan with sorted closed kinds. It keeps the global limit, quoted
literal behavior, typed digest and cursor identity intact. It does not place
oversized text into an unchecked model copy. The specification was amended
before implementation; existing assertions now pin the typed restriction.

A separate pre-existing default CLI defect passed the search facade into a
stored-advisory reader that needs the project owner. The default source now
receives the existing underlying `ProjectService`. It does not open another
project or bypass locking. The injected source keeps its existing facade
argument. Real default CLI invocations read persisted synthetic CSAF, preserve
facts/project state and release the lock. Empty stored advisories retain exit 4;
an incomplete index retains an honest partial/unknown result.

The five #305 test modules add useful guards for false-positive promotion,
independent lineage, provider scope and direct worker project opens. Their 15
tests already passed current #304. The worker AST scan is a direct-call heuristic,
not a proof about transitive helper calls. Its single extra EOF blank line is
removed; no production change is justified solely by those passing tests.

## Evidence packaging

The [verbatim evidence archive](search-anchor-integration-20261118/evidence.zip)
contains all raw receipts, logs, review scripts and original manifests. Paths in
the adjacent payload manifest refer to archive members. The four readable review
summaries remove trailing whitespace only; exact originals remain inside the
archive. This preserves the raw failed outputs while keeping repository text
whitespace checks meaningful. [Archive identity and packaging record](search-anchor-integration-20261118/archive.json).

## Local and independent qualification

| Invocation | Result | Evidence and scope |
|---|---|---|
| New compatibility controls before repair | **7 failed, 9 passed** | Five query-budget failures and two default stored-source CLI failures; raw log/JUnit retained |
| Focused repaired selection | **79 passed** | Anchor plans, circularity, new compatibility and CLI |
| Broader selection at `b9fac06b` | **942 passed** | All search modules plus the five #305 modules and adjacent intelligence/pilot/KB checks; 15.87 seconds |
| Independent frozen-source invocation | **85 passed** | The 79 focused cases plus six external boundary/persistence controls; 1.78 seconds |
| Independent three-head boundary probe | Assertions passed | 108 boundary combinations, 36 unchanged string/PDB cases, literal/invalid inputs, six digests and five actual cursor controls |
| Whole `ruff check src tests tools` and full additive diff whitespace | Passed | No schema field change; JSON round-trip checks remain explicit |

These invocations overlap and are not summed. All search fixtures are authored
offline data. The independent original circularity probe used the actual CSAF
parser, anchor extractor, source adapter and `SearchService`; the CLI controls
used the production default opener/source. None establishes live-provider,
native Windows, or vulnerability-ranking accuracy.

The initial boundary probe correctly rejected a surrogate at `Anchor`
construction, earlier than its first harness expected. That failed harness and
the corrected expected admission-stage record are retained separately. No
product behavior was changed to accommodate it. The earlier misconfigured
upstream review attempt is likewise retained and excluded from qualification.

Exact commands, environments, source guards, raw outputs and SHA-256 manifests:
[root checks](search-anchor-integration-20261118/commands.json),
[initial PR review](search-anchor-integration-20261118/upstream-review.md),
[independent repair review](search-anchor-integration-20261118/independent-review.md),
[boundary review](search-anchor-integration-20261118/boundary-review.md), and
[complete payload manifest](search-anchor-integration-20261118/manifest.json).

## Frozen real-source L1 replay, preserved at its actual source

The final replay on published `f69614fa` completed in 39.31 seconds:
**73 PASS, 6 FAIL, 0 BLOCKED, 8 excluded** across 87 manifest cases. The runner
returned exit 1 and a FAIL receipt because the six failures remain. Advisory
checks were 79/79, product checks 76/76, and requested expected-file checks 64/70.
Outcomes, exclusions, expectations and frozen raw inputs did not change.

The single case-record difference is CVE-2022-41073 / KB5019959 / `winspool.drv`:
one viable candidate became two, while the change claim stayed unknown and the
case remained PASS for its expected-filename check. Both plans need bytes, have
a confounded window and an unverified fix boundary. Automatic selection is
refused without an explicit pair. This is not unique-pair or fix attribution.

Four Windows Server coverage gaps and two files already present in earlier
preview updates remain failures. The corpus has been used for debugging; no
independent prediction accuracy or confidence bound is claimed. This replay is
source-specific evidence for `f69614fa`, not a claimed new execution at the later
search commit. [Full receipt, comparison and source-preservation checks](search-anchor-integration-20261118/l1-replay.md)
are retained unchanged, including receipt SHA-256
`b84daff99d229d958ef2fea91deea70d5878be34b3e64c935f2dd2e4f4999e45`.

## Hosted gates and next action

At the preserved 09:51:59 UTC checkpoint, all seven workflows were verified on
`f69614fa`: 21 returned jobs queued, two succeeded, two intentionally skipped,
zero failures returned. The successes were Linux BinDiff and the corpus plan;
all overall conclusions remained null. Native Windows publication, full QA,
Qt and packaging were not accepted. [Raw checkpoint](search-anchor-integration-20261118/evidence.zip).

Qualify the final published head on every required full Linux/Windows, Qt,
package/installer, native and dependency gate. Refresh refs/reviews/settings
before a REST merge guarded by the exact head SHA, with literal `[no release]`
in the merge message. Verify main integration before closing any superseded PR,
and preserve every remote branch. The PW01 capacity/admission continuation and
L2 discovery failure/L3 unapproved acquisition remain separate open work.
