# Independent review: PR #305 and PR #306

## Verdict

**PR #306 addresses a reproduced current defect, but its exact reviewed head needs one correction before integration.** Its generated kind filters reduce the accepted component-anchor text budget from 240 to 134 characters. The closed binary-evidence restriction itself works and should be preserved.

**PR #305 is a compatible test-only follow-up.** Its five new files and 15 tests pass against current #304 production code and helpers; they reveal no current production failure. A trailing blank line at the end of one added test fails `git diff --check` and needs routine cleanup.

Reviewed current #304: `f69614fa6b5bb9d25d4233b06a4c4ce179964a52`. PR #305: `16ab88b0626ef05700c4199e926103932312e5c7`. PR #306: `f6ef1528c15b2281ee7b6f32625d02a5211c926d`. Both new PRs branch from `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`; neither contains the current #304 integration. REST rechecks at 09:45 UTC still reported the assigned heads, open and draft.

## 1. PR #306 regression: valid long anchors become unsearchable

**P2; candidate `src/patchtrace/search/anchors.py`, lines 65–72.** The implementation serializes all nine binary-kind filters into query text before passing it to the existing 256-character parser. Those fixed filters consume 106 characters. The ordinary changed-scope component payload consequently shrinks from 240 characters to 134.

The independent probe parses a synthetic CSAF title through the actual validator/normalizer and `anchors_for`, producing a valid 160-character component anchor. The exact phrase occurs in a changed synthetic function's code. Results:

| Source | Query length | Coverage |
|---|---:|---|
| Current #304 | 176 | `changed`, 1 hit |
| PR #306 | 282 | `not-searchable`, 0 hits; query exceeds 256 characters |

This is a new loss of an existing valid match, not an overlong source value newly becoming valid. The smallest repair is to preserve the existing bounded phrase/scope parsing while applying the closed kind restriction to the validated typed plan, without charging generated filters against the payload budget. Preserve the global query limit and add valid boundary controls around 134/135, 160 and 240 characters.

Evidence: `probe_search.py`, `current304-probe.json`, `pr306-probe.json`; the corresponding context JSON files contain exact executable, environment, source SHA and working directory.

## 2. Current circularity is real; the core guard works

The PR's real-service test fails on current #304 with `clfs.sys -> indexed-only, hits=1`, solely from its indexed advisory. Three positive/premise controls pass. The same four tests pass on PR #306 with source-module paths asserted at session start.

Independent controls also use the real CSAF parser, `anchors_for`, production `advisory_specs`, and a real `SearchService` over synthetic project data. On #304 all four unrestricted kinds—module, feature, component and API—count advisory-only text as `indexed-only`. A token occurring only in an analyst note, using default source groups without advisory injection, becomes `changed` with one hit. PR #306 removes those false hits and returns `unknown` with zero hits because binary IR coverage is unavailable. Actual changed `CheckLength` and unchanged `MainLoop` controls remain `changed` and `indexed-only`. Quoted filter-looking input remains one phrase, with no injected exclusions or query terms; string/PDB overrides remain intact.

This substantiates the section 5.1 repair. It does not establish vulnerability causation or complete absence in an incompletely indexed project. Default production CLI/desktop calls do not currently supply advisory extra groups; the default-group note control therefore matters in addition to the injected advisory-group reproduction.

## 3. Separate existing defect: default stored-advisory CLI

**P2; `search/anchor_cli.py` lines 22 and 40, called from `search/cli.py` line 208.** The real CLI with a persisted synthetic CSAF and no injected opener or anchor source returns exit 3 / `AttributeError` on both heads. The search dispatcher constructs `SearchService`; the default anchor source treats it as `ProjectService` and accesses `.root`, `.store` and `.project`. The wrapper instead retains that object as `.service`.

A direct boundary probe records `'SearchService' object has no attribute 'root'` at `anchor_cli.py:22`. That file's blob is identical on both heads (`be002d66777868a3dbb11016adf307be03c6e402`). Track this as a separate narrow adapter repair with a default-port CLI regression. It is not introduced by #306, and #306 should not be described as completing that CLI journey.

Evidence: `scope-and-cli-boundary.json` and both cross-head probe results.

## 4. PR #305 scope and limitations

The five added paths are absent from current #304. They add useful guards for unexplained leads staying queued, duplicate anchor/provider lineage, channel-set aggregation across multiple KB leads, absence of calibration imports, the current provider decision, and direct project-open calls in submitted GUI work.

All 15 tests pass using byte-identical external copies with current #304 production modules and helper fixtures. The source scans resolve to current #304, not to the PR's older main-based tree. The worker scan observes 27 files and 37 submit sites. Its explicit AST heuristic does not follow helper-call chains: a worker that calls a helper containing `ProjectService.open` is outside what this test proves. This is a test-scope limitation, not a reproduced production violation. The OSV text scan is broader than checking provider wiring alone and may require adjustment alongside future source-policy changes.

Changed-file Ruff passes for both PRs. PR #306 whitespace checks pass. PR #305 whitespace checks fail only at `tests/test_source_lineage_counts_once.py:87` (new blank line at EOF).

These tests can remain a separate follow-up; they do not require importing unrelated PR history into the consolidation or adding a production change now.

## Evidence integrity and limits

All three detached worktrees remain clean. No product source, target binaries, original receipts or remote state was modified. Tests are synthetic and offline; no hosted acceptance is claimed. Counts from overlapping invocations are not summed.

One initial purported green attempt selected current #304's pytest configuration, whose `pythonpath = [\"src\"]` overrode the intended source. Its failure is retained and explicitly disqualified as PR #306 evidence in `harness-correction.json`. Corrected red and green runs select each target's own configuration and assert the actual imported source file. Full original logs, JUnit and argv receipts remain preserved.
