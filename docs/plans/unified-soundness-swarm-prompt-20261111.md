# PatchTrace: unified-engine soundness swarm prompt (plan + execution)

Written 2026-11-11 for `djshellshoxxx/patchtrace`. Orchestrator session: `claude/funny-feynman-d2m0b5`.
This file is both the plan and the paste-ready brief for every worker. Workers skip to section 3.

## 0. Why this is the most difficult remaining part (orchestrator's finding)

Candidates checked against GitHub on 2026-11-11 (default branch `882d1ca0`, push run 42605088788 green on Linux,
Windows and Qt gates; 48 open PRs, the newest being #279, #268, #259):

| Candidate | Difficulty | Why it was not chosen |
|---|---|---|
| PT-TIMEOUT-2: profile and repair Ghidriff's 2.16 M-entry structural candidate expansion (`docs/qa/ghidriff-timeout-20261106.md`) | very high | needs Windows, the owner's unsupplied binary pair, a real Ghidra/Ghidriff run and owner-side measurement; the handoff lists it under "Owner-side items". Nothing can be measured from this sandbox. |
| L3 accuracy scoring of real Windows pairs (`docs/plans/accuracy-program-handoff-20261107.md`) | high | blocked on a verified Ghidra URL/hash, symbol-server terms and real BinDiff/Rizin exports; cases stay BLOCKED by design. |
| #268 live-gate harness (G-U1 identical-input misses, runner `libEGL`) | high | needs the GitHub-hosted live runner and clang/mingw builds; cannot be reproduced here. |
| **#259: four reproduction-confirmed soundness and orientation defects in the SPEC-31 unified matching engine, plus a forward-port of its five fixed commits (branch 134 behind main)** | **high, and tractable here** | pure Python over synthetic IR, red/green testable offline, needs a spec amendment (DATA-MAP consensus rule), registry version bumps, hypothesis property tests, and independent review. The handoff names it the first "remaining active work" item. |

Chosen: the #259 follow-up. The four open defects, in the PR author's words, confirmed by reproduction:

- **p1 swap orientation:** after `ProjectService.swap_orientation`, the raw Ghidriff `matches.address_matches` table is read the wrong way round (the table is keyed by the VA of the *run's* older file; the service swaps `project.matches` but not the raw file).
- **p7 IR-only runs:** added and deleted functions are dropped when no other source lists them (the ladder's leftovers never become one-sided atoms; `sources/ladder.py` counts them in `limitations` instead).
- **p15 DATA-MAP majority vote (soundness):** a coordinated retarget of several functions to an *existing* global can become COS-ADDR/1 (a cosmetic proof) because the retargeted functions form the strict majority of the new datum's voters and prove each other.
- **p11 / p17 orientation asymmetries:** the DATA-MAP function vote (`_collect_votes` checks only `a.target not in pair_old`) and the alignment tie-breaks (`pair_blocks` queue order, LCS/patience ties) give different verdicts when older and newer are swapped.

## 1. Mission, scope, non-goals

Mission: land, on one draft PR against `main`, (a) the five already-fixed #259 commits, forward-ported by a clean merge
(done: `fb038ab9`), and (b) a red-then-green fix for each of p1, p7, p15, p11 and p17, with spec amendments first,
registry version bumps so cached results recompute, hypothesis orientation-symmetry properties, the full unified test set
green, Ruff clean, schemas without drift, and an independent review of the combined diff.

Non-goals: no change to gate thresholds, to the Qt panel, to Ghidriff's own matching, to the result-file layout
(additive only), to any workflow file, and no claim of live or Windows evidence. Keep #259's original branch
`claude/gallant-knuth-8gxuzd` untouched (it is another worker's branch).

## 2. Facts verified this session (do not re-derive)

- Repo: Python >= 3.12 (sandbox has 3.13.18), PySide6 6.12.0, pydantic 2.13.5, protobuf 7.36.2. Install: `pip install -e '.[dev]'`
  plus `pip install pytest-xdist`; Qt needs `apt-get install -y libegl1 libopengl0 libgl1 libxkbcommon-x11-0 libxcb-cursor0 libfontconfig1 libdbus-1-3`.
- Tests: `QT_QPA_PLATFORM=offscreen python -m pytest -q -p no:cacheprovider -n 8 --dist loadfile <files>`.
  Lint: `python -m ruff check src tests tools` (line length 110). Schemas: `python tools/generate_schemas.py && git diff --exit-code docs/schemas`.
- Baseline on `fb038ab9` (main `882d1ca0` + #259 merged): `tests/test_unified_*.py tests/test_ui_unified*.py tests/test_evalcore_unified.py`
  = 2,628 passed in 118 s; Ruff clean.
- Specs that govern this work: `docs/specs/unified-engine/04-matching-pipeline.md` (ladder, s9 properties: "swapping sides -> mirrored
  correspondence"), `05-fusion-and-noise.md` s1.3 (one-sided observations), s2.3 (alignment), s2.7 (DATA-MAP/1), s7 (as built),
  `06-adapters.md` s2/s10 (Ghidriff adapter), `10-amendments.md` (rows A-28..A-31 added by this plan), `02-data-model.md` s5 (`config_digest`).
- Code map: `src/patchtrace/unified/sources/ghidriff.py` (`load_raw`, `_relations`, `_collect`), `sources/__init__.py` (`RawGhidriff`,
  `GhidriffRun`, `SourceInputs`), `sources/ladder.py` (`ladder_output`), `ladder/types.py` (`Correspondence`, `Leftover`),
  `fusion/arbiter.py` (`decide`: one-sided rows from `one_old`/`one_new`), `facts/datamap.py` (`TargetMap`, `_Votes`),
  `facts/align.py` (`pair_blocks`, `patience_anchors`, `diff_tokens`, `_align_block`), `registry.py` (`CHANNEL_VERSIONS`,
  `PROOF_VERSIONS`), `ladder/passes.py` (`LADDER_VERSION`), `keys.py` (`config_digest`, `ENGINE_VERSION`).
- Fixture builders: `tests/unified_facts_builder.py` (`function`, `build_pair`, `run_facts`, `e_load_g` ...), `tests/unified_s0_fixtures.py`
  (`make_project`, `patch_document` with `old_meta`/`new_meta` SHA-256, `raw_ok`, `inputs`), `tests/unified_wire_support.py` (`place_pair`).
- `normalization.verify_diff_identity` requires `old_meta`/`new_meta` with the input SHA-256 on every imported raw document, so every
  persisted raw file identifies its own sides. `AnalysisRun` records no sides; `Plan.older_sha256/newer_sha256` are the project's
  *current* sides.
- GitHub from the sandbox: MCP `mcp__github__*` tools and repo-scoped REST; GraphQL blocked. Never force-push another worker's branch.

## 3. Hard rules (every worker)

1. Spec first: the rule you implement is the amended text in section 7 (already applied to the spec files). If the code forces a
   different rule, stop and report; do not silently diverge.
2. Red test first, then the fix, then green. Name the defect id (p1, p7, p15, p11, p17) in the test docstring.
3. Exclusive file ownership (section 5). Never edit a file you do not own; report the exact change you need instead.
4. No new runtime dependency. Pure domain code stays free of Qt. Persisted contracts change additively only.
5. Never weaken or delete an existing assertion to get green. If an amended rule changes an existing test's premise, rewrite that
   test so its *purpose* survives and say so in your report.
6. Keep determinism: sorted iteration, no dict-order dependence, no clock, no randomness without a seed.
7. Bounded work: tick the run budget in any new loop over functions or references; respect existing caps (L-27, L-38, L-40).
8. Synthetic data only; say so in every docstring. No live-evidence claims.
9. Report in the fallback format: TASK | SCOPE | CONSTRAINTS | RESULT | EVIDENCE | BLOCKERS. Include exact commands and counts.

## 4. Plan and acceptance gates

| Phase | What | Gate |
|---|---|---|
| P0 (done) | Branch from main, merge #259's branch (clean), install deps, baseline | 2,628 unified tests pass, Ruff clean |
| P1 (done) | Write this plan; apply spec amendments A-28..A-31 (section 7) | amendment rows present, spec text changed |
| P2 | Four parallel workers implement p1, p7, p15+p11, p17 with red/green tests and symmetry properties | each worker: new tests fail before, pass after; owned-area tests green; Ruff clean on owned files |
| P3 | Orchestrator integrates: registry/ladder version bumps, schema regen, whole unified set, full-suite smoke of neighbours (pilot, report2, UI unified), docs (`modules.md`, `tasks/todo.md`, `qa.md`, spec status lines) | whole unified set green; `git diff --exit-code docs/schemas`; Ruff clean |
| P4 | Independent review of the combined diff (fresh agent, not anchored on the fixes) | no CONFIRMED finding left unaddressed |
| P5 | Commit, push `claude/funny-feynman-d2m0b5`, open a draft PR to `main`, subscribe to PR events, record the handoff | PR URL, CI watched |

Out of reach here and reported as open: Windows CI, the live unified gates, any real-pair measurement.

## 5. Agent roster, models and file ownership

| Agent | Model / effort | Owns (exclusive) | Defect |
|---|---|---|---|
| A `orient` | Sonnet, medium | `src/patchtrace/unified/sources/ghidriff.py`, `src/patchtrace/unified/sources/__init__.py`, `src/patchtrace/unified/pipeline.py`, `src/patchtrace/unified/compute.py`, `src/patchtrace/unified/exchange.py`; tests `tests/test_unified_followup_orientation.py` (new), `tests/test_unified_ghidriff_adapter*.py`, `tests/test_unified_s0_*.py`, `tests/test_unified_wire_*.py`, `tests/unified_s0_fixtures.py` | p1 |
| B `leftover` | Sonnet, medium | `src/patchtrace/unified/sources/ladder.py`, `src/patchtrace/unified/ladder/types.py`, `src/patchtrace/unified/fusion/arbiter.py`, `src/patchtrace/unified/fusion/components.py`; tests `tests/test_unified_followup_ironly.py` (new), `tests/test_unified_ladder*.py`, `tests/test_unified_fus*.py`, `tests/test_unified_fusion*.py` | p7 |
| C `datamap` | Opus, high | `src/patchtrace/unified/facts/datamap.py`; tests `tests/test_unified_followup_datamap.py` (new), `tests/test_unified_datamap.py`, `tests/test_unified_fct_datamap.py` | p15, p11 |
| D `align` | Sonnet, medium (escalate to Opus after two failed attempts) | `src/patchtrace/unified/facts/align.py`, `src/patchtrace/unified/facts/layout.py`; tests `tests/test_unified_followup_align.py` (new), `tests/test_unified_facts_align.py`, `tests/test_unified_fct_layout.py` | p17 |
| R `review` | Opus, high | read-only over the combined diff | P4 |
| Orchestrator | this session | `registry.py`, `ladder/passes.py` (`LADDER_VERSION`), `keys.py`, every `docs/**`, `tasks/todo.md`, schema regeneration, commits | P3, P5 |

Shared test support files (`tests/unified_facts_builder.py`, `tests/unified_wire_support.py`) are read-only for workers; a worker
that needs a new helper puts it in its own new test file.

### 5.1 Brief for A `orient` (p1)

TASK: after an orientation swap the raw `address_matches` relations must be read in the project's current orientation.
SCOPE: `load_raw` records the document's own identity (`old_meta`/`new_meta` input SHA-256, same `HASH_KEYS` as
`normalization.verify_diff_identity`) on `RawGhidriff` (new optional fields `older_sha256`, `newer_sha256`, default `None`).
`GhidriffAdapter.atoms` compares that identity with `inputs.older_sha256/newer_sha256`: equal in order -> forward;
crosswise equal -> every relation is flipped to (older RVA, newer RVA) of the *current* orientation; both present but
matching neither orientation -> raw status `identity-mismatch` (fourth failure kind: flag `raw-identity-mismatch`, degrading,
`source_ref` suffix `[raw-identity-mismatch]`, the table is not used, the already-swapped `modified`/`added`/`deleted`
matches still are); identity absent (only a fixture builds such an object) -> forward, counted `raw-identity-unverified`.
`Plan`/`capture_plan` and the worker path (`compute.py` line ~393) must carry the identity through `load_raw` so the
owner-thread verdict and the worker agree.
RED TEST: build a project with `unified_s0_fixtures.make_project`, call `service.swap_orientation()`, run the S0 pipeline
in-process (`pipeline.make_plan` / `prepare` / `execute` / `publish`, see `tests/test_unified_wire_pipeline.py`), and assert
that the row for the swapped pair has the Ghidriff atom with `older_rva`/`newer_rva` in the swapped orientation and that no
row pairs a newer-side RVA on the older side. A second test: a raw document whose identity matches neither side is
`identity-mismatch` and the result carries the degrading limitation. A third: `patch_document` without swap is unchanged
(result id and rows), so unswapped projects keep their ids.
CONSTRAINTS: `RawGhidriff` is constructed directly by many fixtures; defaults must keep them valid. Do not touch
`registry.py` (report whether a version bump is needed: the answer is yes if any swapped project could have a cached
result computed under the old reading; say which version you recommend). Do not touch `normalization.py`.
RESULT: diff limited to owned files; new tests fail on the baseline tree and pass after.
EVIDENCE: exact pytest command and counts for `tests/test_unified_followup_orientation.py tests/test_unified_ghidriff*.py
tests/test_unified_s0_*.py tests/test_unified_wire_*.py tests/test_unified_followup_keys.py tests/test_unified_worker.py`;
`python -m ruff check` on owned files.
BLOCKERS: anything that needs a file you do not own.

### 5.2 Brief for B `leftover` (p7)

TASK: an IR-only result (no `ghidriff` source) must show `older-only`/`newer-only` rows for the ladder's leftovers.
SCOPE: `ladder_output` emits, for every `Correspondence.older_only`/`newer_only` leftover whose function kind is
`function` or `thunk` (never `import`/`external`: count those as `ladder-leftovers-not-shown:<kind>`), one tier-W atom
(source `pt-ladder`, step `leftover`, class `E-UNKNOWN`, cardinality `1:1`, the side's RVA set and the other `None`,
`native=(('reason', <reason>),)`, hints carried as `ref` text bounded to 128 chars) and a `NodeRecord` for it, so
`arbiter.decide` builds the one-sided rows exactly as it does from Ghidriff `added`/`deleted`. One-sided atoms are
absence of evidence (05 s1.3): they never contest. When Ghidriff is also present the row gains `one-sided-by:pt-ladder`
beside `one-sided-by:ghidriff`; a function Ghidriff pairs but the ladder leaves over is still a pair (the observation
only adds a hint). Respect L-38 (`rows-cap`) and tick the budget.
RED TEST: run the IR-mode pipeline with `sources=('manual',)` plus placed sidecars (see `tests/test_unified_wire_pipeline.py`
and `unified_wire_support.place_pair`; the sidecars have 5 functions per side) after making one function exist on one side
only, and assert the one-sided row exists with decision `older-only`/`newer-only`, hint `one-sided-by:pt-ladder` and the
leftover reason; assert a second run with `ghidriff` included yields the same pairs and merges the hints. Add a fusion
unit test (`arbiter.decide` with a `pt-ladder` leftover atom against a `ghidriff` pair atom) proving the leftover never
contests.
CONSTRAINTS: `Correspondence.atoms()` is used by the parity tool and the digest; keep `atoms()` unchanged and add the
one-sided atoms in `ladder_output` (or a new `leftover_atoms()` method). Do not edit `compute.py`, `registry.py` or
`ladder/passes.py`; report the `LADDER_VERSION` bump you need (rows change, so cached IR results must recompute).
RESULT / EVIDENCE: as for A, over `tests/test_unified_followup_ironly.py tests/test_unified_ladder*.py tests/test_unified_fus*.py
tests/test_unified_fusion*.py tests/test_unified_wire_*.py tests/test_unified_fixture_gate_u1.py`.

### 5.3 Brief for C `datamap` (p15 soundness, p11 symmetry)

TASK: implement the amended DATA-MAP/1 consensus rule (05 s2.7 rules 2, 3 and 4(b) as amended by A-30; exact text in
section 7) and make `TargetMap` orientation-symmetric.
SCOPE: in `facts/datamap.py`: (1) `raw_consensus` = the old rule 3 (strict majority, >= 2 voters, `incomplete` -> None);
(2) `consensus(t) = u` additionally requires that every competing claim on u (votes (t', u) with t' != t) is a lone
dissent: a competing t' with >= 2 voters blocks unless `raw_consensus(t') not in (None, u)` (its voters are explained
dissenters of t'); a competing t' that is `incomplete` blocks; symmetric for `consensus(u) = t` with claims (t, u');
(3) leave-one-out: `data_state(t, u, voter=r)` evaluates rule 4(b) with r's own vote removed from both tables (majority
and the 2-voter floor must hold among the other voters) instead of the "somebody else voted" shortcut; (4) p11: a call
operand votes for (x, y) only when neither x is in `pair_old` nor y in `pair_new`; audit `function_state`, `_region_shift`
and `data_token` for any other left/right asymmetry.
RED TESTS (synthetic, `unified_facts_builder`): (a) p15 two functions f1, f2 retarget g_a -> g_b where g_b keeps one
unchanged referrer g1: neither f1 nor f2 may reach COS-ADDR/1 (expected `review`/`material` with a `data-ref` delta or
`unmapped`), and the same with three retargeting functions and two unchanged referrers of g_b; (b) the typical patch
stays mapped: one function r retargets g_a -> g_b while u1..u3 keep g_a (moved): u's `cosmetic` COS-ADDR/1, r `conflict`
(this is `test_votes_build_a_consensus_and_the_dissenter_conflicts`, which must keep passing); (c) a hypothesis property
over random small vote tables built through `TargetMap` with swapped readers: `data_state(t, u, (o, n))` on (older, newer)
equals `data_state(u, t, (n, o))` on (newer, older), and the same for `function_state`; (d) the amended rule makes the
fixture `majority_moved_elsewhere` in `tests/test_unified_fct_datamap.py` abstain for every function (two competing
claimants with two voters each); rewrite that test's fixture to a lone dissenter so its purpose (a capped vote table never
produces a proof) survives, and say so.
CONSTRAINTS: deterministic order by (t, u); O(votes) extra work at most; keep `datamap-cap` semantics; do not touch
`registry.py` (the orchestrator bumps `datamap` to 3). Document in the module docstring which scenario is still decided
by majority (a lone dissenting vote cannot block) and why that is sound enough (section 7, A-30 rationale).
RESULT / EVIDENCE: counts for `tests/test_unified_followup_datamap.py tests/test_unified_datamap.py tests/test_unified_fct_datamap.py
tests/test_unified_facts.py tests/test_unified_fct_verdict.py tests/test_unified_ir_facts.py tests/test_unified_fixture_gate_u1.py`.

### 5.4 Brief for D `align` (p17 symmetry)

TASK: make `facts/align.py` (and `layout.py` where it consumes the alignment) orientation-symmetric: `align(new, old)`
is the mirror of `align(old, new)` (pairs, replaced, leftovers, block mapping, `by_key`, `capped`), so every verdict,
proof and delta is the same whichever side is older.
SCOPE: find every asymmetric tie-break with a hypothesis property first (random small `FnView` pairs from
`unified_facts_builder`: 1-4 blocks, 1-6 instructions, duplicated bodies, equal `h1` and not); known suspects:
`pair_blocks` processes `sorted(pairs.items())` by old ordinal (use a symmetric order: the entry pair first, then
unique-key pairs ordered by their shared block key, then BFS discovery order, which is symmetric when the per-kind
"exactly one unpaired on each side" rule is applied to mirrored state); `diff_tokens`' LCS DP prefers `below[j]` over
`row[j+1]` on ties; `patience_anchors` chain choice on equal-length chains; `_align_block`'s family substitution scan.
Replace each with a deterministic symmetric rule (prefer: canonical choice by a key that is invariant under swapping, e.g.
the token itself or `(min(i, j), max(i, j))`; a last resort is computing both orientations and choosing the canonical
smaller result, but only inside the per-block DP, never for whole functions, and say so if used).
RED TESTS: the property above (derandomised hypothesis, `max_examples>=300`, `deadline=None`), plus one hand-built
regression per asymmetry found (docstring says which rule it pins). Existing alignment goldens must keep passing unless
the symmetric rule changes a tie; then show both outputs and explain.
CONSTRAINTS: the spec sentence now reads "Deterministic, orientation-symmetric tie-breaks (A-31)" (05 s2.3); keep
`DP_CELL_CAP`, L-27 and `align-cap` semantics; do not touch `registry.py` (the orchestrator bumps `align` to 2).
RESULT / EVIDENCE: counts for `tests/test_unified_followup_align.py tests/test_unified_facts_align.py tests/test_unified_fct_layout.py
tests/test_unified_fct_operands.py tests/test_unified_fct_verdict.py tests/test_unified_facts.py tests/test_unified_ir_facts.py`.

### 5.5 Brief for R `review` (P4)

TASK: adversarial review of `git diff fb038ab9..HEAD` for correctness only. For each of p1, p7, p15, p11, p17 answer:
is the defect closed by the code (not only by the test)? Can you construct an input that still reaches the old wrong
verdict? Does any change alter results of unswapped, Ghidriff-present, non-retarget projects (and is the version bump
sufficient to recompute them)? Report CONFIRMED/PLAUSIBLE findings with a reproduction sketch; no style remarks.

## 6. Orchestrator integration checklist (P3, P5)

1. Collect the four reports; apply any cross-owner change they requested.
2. `registry.py`: `datamap` 2 -> 3, `align` 1 -> 2 (CHANNEL_VERSIONS); `ladder/passes.py`: `LADDER_VERSION` ladder/4 -> ladder/5;
   if A reports swapped-project caching, bump `keys.ENGINE_VERSION` instead of inventing a source version. Update the version
   comment block with the A-28..A-31 one-liners.
3. `python tools/generate_schemas.py && git diff --exit-code docs/schemas`; `python -m ruff check src tests tools`.
4. Whole unified set plus neighbours: `tests/test_unified_*.py tests/test_ui_unified*.py tests/test_evalcore_unified.py
   tests/test_pilot*.py tests/test_report2*.py tests/test_context_unified_notes.py tests/test_search_sources_unified.py`.
5. Docs: `docs/modules.md` rows for the changed modules; `tasks/todo.md` (a new dated section with the five defects ticked and the
   open gates); `docs/qa.md` (dated section: commands, counts, synthetic-only); `docs/specs/unified-engine/README.md` status line;
   `10-amendments.md` status rows A-28..A-31 -> APPLIED.
6. Run R; fix CONFIRMED findings with a red test each; rerun step 4.
7. Commit per logical unit (forward-port merge already committed), push with `-u`, open a draft PR to `main` that lists the five
   defects, the amended rules, the version bumps, the exact counts and the open gates; subscribe to PR activity.

## 7. Spec amendments applied by this plan (authoritative rule text)

- **A-28 (06 s2/s10, Ghidriff adapter orientation; p1).** The raw `address_matches` table is keyed by the older VA *of the run
  that produced it*; its orientation is the document's own identity (`old_meta`/`new_meta` input SHA-256, required by
  `verify_diff_identity`), not the project's current artifact sides, which `swap_orientation` can reverse after the run.
  `load_raw` records that identity on `RawGhidriff`; the adapter reads every relation as (older RVA, newer RVA) of the current
  orientation, flipping the table when the identity is crosswise; an identity that matches neither orientation is the failure
  kind `identity-mismatch` (`raw-identity-mismatch`, degrading: the table is unused, the service-swapped matches still are);
  an identity-less raw object (fixtures only) is read forward and counted `raw-identity-unverified`.
- **A-29 (04 s1 / 05 s1.3, ladder leftovers as one-sided observations; p7).** `ladder_output` emits one tier-W one-sided atom
  (source `pt-ladder`, step `leftover`, class E-UNKNOWN) and a `NodeRecord` per leftover function of kind `function` or `thunk`,
  so an IR-only result shows `older-only`/`newer-only` rows as a Ghidriff `added`/`deleted` list does; imports and externals
  are never rows (`ladder-leftovers-not-shown:<kind>`); the reason is display text in `native`; the atom never contests (D-14).
  `LADDER_VERSION` is bumped.
- **A-30 (05 s2.7 rules 2, 3, 4(b); p15, p11).** Rule 2: a call operand votes for a function pair only when neither target is
  already in a matched pair (symmetric). Rule 3: a consensus is a strict majority of >= 2 voters *and no blocking competing
  claim*: for `consensus(t) = u`, a vote (t', u) with t' != t blocks when t' has >= 2 voters for u and t' has no raw consensus
  of its own elsewhere (raw = plain strict majority) or is incomplete; a single dissenting vote never blocks; symmetric for
  `consensus(u) = t`. Rule 4(b): leave-one-out: the bidirectional consensus for row r is a strict majority among the voters OTHER than r,
  with at least one of them, where an explained dissenting vote (its other endpoint has a full-table consensus elsewhere)
  is not counted (r's vote never tips its own majority; two agreeing functions with no competing claim map, as before;
  revised twice on 2026-11-11 after worker C showed that a literal 2-voter floor after removal makes every two-referrer
  global unprovable, and that without the explained-dissenter exclusion a lone dissenter ties two innocent referrers). Rationale: by votes alone, "several functions retargeted to a global that other functions still reference" is
  indistinguishable from "that global moved and the others were retargeted"; a proof must abstain. The remaining majority
  decision (a lone dissenter against a consensus) is the typical patched function and stays as before. Review findings
  2026-11-11 added: a stationary claim (the existing global kept its address) blocks with one voter; an explanation is void
  when the judged datum itself votes for the explaining partner (swapped globals); rule 4(b) keeps a floor of two voters in
  all. Residual: >= 3 retargeters to a MOVED existing global with exactly one referrer still map (indistinguishable by votes
  from a single retarget of that referrer). Known cost: two
  functions retargeted together to a brand-new global abstain for everyone who references the old datum (`review`, never a
  wrong `cosmetic`). `datamap` version 3.
- **A-31 (05 s2.3 and s7 alignment; p17).** Tie-breaks in block pairing (`pair_blocks` order), patience anchors and the LCS fill
  are deterministic *and orientation-symmetric*: `align(newer, older)` is the mirror of `align(older, newer)`; "deterministic
  tie-breaks by RVA" is withdrawn where it was side-dependent. `align` version 2. Property test required (04 s9 style).

## 8. Reporting template (workers)

```
TASK | SCOPE | CONSTRAINTS | RESULT | EVIDENCE | BLOCKERS
files changed: ...
tests added: ... (fail-before: <command + count>, pass-after: <command + count>)
owned-area run: <command> -> N passed, M failed (list), K skipped
ruff: clean | findings
cross-owner requests: <file: exact change>
version bumps recommended: ...
spec text implemented verbatim? yes | deviation: ...
```
