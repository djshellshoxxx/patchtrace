# Audit U7: unified engine (`src/patchtrace/unified/**`, `tools/unified/**`) - 2026-10-15

Scope: the code of the unified engine and its dev tools against `docs/specs/unified-engine/*` (00-12), after the S0a-FIX
pass. `20261014-C-unified-s0a.md` covered `limits/contracts/keys/store` at S0a only and is not repeated; its findings were
fixed in `98182e5` (spot-checked: V2 pointer keyed by pair, deep `verify_result_dir`, `parse_line` rejects duplicate keys).
Base `fb39bc2` on `claude/instance-d-gui`. Read-only reading of about 60 modules plus targeted reproductions on Linux
(Python 3.13, pydantic 2.13). Items marked `[reasoned]` were not run. `hypothesis`, `PySide6` and Ghidra are absent here, so
`test_unified_contracts/store/pair_text` and the `test_ui_unified*` files could not be collected; no change touches them
except through the imports checked below.

Counts: High 0, Medium 6 (4 fixed, 2 deferred), Low 8, Info 4.

Checked and clean (no finding): fusion never computes or compares native numbers (`arbiter.decide` reads tier, component,
class only; `base_decision` matches 05 s1.3 rule for rule, including "two components AND two classes"); one-sided atoms never
contest; `contested` keeps `uncontested:<base>`; manual claims win and overlap raises `manual-overlap`; component union-find
reproduces 05 s1.1 (K0 manual, K1, K2); the registry tier and class tables equal 05 s1.2 for Ghidriff, rz-diff, manual and
the ladder (P00-P19 table in `registry.PASSES` equals `ladder.passes`/`ladder.residual` in id, name, tier, class; P18 is
E-LAYOUT, P16/P17/P19 E-RESID); verdicts follow 05 s2.5 order (UNCH, COS-ADDR, COS-LAYOUT, COS-PSEUDO, then material
needs an anchored second channel of another data group, else review, else unknown; absence is never cosmetic/unchanged);
worker isolation (request is strict and size-bounded, every private input is re-hashed and confined by `exchange.inside`,
the worker never opens the project database, child argv/env come from C3's recipe, L-42 cap and OOM classification,
extractor runs with `-B -X utf8` from a private directory holding only the script copy, `OutputGuard` bounds output,
symlinked outputs refused); persisted contracts changed additively (pointer V2 beside /1, new fields default; only tightenings
are listed as U7-14); the `clean()` fast path (`str.isprintable`) is exact (checked over all code points against
`sanitize_text`); G-U8 names only tests that exist.

## Medium

### U7-01 A lone surrogate in a Ghidriff function name or callee stops the whole unified run (fixed)
- `sources/__init__.py:182-196` (`_function`), `:153-157` (`clean_name`), `:160-163` (`native`); `SnapshotFunction` is
  `strict` so a `str` holding `\ud800` raises a pydantic `ValidationError` (not a `UnifiedError`); `sanitize_text` keeps
  surrogates. Project models (`models.FunctionRecord.name`) accept them (JSON `"\ud800"` decodes to one).
- Repro: `snapshot_from_project(SimpleNamespace(matches=[FunctionMatch(... name='f\ud800' ...)]), 'r')` raised
  `ValidationError` before any pass ran. 02 s9.1 promises "a hostile symbol never makes a record unbuildable".
- Fix: `contracts.replace_surrogates`; snapshot builder and adapter name helpers use it. Test
  `test_a_function_name_with_a_lone_surrogate_does_not_stop_the_snapshot`.

### U7-02 Invisible and bidirectional characters survive three untrusted-text paths (fixed)
- `extract/decomp.py:20,75` (`_CONTROL` lacked LRM/RLM U+200E/F, ALM U+061C, zero-width U+200B-D, word joiner,
  BOM, soft hyphen, U+206A-F), `read_text.py:70-75` (`clean` delegates to `secondary.evidence_view.sanitize_text`, whose
  `_UNSAFE` lacks U+061C, U+200B-D, U+2060-206F, U+FEFF, U+00AD), `pair_text.py:~278` (stored decompiled C was split into
  pane lines with no scrub and no per-line control removal at all).
- Evidence: before the fix the decompile reader kept `a<RLM>b`, `clean` kept `a<ALM>b` and zero-width text, and the pane kept
  every character of stored C; stored row text was already safe because `contracts._display`
  uses the full range, so only code panes, IR instruction text and decompiler text were open. 07 s4 requires bounded,
  escaped text everywhere.
- Fix: `contracts.strip_unsafe(text, keep_layout, replacement)` is the single definition (the `_display` ranges); the
  decompile reader, `read_text.clean` and `RowCodeSource._c_side` use it. Tests in `tests/test_unified_audit_text.py`
  (parametrised over nine characters). The other copies stay (U7-09).

### U7-03 G-U6 and G-U7 can pass on an anti-conservative interval (fixed)
- `tools/unified/rowgates.py` `g_u6` (pass at the end of the function) and `g_u7`: both compute a lineage-cluster interval
  (`cluster.ci(...)['anti_conservative']`) but never read it; G-U3 does (`insufficient-data` under 30 lineages). The old
  tests passed G-U6 with two pairs of one lineage and G-U7 with one pair. G-U6 is one of the six U-05 gates, so
  `flag.decision_ready` could become true on thin data; G-U7's rule is "never assumed safe".
- Fix: both gates return `insufficient-data` (reason names the lineage count) when a pass would rest on fewer than
  `MIN_GROUPS_HEADLINE` lineages; a failing verdict still fails. Existing tests now supply 30 lineages
  (`tests/test_unified_row_gates.py`), two new tests pin the thin case.

### U7-04 `flag.decision_ready` ignored a failing G-U8 (fixed)
- `tools/unified/gates_u.py:decision_ready` required G-U1..G-U6 only. G-U8 is the integrity gate (snapshot untouched, no
  socket, schemas, old reader); a `fail` there still printed READY. 08 header: "every gate must pass before the flag
  defaults on"; U-05 lists G-U1..G-U6. Compromise kept: G-U7 stays advisory (the existing test and U-05 say so), a G-U8
  `fail` now blocks; `insufficient-data` on G-U8 does not (it is not a verdict). Test extended in
  `test_unified_gates.py`.

### U7-05 BinDiff stub rows reach tier A alone and become `matched` (deferred)
- `sources/secondary.py:131` records `bindiff-stub-rows-not-identified`; `registry.py:107` maps `edges flowgraph` to A;
  `fusion/arbiter.py:184` makes any single tier-A component `matched`, and a matched A row maps call targets for proofs
  (`Decided.mapped`). 06 s3 says rows with `basicblocks = 0` are tier A only when both ends are imports, else C.
- Why deferred: `SecondaryMatch` has no `basicblocks` (shared contract, S0b gap A-16/02 s10 item 8a); the IR import kind is
  not visible to the adapter. Needs an additive field on `secondary.contracts.SecondaryMatch` (importer) or an IR-aware
  demotion in `compute` (kind lookup in the two sidecars before fusion). Mitigation today: a ladder pair that disagrees
  makes the row `contested`.

### U7-06 A spent deadline after the ladder discards the partial result (deferred) [reasoned]
- `ladder/engine.py:66-81` turns `BudgetExhausted` into a `partial` correspondence (04 I7, s8), but `compute.py:190,196`
  keep using the same `Budget`; `Budget.tick` re-raises at the next 4,096-unit boundary, so for any large image
  `arbiter.decide`/`FactsContext` raise `PT-UNIFIED-TIMEOUT` and the partial ladder is lost (run status `timeout`).
  Cancel should still abort. Needs a decision: a bounded grace budget for fusion/facts after a ladder deadline, or document
  that partial applies to the ladder only. No local fix without that choice.

## Low

- U7-07 `tools/unified/mutations/classes.py` has no trace-arg mutant class although 08 G-U2 says "frame-only and trace-arg
  mutants must land in `review`"; only buf-resize carries `('review',)`. G-U2 can pass without ever planting F17. Add a class
  (needs a tracing import in the freestanding profile) or move the sentence to PENDING.
- U7-08 `tools/unified/evaluators.py:143,150` G-U4 mirror check compares only `matched`/one-sided decisions; a
  `tentative`/`candidate`/`contested`/`ambiguous` row that changes on swap is invisible. 08 says "mirrored rows". Widening
  needs a decision on the tie-breaks of `arbiter.strength` (`-edge[0], -edge[1]` is not orientation symmetric in general).
- U7-09 Remaining copies of the narrow control regex: `extract/ghidra_script.py:66-67` (runs in the external Python, cannot
  import `patchtrace`), `ir/records.py:34`, and `secondary/evidence_view.py:101` (outside this slice). Display now
  re-scrubs (U7-02), so this is defence in depth; changing the script changes IR text and `script_sha256`.
- U7-10 `sources/__init__.py:233-237` `read_snapshot` iterates `for line in handle` (reads a whole line before the 256 MiB
  cap is tested); input is the owner's private file and hash-checked afterwards, so only a memory spike in the capped worker.
- U7-11 `exchange.py:186-193` `read_report` uses `model_validate_json` without `strict_json` (duplicate keys last-wins);
  the report is written by our own worker, strict models still bound every field.
- U7-12 `ladder/passes.py:252,286` P15 treats an unresolved indirect call (`'?'`) as an equal token and the pair stays tier A
  when the substituted callees are all A/M; 04 s4 says A only if every substituted pair is A/M (unresolved callees are not
  substituted). Bounded by the h1 uniqueness, listed for G-U3 per-pass precision.
- U7-13 `tools/unified/bench.py:241` `subprocess.run(..., capture_output=True)` is unbounded and on Windows `timeout` does not
  kill a process tree (dev tool, child is our own code).
- U7-14 Non-additive tightenings since S0a (read side only, no field removed): `ChangeFacts.deltas_omitted` gained
  `maximum 800000`; timestamp patterns `\d` -> `[0-9]`; `ExtractRequest` limit minimum 0 -> 1 (request model, not persisted).
  Rows written by this build always satisfy them.

## Info

- U7-15 08 s1 header says every gate must pass before the flag defaults on; U-05 and `gates_u` say G-U1..G-U6. Reconcile
  the text (now also G-U8 `fail` blocks).
- U7-16 05 s1.2 lists BinDiff "every step with confidence <= 0.75" under tier C while the same section and the registry say
  no rule reads confidence (R02 s7); the code follows the second statement.
- U7-17 G-U7 compares the point estimate with 2x the tier-A rate; with a tier-A rate of 0 any single B+B error fails.
  Conservative; the spec says "(cluster CI)" without naming the bound.
- U7-18 G-U5 cannot reach `pass` today by design (`GATES['G-U5'].waits`, bench `PENDING` stages facts/read_model/ui_calls).

## Deferred summary

U7-05 (SecondaryMatch.basicblocks or IR-aware demotion), U7-06 (deadline policy after a partial ladder), U7-07 (trace-arg
class), U7-08 (mirror check scope), U7-09 (remaining regex copies, shared `evidence_view`), U7-10 to U7-14, U7-15 to U7-18.

### U7-05 fixed (BinDiff stub rows)
- Additive `SecondaryMatch.basicblocks` (default `None`, `ge=0`; schema regenerated); the BinDiff importer records the
  `function.basicblocks` column. `SecondaryAdapter` emits a `basicblocks == 0` row as tier C with native `demoted =
  stub-basicblocks-0` and the limitation `bindiff-stub-rows-demoted:N`, so it stays a `candidate` with provenance and
  cannot reach `matched` alone. `None` behaves as before (`bindiff-stub-rows-not-identified` is now raised only then).
  Tests: `test_unified_fusion.py` (stub alone, stub plus agreeing source, non-stub, legacy row parses).

### [U7-06:fixed] Deadline after the pass ladder keeps the partial result (2026-10-15)
Decision (lead): keep the partial result. `compute_stage` runs fusion and the fact context under a cancel-only budget when
the deadline is already spent after the ladder; the row loop stops at the deadline and the remaining pair rows are stored
with their decision and materiality `unknown` (never negative). The manifest gets the degrading limitation `timeout`
(plus `ladder-partial:deadline` when the ladder itself stopped), so the run ends `partial` (CLI exit 3, envelope status
partial). A cancel still aborts. Red/green tests with a fake clock in `tests/test_unified_wire_compute.py`. Scope note: a
deadline that passes before the ladder, or inside fusion of a run without ProgramIR, still ends as `PT-UNIFIED-TIMEOUT`.

### [U7-07:pending-class] trace-arg is a pending G-U2 mutant class (2026-11-04)
`tools/unified/mutations/classes.py` gains `PendingClass('trace-arg', review_finding='R-29')`: F17 marks a constant only
when it feeds an argument of a call to an imported tracing function, and the freestanding clang profile links with no
import library, so the class needs an import library for a tracing callee (an EtwWrite or TraceMessage import) before it
can be planted. The corpus manifest lists `mutation:trace-arg` as pending, so G-U2 reports `pending` instead of passing
without F17 mutants; the 08 G-U2 row says so. Unit-level coverage stays in `tests/test_unified_gu_mutants.py`. Red/green:
`tests/test_unified_mutations.py::test_trace_arg_is_a_pending_g_u2_class`; pins updated in `test_unified_mutations.py`,
`test_unified_gates.py`, `test_unified_gate_eval.py`, `test_unified_fixture_gate_u2.py`, `unified_support/fixture-gaps.md`.

### [U7-08:fixed] G-U4 mirror check covers every decision; the arbiter is orientation symmetric (2026-11-04)
(a) New derandomised property `tests/test_unified_fusion_mirror.py::test_swapped_inputs_give_the_mirrored_rows` (300
examples: atoms of both components and every tier, tier-M pairs and one-sided declarations, one-sided observations, engine
groups that merge into pools, manual groups; equal RVA numbers on both sides). Deciding the swapped input gives the mirror
of the forward rows on endpoints, decision (older-only <-> newer-only), pair, `mapped`, hints, atom set, and support and
contest through the atoms their indices name; an analyst overlap is refused the same way in both orientations. No
counterexample (also 20,000 random scratch inputs with groups, 0 asymmetric): the `(-older, -newer)` tie-break is a master
list on both sides, so greedy selection gives the unique stable matching. The property fails on a planted
orientation-dependent tie-break (`-edge[0], edge[1]`, not committed), so it has power. Arbiter, registry and
`config_digest` are unchanged; `engine_version` stays `ude/1`. Outside the property: `ghidriff_match_id` of an `ambiguous`
row of two merged Ghidriff groups is the first match id in atom order (a swapped Ghidriff run has its own ids anyway).
(b) `tools/unified/evaluators.py::_pairing` compares every row of every decision (tentative, candidate, contested,
ambiguous); group rows compare their endpoint tuples whole. Red/green:
`tests/test_unified_gate_eval.py::test_g_u4_a_swap_that_changes_a_tentative_row_is_not_mirrored` and
`::test_g_u4_rows_of_every_decision_mirror_and_a_moved_group_endpoint_does_not`.

### [U7-10:fixed] The match snapshot is read with a bounded line read (2026-11-04)
`read_snapshot` reads `readline(LINE_MAX_BYTES + 1)` instead of iterating the file, so an oversize line fails with
`PT-UNIFIED-LIMIT` (`rows-cap`) before it is held whole; error codes are unchanged. Red/green
`tests/test_unified_sources.py::test_oversize_snapshot_line_fails_before_it_is_read_whole` (a byte-counting raw reader:
4,194,689 bytes pulled before, at most the limit plus two buffers after); boundary and no-final-newline cases are pinned
beside it.

### [U7-15:docs] 08 s1 header states the U-05 rule (2026-11-04)
The header now says G-U1..G-U6 must pass, a failing G-U8 blocks and G-U7 is advisory, as `gates_u.U05_GATES` and
`decision_ready` apply it (tested by `test_unified_gates.py::test_the_decision_is_ready_only_when_g_u1_to_g_u6_pass_and_nothing_else_counts`).

### [U7-16:docs] 05 s1.2 BinDiff row follows the code (2026-11-04)
The C cell lists the C-tier algorithm names of `registry.BINDIFF_STEPS`, unknown names and the `basicblocks = 0` stub
demotion (U7-05) instead of "every step with confidence <= 0.75"; tiers come from the algorithm name alone
(`sources/secondary.py`), confidence is never read (R02 s7).

### U7-11 and U7-12 already fixed (checked 2026-11-04)
`exchange.read_report` calls `strict_json` before `model_validate_json`; P15 abstains on an unresolved callee
(`tests/test_unified_p15_unresolved.py`, `LADDER_VERSION = 'ladder/2'`).
