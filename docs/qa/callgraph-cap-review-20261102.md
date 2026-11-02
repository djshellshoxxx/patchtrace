# Independent review: BUG-CG-3 cap truth

No blocking findings in the bounded BUG-CG-3 cap-truth repair.

- Source: `96256be573481757c705d4e6b09c67628fa713f7`
- Tree: `f9c961b1a431d38912116e2dd2233547fb075638`
- Parent: `424e59dbc800ff7419c2fe47a3eb7f642a5a49b4`

## Scope and reasoning

- The existing per-origin 64-neighbour exploration cap now marks its view partial. Unique focus positions are collected before node budgeting, preserving a distinct root after duplicate requests.
- Per-origin more counts remain separate and are never summed into a claimed missing unique-node total. The new wording says nodes or edges may be omitted, including when another frontier recovers some or all skipped elements.
- Paired export aggregates query limitations deterministically without duplicates; DOT adds a fixed comment and graph label only for a partial export. Existing safe label escaping, output bounds, and schema are unchanged.
- The controller derives cap state from both Changes and the current neighbourhood, so later independent Changes delivery cannot clear an active query cap. It clears the flag when all contributing caps disappear; query-cap wording avoids a false 64 of 64 total.
- Actual CLI neighbours and paired exports propagate partial exit 3 under the existing envelope. This is a query/presentation repair, with no new numerical cap or resolver/cache-policy change.

## Independent validation

- 185 passed in 9.01 seconds, including actual synthetic-project CLI persistence/export, DOT escaping/goldens, schema comparison, and offscreen Qt delivery lifecycle.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q --tb=short tests/test_callgraph_cap_truth.py tests/test_ui_callgraph_cap_truth.py tests/test_callgraph_snapshot.py tests/test_callgraph_dot.py tests/test_callgraph_cli.py tests/test_callgraph_schemas.py tests/test_callgraph_inspection.py tests/test_ui_graph_panel.py tests/test_ui_graph_inspection.py tests/test_callgraph_view_model.py::test_every_headline_state_has_its_text tests/test_callgraph_view_model.py::test_notes_follow_the_headline_and_headline_precedence tests/test_callgraph_view_model.py::test_footer_and_state_copy_exact`
- Independent normalized graph control: the second frontier recovers all 66 nodes and 65 edges, but exploration remains partial with conservative wording; two duplicate-focus permutations preserve both roots without false truncation.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python /workspace/scratch/142cb233d750/reviews-resume/callgraph_cap_controls.py`
- All eight combinations of Changes cap, query cap, and row slicing preserve the union; empty state clears the cap and keeps unrelated flags. This direct state control supplements, rather than replaces, the offscreen Qt tests.
  Command: `Same independent control script: actual CallsController._update_capped function on controlled state`
- Passed; twelve changed paths total, clean worktree.
  Command: `Ruff on the eight changed Python paths; git diff --check HEAD^ HEAD`

## Limits

- No path-complexity/performance run, full-suite duplication, native Windows or human visual acceptance claim.
- CG-1 successor-scan complexity and other #105 findings remain separate; this receipt only addresses the bounded CG-3 repair on top of independently reviewed CG-2.
- No source edits, target execution, remote mutation, or GitHub approval performed.

The JSON sibling binds every changed file and the independent control script by SHA-256.
