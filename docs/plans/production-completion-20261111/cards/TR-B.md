# Slice card TR-B - test tooling: skip ledger, live-status honesty, base-ref triage, schema drift check

Evidence and designs: `jq '.actionable_now[] | select(.id=="K-T03" or .id=="K-T04" or .id=="K-T09")' docs/status/inventory/K.json`,
`jq '.features[].defects[]? | select(.id=="K-D05" or .id=="K-D06")' docs/status/inventory/K.json`, `jq '.actionable_now[] | select(.id=="I1-T10")' docs/status/inventory/I1.json`.

Four items, one commit each, red test first:

1. K-T09 - tools/run_test_suite.py (K-D06): the FAILED/ERROR regex stops at the first space, so a parametrized node id
   that contains a space is truncated and base-ref triage then labels every failure "new". Keep the whole node id
   (pytest prints `FAILED <nodeid> - <message>`; the separator is " - " only when a message follows - handle ids that
   themselves contain " - " conservatively and say how). Also print skipped and xfailed counts from the summary line.
   Tests in tests/test_dev_test_tools.py.
2. K-T04 - tools/check_live_status.py (K-D05): show the `mocked` flag of every status row instead of labelling every
   row "not mocked"; add `--require ENGINE` (repeatable) that exits non-zero unless that engine's status is a real
   (not mocked) pass - blocked and mocked never satisfy a requirement. Tests in tests/test_live_harness.py. Evidence
   classes must stay separate: mocked is never live.
3. K-T03 - new tools/skip_ledger.py (stdlib only) + tests/test_skip_ledger.py: read a junit XML file (the suite writes
   one with --junitxml) and classify every non-pass as: failed | error | xfailed | xpassed | skipped:platform |
   skipped:blocked (reason starts with "BLOCKED:" or names a missing external tool) | skipped:missing-dependency
   (importorskip) | skipped:other; print a text table and `--json`; `--fail-on missing-dependency` exits 1 when that
   class is non-empty (so CI can refuse silent importorskip skips). Parse XML with the stdlib safely: refuse DTDs /
   entity declarations (junit files come from our own runs, but keep the parser strict), cap file size. Confine the
   input path the way tools/research_qualification/pathguard.py does or with an explicit existing-file check. Classify
   the checked-in sample you generate in the test, and also run the tool once on
   <junit file of a full run on main> (the
   real baseline of main: 20,809 passed, 56 skipped, 8 xfailed, 1 failed) and put the resulting class counts in your
   report.
4. I1-T10 (WP-05) - tools/generate_schemas.py: any argument is ignored today and docs/schemas is rewritten, so a drift
   check can never fail. Give it `main(argv)` with `--check` (write nothing; exit 1 and list drifted files when the
   generated output differs from the tree) and reject unknown arguments (exit 2). Running it with no arguments must
   produce a byte-identical docs/schemas tree (prove it: run it in your worktree and `git status --porcelain` stays
   clean). Other tests import or run this script at module level (tests/test_unified_contracts.py and others -
   `grep -rn generate_schemas tests | head`): keep them working unchanged. New tests/test_core_schemas_check.py:
   --check exits 0 on the clean tree, 1 after altering a schema in a TEMP COPY of the tree (never alter the worktree),
   and writes nothing in check mode.

## Owned files
tools/run_test_suite.py, tools/check_live_status.py, tools/skip_ledger.py (new), tools/generate_schemas.py,
tests/test_dev_test_tools.py, tests/test_live_harness.py, tests/test_skip_ledger.py (new),
tests/test_core_schemas_check.py (new).
NOT yours: .github/workflows/** (wiring the skip ledger into CI is an integrator ask), pyproject.toml, tests/conftest.py.
