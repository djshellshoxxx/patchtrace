# Slice card NA-2 - BinDiff importer and runner bounds (B-D02, B-D07) and a truthful exit code (F-D03)

Evidence and designs: `jq '.actionable_now[] | select(.id=="B-T02" or .id=="B-T06")' docs/status/inventory/B.json`,
`jq '.features[].defects[]? | select(.id=="B-D02" or .id=="B-D07")' docs/status/inventory/B.json`,
`jq '.actionable_now[] | select(.id=="F-T01")' docs/status/inventory/F.json` and `jq '.features[].defects[]? | select(.id=="F-D03")' docs/status/inventory/F.json`.
Specs: docs/specs/bindiff-execution.md (SPEC-29), docs/specs/bindiff-adapter.md (SPEC-10).

Three items, one commit each, red test first.

1. B-T02 - cap the number of `function` rows the .BinDiff importer reads (src/patchtrace/secondary/bindiff.py). A
   hostile or corrupt database exhausts memory before the 120 s deadline (open tracker item tasks/todo.md:123). Spec
   first: choose the cap in docs/specs/bindiff-execution.md with a stated basis (it must stay well above real results;
   look at the existing caps in the same module and in src/patchtrace/diaphora for consistency). A database with cap+1
   rows raises SecondaryError PT-SECONDARY-LIMIT BEFORE any record object is built (count with a bounded SQL query, not
   by materialising rows); exactly cap rows import; tests/test_bindiff_real_golden.py still imports the real golden.
2. B-T06 - type the post-exit filesystem failures in src/patchtrace/secondary/bindiff_run.py `execute`: an unreadable
   out/ directory after exit 0 raises SecondaryError PT-SECONDARY-RUN with a failure kind (SPEC-29 section 6 lists the
   kinds - add one there only if none fits), never a raw OSError; the work directory is still removed.
3. F-T01 - `patchtrace secondary import-bindiff` with a missing or unreadable input file: today it exits 3 with "Could
   not prepare a private working folder (FileNotFoundError)" AFTER creating runs/<id>/raw/secondary/. Required: exit 2
   (usage/environment) with a message that names the input path problem, and nothing is created in the project. Find
   where the input is first touched and validate it before any project write. Test in tests/test_cli_secondary.py:
   exit code, message, and the project directory tree is byte-identical before and after.

## Owned files
src/patchtrace/secondary/bindiff.py, src/patchtrace/secondary/bindiff_run.py, docs/specs/bindiff-execution.md,
tests/test_bindiff_import_hardening.py, tests/test_bindiff_run.py, tests/test_cli_secondary.py,
tests/test_secondary_bindiff.py.
NOT yours: src/patchtrace/secondary/bindiff_probe.py and runs.py (slice SEC-B), rzdiff.py, contracts.py, registry.py
(slice NA-1), bindiff_inputs.py.
