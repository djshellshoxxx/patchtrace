# Consolidated candidate validation checkpoint

Publication checkpoint: **2026-11-02 23:05 UTC**. This record deliberately does
not assert full-suite, Windows, native-tool, packaging, or release acceptance.

The complete local pytest run is executing against an immutable checkout of
`f2b7d981008dea25ac09ea82734da64a1dccb96d`, tree
`985078aed0feb4f909690d6082ec4940540cda17`. Its input is the complete reviewed
candidate plus the inventory and initial independent review receipts.

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python3 -m pytest -q \
  --junitxml=/tmp/patchtrace-consolidation-full-20261102.xml
```

The published candidate adds only the final independent-review/CI-triage receipts
and this checkpoint to that input. Its source, tests, tools, workflow, packaging,
schema, and fixture contents remain unchanged. The full-run worktree is separate
from the publication worktree and is not edited during execution. A pending run
must not be described as passing. The PR description and exact published-head
Actions results provide later live status.

All bounded merge/repair reviews have passed independently:

| Scope | Independent evidence |
|---|---|
| Main/candidate merge | 1,131 passed; parent-content and saved-scope controls |
| Portability | 37 passed; parent helper failure reproduced; original pins retained |
| Replay/schema merge | 238 passed, 1 unavailable-tool skip; all 17 schemas match; metadata boundary controls |
| Protocol merge | 138 passed; complete integration/protocol parent preservation |
| Backup repair | 60 passed; original reader safeguards and bounded extra read retained |
| UI repair | 7 existing plus 4 additional resize/shrink/hidden/convergence controls |

Those counts overlap and are not summed. The final author-integrated backup/UI
selection additionally passed 161 tests. Whole-tree Ruff, whitespace, and merged
schema-render checks passed on the final assembled source before this docs-only
publication slice.

Required remaining gates are the full immutable local result, exact published-head
Linux/Windows QA and Qt, packaging/smoke checks, and applicable hosted review/quality
checks. Preserve the separate Rizin orientation quarantine and main Sonar baseline
issues documented in the handoff. No original PR is closed by this checkpoint.
