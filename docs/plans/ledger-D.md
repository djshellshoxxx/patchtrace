# Ledger D (instance D: GUI framework, Qt panels, audits, migration readiness)

Session `session_01Mr844cQDLwXi9iMUoGmBXk`; branch `claude/instance-d-gui`; parent A `session_01WUziRNgNiy3umAsePrnNZ1`.

| Item | State | Evidence |
|---|---|---|
| Setup (docs from A's branch, plans read) | done 2026-10-14 | rate limit `allowed_warning` (no Opus) |
| F0, F1, F1b (A) | waiting for A's merge | not on main at fd6cdba |
| F2-F9 framework | ALL BUILT; PR #58 (draft) open; full suite x2 10068 passed locally; waits Windows+Linux CI | follow-ups: evidence threads/table on TaskRunner/VirtualTable, M4, TSV formula prefix, CI 20x job text |
| F4 VirtualTable | built, in branch (bbb92ad,f1d23cc); 47 tests, qt_gate 5x ok; open: TSV formula-prefix neutralisation, sort command for panels | |
| F3 | built, in branch (a98bf40..1784c44); 177 tests, 10x gate ok | dark stylesheet == DARK_STYLE |
| F6b GraphCanvas | built, in branch (a512c67); 59 tests, 5x gate ok; minimap not built | |
| F8 evidence+engine-setup migration | built, in branch (a7ce5e2); 800 tests 5x; ui.py ceiling 25->17; threads/table/StateView migration + M4 done in the GUI2 follow-through (below) | |
| F7 theme variants | built, in branch (2089c06,2fc7f58); 17 new tests, qt_gate 5x all GUI files 6295 passed; M22 blocked (Windows) | 
| F9 | worker running | |
| F6a CodeDiffView | built, in branch (d9ccfb6); 105 tests, 5x gate ok; ui.py M4 selection sites move in F8 | |
| F5 host + ui.py seam | built, in branch (7f88cf0,da031ea,d320908); 91 host tests, qt_gate 5x over all GUI tests 5665 passed (one F4 timing flake under load); ui.py +25 lines (ceiling) | CI repeat job text in docs/qa.md [GUI-F5:host]; announce F5 to A and B after the PR merges |
| F5, F6a/b, F7, F8, F9 | waiting on deps | GUI plan section 9 |
| Panel wave | waits for F5 + feature view-models | |
| Audits + `migration-readiness.md` | waits for features | |
| GUI2 follow-through | done 2026-10-15; qt_gate 5x over all GUI files 6465 passed (6 commits after the merge of claude/instance-d-gui) | TSV formula prefixes neutralised in `build_tsv`; M4 selections via `compose_selections` (ui.py 3,077 lines, ceiling -65); evidence load/run/probe on `TaskRunner` (engine events through a drained queue so latest-wins progress cannot drop an outcome); evidence matches on `VirtualTable` (pure `secondary/evidence_table.py`, prepared in the load worker; `set_filter` row predicate and `ColumnSpec.tooltip` added); evidence state page on `StateView` (`text_limit`/`multiline` kwargs); tips `evidence.retry`, `evidence.copy_error`, `evidence.open_engines` removed, test_tooltips id floor 25 -> 22 |
