# Ledger D (instance D: GUI framework, Qt panels, audits, migration readiness)

Session `session_01Mr844cQDLwXi9iMUoGmBXk`; branch `claude/instance-d-gui`; parent A `session_01WUziRNgNiy3umAsePrnNZ1`.

| Item | State | Evidence |
|---|---|---|
| Setup (docs from A's branch, plans read) | done 2026-10-14 | rate limit `allowed_warning` (no Opus) |
| F0, F1, F1b (A) | waiting for A's merge | not on main at fd6cdba |
| F2 Qt runtime | built, merged into branch (unmerged to main; PR after F1 lands) | 0708da9,1f0864f,3f55d56; 113 tests, qt_gate 20x 2260 passed, ruff clean; Windows unverified; local Progress/TaskFailure to reconcile with F1 |
| F4 VirtualTable | built, in branch (bbb92ad,f1d23cc); 47 tests, qt_gate 5x ok; open: TSV formula-prefix neutralisation, sort command for panels | |
| F3 | built, in branch (a98bf40..1784c44); 177 tests, 10x gate ok | dark stylesheet == DARK_STYLE |
| F6b GraphCanvas | built, in branch (a512c67); 59 tests, 5x gate ok; minimap not built | |
| F6a CodeDiffView | built, in branch (d9ccfb6); 105 tests, 5x gate ok; ui.py M4 selection sites move in F8 | |
| F5 host + ui.py seam | built, in branch (7f88cf0,da031ea,d320908); 91 host tests, qt_gate 5x over all GUI tests 5665 passed (one F4 timing flake under load); ui.py +25 lines (ceiling) | CI repeat job text in docs/qa.md [GUI-F5:host]; announce F5 to A and B after the PR merges |
| F5, F6a/b, F7, F8, F9 | waiting on deps | GUI plan section 9 |
| Panel wave | waits for F5 + feature view-models | |
| Audits + `migration-readiness.md` | waits for features | |
