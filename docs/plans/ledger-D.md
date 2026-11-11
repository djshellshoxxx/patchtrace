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

## Update 2026-10-15 ~01:00Z (owner: bundle first, plus 8 track agents)
| Item | State | Evidence |
|---|---|---|
| Bundle B10 pins | pin_verify run 38661029764 (sigstore 4.5.0) result verified: python-windows 4acbed6d...a3c3 (sigstore), ghidriff tarball 613449a2...fe87f (git-rebuilt, 117/117 identical); writing them into backend_pin.json was blocked by the auto-mode classifier, owner permission requested | next: record pins, full build both OS, acceptance, prerelease |
| UE panel S4b | built, in branch (7b70d63 -> cherry-picked) | 39 tests, qt_gate 20x |
| PIL: D1 core, D2 workflow, C2 Leads dock | built, in branch | read_model + ui_leads, 96 tests |
| WBQ S6 + S9 Qt | built, in branch | 73 tests, qt_gate 5x; wiring into Files panel / ui.py seam open |
| KB K4b/K7 panels | built on worktree branch worktree-agent-ae1ddf7ace07cf49d (commit 72605cd, needs B's K1-K7 on main, NOT in PR #58) | 89 tests, qt_gate 6x |
| WB1-WB3 panels, GUI follow-through | agents running | |
| GUI2 follow-through | done 2026-10-15; qt_gate 5x over all GUI files 6465 passed (6 commits after the merge of claude/instance-d-gui) | TSV formula prefixes neutralised in `build_tsv`; M4 selections via `compose_selections` (ui.py 3,077 lines, ceiling -65); evidence load/run/probe on `TaskRunner` (engine events through a drained queue so latest-wins progress cannot drop an outcome); evidence matches on `VirtualTable` (pure `secondary/evidence_table.py`, prepared in the load worker; `set_filter` row predicate and `ColumnSpec.tooltip` added); evidence state page on `StateView` (`text_limit`/`multiline` kwargs); tips `evidence.retry`, `evidence.copy_error`, `evidence.open_engines` removed, test_tooltips id floor 25 -> 22 |

## Update 2026-10-15 ~01:30Z
- Master plan + to-do + ChatGPT panel-specs prompt: docs/plans/master-plan-d.md, master-todo-d.md, chatgpt-panel-specs-prompt.md. 6h routine trig_0122FzH1LktnkdDiqZrkJVZt.
- WB1-WB3 panels built on LOCAL worktree branch worktree-agent-ac64fcf9a50ccae01 (commits a338d6a search, 536de75 graph, 690ee91 strings, 6620230 palette test fix): depend on B's unmerged branch; NOT in PR #58. Findings: TaskRunner dropped by a worker thread / gc off the GUI thread segfaults in Shiboken (harden tasks.py); palette results cap 50.
- KB panels: local branch worktree-agent-ae1ddf7ace07cf49d (72605cd), depends on B.
- All track agents finished; none running.

## Update 2026-10-15 ~02:45Z: PR #58 MERGED as 21a005e
GUI F2-F9 + follow-through, Unified panel (S4b), Leads dock (PIL C2), PIL D1/D2, WBQ S6/S9 Qt views, TaskRunner thread-safety fix (T15), unified frozen hook, rules timeout test fix, sigstore 4.5.0. All Linux/Windows checks green on b93a6ad. Branch reset to main.
Local-only worker branches awaiting B: KB panels (72605cd) and WB1-WB3 panels (a338d6a..6620230), see master-todo T19.

## Update 2026-10-15 ~04:00Z: audits, QA, research, fix pass
- Audits (all in docs/audits/20261015-*.md, Haiku, read-only): reports-cli 0H/7M/8L; core-app 0H/3M/9L; secondary-engines 1H/4M/8L; acquisition-enrichment 0H/8M/5L; gui-framework 0H/8M/8L; tools-workflows 0H/3M/17L; pe-codetext-representations 0H/3M/11L; series-providers-calibration 0H/6M/14L; intelligence-kev-rules-fabric-pilot 0H/2M/2L; test-suite-hygiene 0H/8M/8L.
- QA: tests/stress/ (GUI 45 pass + 1 strict xfail QA-GUI-1; fuzz 107 pass + 4 strict xfails). CLI/persistence QA still running.
- Research notes in docs/research/: kb-msrc-sources, kb-winbindex-packages, vuln-data-feeds, tools-capa-floss-diec, yarax-and-rule-sources, qt-accessibility-windows, lbl-datasets-and-methods, ue-matching-literature, windows-signing-options. Ghidra headless note still running.
- Fix pass launched (Sonnet, red test first, owner-decision items skipped: CORE-3, CLI-1/4/12): core+series, acquisition, secondary (SEC-1 High), GUI+ops, CLI/PE/fuzz/intel, test hygiene.
- Open owner questions: pin digests permission (bundle blocker); C's branch restore; CORE-3; exit codes; LBL corpus size (38 vs 48 lineages) and prereg lock; signing; symbol-server legal; PR closes; dropped specs.
- Running: UE gates + panes, LBL-11 + recipes/csrc, docs writer, QA CLI, R1 diagnostic runs queued on corpus-tier-r.

## Update 2026-10-15 ~06:20Z (6h check)
- Integration branch `claude/instance-d-gui` (draft PR #64) contains main 00db4c9 (B wave 1-3, bundle licence gate), 50 formatted help pages, 8 Qt panels (search, graph, strings, capabilities, build_env, rules, kb, kev) + FAB-6 related panel, CAP-8/9/11, DIE D7-D9, YRX R6a, K8 adapters, WB1 S9-S10, WB2 G8, WB3 S8-S9, B7 bundle strip/jlink, LBL-05/06/07/13/14/08 + pre-lock audit LBL-26 (2 High fixed), prereg tooling, vendoring scan, unified audit U7 + U7-05/06 fixes, QA/stress suites with QA-S2 fixes.
- CI: PR #64 head checks still queued/stale-head failures; known fixed since: tests/stress conftest shadowing, eval-engine SHA fixtures, Leads Windows wait, unified code-view names, CLI seam baseline, tooltip coverage registration. Next: read `qa` + `qt-gate` on the newest head; fix; mark ready; squash-merge (no skip-ci text).
- Bundle: Ghidriff source tarball sha differs on the Actions runner (runner 8f96e687.. vs pinned 613449a2..; sandbox reproduces the pin on Python 3.11-3.13, git 2.43). Diagnostic output added (describe_tarball); Linux-only bundle run dispatched on this branch.
- Handoff docs: five Sonnet writers produce docs/handoff/* (label training, unified, bundle, features+panels, operations/owner actions). A second label-training/unified worker batch starts after them (Tier W 20-22/24, LBL-12 unified adapter, G-U5 perf, ladder/fusion property tests).
- Open owner items unchanged: Windows desktop pass, Tier W runs, prereg sign-off at the right time, signing application, QA-CLI-3 exit-code decision (recommend 2), QA-S2-2 store threading decision (recommend owner-thread-only + test change), card-audit items (pcre2 licence, postgresql-libpq card, brotli/zstd licence rows, Windows-scope field).
- ChatGPT: branches chatgpt/{corpus-1,deferred-audit-fixes-1,help-docs-1,kb-fixtures-1,panels-1,unified-fixtures-1} exist (draft PRs #67-#72 per A); unified fixtures validated and merged; others unreviewed. Prompts 6-12 in docs/plans/chatgpt-prompts.md.

## 6-hour check 2026-10-15 ~12:20Z
- PR #64 head 85f1b9e (GC-collect fixture for the Linux qt-gate segfault): `linux`, `windows`, native x5, shards, live lanes green; `qa` (both OS) and `qt-gate` (ubuntu, windows) still running.
- Bundle: Ghidriff source tarball rebuilds with identical contents on the runner (git 2.55) but different tar bytes (pin 613449a2, runner 8f96e687); fix needs owner choice (content-digest fallback vs reproducible tar writer). Diagnostic run 38686279359.
- R1 diagnostic runs (corpus-tier-r 38679899059/38679901515): all shards green; per-recipe detail needs artifact read.
- Open PRs: #74 (C), #72-#67 (ChatGPT drafts, untriaged except #71 merged content), #61 (codex).
