# PatchTrace consolidation ledger

The machine-readable authority is [task-ledger.json](task-ledger.json).
This page and the other uppercase engineering pages are navigation and current
human-readable views of that record. Historical dated evidence remains intact.

## Cycle 95fe — 20 November 2026

- Captured main: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`.
- Captured latest stack: PR #344, `67f7e08ea9bee61653f8ab5ad66048d3e7141810`.
- Combined local source: `ccc3664f11a81d3d30f907da36fc3d22da0063d0`.
- Source tree: `a72efdcbf503e0480a182fd323c5c4320d27c098`.
- Local branch: `codex/patchtrace-consolidation-20261120-95fe`.
- Publication branch: `consolidation/patchtrace-20261120-95fe`, based on PR #344.
- Verified remote code counterpart: `406acf96f5b1a299aca940f98eeb69d0b9583729`; identical source tree.
- [Commit mapping](evidence/cycle95fe/code-commit-mapping.json) preserves all nine code commits and three local merge relationships.
- Main promotion and release remain blocked; no branch deletion is authorized.

| Work | Implementation identity | Review | Current disposition |
| --- | --- | --- | --- |
| Candidate request admission before current-input reads | `649ed46ead79ad12c9fa35085e704ac3f0d32631`; spec first `c46b5efd` | Fresh independent review accepted; four inherited-runtime failures preserved | Merged locally; 183 related cases also pass on clean combined source |
| Registered header help and Evidence announcements | `2c7f506b61ad1f8010c82c1303dd181baf8c0158` | Fresh independent review checked donor blobs, AST scope and eight evidence hashes | Merged locally; 212 affected cases passed before combination |
| Bounded replay of large inventory evidence | `076c1ffaea35e922b206da5818023fe96459de23`; spec first `baaf4b1e` | Independent source/evidence review accepted | Ten cases also pass on clean combined source; actual 353-row replay is byte-identical |
| Required form-feed and Qt diagnostic fallback coverage | `c71d604edbd63e3b8d0f10b120c775acd1c5f8b4` | Coordinator reviewed exact test-only diff against existing requirements | Merged locally; 47 cases passed before combination |
| Historical semantic triage | Frozen candidate `ccc3664f` | Independent UI and integrity reviewers | Eight scoped donors superseded; one already in main ancestry |

These test selections overlap. Do not sum them into a unique-test or full-suite
count. Current combined-source results are recorded separately in the
[qualification record](cycle-95fe-qualification.md).

## Why recovery was selective

PR #321 at `f851d74d134a09cb9b12013d2c1adba1fde0c24f` retains useful GUI
code. Its table/spec/test blobs were recovered exactly. Only constructor and
StateView announcer plumbing was adapted in `ui_evidence.py`; newer attempt
storage, result accounting and log-reset behavior were preserved. Broad donor
replacement would lose newer behavior. Search tool-source wiring and Strings
composition remain separate retained features, not implicitly completed.

## Concurrent ownership

A separate active foreground session in `/workspace/scratch/2bade0b323c3/PatchTrace`
owns TaskRunner completion/cancellation lifecycle, report cleanup outcomes and
Linux forced-export publication. Its branches and worktrees were not edited.
The existing hourly continuation prompt records both sessions' scopes through
their handoffs or 2026-11-21T03:00:00Z. Read its current state before assigning a
successor. That ownership record is not proof that another session's work passed.

## Evidence rules

Use exact commit/tree identities. Earlier main, parent PR, unit-only, synthetic,
offscreen or native results qualify only their named source and scope. Preserve
original failures. A clean focused run cannot replace full/native acceptance.
