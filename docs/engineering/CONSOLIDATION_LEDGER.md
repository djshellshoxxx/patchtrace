# PatchTrace consolidation ledger

## Current PR349 Intel + C4 follow-up

[Current report](cycle837fe-native-c4-20261121.md) and [ledger](task-ledger.json):tested `6bf79fef` / `dc659c7e`, 1,396 passes/1 CODEX-5xfail, zero failures/errors/ordinary skips, required lint/dependencies/source binding and independent whole-tree review. ExistingPR349 combines fixed Windows identity, five Build environment help mappings and bounded Pages lock/isolation with earlier storage/Search/pinning/cache/frozen work. Exact new-source hosted/native/package gates remain pending;main/release readiness is not claimed.

Original Windows failures and Tier R 5/11 coverage gap remain evidence; the same Tier R gap occurred on original PR349. Four more historical scopes need no port;whole branches remain partly reviewed and 181/16 census unchanged. Root owns PR349 qualification;C4/Intel histories are retained. Earlier current-state paragraphs are historical for these scopes.

## Cycle4 parent integration update — 2026-11-21 UTC

The separate C4 follow-up includes PR349 `daee337c` and preserves both implementations
and histories. Source `111803d5` / REST code checkpoint `7ddb1130` passed 580 cases,
with one CODEX-5 expected failure and no ordinary skips; all 110 registry cases are
included. Required Ruff/pip/source binding and independent merge/history reviews
passed. CODEX-1 is closed by the parent; wider CODEX-5 and hosted/native/manual/release
gates remain open. [Current report](cycle4-consolidation-20261121-95fe.md) and [exact qualification](evidence/cycle4-parent-20261121/qualification.json)
supersede the earlier pending C4 combination state. PR349 ownership stays with 837FE;
resolve final follow-up head/checks from its live PR. Main/release eligibility remains
false. A qualified main commit requires `[no release] [no deploy]`. Earlier sections
remain source-specific history.

## Cycle4 bounded parallel follow-up — 2026-11-21

This is a separate bounded follow-up to PR #349. Its integration remains with
the parallel 837FE owner. Read the [cycle4 report](cycle4-consolidation-20261121-95fe.md)
and [authoritative ledger](task-ledger.json); resolve the live follow-up PR for
the final published head and hosted checks. Earlier sections below remain source-specific history.

Local tested source `8c5e77e2c1ad3f6cfa62c2e474f7bcc2f4af1dd5` maps to `2162708d86bb655f85410d8064aea04c396d5e6e` with identical complete tree.
The later README-only prerequisite fix is independently reviewed. Both slices retain
contract-first author histories. Final selection:391 passed,2 CODEX-1/5 xfailed,0 ordinary skips.
Do not merge over the owner's Search/storage/Action-pin changes.

## Current integration candidate — cycle3

The isolated local candidate combines reviewed Linux5fa47ac7, cache53e02a47 and Pages e54e4d0a with their histories retained. Tested source: e5a531668ef523cd6faa26d5fec59aa552749134; tree: e622ff8f5624ce73bac63c0976af01c614ce05bb. Planned remote branch: integration/patchtrace-20261121-95fe-c3, base main fdc2696c. [Current report](cycle3-consolidation-20261121-95fe.md) and [machine qualification](evidence/cycle3-95fe/qualification.json).

Recovered20 previously published PR #346 documentation/evidence files without overwriting application source; exact recovery blobs are recorded. Both candidate histories are local merge parents; REST publication will preserve complete trees and mapped parent relationships. No blanket PR #346 ancestry/supersession or branch deletion claim is made.

469 distinct affected tests pass; whole-tree Ruff/dependencies pass; independent source reviews have no blocking finding. Exact new-source hosted checks remain pending. PR #348's earlier full/platform successes remain separate evidence. Main/release/deployment have not changed. A future qualified main merge requires `[no release] [no deploy]` in its actual message and a fresh expected-head REST guard.

## Retained historical cycle95fe record

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

## Verified publication and parallel sibling

Draft [PR #346](https://github.com/djshellshoxxx/patchtrace/pull/346) was created
at remote `87328763478db060909b75cd6849295056f9b405`, identical to local publication
`61965a71047d54003d400d9aff779a83cba3dedb`, tree
`e85b8c5b94806278627c9efd03669656c02be070`. Later documentation-only commits add
this receipt; resolve the PR for its current head. The first exact-source QA,
five Qt and five native jobs were queued; the release gate was skipped. Main
remained `fdc2696c23bdbfe7668348f25e3b336ce33039f7`; 80 PRs were open at capture.

The separate foreground concurrently published [PR #345](https://github.com/djshellshoxxx/patchtrace/pull/345)
at `39c38a02f126963fc03827fa49741255590227ad`, from the same g41 parent. Exact
comparison found identical table-spec/table-model and GUI-specification blobs;
Evidence source differs only in line wrapping and has an identical whole-file
AST. The GUI recovery is therefore shared work and must be counted once. PR345
also preserves additional header/Evidence assertions and tests. Its report,
TaskRunner and Linux publication changes remain separately reviewed/qualified.
See [publication receipt](evidence/cycle95fe/initial-publication.json).

## Current combined PR349 candidate — 837FE

[Combined report](cycle837fe-combined-pr349-20261121.md) and [authoritative ledger](task-ledger.json) supersede earlier next-action text only for the completed named scopes. Reviewed storage/Search, CODEX-1 and Intel repairs are integrated with the released 95FE Linux/cache/Pages source. Final code `2a67980c` passes 1,296 affected cases with 1 CODEX-5 xfail; new-head hosted qualification and main promotion remain pending. Preserve original failed controls, the PR349 registry failure, Windows Intel limits, all historical branches and separate release gates.
