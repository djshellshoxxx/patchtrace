# PR #349 combined recovery and qualification — 837FE

## Outcome and exact source

This continuation consumes the completed 95FE-C3 handoff and combines its reviewed Linux frozen CLI, archive-cache and Pages changes with reviewed storage recovery, Search help, immutable direct Action references and Intel probe repairs. It updates the existing main-integration PR #349; it does not introduce a competing integration target.

| Identity | Exact value |
| --- | --- |
| Main at discovery | `fdc2696c23bdbfe7668348f25e3b336ce33039f7` |
| Starting PR #348 application baseline | `6b6fcd3597a604212032ffc453477aeb6edc69ff` |
| Consumed PR #349 head | `11f51c105bf63946f59373ae605b937c4fee607a` |
| PR #349 complete starting tree | `4939056ceb0e02b419c820b9e5748c869c40a857` |
| Final tested local combined source | `2a67980cfeb88ad72bf8ad523d2bafc8426e5b7c` |
| Tree-identical mapped remote code commit | `61b26107d77fb632571ede932e0796d4b643f50c` |
| Complete tested code tree | `2666e72d5efd51600b170cef033103c9947bae3b` |
| Publication target | `integration/patchtrace-20261121-95fe-c3`, PR #349, base `main` |

The final publication adds documentation and retained evidence. Resolve the live PR body for its exact publication head, complete tree and hosted run identities. Source results never transfer to an altered implementation. The [code publication map](evidence/cycle837fe-combined-20261121/code-publication-mapping.json) retains all 35 new local commits, exact trees and mapped ordered parents; a verified Git bundle retains original commit identities and authors.

## Implemented and reviewed changes

### Committed project state survives interrupted saves

`ProjectService` reconciles its in-memory snapshot after save failures, including errors raised after the database transaction already committed. Readback uses `recover_interrupted=False` and preserves the original exception. If readback fails, the service refuses further writes and backup until reopen, retaining the lock and available evidence. This prevents a later edit from silently replacing current state with a stale snapshot; prior history or backups may still retain earlier copies.

Independent review found two additional backup paths: backup could bypass an uncertain-state guard, and normal backup recovery could itself commit before raising. Both paths now use the same reconciliation rule. SVC-R1 and SVC-R2 are closed by independent controls. [Detailed storage/Search record](cycle837fe-recovery-and-search-20261121.md).

### Backup cleanup preserves the primary outcome and ownership

Failed backup construction/publication keeps its original error or cancellation when temporary-directory cleanup raises `OSError`, adding a fixed path-free note. Successful publication no longer revisits the consumed staging pathname, so a separately recreated path is not removed. The contract does not suppress every arbitrary cleanup exception, and the exception note does not create a new visible CLI warning. Author and independent controls retain baseline failures and verify source/destination preservation.

### Search headers explain the actual evidence

Side, Kind, Match, Where, Change and Why now use registered semantic header help. The real host activates Search during the global header audit; removing the Why mapping fails the audit for that exact ID. An independently identified overpromise about showing all reasons was corrected. Labels, cells, queries, sorting, copy and navigation behavior remain unchanged. This establishes `ToolTipRole` help, not native screen-reader acceptance or `WhatsThisRole` support.

### CODEX-1 direct Action references are immutable

The reviewed mapping replaces 176 mutable uses of 11 references across 21 workflows. Two already pinned uses remain unchanged, giving 178 direct remote repository uses with full commit pins and readable release comments. Official Git refs, annotated-tag peeling, release tags, commit objects and exact action manifests were independently verified.

Exact changed-line and parsed-YAML comparisons preserve workflow events, permissions, scripts, inputs, ordering, concurrency, budgets, cache verification, frozen CLI checks and release/Pages conditions. Coupled tests verify actual `uses` entries, not comment-only substitutes. The existing CODEX-1 strict expected failure becomes a positive gate. A legacy YAML source check was corrected to accept valid comments while retaining malformed plain-scalar refusal. [Implementation and source evidence](codex1-direct-action-pins-20261121.md).

This closes the direct-reference source gap. A nested Pages upload Action remains mutable; Codex npm downloads and toolchain patch selection are separate. CODEX-5 package hash enforcement remains a strict expected failure.

### Windows Intel version names and actual probe evidence

The capa and FLOSS version patterns accept an optional literal, noncapturing `.exe` suffix. All other production AST nodes are unchanged. Exit-code requirements, supported majors, executable pins, explicit untested-build opt-in, help options and backend checks remain enforced.

The live acceptance harness now observes its existing version/help calls and retains bounded, redacted stdout/stderr tails, basename/fixed arguments, return status and explicit truncation metadata in the existing status artifact. It forwards each actual call once, returns the identical result and restores the prior callable. Acceptance predicates and failure/skip decisions are unchanged; no extra process is launched to manufacture evidence.

The original Windows capa exit-zero failure is consistent with the format gap, but its missing streams prevent causal proof. The original FLOSS exit-one failure remains unresolved and refused. The next actual Windows run must supply diagnostic evidence; controlled parser/harness tests do not establish native compatibility.

### The hosted registry failure is repaired without weakening its test

Original PR #349 Linux QA completed with **1 failed, 24,066 passed, 53 skipped and 4 xfailed**. Its only failure was the absent exact registry path for `docs/specs/pages-deployment-control.md`. The combined source exposed two additional missing entries, for Action pinning and live probe diagnostics. Ten added registry lines register all three, using the existing proposed-alias/path-first convention and explicit acceptance limits. The maintained registry test is unchanged; its normal-conftest progression is **3 failed / 105 passed**, then **108 passed**.

## Verification on exact sources

Selections overlap and must not be added.

| Source and selection | Actual outcome |
| --- | --- |
| Final combined `2a67980c`, 57 selected files/node selectors | **1,296 passed, 1 xfailed, zero failed/errors/ordinary skips**; 1,297 distinct case identities; 95.946 s supervisor wall time |
| Same final source | Whole-tree Ruff, dependency consistency and isolated source binding passed; source remained clean |
| Storage/Search `b880c317` | 450 affected cases passed; independent S-H1/SVC-R1/SVC-R2 findings closed |
| CODEX-1 `ff6c79f1` / documentation-equivalent `ad099704` | Author and independent reviewer each passed 272 maintained cases with CODEX-5 xfailed; reviewer separately passed 13 controls |
| Intel version repair `eeb7bc07` | Author 169 passed; independent selection 185 passed, including 16 fresh controls; the same fresh controls had 8 failures / 8 passes on PR #349 |
| Probe evidence `03db821b` | Author 105 passed; independent selection 110 passed, including five fresh controls |
| Registry repair `2a67980c` | 108 maintained cases passed; the original registry test blob is unchanged |

The final combined expected failure is exactly `tests.test_codex_pkg_workflows::test_pip_downloads_require_hashes` (CODEX-5). The diagnostic selection includes an intentionally mocked blocked-DIE harness case; that is a passing harness control, not a native result. Original failed controls and reviewer corrections remain in the archives.

No successful local full aggregate is claimed. The earlier `b51b1761` aggregate failed an AF_UNIX construction case and later ended with SIGKILL at 83%, without a terminal summary. Plain isolated Python reproduces the socket restriction; the kill cause remains unknown and has no established causal connection to that earlier failure. No limit, assertion or skip policy was weakened. [Preserved diagnosis](evidence/cycle837fe-20261121/full-suite-diagnosis.md).

## Hosted predecessor evidence and limits

PR #345–#348 non-release checks passed on their respective published heads, with the original PR #345 NSIS HTTP 503 retained before its single successful retry. PR #348 Linux full QA reported 24,043 passed / 53 skipped / 6 xfailed; Windows reported 23,916 passed / 181 skipped / 5 xfailed. These are ancestor results.

On original PR #349 `11f51c10`, five Qt jobs and five Ghidriff jobs passed. Actual BinDiff checks passed once on each platform, rizin reported passed on both, and Linux Intel reported four passes. Windows Intel's successful workflow still contains **2 failed, 1 passed, 1 skipped**; its advisory status is not compatibility success. Original Windows full QA was still running at the last 06:19 UTC prepublication snapshot. The Linux failure described above prevented full qualification of that head.

Tier R provides actual rizin archive acceptance on `11f51c10`: shard 0 missed, verified and saved the original archive; shard 1 restored the same digest-keyed cache and verified the archive before use. Each shard completed six cases without failed/blocked cases. Ghidra installation was skipped on both, so its archive-path acceptance remains open.

- [Original PR #349 QA](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44870397228)
- [Original Ghidriff run](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44870397150)
- [Original Tier R run](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44870397157)
- [Original Windows Intel job](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44870397141/job/136743396511)

## Consolidation, ownership and remaining gates

The complete technical inventory retains all 364 captured live heads, 338 PR records and 59 tags. Exact objects, merge bases, divergence, changed paths and PR joins are available in a lossless compact artifact. Technical coverage does not classify every branch semantically. The existing unmatched/patch-equivalent backlog remains explicit, along with the three precisely scoped historical dispositions in the first 837FE report.

Six additional historical scopes were reviewed against frozen `4ca982e7`: PR #162 backup-verdict observations, #196 stale inspection failures, #198 transactional project adoption and #227 lock identity are DUPLICATE in the reviewed declarations; #219 wizard retry and #226 investigation accessibility are SUPERSEDED within newer retained implementations. All six whole branches remain PARTIALLY_REVIEWED. Twelve production-file and eight test-file comparisons retain exact source evidence; the 53 AST-identical test-source declarations include helpers/fixtures and are not executed-test counts. No unique port is warranted in these scopes. The 181 unmatched / 16 patch-equivalent branch-level backlog is unchanged. See the [scoped dispositions](evidence/cycle837fe-combined-20261121/historical-followup-dispositions.json).

The completed 95FE-C3 handoff released ownership before this integration. PR #346's unique work remains selectively retained through #347/#348; no sibling wholesale merge, force update or branch deletion is used. Original implementation histories and all prior failures are preserved.

Use the existing [authoritative ledger](task-ledger.json) and [current combined handoff](../engineering-handoffs/cycle837fe-combined-pr349-20261121.md). Require exact-publication-head full Linux/Windows, Qt, native and package outcomes, actual both-Ubuntu frozen CLI smoke, and disposition of every applicable blocker. Merge only through REST with a fresh expected-head guard and **`[no release] [no deploy]` in the actual resulting merge commit**.

CODEX-5, transitive dependency closure, Ghidra Tier R cache acceptance, Windows Intel compatibility, native/manual accessibility and trust, complete raw-input/index membership, historical semantic consolidation and separate L1/L2/L3 release gates remain open. Main promotion and release readiness are distinct decisions; this report declares neither complete before those decisions are evidenced.

The [evidence manifest](evidence/cycle837fe-combined-20261121/manifest.json) covers combined receipts, author/independent reviews, unchanged predecessor logs, the registry failure/repair, exact Git history and the publication map. Remote head/run observations belong to the live PR body and a later evidence snapshot, so recording them need not invalidate a running implementation head.
