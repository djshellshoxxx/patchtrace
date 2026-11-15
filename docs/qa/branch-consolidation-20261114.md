# PatchTrace branch consolidation and historical review — 2026-11-14

Baseline: `main` at `882d1ca0b4190bccddb6ce1f66b46c4db856703b` before this session.
Resulting `main`: `2c27da13144c19bff99e797c132846752a187189`.

This record distinguishes merged implementation from research-only branches and from changes deliberately held back. A clean mergeability result is not, by itself, evidence of correctness; merges below were limited to focused PRs whose recorded CI checks were green and whose diffs/tests were inspected.

## Merged into main

| PR | Change recovered | Merge commit |
|---|---|---|
| [#280](https://github.com/djshellshoxxx/patchtrace/pull/280) | SPEC-53 backend diagnosis now reports whether the Ghidriff launcher revision is tested or untested. Includes CLI regression tests and tracker update. | `387dd33284be4a2a3bf27a73231363e49bc6ad56` |
| [#288](https://github.com/djshellshoxxx/patchtrace/pull/288) | Seven regressions: SQLite address overflow, infinite search cursors, signature phrase/exclusion matching, exact CVE ID matching, impossible stored UTC review dates, build provenance line breaks, and report technical-line capacity. Nine regression tests. | `628a0f616447b7447c2da729c1fc2922adfb69ea` |
| [#285](https://github.com/djshellshoxxx/patchtrace/pull/285) | Rules and call-graph hardening: RULE-2, RULE-6 byte limit, RULE-7, CG-3; includes regression tests and minimized repro scripts. Supersedes older `claude/bugfix-rules-cg-20261029`. | `4067914793fa1822e9829484302120b137b6fe82` |
| [#286](https://github.com/djshellshoxxx/patchtrace/pull/286) | Unified live-gate harness improvements: Ghidra executable-bit handling, EGL setup, opt-in identical-input A/A control, and native failure diagnostics. | `796c48c495a0065d1d061a968e546a384430ebe6` |
| [#287](https://github.com/djshellshoxxx/patchtrace/pull/287) | Unified-engine soundness repairs: raw orientation, IR-only leftovers, DATA-MAP consensus and alignment symmetry, with focused regression coverage and spec amendments. | `2c27da13144c19bff99e797c132846752a187189` |

The PR heads above were guarded by their exact inspected head SHAs at merge time. The recorded required QA, Windows, Linux, Qt and native fixture jobs for these five heads were green; release jobs were skipped where shown. These CI fixtures do not replace the still-open live Windows acceptance gates.

## Historical work deliberately not merged

| PR / branch | Useful work found | Disposition |
|---|---|---|
| [#291](https://github.com/djshellshoxxx/patchtrace/pull/291) `claude/sleepy-fermi-kbc-1` | KB lineage, Windows product aliases, canonical KB ID support, KB context in report/2. | Hold. PR records one minor review finding and three nits, no completed second review, and a severe unfinished K3 desktop worker-thread/project-loader defect. Do not merge until these are resolved and independently reviewed. |
| [#292](https://github.com/djshellshoxxx/patchtrace/pull/292) `claude/sleepy-fermi-cli-parity-1` | Headless project, compare, profile and doctor CLI commands plus help/specs. | Hold. Both Linux and Windows QA checks were failing on the inspected head. Fix and rerun full gates before reconsideration. |
| [#293](https://github.com/djshellshoxxx/patchtrace/pull/293) `claude/sleepy-fermi-na-rzdiff-ownership` | Rizin singleton-result side-ownership protection. | Hold. PR explicitly reports eight existing tests red; merging would knowingly regress the suite. |
| [#294](https://github.com/djshellshoxxx/patchtrace/pull/294) `claude/sleepy-fermi-rq-l1-runner` | Frozen-manifest L1 advisory-join qualification runner. | Hold as research/qualification tooling. No independent review; no real MSRC month/Windows run; synthetic-only evidence and no accuracy claim. |
| [#295](https://github.com/djshellshoxxx/patchtrace/pull/295) `claude/sleepy-fermi-test-reliability` | xdist-independent pathguard test and workflow-contract test. | Hold. Windows QA failed on the inspected head. |
| [#282](https://github.com/djshellshoxxx/patchtrace/pull/282) `consolidate/research-r7-20261104` | Bounded semantic slicing and evidence-grounded patch-pattern research prototypes with synthetic tests and roadmap. | Preserve as research, not production feature. It is not wired into PatchTrace and makes no accuracy claim. Revisit only with a product integration spec and real held-out validation. |
| [#290](https://github.com/djshellshoxxx/patchtrace/pull/290) `claude/sleepy-fermi-security-1` | Deep JSON, hostile-text, path, archive, environment and PE-boundary hardening. | Hold for completed independent security review and explicit disposition of all findings; the PR handoff says review stopped mid-way. |
| [#289](https://github.com/djshellshoxxx/patchtrace/pull/289) `claude/autonomous-finish-20261104` | Large integration/handoff snapshot. | Do not merge as-is: PR title and repository handoff explicitly mark it paused and conflicted/dirty. Selectively recover reviewed commits only. |

Other historical branches remain available. The repository has a large branch inventory; this targeted review examined the current default branch, the first two 100-branch inventory pages, the open PR set and the named high-value feature branches above. It is not a claim that every historical branch or every file in every branch has been exhaustively audited.

## Remaining engineering work

1. **Ghidriff timeout/performance (P1, high priority).** SPEC-01a progress and receipts are present, but timeout-entry validation/presets, profiling the 2.16-million-candidate structural stage, semantics-preserving performance repair, per-function decompiler timeout diagnosis, cache/checkpoint behavior and original-pair Windows acceptance remain open. A larger timeout is only a workaround, not a verified fix.
2. **KB/CVE desktop lifecycle.** PR #291's K3 issue is a production blocker: the dock can try to reopen an already-open project from a worker thread. Repair and test before taking the otherwise useful KBA/report work.
3. **Search/pilot/buildenv remaining issue #105 backlog.** PR #288 only closes S4-S7, P1, B1 and B2. S1-S3, S8-S9, E2-E9, N1, P2-P4, B3 and B4 remain outside that PR.
4. **CLI parity.** PR #292 is promising but must first become green on both Linux and Windows.
5. **Rizin side ownership.** Keep the fail-closed behavior; repair the eight red controls before integration.
6. **Release acceptance.** Do not describe the product as complete or issue a final release based on these merges. A clean Windows standalone build, native Ghidriff comparison on the reported real binary pair, offline bundle acceptance and manual desktop QA remain separate gates.

## Verification limits

This consolidation used GitHub-hosted PR metadata, diffs, CI check-run records, branch inventories and repository documents. No local Windows desktop, real user binary pair, air-gapped runtime payload or interactive manual QA was available in this session. No such acceptance is claimed.
