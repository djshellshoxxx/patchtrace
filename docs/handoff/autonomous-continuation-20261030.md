# Autonomous PatchTrace continuation prompt

Continue `djshellshoxxx/patchtrace` autonomously as the implementation and integration coordinator.
The owner authorizes required code/spec/test/documentation repairs, branch reconciliation, commits,
pushes and reviewed passing merges. Work until the agreed essential product and release acceptance
criteria are met, or the actual session/tool/credit limit prevents progress. Do not stop after a plan
or one small fix. Do not claim that a prompt can bypass platform limits or keep running after a session ends.

First fetch current GitHub state and establish the real default-branch SHA, open PR heads, checks,
review threads, active coordinator and working-tree ownership. Read AGENTS.md, relevant module/spec
sections, docs/audits/20261030-consolidation-review.md, docs/plans/essential-integration-20261029.md,
docs/qa.md and tasks/todo.md. Treat current source/checks as authoritative over stale handoffs.
Use PatchTrace's own configured environment; never borrow another project's executor or credentials.
If authentication or environment setup is missing, complete independent review and state exactly what is missing.

Use one coordinator and isolated worker worktrees with explicit file ownership for independent
implementation, QA and security reviews. Check for existing active work before creating a branch.
Prefer completing/reconciling an existing PR over creating duplicate repair stacks. Preserve other
developers' changes, especially external Claude PR #102. Do not force-push, delete useful branches,
weaken tests, bypass protection rules, or merge unverified/conflicted work.

Priorities, in order, with usable GUI work progressing alongside each completed flow:

1. Reconcile remaining essential PR work; fix conflicts and regressions before merging. Verify
   #110/#123 and the 2026-10-30 consolidation's actual merged state rather than assuming it.
   Use the disposition table for #67/#69/#72/#100/#102 and calibration branches. Preserve unique work.
2. Complete the unified matching/diff engine end to end: automatic ProgramIR extraction, sound
   matching/abstention and materiality, explainable evidence, safe decompile refresh, deterministic
   results and all required G-U gates. Record real corpus evidence separately from synthetic tests.
3. Complete KB → CVE → product → binary correlation and patch search, real advisory parsing,
   freshness/provenance, generation/architecture separation and explicit ambiguous-pair selection.
   Legacy client scope IDs require refresh/reselection; do not silently reinterpret historical contexts.
4. Finish BinExport2/BinDiff/rz-diff adapters and orchestration with unified comparison; obtain
   pinned real-tool acceptance. Preserve distinct engine attribution and disagreements.
5. Finish project creation, immutable ingestion, persistence, previous-result preservation, run
   history, cancellation/recovery, enrichment signals/ranking, WIL/CVE context and Winbindex
   acquisition/verified pairing. Expose complete workflows clearly in the GUI.
6. Audit and fix correctness, security, concurrency, data loss, performance and packaging; build
   and validate Windows standalone/portable/installer and supported Linux artifacts. Verify hashes,
   notices and frozen smoke tests. Windows builds must run on Windows.

Defer AI interpretation expansion, guided teaching, DiE/YARA feature expansion and unrelated planned
features until the essential product is accepted. Before locked calibration claims, reconcile the
unique #78/#79/#82/#85 safeguards. No target binary execution, implicit downloads, credential
persistence, unpreviewed transmission or model-suggested command execution. Preserve raw evidence.

Deliver in small complete slices. Reproduce defects, add meaningful regressions, repair the cause,
review independently and run focused tests. Update specs before contract changes. Run the combined
offscreen pytest suite and Ruff, plus appropriate exact-head Linux/Windows QA, repeated Qt,
packaging/native-tool checks before merging. Diagnose failures; distinguish real failures from
environment blocks without removing gates. Mocked tests are never native compatibility evidence.

Commit and push after every verified meaningful slice and roughly every 15–30 minutes of productive
work; if work is incomplete, push a clearly marked draft checkpoint with remaining failures. Keep
one integration ledger with branch/commit/PR links, decisions, actual test counts/run URLs and next
steps. Merge reviewed passing work promptly, then verify main and only close proven superseded PRs.
Do not close a PR merely because some files overlap.

Continue to the next highest-priority task after each merge. Report progress briefly. Ask only for
essential information or permissions absent from this authorization. At a real hard limit, push all
recoverable work safely, record exact SHAs, failures, blockers and the next executable step, and give
a concise handoff. Claim completion only against explicit feature and release acceptance evidence.
