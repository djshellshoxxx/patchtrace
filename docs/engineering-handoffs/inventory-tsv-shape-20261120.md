# Successor handoff — exact branch TSV column-shape admission (2026-11-20)

Authority: [task ledger](../engineering/task-ledger.json); predecessor [sibling reconciliation](sibling-reconciliation-20261120.md). Read `AGENTS.md` before more engineering.

## Current ownership and source
- This narrow **isolated** branch is `codex/patchtrace-inventory-tsv-shape-20261120`, forked at the refreshed draft PR347 head `b461ac64eb9beb74449ce2b18b6795a2af34a02a`, which retains PR345 report/TaskRunner/Linux refusal/Evidence work and unique PR346 candidate-ordering/inventory/Qt/Strings tests. No other branch moved.
- Contract first: `007302ed551e3a2aa4fdfe44470718049d396cba` (extends the retained 95fe branch snapshot contract).
- Red regressions: `86d52cd09ff83cf595bbe6e7a92620e855d66a5e`; test fixture cleanup `75eda626847d4ae5ea46dae81a7425ba3fbc779a`.
- Production repair: `fbdb66a7a44b6170782b3f981887db284765bfd6`. Added independent CLI prior-output regression: `e9b02971e7babccd045d031cc38722c2b84cb3c5`.
- Only `tools/branch_inventory.py`, `tests/test_branch_inventory.py`, the specific snapshot contract, and additive evidence/navigation files change relative to PR347. Review remote final head/tree after documentation commits; do not claim local full-tree equality from API publication.

## Proven distinct defect and contract
On PR347 and the PR346 donor, `branches(..., snapshot=...)` used `list(csv.DictReader(...))` without validating its column shape. A repeated `branch` header silently overwrote an earlier branch value. Extra cells were accepted under key `None`, and missing cells used `None`. This could associate an exact retained commit with the wrong branch name without a parsing failure. It is **not** a feature-recovery or semantic-equivalence finding.

The repair verifies that header names are distinct/nonblank, that both `branch` and `tip_sha` exist, and that every declared row has exactly one value per column and a nonblank branch/tip. Malformed TSV returns `ValueError` before Git is contacted. It preserves legacy column order flexibility, additional **named** metadata, 32 MiB file cap, large quoted note, UTF-8 semantics, global CSV field-limit restoration, and prior published report preservation. No branch mutation, deletion, vulnerable-target execution, or CVE/matching behavior is added.

## Reproducible evidence, carefully scoped
- The [local stdlib control receipt](../engineering/evidence/inventory-tsv-shape-20261120.json) records six original `DictReader` malformed inputs admitted at parse stage and six source-equivalent amended algorithm refusals; a reordered-plus-extra-named-column compatibility control passes and CSV field limits restore across all seven. This was a manually reconstructed algorithm run on Python, **not repository pytest**.
- Seven new parametrized/standalone repository test cases plus one full CLI existing-output-preservation case have been authored. Their execution against a supported full checkout remains pending; counts must not be represented as pytest passes.
- A source/contract self-inspection checked the exact code hunk and the test fixture cleanup against the originating PR346/PR347 inventory parser. This is **not** independent reviewer approval.
- The runtime lacks a mount of the PatchTrace repository, and GitHub cannot be resolved by the container's Git transport. No complete-source `QT_QPA_PLATFORM=offscreen python -m pytest -q`, `python -m ruff check src tests tools`, dependencies or native acceptance has been performed for this branch.

## Hosted snapshot (not transferred to this source)
- Exact PR347 QA run `44843482603`: six queued, one in progress, release-gate skipped; native `44843482467`: five queued.
- PR346 native `44841261831`: five successful; its QA `44841261805`: seven in progress, release-gate skipped.
- PR345 native `44840721268`: five successful; its QA `44840721370`: four succeeded, three in progress, release-gate skipped.
These are time-specific observations for **other source identities**. No competing full workflow was requested for this unqualified successor.

## Precise successor tasks
1. Verify latest PR345/346/347 heads, running jobs and worker ownership; inspect actual failed job logs if any become terminal. Avoid rerunning queued or in-progress full jobs without new evidence.
2. On a supported source-bound checkout, run `python -m pytest -q tests/test_branch_inventory.py` (include the malformed header, complete TSV replay and prior-output tests), `python -m ruff check src tests tools`, then the mandated offscreen aggregate with per-test/phase termination receipts. Do not repeat prior SIGKILL runs without diagnostics.
3. Assign a genuinely independent reviewer to check the difference between strict column admission and historical replay compatibility, plus Python CSV exception/field-size restoration and malformed row controls. Correct defects before eligibility.
4. After parental CI is terminal, open a stacked **draft** against PR347 and use exact new-head QA/Qt/native/package checks without duplicate dispatch. Merge only with all required applicable green checks and no blockers, with fresh expected-head REST guard.
5. Continue registered application header-help ID mapping, historical semantic review and raw index/source exact-membership provenance separately. Retain Windows trust/manual accessibility and separate L1/L2/L3 acceptance, unverified Java cause, strict ASM timing and original local SIGKILL records. Linux forced overwrite remains disabled.

No merge to main, force push, rebase, release, deployment, branch deletion, analyzed-target execution, or outgoing email/chat message occurred.
