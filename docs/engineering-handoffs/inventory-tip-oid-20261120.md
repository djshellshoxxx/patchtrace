# Continuation — bind offline branch snapshots to immutable Git commit IDs

**Date:** 2026-11-20 (America/Vancouver). **Authority:** [task ledger](../engineering/task-ledger.json).
**Base:** `codex/patchtrace-inventory-tsv-shape-20261120` at `eaae7e504f8b43051f0c0d6d57c314d37c66d7ff` (successor to draft PR347).
**Isolated branch:** `codex/patchtrace-inventory-tip-oid-20261120`. Original PR345/346/347, the TSV-column predecessor, tags and main are preserved.

## Verified scope and ordered commits

1. Contract-first `f9feb421e0e5d880429556dba734acdf675fedcf` extends `docs/engineering/branch-snapshot-contract-20261120.md`.
2. Red regression source `2d0ddf8347093bb79d28959ebf23376bc38d75b8` adds five parametrized malformed commit-ref tests, one annotated-tag object test and one canonical-OID compatibility test.
3. Narrow implementation `30411f9a344be757da26aa0f9b914605c7699353` changes only `tools/branch_inventory.py` (a canonical OID regex; one pre-Git validation and one exact resolved-OID check).
4. [Receipt](../engineering/evidence/inventory-tip-oid-controls-20261120.json) and the authoritative ledger preserve synthetic evidence. Refresh final remote head/tree **after** documentation commits.

The parent TSV-shape repair checks header uniqueness, complete columns and prior-output preservation. It nevertheless calls `git rev-parse --verify <tip_sha>^{commit}` on unvalidated Git revision text. In a local temporary Git repository, `HEAD`, abbreviated object names and `HEAD~0` all resolved to a valid commit. Replaying them later could misassociate a branch label with whatever those aliases then meant. The new parser rejects noncanonical tips **for all rows before consulting Git**, and additionally rejects full-length annotated-tag IDs that peel to another commit. Accept canonical lowercase 40-hex SHA-1 or 64-hex SHA-256 only, then verify returned commit ID equals captured text. This is admission fidelity, not proof that every original branch was enumerated.

## Evidence and precise limitations

- Local synthetic Git exercise using source-equivalent parser logic: six pre-Git malformed-input refusals (including a valid row followed by a bad row), one canonical commit acceptance, one annotated-tag object refusal and six CSV global-limit restorations. The original resolver's acceptance of three mutable refs was reproduced. All synthetic objects are ordinary Git fixtures, **not analyzed target binaries**.
- **Not run:** repository-bound `python -m pytest -q tests/test_branch_inventory.py`, whole-tree `python -m ruff check src tests tools`, required full `QT_QPA_PLATFORM=offscreen python -m pytest -q`, or exact new-head hosted/native/packaging tests. This runtime has no PatchTrace checkout or GitHub DNS, and Ruff is not installed. A source-aware author review checked the emitted code and tests but a genuinely independent reviewer remains unassigned.
- Existing source still permits only nondeletion read-only inventory; no semantic branch-review counts have been improved by these parsing tests.
- PR347 run `44843482467`: all five native jobs successful on **PR347's source only**. PR347 QA `44843482603` had Linux QA and three Linux Qt shards successful, Windows QA/Qt and one Linux Qt still running at inspection. Do not duplicate active workflows or transfer those results to this branch.
- A new **historical failure disposition**, not a repair: PR345 Windows QA `44840721370` / job `136648122555` completed failed after **23,847 passed / 181 skipped / 5 xfailed** in its pytest stage, due to Chocolatey NSIS version 3.13 installation returning external HTTP **503 Service Unavailable** from `community.chocolatey.org`. The package-feed error is established by its raw job log; do not call the workflow passing, label it a PatchTrace code regression or change source/dependency gates without further evidence. PR346 Windows QA passed independently; no failed-job replay was dispatched.

## Next owner — exact executable tasks

1. Reconfirm current main/PR345/346/347 and this isolated head, tag/branch reference census and any active worker ownership. Preserve all original remote refs.
2. Run the seven new repository regression identities plus `tests/test_branch_inventory.py` with temporary local synthetic Git. Verify malformed refs never reach Git, canonical IDs remain exact, tagged object SHA is refused, strict UTF-8/bounded fields and old output are preserved. Run whole-tree Ruff and declared dependency check. If full aggregate is run, use a source-bound environment and per-node/phase termination evidence; don't repeat the historic uninstrumented SIGKILL attempts blindly.
3. Have an **independent** reviewer check canonical 40/64 hex compatibility across actual repositories, Git tag peeling, all-rows prevalidation, CSV field-limit restoration and exact prior-output retention. Record reviewer receipt separately; current author inspection is not independent signoff.
4. When PR347 QA/native/package has terminal receipts and exact new source is independently reviewed, consider a stacked draft PR (not main) with no redundant workflow dispatch. Merge only with all applicable checks green, zero blockers, and REST expected-head guard.
5. Continue registered header-help IDs, raw Winbindex/index membership, Windows trust/catalog/clean-machine/manual accessibility, old Linux force-overwrite semantics, native Qt, unresolved native-cache java=unverified / ASM / SIGKILL, 16 patch-equivalent and unmatched historical branches, and separate L1/L2/L3. Never score `facts:unverified` or claim numerical accuracy/performance gains from authored tests.

No main merge, force push, rebase, branch deletion, release/deploy, target execution or outgoing messages occurred.
