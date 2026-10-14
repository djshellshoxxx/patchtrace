# PatchTrace — Claude Code continuation handoff (October 13, 2026, Vancouver)

This is a working handoff, not a claim that all design specifications are implemented.
**Before editing anything, re-check main, open PRs, commit statuses and Actions.**
Last inspected baseline: main `58578e176ff420f0e80eb1d41c740d43bd01ea4a`, shipped
`v0.1.0-beta.120` (Windows ZIP, Linux tar.gz); QA and native Ghidriff Windows CI
passed on that commit: runs 38502478511 and 38502478534.

## Mission and architecture
PatchTrace is an offline-first Python 3.12/PySide6 desktop and CLI to compare
explicitly oriented pairs of **Windows PE AMD64** builds, review likely patch
intent and security-relevant changes, and retain provenance, project snapshots,
analyst decisions and optional AI hypotheses. It supervises separately installed
Ghidra/Ghidriff; PatchTrace does not execute the inspected binary. Project-owned
immutable files, SHA-256 identity, versioned strict data contracts, bounded
processes, cancellation, worker/GUI-thread isolation and atomic SQLite commit
are safety invariants. It is NOT an exploit generator. Optional network access
for Microsoft acquisition, NVD/MSRC fetches and provider interpretation
requires explicit consent. Reports may contain private code, so preserve
redaction defaults.

See `AGENTS.md`, `CLAUDE.md`, `docs/modules.md`, `tasks/plan.md`,
`tasks/todo.md`, `docs/qa.md` and `docs/specs/*` as authoritative context.
Some README and older SPEC introduction sections are historical; cross-check
claims against code, tests, the item-level tracker and latest CI.

## Completed and merged
- Phase 1: typed ingestion, hash-identified older/newer artifacts, supervised
  Ghidriff backend, normalization, transactional SQLite projects and backup,
  cancellation and logs, code/assembly/metadata side-by-side review, function
  navigation/filtering, manual match correction/undo, findings/evidence/notes,
  optional bounded Ollama/OpenAI-compatible interpretation, report export,
  Windows standalone package.
- Runtime reliability: Ghidra dot-free output, external scratch, isolated
  Ghidra settings/PDB cache, no-symbols default, runtime discovery and
  diagnostics, importer/installer of *provided* offline bundles, Linux package.
- Phase 2: deterministic change-signal heuristics (BND/INT/OVF/VAL/ERR/SIZE/
  WIL/SCRUB), prioritization/ranking, CLI flag and CVE correlation, local
  feature profiles, raw and derived caches, GUI and exported explanations.
  Attention score is NOT a probability or evidence of a vulnerability.
- Phase 3 foundations: Winbindex search and consented Microsoft binary
  acquisition; ordered 3–8-build series **CLI** over adjacent pairs; import
  existing BinDiff results, run/parse rz-diff, and experimental conflict-first
  secondary evidence CLI. These are NOT turnkey multi-engine GUI orchestration.
- SPEC-26 alpha: file overview and PE header/section/import/export/entropy/
  overlay/checksum/RSDS inspection, embedded Authenticode probe with NO online
  revocation, verified raw bytes, Hex/Binary/Base64 paged views, file/entry
  scopes (not guaranteed function extents), improved changed-hunk navigation,
  extensive declarative tooltip registry, Qt worker integration.
- PR #26, if merged at handoff: sanitize dynamic PE and Authenticode row
  tooltips, display complete unavailable-state table, retain signature row
  on PE comparison failure. Regression suite tests these cases.

## Remaining scoped work (see tasks/todo.md for exact unchecked gates)
P0 reliability/acceptance:
- Clean Windows x64 ZIP GUI acceptance: launch on clean user profile; Sample,
  New/Open, File overview, imported/native Ghidriff, filters, next/previous
  diff, raw views offsets and copy provenance, tooltips, DPI 100/125/150/200%,
  cancel, setup, annotations, export, safe close. Record actual evidence.
- Verify signed/trusted/invalid/revoked Authenticode samples; catalog signing
  and true timestamp/revocation support remain separate new features. This
  alpha's `WinVerifyTrust` runs offline without revocation checks.
- Produce audited, licensed, complete **relocatable** Python/Ghidriff/Ghidra/
  JDK offline bundle, and test actual disassembly on network-isolated Win11.
  The desktop ZIP itself does NOT contain this runtime.
- Live provider acceptance, Winbindex MSDelta acceptance / per-byte progress,
  Windows OneDrive/Ghidra scratch and local-only symbol policy tests.
- Performance/cache benchmark: 10k-pair derived-cache 3.1s vs 0.5s target;
  protect identity checks when optimizing.

P1 meaningful next development:
- Reliable per-engine process capture: rz-diff currently has merged stdout/
  stderr from `jobs.run_process`; valid JSON plus harmless stderr can fail.
  Solve with bounded **separate** pipes while retaining Windows suspended
  Job Object containment, cancel/timeout/process-tree termination and tests.
  Do not simply use uncontained `subprocess.run` on Windows.
- Complete BinExport protobuf support and real BinDiff/rz-diff fixture runs,
  then a source-labelled disagreement/evidence pane and opt-in bounded engine
  orchestration. No arbitrary uncalibrated numerical confidence promises.
- N-way Series window, per-hop ranking, native 3-build acceptance.
- Finish PE version info/manifest/resource/signature details and cache;
  verified function extents/raw-byte async paging; remaining item tooltips,
  robust availability messaging and accessibility/DPI checks.
- Ensure all GUI controls introduced later have registry tooltips and tests.

P2 specification-only; implement after engine/evidence gates:
- SPEC-28 Microsoft CSAF 2.0 advisories, exact product/VEX applicability,
  deterministic CVE/CWE hypotheses, immutable citations, cautious unknowns.
- SPEC-29 optional capa/FLOSS/diec adapters with controlled subprocesses,
  pinned rule sets and provenance; DiE is a compiler/packer NOISE flag.
- SPEC-30 patch intent localization and typed evidence graph / rules.
- SPEC-12 onward Ghidra CFG/p-code semantic comparison, controlled runtime
  tracing, Ghidra-hosted extension and future architectures.
- Held-out annotated real patch corpus; calibrate function identity, correct
  block correspondence, mechanism support and actual vulnerability proof
  SEPARATELY. A score from one engine is not P(vulnerability).

## Verification and packaging
- Focused `python -m pytest -q tests/<relevant_test>.py` for each code slice.
- Full `QT_QPA_PLATFORM=offscreen python -m pytest -q`.
- `python -m ruff check src tests tools`.
- CI `QA and Windows standalone` builds Windows ZIP and Linux package, runs
  smoke/tests; `Native Windows Ghidriff acceptance` checks a known patch
  fixture and isolated symbol cache behaviors. Check the latest **head SHA**
  not a prior passing run, and verify release tag points to merged SHA.
- Release workflow auto-publishes beta on main if permission available. One
  workflow-changing commit failed publish with `GITHUB_TOKEN` HTTP 403 while
  builds/tests passed; subsequent non-workflow pushes released normally.
  Do not weaken workflow token security to bypass this. Actions ZIP is a
  legitimate alpha test artifact when release publishing is unavailable.
- Native test on one compiled DLL pair proves integration only, not matching
  accuracy over commercial binaries. Do not claim production-ready,
  fully offline runtime, or signed-file trust acceptance without evidence.

## Required operating discipline for Claude Code and all workers
1. Inventory open PRs, current CI, branches and worktree before editing.
   Never overwrite in-flight contributions, duplicate work, or merge stale
   divergent branches merely to remove branch clutter. Integrate one reviewed
   coherent PR at a time; squash-merge after fresh green gates; close superseded
   PRs with notes. Preserve branch ownership and hashes.
2. Work modularly: pure domain logic, typed inputs/outputs, adapters, Qt only
   in presentation; backwards-compatible storage and formats. Document
   integration and exposed controls, status, limitations and downstream
   dependencies. Add regression tests FIRST for each bug; prove RED, GREEN and
   refactor, then run appropriate full CI. Never remove tests to go green.
3. Spawn as many agents/workers as useful *when the work is genuinely
   independent*. Assign non-overlapping files and bounded deliverables,
   freeze shared interfaces first, designate one integrator for UI/build,
   review and merge in a timely sequence. Do not spawn idle agents or
   parallel workers that modify the same source. No orphaned branches.
4. All agents use the **cheapest model reasonably capable of solving their
   specific task reliably**. Inventory, docs, simple tests and formatting use
   inexpensive workers; mid-tier for ordinary implementation; stronger model
   only when complexity/security/debug failures justify it. Avoid excessive
   retries on a model too weak for the task; escalate intelligently. Minimize
   input context with file ranges, searches and concise shared status notes;
   reuse existing contracts/tests/code; avoid duplicate searches and broad
   unexplained refactors.
5. Research only where needed. Prefer official upstream docs and source,
   standards, authoritative technical references, peer-reviewed journals and
   textbooks for scientific claims; GitHub and Wikipedia may help discovery.
   No YouTube/blogs as research foundations. Check licenses, version pinning
   and upstream compatibility before copying code or adding dependencies.
6. Do not execute target binaries, expose binary content to remote services,
   enable unintended downloads or network calls, alter existing projects, or
   suppress security failures to make builds green. Handle hostile PE metadata
   as untrusted, escape UI output, and verify source provenance.
7. **User communications:** output nothing to the user during routine work.
   Ask only when a true approval, credential, inaccessible Windows resource,
   policy choice or other user-specific input is essential. Continue
   autonomously where feasible. Once work is complete, provide one succinct
   final report: changed modules, PRs merged, tests/CI/Windows artifact and
   remaining validated blockers. Do not promise later work as completed.
