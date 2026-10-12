# PatchTrace build plan, phases and gates

Status date: 2026-10-12. `tasks/todo.md` is the item-level tracker; `docs/qa.md` holds evidence. A phase is complete only when its implementation, integration, user-facing wiring and verification are done; unverified live/native gates stay open.

## Phase 1 — static two-binary review beta (M1–M6) — implemented, released
Contracts, PE ingestion, Ghidriff backend with containment, transactional projects, paired desktop review, manual matching, evidence-linked optional AI interpretation, exports, Windows standalone. Open gates: live local/remote AI provider acceptance; hands-on clean Windows GUI session; Windows OneDrive-backed native run.

## Phase 1.5 — runtime reliability — implemented, released
Dot-free Ghidra paths (PR #2), external scratch (#3), explicit symbol opt-in (#4), runtime discovery (#5), exit diagnostics (#6), offline installer (#7), cached-PDB isolation (#9, native Windows verified), Linux x86-64 package (#9). Open gates: real relocatable offline runtime payload + air-gapped Windows end-to-end (SPEC-06 §7 D/E); local-only symbol policy (needs a PatchTrace-owned Ghidriff launcher).

## Phase 2 — enrichment (SPEC-07) — implemented (PR #10), released beta.80
Change signals, attention/1 ranking, WIL, CVE context, cache, storage, CLI, desktop and export wiring. Remaining Phase 2 work, in order:
1. Code audit (5 areas) and repair — in progress.
2. SPEC-07 §12 analysis profiles (Setup tab, `--profile`).
3. SPEC-07 §13 raw output cache integration in the backend.
4. Live NVD/MSRC probe recorded through the CLI.
5. Cache-hit performance (objective 500 ms at 10k pairs; measured 3.1 s) and UI responsiveness measurement.
6. Reconcile SPEC-07 with the supplied handoff schema and validate its 9+9 examples — blocked: package not supplied.

## Phase 3 — later approved features — specification first
Contracts complete (SPEC-08..11, research in docs/research/phase3). Implementation order: Order: 3a acquisition (candidate search, consented download, quarantine, PE/PA30 identification; MSDelta reconstruction Windows-only), 3b N-way comparison over adjacent pair projects, 3c BinExport/BinDiff adapter (genuine pinned tools only), 3d Rizin rz-diff secondary engine. The two-artifact project invariant is not changed; N-way composes pair projects.

## Phase 4 — deferred design
Semantic IR, capa/call graphs, further AI transports. Not in current scope; requires typed IR/capability schemas, benchmarks and privacy/citation rules first.

## Standing gates for every merge
Linux+Windows pytest and Ruff, frozen Windows/Linux package smoke including CLI, native Windows Ghidriff matrix for backend-affecting changes, independent review for security-sensitive slices, schemas regenerated after contract edits, QA record and tracker updated.
