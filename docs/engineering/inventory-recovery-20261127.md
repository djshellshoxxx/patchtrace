# PW-01 inventory feature recovery — 2026-11-27

Baseline: current main `151a3869d055ffcb0c4a76fcdbb2703e56a23451`, with the isolated packaged-version acceptance candidate as the worktree base. Donor: PR #321, `f851d74d134a09cb9b12013d2c1adba1fde0c24f`; PR #307 is retained history. No broad donor merge or replacement of evolved acquisition code is authorized by this recovery.

## Plan and completion gates

1. Recover pure CSV contracts/parser, preserving captured v1 5,000/50,000 budgets and separate v2 5,000-entry pages. Register the specification and schema before integrating consumers.
2. Recover inert saved-HTML link extraction and exact-consent source plans with bounded retrieval. Keep offline operations inert.
3. Restore immutable source persistence and revision-guarded selection through current WorkspaceStore ownership and acquisition evidence seams.
4. Wire shared operations into CLI and Qt, including retained-page inspection, explicit selection, cancellation and stale-result guards.
5. Regenerate all schemas, independently review, run focused and full offscreen validation plus Ruff, and obtain current-head Linux/Windows CI before guarded merge. Live source capture and native UI/release acceptance remain separate gates.

## Slice 1: pure CSV foundation

The retained parser regression initially failed collection because `inventory_csv` did not exist on the current source. After recovery, all 165 parser cases passed, including the real 50,001-row boundary and older captured budgets. The combined run recorded **326 passed / 4 failed**: the failures were two unregistered module boundaries and two schema assertions that assumed every record used the old contract. Explicit symbol allowlists and separately versioned schema expectations repaired those integration gaps; the 165 existing contract/schema checks then passed. Focused Ruff and whitespace checks passed. This is authored/synthetic parser evidence, not live Microsoft format acceptance.

The current `AcquisitionEvidence` generator registry, valid fixture, invalid example and dispatch remain intact. No external source was fetched, target executed, source bytes repaired, or retained decision reinterpreted.

## Slice 2: support links and exact source plans

The retained source regression initially failed collection because `inventory_fetch` did not exist. Recovered inert saved-HTML extraction, strict URL validation and exact ordered-consent retrieval; all **84 authored/injected source tests passed**, including malformed framing, DNS/address refusal, redirects, no-network planning, cancellation and byte bounds. Focused Ruff and whitespace checks passed. These tests do not establish live Microsoft source compatibility; no external request occurred.

## Slice 3: immutable evidence and explicit filename selection

Recovered the additive inventory backend into the current service and store. The baseline produced nine missing-module collection errors. The backend lane passed **269 tests with one native-Windows-only skip**; existing store/fixture controls passed **153**; current saved-scope and acquisition-evidence controls passed **111**. These lanes overlap and are not a summed test total.

Review exposed a donor ordering defect: pair lookup and plan preview decoded full saved decision bodies before bounded inventory admission. Four actual-route regressions failed before the repair. Inventory replay now precedes the general decision reader; the final admission/service/components/pair lane passed **129** tests. Failure preserves earlier decisions/revisions and never reaches the file index.

The entire current `service.acquire()` implementation onward and `store.AttachRequest`/`ProjectAttachment` were checked byte-for-byte against the baseline and preserved. Current `owned_publication`, `wiring`, `ports` and `saved_scope` files remain unchanged. Generated schemas retain `AcquisitionEvidence`; inventory schemas/examples are additive. Final schema, explicit architecture-boundary and specification-registry checks passed **324** tests; whole-tree Ruff passed. The initial schema integration attempt recorded two failures (a missing exact shared constant allowance and a mistaken expected import discriminator); both are corrected without changing runtime contracts.

Native Windows existing-object sharing remains unexecuted locally. No live source compatibility, L1/L2/L3 accuracy or release completion is claimed.

## Slice 4: CLI and desktop completion

The baseline produced **59 CLI/retention failures with 17 existing cases passing**, plus two Qt collection errors for the absent adapter. Recovered eight inventory commands and the dialog through current service interfaces; the four adapter/UI modules passed **110** tests. Existing KB panel tests passed **27**. The global tooltip sweep initially exposed an unreachable tab-bar tooltip: the actual widget now has a semantic ID and registered tooltip/accessibility description. The final tooltip plus keyboard control lane passed **19** tests. Counts overlap and are not an aggregate.

CLI and panel help now link the full inventory guide. Unrelated donor retained-CVRF claims were deliberately not included. Local/injected verification remains separate from live source capture, native Windows accessibility/high-DPI acceptance, current-head hosted CI, and guarded merge. Full combined verification and independent review are in progress.

## Final local integration and independent review

Independent review identified that SQLite character lengths did not enforce the promised fixed byte size of stored identity fields. Direct reads, paged IDs and orphan-reference enumeration now require TEXT plus exactly 64 encoded bytes before Python projection. Existing semantic/identity checks remain. The corrected standalone 24-case authored boundary suite failed on the prior implementation and passed on the fix; all 24 also passed independently. An initial support-fixture import-order issue was retained separately and corrected before the clean baseline run. Adjacent store/decision checks passed **152** tests.

The combined current KB/inventory/desktop/owned-publication/specification lane covered 113 test modules: **2,767 passed, 4 skipped in 180.63 seconds**. It ran from the isolated inventory source environment with the metadata correction present; the source file blobs reviewed were `4c5b34a438a4ad3d277fd4ba7bd6a1349bc45cd3` (inventory store) and `97a6aced0d65ea9202d2af57f2676ba023b302d4` (boundary controls). The independent reviewer additionally passed 22 targeted compatibility, consent and stale-result controls and confirmed current acquisition/attachment seams unchanged. No remaining implementation-review blocker was identified.

The complete feature is implemented and locally verified. Full-suite and current-head hosted/native qualification remain separate unfinished gates; synthetic and injected tests are not live Microsoft-source or release acceptance.

## Full-application attempt and retained diagnostic evidence

The common packaging follow-up was merged at local `46423952fcfa536f5eb2b4d3550a39832847a521`, tree `6520d3711a460f2908330ec83b0c8c4809e0f8fe`, exactly matching the initial published implementation tree. The first full offscreen attempt could not retain a child result because the verification harness encountered ENOSPC while writing its final receipt. Reproducible completed build outputs were cleared or relocated after checksum verification; source, archives and earlier logs were preserved.

The subsequent full offscreen run at that unchanged clean source ended with **SIGKILL (-9) after 930.203 seconds**, at 41% reported progress. Its log contains 10,564 pass markers, 24 skip markers and two expected-failure markers, with no failure marker or 120-second faulthandler timeout. There is no completed pytest summary or JUnit result, so these progress observations are **not a full-suite pass**. Recorded peak child RSS was 1,144,840 KiB. The signal's origin is unestablished; memory-event counters were unavailable. Neither an out-of-memory diagnosis nor a product failure is inferred.

The exact command, unchanged before/after source identity, terminal result, progress log and periodic memory samples are retained under `docs/engineering/evidence/inventory-recovery-20261127/`. Current published-head Linux/Windows/full/Qt/package and applicable native checks still govern integration. The already-passing 2,767-test focused lane and independent implementation approval remain separately attributed.
