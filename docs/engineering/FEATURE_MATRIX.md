# PatchTrace feature matrix

## Current bounded feature status — cycle3

[Authoritative ledger](task-ledger.json) · [Qualification](cycle3-consolidation-20261121-95fe.md).

| Scope | Current state | Remaining acceptance |
| --- | --- | --- |
| Prior PR #348 application repairs and eight Strings header IDs | Independently reviewed; exact-tree full/platform CI passed | Other header mappings and native accessibility remain open |
| CODEX-14 full extracted Linux CLI smoke | Implemented, independently reviewed, local tests/lint passed | Both new-source Ubuntu frozen jobs and applicable hosted gates |
| CODEX-6 archive integrity and cache-hit fixtures | Implemented; test oracle repaired; two independent reviews; actual Bash fixture controls passed | Hosted restore/save/cache-hit and Ghidriff-path acceptance |
| Pages deployment opt-out | Implemented and reviewed; source regressions pass | New-source hosted QA; no deployment authorized |
| Engineering indexes/evidence |20 omitted files recovered with exact original blobs; six indexes reconciled | Keep source-specific CI/publication state current |
| Whole-product/manual/raw/accuracy work | Partial; no defensible overall percentage | Unchanged explicit release and historical-review gates |

Clean combined source e5a53166 has469 distinct affected passes after resolving11 missing-site-dependency skips; CODEX-1/5 remain2expectedfailures. Counts overlap prior author/peer selections and are not a full-suite total.

## Retained historical cycle95fe record

Authority: [task-ledger.json](task-ledger.json). The existing detailed feature
record remains [feature-status-20261119.json](feature-status-20261119.json).
Percentages below estimate only the named implementation slice; they do not
measure the whole feature, release readiness, or verified user acceptance.

| Feature / current slice | Implementation estimate | Evidence | Remaining acceptance |
| --- | ---: | --- | --- |
| Candidate request validation ordering | 100% of this bounded slice | Implemented, independently reviewed; 183 related cases on clean combined source | Full and final-source hosted qualification |
| Registered table-header help support | 100% of this bounded slice | Compatible API and fallback; donor equality; recovered regression passes on combined source | Full/native UI; individual columns may still need registered IDs |
| Evidence state announcements | 100% of this bounded slice | Shell wiring and existing duplicate/assertive policy; worker 212-case selection; recovered case passes on combined source | Actual Windows NVDA/Narrator output |
| Inventory replay | 100% of this bounded slice | Bounded input; ten cases pass on clean combined source; byte-identical 353-row real replay | Final-source hosted qualification |
| CSV/diagnostic required test coverage | 100% of four named additions | 47 cases; unchanged production behavior | Hosted Windows and application-specific acceptance |
| Branch consolidation | Not reliably estimable | 354 refs enumerated; all 334 PR metadata records; nine further scoped reviews | Many historical semantic reviews and qualified main integration remain |
| Raw source retention / reproducibility | Partial; no defensible overall percentage | Existing normalized source/provenance safeguards | Full raw Winbindex entry/index retention and exact resolver membership |
| General adapter compatibility | Partial; no defensible overall percentage | Existing source-specific and synthetic receipts | Supported native tools/platform acceptance on final source |
| Full application/release qualification | Blocked | Whole-tree Ruff, dependency and bounded scope checks | Full local attempt killed; current hosted/native/package/manual gates |
| Accuracy / matching research | Outside this cycle | Historical L1/L2/L3 records retained separately | No new measured accuracy or feature-completion assertion |

Current source: `ccc3664f11a81d3d30f907da36fc3d22da0063d0`.
Preintegration selections overlap and are not summed. See
[qualification](cycle-95fe-qualification.md) and
[integration order](INTEGRATION_QUEUE.md).
