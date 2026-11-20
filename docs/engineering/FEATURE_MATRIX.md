# PatchTrace feature matrix

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
