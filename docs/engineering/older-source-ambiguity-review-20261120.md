# Coordinator adversarial inspection — generation26 (not independent acceptance)

Scope: predecessor source matching through `row_for` in the consented `KbService.acquire` route. Source selection formerly used SHA/basename only and could persist an arbitrary older KB/BASE row. Parent generation25 corrected only the newer target.

Potential edge cases assessed: (1) reversed ordering of distinct KB and BASE rows now gives deterministic `PT-KBC-INPUT`; (2) equal duplicate mappings still pass; (3) single historical row still passes; (4) mismatch/missing source still refuses; (5) explicitly anchored newer target remains unchanged; (6) a distinct version key also counts as ambiguity; (7) no provider is planned for a refused older row.

Residual risks: equality of normalized mappings is not equality of original raw source entries; the current resolver may have selected one of several older bodies with the same SHA without preserving its source identity. Additional rows with different normalization or user-overridden index inputs may cause conservative refusal; this intentionally trades availability for avoiding false provenance. The index could change between resolution and the separately read source; this is **not** fixed. A malicious or malformed Mapping injected at the port boundary remains outside this deterministic test. The original Linux force-publication race remains open.

The reviewer is the author/coordinator, so this record is **not** an independent security signoff. Required: independent red-team source inspection and actual hosted source-level tests/QA/Ruff before promotion.
