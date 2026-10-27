# Phase 2 handoff provenance

These files were imported unchanged from the developer-ready handoff package
`PatchTrace-Developer-Ready-Agent-Package-v2` (folder `PatchTrace-Agent-Package-v2`, 2026-10-27 hand-over). The
package's own `SHA256SUMS.txt` verified every file before import. The digests below are the import-time values; the
test `tests/test_phase2_contract_examples.py` recomputes them and fails on any silent edit.

```
cdd94117ee9a4e847a9ffe2dcf14c21e1a9c68c9ce250751ccb5d4ccacc9209d  PatchTrace-Extension-Specification-2026-10-11.md
e903f4a604bcef4d7a8728317198a99b8e49bd1cfb5b9725dc8d6b647472522c  PatchTrace-Phase2-Contracts-v1.schema.json
9a579d01bdb0ec771f83e8f83ef2a9ad1a715c9b76938e0dd8de394593c3b0eb  PatchTrace-Phase2-Synthetic-Examples-v1.json
```

## Status of these documents

- The extension specification is grounded in an older commit (the handoff states this). It is a requirement
  reference, not a statement of what the repository implements today. Current status must come from the
  traceability map and from the code, not from this document.
- The schema describes the nine Phase 2 contracts. The file's own `$comment` says it has no application
  implementation and that semantic checks (exact score arithmetic, identity hashes, ownership, evidence linkage,
  store invariants) are required beyond JSON Schema. Those semantic checks are not implemented by this import.
- The synthetic examples are labelled synthetic in their own `$comment`; they are not authentic CVE data.
- The examples file contains nine valid and nine invalid objects. Each valid object passes its named contract and
  each invalid object fails it, as tested. An inline example in the specification is deliberately incomplete and is
  not a fixture.

## Where the files live

- `docs/specs/phase2/PatchTrace-Extension-Specification-2026-10-11.md`
- `docs/schemas/phase2/PatchTrace-Phase2-Contracts-v1.schema.json`
- `docs/schemas/phase2/PatchTrace-Phase2-Synthetic-Examples-v1.json`

Do not edit these copies in place. A later revision should be added as a new file with its own provenance line.
