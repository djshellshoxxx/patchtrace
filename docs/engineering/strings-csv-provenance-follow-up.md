# Confirmed follow-up: strings CSV document provenance

Observed 2026-11-19 on review commit
`924ea0435d669f88a4417cae96081d959cd3ad50`. Runtime source is unchanged from its
integration base, `f4503de3`; `src/patchtrace/strings/export.py` has Git blob
`6191d24744362c36401f6f68f33b75ef7b749e4a`.

`strings/export.py:104-107`: CSV serialization drops document-level provenance.
Define and implement a compatible, versioned CSV metadata representation that
survives zero selected rows, then cover it through the public export path.

This is a reproduction of the existing empty-export metadata obligation in
`docs/consolidation/REMAINING_WORK.md`, not a new raw-alignment finding or a claim
that the broader export scope is complete.

## Reproduction

The current WB3 integration contract says exports record basis and lineage.
`document()` correctly retains the basis digests, harmonized settings, notes,
counts, truncation state, redaction policy, anchors, and document contract.
`render(..., 'csv')` uses only the `changes` member. Its row schema contains no
place for the document fields, so their loss also follows for populated CSVs by
inspection of this serializer.

Three independently authored controls invoke the actual public `export_delta`
function twice with valid, comparable, empty deltas. Each control changes one
document property while holding its empty row list fixed:

| Difference | Expected distinction | Actual CSV |
| --- | --- | --- |
| Different older/newer basis digests | Different extraction identities remain traceable. | Identical header only. |
| `truncated=False` versus `True` | A complete empty result remains distinguishable from a partial empty result. | Identical header only. |
| Default redaction versus explicitly supplied empty reveal mapping | The exported redaction policy remains available independently of row count. | Identical header only. |

All six published files are the same 103-byte header, SHA-256
`59737cc7ddb7efc6fc89018083bd5170d25b04e74724d32b1d0c14aab784b8cc`.
The three desired-behavior assertions fail in 0.46 seconds. The in-memory
documents are explicitly asserted to differ before publication. There is no
mocked publisher or formatter.

- Counterexamples: [test_strings_csv_metadata_gap.py](evidence/test_strings_csv_metadata_gap.py).
- Failure evidence: [strings-csv-metadata-gap-result.txt](evidence/strings-csv-metadata-gap-result.txt).

```sh
QT_QPA_PLATFORM=offscreen \
/workspace/scratch/4c8dc848d760/venv/bin/python -m pytest -q --tb=short \
  docs/engineering/evidence/test_strings_csv_metadata_gap.py
```

The deliberately failing controls are stored outside `tests/`, which is this
repository's configured aggregate test path. They record unfinished work and
must not be reported as a passing acceptance gate.

## Bounded implementation task

Update the WB3 export contract before changing the wire format. Decide explicitly
how existing CSV consumers identify metadata and string records, and preserve
document metadata when there are no string records. A single-file representation
can retain the existing publication boundary; a separate sidecar would require
additional multi-file publication semantics and should not be introduced as an
incidental formatting fix.

Cover empty and populated exports, changed/all selection, truncation, redaction,
formula neutralization, and deterministic output. Keep the existing artifact
publication code and its unresolved Linux forced-replacement race separate.
The present commit makes no runtime or specification change and does not resolve
that race, native Qt, or other existing release gates.
