# Independent Strings CSV v2 review — 2026-11-19

Reviewed runtime source: `9308cef64592a5a7e7d7fb051cffa68464277c31`.
Reviewed documentation correction: `53d9b33da5081bb080623049a2f1759522461188`.
The isolated reviewer started from root checkpoint
`1a9f6429` and did not edit production code, the implementation worker's
worktree, shared QA/task files, or remote refs.

## Result

**No remaining blocking finding in the CSV encoding slice.** Ten independently
authored controls pass in **0.60 seconds**. Whole-tree Ruff, the independent
control file, and diff whitespace checks pass.

The new first record has an explicit `strings-export-csv/2` marker and one
canonical JSON metadata field. The existing eleven-column header and finding
rows follow it. Source AST comparison identifies `render` as the only changed
function in the exporter; the added contract constant is outside that AST
comparison. `document`, selection, result construction, and all publication
functions are unchanged. `owned_publication.py` is byte-identical. The JSON
early-return branch and existing row/formula formatting are textually unchanged.
These comparisons are retained in `evidence/csv-metadata-peer-source.json`.

## Independent runtime controls

The reviewer exercised the public `export_delta` path and read the resulting
files using Python's CSV parser, independently of the formatter's helper methods.

- Actual `compute_delta` redaction was tested for a recognized secret pattern
  and a different value marked `FLAG_SECRET`, with default redaction and explicit
  reveal. Raw values remain absent from metadata in both modes; only explicitly
  revealed finding cells contain them. Returned digests match the whole file.
- An actual identical-input delta retains its `both` count, extraction digests
  and complete state while emitting zero findings: exactly metadata plus header.
- Formula-like lineage and basis text containing commas, quotes, CR/LF, NUL,
  Unicode line separation and non-ASCII characters round-trip as data. Metadata
  stays in one parsed field; finding-cell formula neutralization is preserved.
- A valid 1,200-row lineage union exercises metadata beyond the CSV parser's
  default field limit and executes the migration example directly from the
  specification. This is a small authored export, not a claim about every
  possible maximum-size export or every spreadsheet application.

## Finding discovered and corrected

The initial seven controls on the runtime candidate produced **one failure and
six passes in 0.75 seconds**. The serializer retained all bytes, but the exact
documented migration reader raised:

```text
_csv.Error: field larger than field limit (131072)
```

The valid witness contains **443,201 CSV bytes**, **157,612 metadata characters**
and **1,200 distinct lineage groups**. Its measurement and original failure are
retained in `evidence/csv-metadata-peer-large-reproduction.json` and
`evidence/csv-metadata-peer-initial.txt.gz`.

The author corrected only documentation and its review record. The example now
reads at most an explicit **8 MiB plus one sentinel byte**, refuses overflow
before decoding, parses that bounded snapshot, and temporarily sets the CSV
field limit to match the byte budget. A `finally` block restores the previous
process-global limit. The specification distinguishes this reader policy from
the exporter's capacity, explains deliberate larger budgets, and identifies
spreadsheet display limits and process-global parser coordination.

The original pytest output contains trailing whitespace and is retained as a
lossless gzip file rather than editing that diagnostic text.

The final review adds three controls for the new policy: an oversized local
file is refused, and invalid-marker failures restore both a smaller and a
larger prior CSV field limit. The large-field success control also checks
restoration. The resulting **ten controls all pass**. No runtime source changed
between the original and corrected documentation.

## Compatibility and limits

The format change is intentional: a header-first CSV consumer must validate and
consume the two-field preamble before using the unchanged finding table. The
specification explicitly describes this migration. It does not pretend that
old readers automatically understand the new format, and it does not introduce
a metadata record disguised as a finding.

This review qualifies authored export mechanics and the documented local reader.
The example is not an untrusted-file import boundary. Repository-wide testing,
native Windows publication, desktop/manual acceptance, and release qualification
remain root-owned. The existing Linux forced-publication race is outside this
encoding correction and remains open.

## Replay

From the reviewed checkout, with its dependencies installed:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src:tests python -m pytest -q -c pyproject.toml \
  docs/engineering/evidence/test_csv_metadata_peer_controls.py
python -m ruff check src tests tools docs/engineering/evidence/test_csv_metadata_peer_controls.py
```

Final output is retained in `evidence/csv-metadata-peer-final.txt`; Ruff output
is in `evidence/csv-metadata-peer-ruff.txt`. The evidence manifest records all
payload hashes and the exact runtime source identity.
