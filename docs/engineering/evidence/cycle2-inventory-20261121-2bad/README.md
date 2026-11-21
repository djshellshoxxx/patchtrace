# Inventory review evidence

Scope and conclusions: [independent review](../../cycle2-inventory-review-20261121-2bad.md).

- Frozen inherited source: `91618abec4c4f13a27fd5821a25d1500f17601e4`.
- Reviewed/changed source: `dc1ebfcd02d15bf94a707ee431ec585805a93cdb`.
- [Archive](review-receipts.zip): 22 original payloads, 29,145 compressed bytes.
- Archive SHA-256: `4c92b88177bd03b38560b700c0097128ce9bc50c782d5bf48b02ef26cc97699f`.
- [Manifest](manifest.json): original payload lengths and SHA-256 values;
  every member was reread and verified after writing the archive.

`maintained-initial` records 36 passes on inherited source. `quoting-red`
preserves all three expected pre-repair failures. `maintained-fixed` records
40 passes for the source subsequently committed as `dc1ebfcd`. Separate
baseline records retain the large-field, column, OID and JSON comparisons.

The control scripts import the actual inventory tool; the lower-source
comparison script obtains exact source blobs with `git show`. Their recorded
scratch paths identify the original execution. To reproduce on another
checkout, set the scripts' `ROOT`/`OUT`/interpreter paths accordingly. The
independent-control script exposes `--source-root` and `--output` arguments.
No mirror implementation is substituted for the reviewed reader.

The original 2,228,790-byte captured TSV is already retained in PR346's
committed cycle95fe archive, identified by commit/path/hash in
`retained-snapshot.json`; this archive does not duplicate it. Parsing those
353 rows is a compatibility check, not a new semantic census or an additional
353 passing tests.

The worker did not rerun the full suite or modify CI gates. Focused and
synthetic counts overlap and must not be pooled. The additional quoted-field
repair still needs a separate peer's acceptance before integration.
