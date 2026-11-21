# Independent integration review — cycle 2

## Disposition and exact source

**No blocking finding remains in the reviewed changes.** This is an independent
review of source `3cf7ad23f66611d6bbf3e4d08e10daa2715fd300`, complete tree
`60ed420c11116f1b92bdbedae34e3e82269458e5`, against the published inventory
checkpoint `91618abec4c4f13a27fd5821a25d1500f17601e4`. The reviewer authored no
production, maintained-test, specification, or global-ledger changes.

Scope includes the damaged-quoted-TSV repair, corrected invalid-UTF-8 fixture,
eight Strings header-help mappings, registered-help copy, the actual-header
coverage audit and its follow-ups, the CSV/JSON display assertion, and the
corrected Linux-publication module description. This review does not qualify
the entire repository or authorize a main merge.

## Findings and reasoning

- **TSV quotation integrity:** `csv.DictReader(..., strict=True)` rejects
  unterminated quoted fields and trailing data after a closing quote while the
  existing complete-row parsing still precedes Git lookup. The `finally` block
  restores the process CSV field limit on success and failure. Independent
  controls accepted reordered columns, a 150,000-character note, quoted tabs,
  LF/CRLF, doubled quotes and Unicode while restoring a deliberately small prior
  CSV limit. A separate invalid-byte control restored that limit without any Git
  lookup. The maintained CLI control preserved previous report bytes and fixed
  error text on damaged quoting. These checks do not establish dataset
  completeness or branch semantic equivalence.
- **JSON negative fixture:** the corrected fixture contains a real `0xff` byte
  and independently asserts that UTF-8 decoding rejects it. The former literal
  backslash escape remains a separate malformed-JSON case. An additional peer
  control rejected keys that become duplicates after JSON Unicode-escape
  decoding while preserving ordinary string values containing `NaN` and
  `Infinity`. The error did not disclose the supplied values.
- **Strings header help:** the eight `ColumnSpec` identifiers match the panel's
  eight registered entries. Existing cell getters, widths, sorting, filtering,
  navigation, copying and export implementation remain unchanged. Display and
  accessible labels retain their existing framework roles; registry tooltip
  rendering remains escaped rich text with the existing missing-ID fallback.
  A fresh control sorted and filtered the real table to zero rows, verified all
  eight distinct registered headers, then restored the filter and compared row
  identities and complete cell-text tuples with the original values.
- **Coverage-audit follow-up:** inspecting `QTableView.horizontalHeader().count()`
  tests the actual table sections and avoids treating Qt list models as tables.
  Calling the real `show_panel('strings')` route activates the host's existing
  project hook; `build_all_for_test()` only constructs hidden controllers. The
  audit now asserts the visible prepared table has eight sections. No exemption
  set was expanded. An independent mutation suppressed only the Source header's
  tooltip while leaving its registry entry present: the global audit correctly
  failed with `strings.col.source` missing. This demonstrates that declaration
  alone cannot satisfy the updated gate.
- **CSV/JSON invariant:** the added assertion checks the original display text
  in JSON for each existing CSV prefix parameter, including form feed. All 28
  maintained export cases passed. The production serializer is unchanged.
- **Module description:** the updated entry now agrees with the implemented
  Linux refusal of existing destinations, including `--force`, and preserves the
  distinction that compatible Linux overwrite remains unavailable.

The original coordinator audit failure and Ruff import-order finding precede
this final reviewed source. The four retained follow-up commits address the Qt
binding call, actual table-section enumeration, real host activation and import
order; they do not modify production behavior or broaden test exemptions.

## Executed verification

| Selection | Result | Boundary |
| --- | --- | --- |
| Maintained global tooltip audit and uniqueness, all Strings exports, three quotation regressions, actual invalid-UTF-8 regression | **34 passed** | 3.22 seconds; same source above |
| Initial five independent controls | **4 passed, 1 failed** | Reviewer expected plain text at the start of an escaped rich-text tooltip |
| Corrected independent controls | **5 passed** | 2.94 seconds; only reviewer control changed |

The initial independent failure was a reviewer assertion error: `tooltip()`
intentionally wraps its escaped content as rich text. The corrected control
checks the rendered plain text and retains the exact registry-tooltip equality
assertion. The original control source, failure log and JUnit are retained.
Application source did not change between these runs.

The 34 maintained cases overlap author/coordinator selections and must not be
added to their totals. The five independent identities are retained separately;
their first and corrected runs are the same identities, not ten tests.

A dedicated editable environment was bound to this review worktree and verified
under `python -I`; Python was 3.12.14 and PySide6 was 6.12.0. No local full-suite
rerun, native Windows screen-reader exercise, external service qualification or
target execution was performed. Exact new-source hosted checks and all remaining
project/release gates remain separate.

## Retained evidence and replay

- [Receipt and archive identity](cycle2-peer-review-20261121-2bad.json)
- [Logs, JUnit, controls, source binding and SHA-256 manifest](evidence/cycle2-peer-review-20261121-2bad.zip)

To replay the fresh controls, extract `independent-controls.py` from the archive
to `tests/_cycle2_peer_controls.py` in the exact reviewed checkout. Use a
source-bound environment and `QT_QPA_PLATFORM=offscreen python -m pytest -q -p
no:cacheprovider tests/_cycle2_peer_controls.py`. The complete maintained command
and both independent command receipts are in `receipts.json`; adjust only the
temporary environment and JUnit-output paths. All archive members were read
back and verified against the manifest before committing this review.
