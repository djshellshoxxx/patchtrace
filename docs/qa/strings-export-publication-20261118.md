# Strings export publication repair — 2026-11-18

Baseline: `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`.
Reviewed source: `922af3b8f048ce819dc78cf547cf269fd96b5d5f`.

## Reproduced defects

Five authored controls fail on the baseline. An export without `--force`
overwrites a destination created after the initial existence check. A dangling
destination symlink is replaced despite the same flag being absent. The
predictable process-ID temporary name follows a pre-existing symlink and changes
unrelated evidence, with and without `--force`. An interruption during sync
leaves the operation's partial file behind.

The repair uses exclusive, unpredictable temporary creation, flushes and syncs
the stage, and publishes with an exclusive hard link when `--force` is absent.
An unsupported exclusive-publication primitive produces a typed error; it does
not fall back to replacement. Only explicit `--force` uses replacement. Failure
and cancellation close the descriptor and attempt to remove the unique stage.
Existing JSON/CSV output, hashes, redaction and CLI exit conventions are retained.

This is a focused publication repair. It does not establish resistance to every
adversarial parent-directory or stage-path replacement. Native Windows and full
candidate qualification remain required.

## Tests executed in this session

```text
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_strings_export_publication.py --tb=short
Baseline: 5 failed in 0.48s.

QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_strings_export_publication.py tests/test_strings_export.py \
  tests/test_strings_cli.py --tb=short
Repair: 34 passed in 1.15s.
```

An independent reviewer replayed the same 34 tests and ran nine additional
controls. Those controls cover simultaneous writers, late symlink and directory
destinations, forced symlink replacement without referent writes, unsupported
hard links without replacement fallback, descriptor cleanup, sync failure and
pre-existing predictable stage names. All nine passed. The replay is overlapping
coverage and is not added to the author's count.

Changed-file Ruff and `git diff --check` pass. Raw before/after logs and JUnit,
independent controls and their original review receipt are retained under
`strings-export-publication-20261118/`. The receipt hashes match the reviewed
source commit's files. No target binary or network source was involved.

Document-level extraction/truncation metadata for CSV, including empty exports,
remains a separate contract task. This repair does not claim that broader export
feature complete.
