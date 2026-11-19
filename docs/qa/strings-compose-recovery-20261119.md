# Strings comparison recovery — 2026-11-19

Historical source: `150d9b9618b4f621ce31101c64502fb555734d46` (same shared composition in `ad4c49282a65`). The recovered module combines CLI/dock tables, current pairing, import/export cues, section regions and optional anchors. The dock adds Auto/Built-in/FLOSS source choice. The newer export implementation and accessible state identity are preserved.

## Demonstrated and repaired defects

- Current dock lost GetProcAddress's `api-name` cue and review tier relative to the CLI. The authored PE comparison control failed before the port and passes after sharing composition.
- A refused source selection left an older request active. New requests now cancel prior work and advance the generation before admission, preserving the earlier completed view through refusal.
- Historical FLOSS-backed worker suppressed an artifact verification failure and still returned results. It now requires both verified artifact reads, as the CLI does, and checks cancellation before each read. The first changed-artifact test attempt hit the immutable fixture's file permissions; the corrected fixture replaces its own file and demonstrates DID NOT RAISE against the historical loader. The separate precancel control also failed before correction.
- CLI AnchorSet parsing accepted duplicate identity keys, followed a file link, and trusted a prior path-size check. Three negative controls fail before bounded held-file reads and strict JSON validation.

## Verification and remaining admission work

The initial corrected composition selection passed 110 tests. The expanded CLI/worker/source-choice/anchors/accessibility selection passed 124 tests in 14.53s before the shared source snapshot is integrated. Original and final logs are retained under `../consolidation/evidence/strings-*`. One preliminary selection named nonexistent `test_ui_strings_pairing.py` and collected no tests; corrected selection uses `test_strings_pairing.py`.

**The preceding results describe the intermediate checkpoint.** Shared bounded tool snapshot admission is pending integration from the Search recovery, followed by current consumer/cached-evidence controls and independent review. Do not credit these fixture results as native FLOSS/tool execution, assistive-technology acceptance, or complete final-source qualification.

## Shared admission and consumer completion

The shared capture from `58b5421c`/`9e559383` is integrated at `a070f823`/`323b6407`.
The CLI/dock now use it on the SQLite owner thread; Built-in bypasses tool capture
entirely, unreadable evidence refuses without fallback, and CLI cancellation
precedes artifact reads. Verified cache hits and empty tool results remain FLOSS
sources even when no new raw file exists. Their optional
`normalized_evidence_sha256` identifies the typed retained evidence; it never
masquerades as raw stdout. When this new field is null it is omitted, preserving
legacy serialized bases and their digests. Generated schema and negative
traceability controls are updated.

Consumer regressions reproduced cache refusal, corrupt-row fallback, unnecessary
Built-in store access and pre-cancel artifact reads. One initially authored empty
fixture used a boolean in a strict string/integer metadata map; correcting it to
an integer exposed the actual old `stored_floss` refusal. That corrected negative
control loaded the unchanged function from `fcae8183` and failed in 3.10s. Two
recovered stand-ins were updated to carry the real ToolRun stdout_digest field.
No validation was weakened to accommodate those stand-ins.

Final integrated selection on parent `3be22028` plus these edits:
**1464 passed in 97.89s**, no skips, across all `test_strings_*`,
`test_ui_strings_*`, `test_search_*` and `test_intel_tools_snapshot*` files.
The smaller contract/source selection passed 42 tests in 5.96s; these counts overlap.
Raw final log/XML and original/corrected negatives are in
`docs/consolidation/evidence/strings-stored-*` and
`strings-empty-corrected-red.log`. Full normal Ruff and diff checks pass.
Independent review of the frozen consumer change is pending; no native FLOSS,
assistive-technology or release acceptance is implied.

Independent review of immutable `ecfd5960` passed 49 controls in 6.95 s.
Raw log/XML are retained as `strings-final-independent.*` in the consolidation
evidence directory. No additional native acceptance is inferred.
