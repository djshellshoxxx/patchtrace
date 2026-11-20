# Table header help and Evidence announcements recovery

## Source and scope

Base: `e428a5bdb21e9d3501e08166b9c1c673e3842193` (generation 19).
Reviewed donor: PR #321, `f851d74d134a09cb9b12013d2c1adba1fde0c24f`.
Original header-help source: `4a9e32bb490e4b3c000808554988103b4e50aa61`.
Original Evidence-announcement source: `647502ceff0602d2b03f1864136da431a1436511`.

The current base lacks the optional `ColumnSpec.tip_id` field and does not pass
the host shell to the Evidence matches `StateView`. The two recovered behaviors
are therefore distinct from the base, despite other GUI work already present.
The specification was amended before runtime changes. Only the relevant donor
hunks were taken: replacing the entire donor Evidence file would revert newer
attempt-storage warnings, retained-result accounting, and log reset behavior.
Those newer behaviors remain intact and their regression suite is included.

The header API now uses an escaped tooltip from the existing registry when a
column supplies an identifier. Empty or unknown identifiers fall back to the
title and unit. Display and accessible header text remain unchanged. This is a
shared API recovery; it does not claim every existing feature now supplies a
column-specific tooltip identifier.

Evidence state changes now use the existing host announcer. Changed error text
is assertive, other changed nonempty state text is polite, and repeated text
does not announce twice. Standalone panels retain the optional default of no
announcer. No engine, provider, persistence, analysis, or network behavior changes.

## Verification

The focused baseline tests ran against the unchanged generation-19 runtime:
**2 failed**. The header test raised the expected unsupported-argument error;
the real host-panel test observed no announcement. The original output is
retained in [baseline.log](baseline.log.gz).

After recovery, the combined affected selection passed **339 tests**, with no
failures or skips, in 47.86 seconds. The selection includes the current table
counter scope and Evidence attempt-storage tests alongside table, Evidence,
and shared state-view regressions. The output is retained in
[affected.log](affected.log).

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=$PWD/src python -m pytest -q \
  tests/test_gui_table.py tests/test_gui_table_spec.py \
  tests/test_gui_table_counter_scope.py tests/test_evidence_host.py \
  tests/test_evidence_attempt_storage.py tests/test_evidence_ui.py \
  tests/test_evidence_table.py tests/test_evidence_view.py \
  tests/test_evidence_panel_service.py tests/test_gui_state_view.py \
  tests/test_gui_core_state.py
python -m ruff check src tests tools
git diff --check
```

Whole-tree Ruff and whitespace checks passed. An earlier affected-suite command
named nonexistent test files and ran no tests; its original output remains in
[selection-error.log](selection-error.log). It is not included in the pass count.
The changed GUI dataclass and optional constructor argument do not alter a
serialized project or external JSON schema.

These are Linux offscreen checks. Actual Windows screen-reader speech, native
desktop packaging, full-suite qualification and release acceptance remain
separate. This recovery does not waive those gates.

## Tested file identities

| File | SHA-256 |
|---|---|
| `src/patchtrace/gui/table_spec.py` | `474cf5217e456ab64b75d98155e7580013a34ffc02508a5d79bcf0efcca7e862` |
| `src/patchtrace/gui/qt/table.py` | `c8ff60f1623852435dd9d11519b10356999ce8dd8efd2d5eebb006467b3228dc` |
| `src/patchtrace/ui_evidence.py` | `e85183646f43d055ca4f15e245f45e8a4d49df36881065f0807b31b7959b42cc` |
| `tests/test_gui_table.py` | `d45bd3e2c6d81491651097ba83f5a166252f6387ae200d21b9618fdc77eb5da5` |
| `tests/test_evidence_host.py` | `603bb04ddc0eb1fbd1fbbc955d370735c9627e1ee17492e72f713c91eb9835c2` |

The 2026-11-20 recovery preserves the original baseline log bytes as `baseline.log.gz`; the raw log contained pytest trailing whitespace. Decompression reproduces the original log exactly.
