# Issue 116 profile and inspection repair — November 2, 2026

Source: `3f5b63b8b0d8ea6004f0492bbc9d3e338d5919ec`, based on integrated
`f7e65462e30775b28757c166bd012085afd56a81`. Original issue and its comment were
read fresh: <https://github.com/djshellshoxxx/patchtrace/issues/116>. This receipt
covers profile navigation and stale/cancelled inspection delivery only; it does
not close the broader issue or claim creation recovery is repaired.

Fresh original-source reproduction used actual offscreen Qt widgets, project
adoption, and synthetic PE bytes that were never executed. Four desired-behavior
controls failed in 1.93s: alpha's edited BND value 31 was overwritten by beta's
saved 30 without a prompt; malformed older/newer creation left lock/artifact
residue and blocked corrected GUI retry; a queued A inspection failure delivered
after adoption of B changed B's Files status/log and cached error. Creation
controls and implementation are tracked separately.

The reviewed repair puts profile transition logic in existing `ui_profiles.py`.
Selection, New and Duplicate offer Save/Discard/Cancel for dirty editors. Save
must succeed; validation/storage errors retain the original selection, fields
and inline error. Save-and-rename handles reloaded list items safely. Cancel is
the default and Escape action. Programmatic reload blocks selection signals.
The tooltip audit drives the real modal buttons rather than exempting new IDs.
Existing Setup Save/Cancel, defaults and explicit Delete confirmation are
unchanged.

Inspection failure slots now require the current root/project/artifact key;
queued stale failures cannot update status, logs or cached error. Worker
exceptions after cancellation retain diagnostic logging but emit no failure
signal. Current uncancelled failures remain visible. `ui.py` remains within the
unchanged 3,077-line ceiling, at exactly 3,077 lines.

Author command (offscreen, `PYTHONPATH=.:src:tests`, shared Python):
`pytest -q tests/test_lifecycle_116.py tests/test_ui_profiles.py
 tests/test_ui_setup_dialog.py tests/test_ui_raw_alignment.py tests/test_tooltips.py
 tests/test_gui_host_seam.py` — **92 passed in 32.78s**. Whole-repository Ruff and
`git diff --check` passed. The first expanded run found two new tooltip IDs not
exercised by the global inventory; the audit now drives the actual prompt, and
the complete selection passed afterward.

Independent review at the exact source reported no blocking finding: the same
**92 tests passed in 32.74s**, plus **15 additional controls in 1.84s** for real
modal choices/Escape, failure retention with saved-byte preservation, queued
orientation/current delivery and actual cancelled/uncancelled QThread failures.
These counts overlap; they are not a combined-suite total. The coordinator owns
`reviews-msrc/lifecycle-116-review-20261102.{md,json}`.

No full combined suite, native Windows GUI, native engine or performance claim
is made. No remote write or issue closure was performed by this worker.
