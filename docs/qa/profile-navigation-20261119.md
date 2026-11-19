# Preserve unsaved profile edits during navigation

Baseline: `88b0b52281dd314aa72f93819145a73135618bc4` (PR #317).
Evidence captured 2026-11-19 UTC. No release is qualified by this repair.

## Reproduction and change

Historical issue [#116](https://github.com/djshellshoxxx/patchtrace/issues/116)
still reproduced in the reviewed foundation: changing a weight or other profile
field and selecting another profile immediately overwrote the draft. New and
Duplicate also navigated away without resolving the draft. The newly authored
Qt controls reported **8 failed, 1 passed** before repair.

Dirty selection, New and Duplicate now offer Save, Discard or Cancel. Save must
validate and write successfully before navigation continues. Failed writes or
validation preserve the editable draft and prior selection. Save with rename
retains the requested destination, even though the list is rebuilt. Cancel
keeps editing; Discard leaves the stored profile unchanged. Unmodified and
read-only profiles do not prompt. Internal refresh blocks selection signals so
saving cannot recursively re-enter the prompt. The existing Setup acceptance
and explicit Delete confirmations keep their established behavior.

The confirmation uses plain text and registry-backed accessible descriptions
and tooltips. The existing global tooltip test now constructs the actual dialog
and inspects those controls; no tooltip IDs are exempted. The host `ui.py` is
six lines smaller because signal-safe refresh lives in `ui_profiles.py`.

## Validation

Linux, Python 3.12.14, PySide6 6.12.0, offscreen Qt; project development
dependencies and `PYTHONPATH=src`:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q \
  tests/test_ui_profile_navigation.py tests/test_ui_profiles.py \
  tests/test_ui_setup_dialog.py
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q \
  tests/test_tooltips.py tests/test_gui_host_seam.py
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q \
  tests/test_audit116_stale_inspection_failure.py \
  tests/test_audit116_export_copy.py tests/test_ui.py \
  -k 'audit116 or failed_note or failed_bookmark or failed_project_save or failed_finding'
python -m ruff check src tests tools
git diff --check
```

- Profile/navigation/Setup suites: **28 passed in 47.62 seconds**.
- Tooltips/accessibility/host seam suites: **43 passed in 48.47 seconds**.
- Existing note/bookmark/project-save/finding failure, export wording and stale
  inspection controls: **9 passed, 28 deselected in 33.75 seconds**.
- Whole-tree Ruff and whitespace checks passed.

An earlier combined Qt process exited 137 before emitting a final test report;
its partial progress is not counted. A subsequent focused run identified the
new tooltip controls missing from the old enumeration (**1 failed, 9 passed**).
The enumeration now opens the real dialog, and the complete relevant files pass
in the separate commands above. No tests were removed or skipped to obtain
these results.

Full integrated Linux/Windows CI remains required. Local offscreen tests are
not native Windows or macOS acceptance. Other #116 creation rollback fixes
remain in the baseline; the separate Windows creation-stat repair targets the
later PR #316 stack.
