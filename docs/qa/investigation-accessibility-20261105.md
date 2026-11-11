# Offline investigation keyboard access — 2026-11-05

Base: published PR #218 head `afc8a2967ba3dec6b1ac3351d20dd08c193ba9bc`. Isolated branch `work/investigation-accessibility-20261105`, worktree `/tmp/pt-independent-accessibility-20261105`. This bounded C1/C2 slice owns the existing investigation Qt adapter, a new focused test file and the accessibility addition to SPEC-31-F; it does not alter the domain request/result, database or wire models.

## Reproduced defects

On the unchanged adapter, `tests/test_kb_accessibility_20261105.py` produced **13 failed, 1 passed** in 24.54 seconds. All seven composite rows lacked a label buddy pointing at the line edit. Four real Alt-key activation cases could not move focus to their corresponding fields. Tab from Search skipped the visually preceding product selector because that selector had been constructed after the project name. Blank-workspace validation left focus on Search rather than its correctable workspace edit. The passing control established that binary-only mode already skipped disabled advisory controls.

The adapter now links static plain-text labels to their edits, provides distinct label mnemonics, explicitly orders keyboard focus by the displayed workflow, and focuses the workspace on that preflight error. Existing semantic accessible names/descriptions, plain-text handling, disabled states, preview invalidation and asynchronous generation guards remain in use. The product selector retains Qt's generated buddy relationship and now has a mnemonic.

## Verification

Source binding was checked with `PYTHONPATH=$PWD/src python -c 'import patchtrace; print(patchtrace.__file__)'`; it resolves this worktree's `src/patchtrace/__init__.py`. No shared editable installation was changed.

- Red: `QT_QPA_PLATFORM=offscreen PYTHONPATH=$PWD/src python -m pytest -q tests/test_kb_accessibility_20261105.py` — 13 failed, 1 passed; raw log `/tmp/pt-independent-accessibility-red.log`.
- Green: `QT_QPA_PLATFORM=offscreen PYTHONPATH=$PWD/src python -m pytest -q tests/test_kb_accessibility_20261105.py tests/test_ui_kb_investigation.py tests/test_kb_binary_only_start.py tests/test_kb_current_project.py` — 54 passed in 37.00 seconds; raw log `/tmp/pt-independent-accessibility-green.log`.
- Exact final adapter accessibility rerun after the lint correction — 14 passed in 6.99 seconds; raw log `/tmp/pt-independent-accessibility-final.log`.
- Whole-tree `python -m ruff check src tests tools` and `git diff --check` pass. Ruff initially identified a missing explicit `zip(strict=...)`; this was corrected with `strict=False`, preserving adjacent-pair iteration.

These are deterministic Linux offscreen Qt checks, including actual label-key focus and Tab/Backtab navigation. They do not establish Windows UI Automation, native screen-reader announcements, high-DPI or frozen-package acceptance. No full suite, GUI stress suite, live source request, target execution, native build or qualification process was started or interrupted. PR #205 and existing native worker files/logs remain outside this worktree's ownership. No serialized schema changed, so schema generation is unnecessary for this slice.
