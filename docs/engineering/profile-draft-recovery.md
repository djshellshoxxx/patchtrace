# Generation 2: preserve profile drafts during navigation

## Exact scope and uniqueness

Implementation base: `1f18fb9aaf24cfc67b7515ae8c265a6c66e8a525`, which includes
the first generation's manifest/cache and WinPairs changes over PR #322.
Retained donor: PR #319 at `8d130aefe1be6e737cff1d90d2a5b1658d60a3a6`.

The baseline connected `currentItemChanged` directly to `_show_current`.
Selecting another profile silently discarded an unsaved draft. New and Duplicate
also changed the editor without resolving its current draft. The retained donor's
nine unchanged navigation tests reproduce eight failures and one passing control
on this exact integration base, confirming a behavioral gap rather than merely
different Git history.

Recovered scope is limited to the existing `ui_profiles.py` navigation helpers,
their `ProfilesPanel` wiring, three confirmation tooltips, the existing tooltip
test's real-dialog discovery path, and section 12 of the profile specification.
The unrelated raw-alignment, Search, inspection-cache and backend-environment
changes in the donor's large `ui.py` were not copied. Backend profile validation,
storage, public schemas and provider consent are unchanged.

## Resulting behavior

Selecting, creating or duplicating another profile offers Save, Discard and
Cancel for an edited profile. Save must validate and commit before navigation;
a failed save retains the draft and selection. Cancel retains both without
writing. Discard opens the requested profile without changing the saved original.
A successful rename still navigates to the originally selected destination.
Internal list reloads block signals so a successful save does not prompt again.
Read-only and unchanged profiles navigate without a prompt.

## Additional defect found during recovery

The retained donor still allowed a mismatched selection and editor when the
destination profile was removed or corrupted after the list was populated.
Four new real-file regressions failed against that recovered implementation:
missing/malformed destinations, each with an unchanged or dirty current editor.

The load operation now reports success or failure to the navigation helper. On
failure, selection returns to the profile whose values are still displayed, the
inline error stays visible, and an uncommitted draft remains intact. The helper
retains the prior profile name, not a QListWidgetItem invalidated by save/reload.
The same tests verify that the saved original is unchanged.

## Verification and retained failures

Environment: CPython 3.12.14, PySide6/Qt 6.12.0, pytest 9.2.0; Linux offscreen Qt.
No target binary, network provider or native acceptance flow was executed.

| Receipt | Source condition | Result |
|---|---|---|
| `evidence/profile-navigation-current-baseline.txt` | Exact integration base plus unchanged donor tests | 8 failed, 1 passed in 2.22 s |
| `evidence/profile-navigation-recovery.txt` | Initial narrow recovery, missing tooltip-harness path | 1 failed, 126 passed in 19.38 s |
| `evidence/profile-navigation-destination-baseline.txt` | Recovered donor before additional load-failure fix | 4 failed, 13 passed in 2.04 s |
| `evidence/profile-navigation-final.txt` | Final implementation and affected integration tests | 221 passed in 36.47 s |

Whole-tree configured Ruff and `git diff --check` pass. The existing UI line and
API seam gates pass without changed thresholds. Tooltip coverage drives a real
confirmation and does not add an exemption. No public schema changes require
regeneration. Counts overlap and must not be added into an aggregate result.

```sh
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_ui_profile_navigation.py tests/test_ui_profiles.py \
  tests/test_profiles.py tests/test_profile_cli.py tests/test_tooltips.py \
  tests/test_ui_setup_dialog.py tests/test_gui_settings.py tests/test_gui_host_seam.py
python -m ruff check src tests tools
git diff --check
```

## Review and handoff

Independent review is required before integration. Review Save/Discard/Cancel,
rename and item lifetime, missing/corrupt destinations, creation/duplication,
and Setup's separate accept/delete semantics. The root owns aggregate testing,
final-head hosted qualification, QA/task-ledger updates and remote delivery.
These authored offscreen controls do not establish native Windows/macOS desktop,
manual accessibility, package or release acceptance.
