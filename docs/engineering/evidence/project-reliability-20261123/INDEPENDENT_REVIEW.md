# Independent candidate review, 23 November 2026

The baselines and replays below used detached Git worktrees, the repository's own tests and Python 3.12. Qt ran offscreen on Linux. Hosted Windows and offline bundle acceptance for a new combined candidate still require separate execution.

## Recent projects in the desktop UI

On base `ea16019601486c831941f9bc1a7ba5862a170317`, adding the four new preference tests from `4c382d811f0cf61c2d87c7b5adf0189502533e4d` produced three failures and one passing existing legacy-path control. The adoption test module passed all 10 cases at `4c382d811f0cf61c2d87c7b5adf0189502533e4d`.

A separate test with a real INI-format QSettings instance exposed a missed case. Qt converted a single stored path containing a NUL into a list containing its truncated prefix. A valid project at that prefix could appear in the recent menu. Reading the raw stored value preserved the original string, allowing the application to reject it.

The new scalar-NUL regression failed on `4c382d811f0cf61c2d87c7b5adf0189502533e4d`. On corrected commit `1fe5f385dd612027bc4403bff396e46c746bc69b`, the implementation reads the raw preference, and 63 of 63 relevant tests passed. These cover project adoption, preserving the selected path in the menu and keyboard palette, and escaping path text in tooltips.

Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q tests/test_gui_project_adoption.py tests/test_gui_host_palette.py tests/test_tooltips.py`. Logs: `ui-red.log`, `ui-green.log`, `ui-edge-red.log`, `ui-verified.log`.

## Branch inventory

The repository-casing fixture failed on `ea16019601486c831941f9bc1a7ba5862a170317`: no PR associated with the branch. The candidate code and test diff (SHA-256 `3aa074be477b2cfd3bfc11331e2a222a3fb428154c13472d0540b12c405530a0`) produced 29 passes in `tests/test_branch_inventory.py`. It associated the same GitHub repository despite differing ASCII capitalization while preserving exact branch spelling and excluding forks. The integrated commit carrying this initial change is `84a411182db3fd888f3ec8539a672cef8fa4dcd9`.

A second synthetic Git graph showed that CLI input with Unicode Kelvin sign U+212A as the initial letter of an owner matched the ASCII name after lowercasing. Only the PR-supplied name was checked for ASCII. The actual repository name used for this census is ASCII, so its rows are unaffected. The finding was returned to the coordinator for correction and replay.

On the corrected integrated commit `eb63ab19ffcda4c2f03100cd04bee888ab9b26b9`, the tool rejects non-ASCII configured repository names before normalization. A new test checks that failure. Independent replay passed all 30 inventory tests. A Git comparison also found byte-identical UI modules and relevant tests between the reviewed UI correction `1fe5f385dd612027bc4403bff396e46c746bc69b` and this integrated commit.

Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q tests/test_branch_inventory.py`. Logs: `inventory-red.log`, `inventory-green.log`, `inventory-verified.log`.
