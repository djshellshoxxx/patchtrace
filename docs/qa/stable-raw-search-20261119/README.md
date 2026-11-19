# Stable raw-alignment and saved-search recovery

This checkpoint recovers the standalone source/specification/test slices of PRs
[#309](https://github.com/djshellshoxxx/patchtrace/pull/309) and
[#310](https://github.com/djshellshoxxx/patchtrace/pull/310) onto the #317 foundation.
It does not import the broader #307/#316 inventory, native or packaging stack.
No source branch was rewritten, no remote ref was changed by this worker, and no
release or platform acceptance is claimed.

## Exact sources

- Foundation: `88b0b52281dd314aa72f93819145a73135618bc4`.
- Tested recovered source: `7daebd699ed942d9a7982bcb72f648e8843cb5f4`.
- Tested tree: `556c83dcb15e771284b7660c04a06ec8dc0386bb`.
- Original raw-alignment reviewed head: `3c9d3f074481b2f609330fa49ab9019eb6637849`.
- Original saved-search reviewed head: `26558cd0723aa5fa6d883f2935ad3c43cef94a86`.

| Original source commit | Recovered commit | Scope |
|---|---|---|
| `9e45b72cbec870e6a8265fa2b65a39a950aabadc` | `97327168` | Raw alignment contract, module index and regression controls |
| `ee41edbd2406dc6ca400bd8824a111358ac8a2a7` | `77508eea` | Bounded paired raw-window desktop adapter and host seam |
| `20a61fc747a452fb8a21ab34d1a146daa620e9a0` | `0e623b12` | Saved/recent query contracts and regression controls |
| `1de7d8df40661eaf61197310d5d123c3b4159edf` | `232293ab` | Project-owned save/run/delete, CLI actions and bounded user history |
| `90d032041de2cee5046cb1ea5f0ad458bcb5e9b2` | `7daebd69` | Bind index-build autosubmit to its captured query generation |

All five source cherry-picks applied without conflicts. The raw adapter and its
regression file, plus saved-search runtime files and new regression files, are
byte-identical to their reviewed source heads. The shared tooltip audit keeps the
foundation's existing panel set and removes the obsolete saved-query exemptions.
No schema contract changed.

The 17 dedicated historical QA files were copied unchanged from those heads.
`raw-search-historical-evidence-manifest.json` records each original Git blob,
size and SHA-256. Every local file was verified against its original Git blob.
Those records keep their original source attribution and are not new executions.

## Actual current-source execution

Runtime: CPython 3.12.14, PySide6 6.12.0, pytest 9.2.0, Pydantic 2.13.5,
Ruff 0.17.5, Linux x86-64. Every test command set `QT_QPA_PLATFORM=offscreen`
and placed this worktree's absolute `src` and `tests` paths first in `PYTHONPATH`.
`raw-search-qualification.json` records the exact source and runtime.

| Invocation | Actual outcome | Evidence |
|---|---|---|
| All search tests, search Qt tests, representation tests, raw alignment, host seam and tooltips | **1060 passed, 1 failed**, 304.41 s | `raw-search-targeted.log`, `.xml` |
| Full `python -m ruff check src tests tools` | **Passed** | Command executed at the tested source; no diagnostics |
| `git diff --check` | **Passed** | No whitespace errors |
| Isolated unchanged host-cost test at recovered source | **1 failed**, 48.62 s | `raw-search-host-isolated.log`, `.xml` |
| Same isolated test at untouched #317 foundation | **1 failed**, 62.22 s | `raw-search-host-baseline317.log`, `.xml` |
| Repeated host-construction observation at recovered source | Cold 1.387 s; warm 0.056/0.085/0.119 s; 13 panels and no host problems on every build | `raw-search-host-cost.json` |

The one broad-suite failure is
`tests/test_gui_host_seam.py::test_building_the_host_is_cheap`: 1.795 s against
the unchanged 0.5 s wall-clock ceiling. The cold isolated recovered-source build
measured 24.865 s; the exact untouched foundation measured 38.348 s under the same
host load. The later observational probe separately records wall/process CPU
and load averages. These observations establish a pre-existing cold/load-sensitive
qualification failure on this host; they do not convert any failed invocation
into a pass or prove that every platform meets the budget. The test and threshold
were not changed. Independent hosted Linux/Windows qualification remains required.

The broad command was:

```bash
QT_QPA_PLATFORM=offscreen PYTHONPATH="$WORKTREE/src:$WORKTREE/tests" \
  "$PYTHON" -m pytest -q \
  tests/test_search*.py tests/test_ui_search*.py tests/test_representation*.py \
  tests/test_raw_alignment_view.py tests/test_ui_raw_alignment.py \
  tests/test_gui_host_seam.py tests/test_tooltips.py \
  --junitxml=raw-search-targeted.xml
```

The isolated command selected only
`tests/test_gui_host_seam.py::test_building_the_host_is_cheap` on each exact source.
Its full original failure outputs remain unchanged.

The separate `tools/qt_gate.py --repeat 20 tests/test_ui_raw_alignment.py
 tests/test_ui_search_saved.py` invocation is **BLOCKED / ABORTED**. During a
general executor stall, the worker sent Ctrl+C to only its owned repeat session.
The retained wrapper log reports `qt_gate: ABORT, pytest died with status -9`
and the wrapper returned 1. There is no completed pytest summary or JUnit file.
The exact origin/timing of SIGKILL is not established by the log, and incomplete
progress dots are not counted as passing repetitions. No Git process was killed
and no test threshold or assertions were relaxed. Hosted repeated Qt qualification
remains open; `raw-search-qt-repeat.log` preserves the full available output.

No full integrated suite, native backend, Windows build, packaged executable,
manual visual/accessibility acceptance or release gate ran in this worker's slice.
