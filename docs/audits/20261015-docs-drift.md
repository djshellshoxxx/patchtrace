# Docs drift audit, 2026-10-15

One line per change: file, was, now, evidence. Docs only; no src, tests or tools changed.

| # | File | Was | Now | Evidence |
|---|---|---|---|---|
| 1 | docs/cli-reference.md | Invocation `python -m patchtrace.cli` | `python -m patchtrace` | `src/patchtrace/__main__.py`; `cli.py` has no `__main__` guard; `pyproject.toml` `[project.scripts]` |
| 2 | docs/cli-reference.md | Exit codes listed without the partial mapping | Added: partial exits 0 for rank/correlate, 3 for flags, series create, secondary run, unified run, intelligence explain, intel-tools run | `cli.py` docstring; `docs/specs/cli-umbrella.md` section 4 |
| 3 | docs/cli-reference.md | "Registry holds one verb: panels" | Five registry verbs: fabric, kev, panels, pilot, rules | `python -m patchtrace --help` |
| 4 | docs/cli-reference.md | Worker verbs omitted list: two | Adds `rules _rules-worker` | `_parser` dump: `rules _rules-worker --request` |
| 5 | docs/cli-reference.md | `unified run` table lacked three flags | Added `--no-residual`, `--python`, `--ghidra-dir` | `src/patchtrace/unified/cli.py` lines 69-75 |
| 6 | docs/cli-reference.md | `--no-decompile` "no effect in S0 mode" | "skip the on-demand decompile of review pairs" | `src/patchtrace/unified/cli.py` line 71 |
| 7 | docs/cli-reference.md | `cache` action listed without choices | Choices `status`, `verify`, `prune` | `cli.py` line 101 |
| 8 | docs/cli-reference.md | No `fabric` section | Section added (4 verbs, flags) | `_parser` dump, `cli_commands/fabric.py` |
| 9 | docs/cli-reference.md | No `kev` section | Section added (7 verbs, flags) | `_parser` dump, `cli_commands/kev.py` |
| 10 | docs/cli-reference.md | No `pilot` section | Section added (3 verbs, flags) | `_parser` dump, `cli_commands/pilot.py` |
| 11 | docs/cli-reference.md | No `rules` section | Section added (7 verbs, flags) | `_parser` dump, `cli_commands/rules.py` |
| 12 | docs/cli-reference.md | Planned list included `kev` and `rules` | Removed (now built); other planned verbs kept | top-level `--help` shows neither patch, search, graph, strings, kb, build-env, pe-meta, calibration, doctor, export, import, show, project |
| 13 | docs/privacy.md | Symbol download "held in quarantine" (no location) | Staged in a private temp folder under `tempfile.gettempdir()`, promoted to `acquire fetch --project`, staging removed | `cli.py` 591-611; `acquisition/quarantine.py` 54-57. The "default downloads location" premise has no code match (see report) |
| 14 | docs/privacy.md | AI key "held in memory for the session" | "held in memory for the current request only and never saved" | `ui.py` 3026; `tooltips.py` 640 |
| 15 | docs/privacy.md | "Checked ... 2026-10-14" | "2026-10-15 (download staging and key handling re-read that day)" | this audit; only those two items were re-read |
| 16 | docs/version-history.md | "After beta.225 ... not yet in a tag" | Notes tag `v0.1.0-beta.243` exists, change set UNVERIFIED | `git tag -l 'v0.1.0-beta.*'` |
| 17 | docs/version-history.md | Registry verbs not mentioned | Notes fabric, kev, pilot, rules; dates UNVERIFIED | `python -m patchtrace --help` |
| 18 | docs/modules.md | `tests/test_intel_tools_capa.py` (missing) | `tests/test_intel_tools_parsers.py` | `ls tests`; parsers file mentions capa 40 times (primary file UNVERIFIED) |
| 19 | docs/modules.md | `tests/test_intel_tools_floss.py` (missing) | `tests/test_intel_tools_floss_wb3.py` | `ls tests` |
| 20 | docs/modules.md | `tests/test_intel_tools_diec.py` (missing) | `tests/test_intel_tools_parsers.py` | `ls tests`; diec mentions in parsers file (primary file UNVERIFIED) |
| 21 | docs/modules.md | `tests/test_intel_tools_normalize.py` (missing) | `tests/test_intel_tools_audit.py` | `ls tests`; audit file imports `intelligence.tools.normalize` (primary file UNVERIFIED) |
| 22 | docs/modules.md | `tests/test_intel_tools_delta.py` (missing) | `tests/test_intel_tools_delta_wb3.py` | `ls tests` |
| 23 | docs/modules.md | `tests/test_intel_tools_store.py` listed (missing) | Reference removed; runner test kept | `ls tests`; store test location UNVERIFIED |
| 24 | docs/modules.md | `tests/test_intel_tools_provision.py` (missing) | `tests/test_provision_intel_tools.py` | `ls tests` |
| - | tasks/todo.md | Checked: all backtick paths, markdown links and cited test functions resolve, except owner-pending items | No change | path expansion check; `site/dist` is build output; `site/assets/source/logo-original.png` absent and listed as OWNER action |
