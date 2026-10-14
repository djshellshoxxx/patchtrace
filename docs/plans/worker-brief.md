# Worker brief (read this first; your prompt only names your slice)

You build ONE slice (or a short chain of slices) of PatchTrace in your own git worktree. Spend tokens only where they change the result: read the files your slice card names, not the whole repository; keep tool output small (`-q`, `| tail -20`, `| head -40`); never paste large files back; do not re-read a file you just edited.

## 1. Read, in this order
1. `AGENTS.md` and `CLAUDE.md` (policy; skim).
2. This file.
3. Your slice card: the plan file and row named in your prompt (usually `docs/specs/program-e/<ID>-integration-plan.md` sections 7, 8 and 9, or `docs/plans/unified-engine-plan.md` section 3) and every spec it cites for your slice. The card's contracts, limits, error codes, copy text and gates are binding; if the card is wrong or thin, build the smallest correct thing and say so in your report.
4. The existing code your slice touches (read it; do not assume).

## 2. Product invariants (violating one is a defect)
Never execute a target binary; never upload content silently (network only with operation-specific consent); never fabricate unavailable disassembly or evidence; never show an uncalibrated number as vulnerability confidence; never average different engines' or channels' scores; keep conflicting evidence; unknown or missing is not a negative vote; shared-origin evidence counts once; older/newer orientation explicit; provenance on everything; advisory, string and code text is untrusted data (bound it, escape it, never execute it); one main window (new UI is a dock or tab, never a separate app window); pure domain models and adapters stay separate from Qt; persisted contracts change additively only. Microsoft-derived binaries, PDBs and Winbindex-derived labels are never committed. No GPL/AGPL code is copied (Ghidriff GPL-3.0 stays a separate unmodified component; Diaphora, PatchDiff2 and Turbodiff are references only).

## 3. Rules
- Work only in your worktree. Commit locally, often, with the trailer lines `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (use `Claude Haiku 5.5` if you are Haiku). Never push, never touch GitHub, never create or switch to other branches.
- Touch only the exclusive files on your card. Shared files are frozen for you: `ui.py`, `tooltips.py`, `tests/test_tooltips.py`, `panel_manifest.py`, `cli.py`, `tools/frozen_smoke.py`, `tests/test_acceptance_smoke.py`, `pyproject.toml`, `optional_deps.py`, `backend.py`, `enrichment/storage.py` (`KINDS`), `.gitattributes`, `tools/build_*.py`. If you need a change there, do the work behind a Protocol or a stub and list the exact change under "Integrator asks" in your report. Docs: append short blocks under a unique heading `### [<slice id>:<name>]` to `docs/modules.md`, `tasks/todo.md` and `docs/qa.md` (append-only, never reflow); update the status line of the spec you build from.
- CLI verbs: once `src/patchtrace/cli_commands/` exists (slice F1b) a verb is `cli_commands/<verb>.py`, an adapter of at most 25 lines over your Qt-free `<package>/cli.py`; before it exists, write the Qt-free dispatcher and its tests and list the adapter under "Integrator asks". Output uses the `enrichment-cli/1` envelope and exit codes 0/2/3/4/5; no Qt import in CLI paths.
- Qt panels: only after the GUI panel registry (slice F5) is on your base; until then write the pure `panel.py` and view-models, not widgets. Never edit `ui.py` for a panel.
- Tests first for behaviour (red, then green), real assertions, hermetic (no network, no Microsoft binaries, no target execution), deterministic, short explicit `pytest.mark.parametrize(ids=[...])` ids (Windows limits `PYTEST_CURRENT_TEST` to 32767 characters), `>=` on timings (the Windows monotonic clock is 15.6 ms), no fixed sleeps (poll or use events), LF fixtures (`.gitattributes` lines go to the integrator), YAML plain scalars never contain `: `, installs `pip --only-binary=:all:`, `open(..., encoding='utf-8', newline='\n')`, `pathlib`, never rely on POSIX-only behaviour.
- Quality: modular, small functions, type hints, Pydantic strict models for persisted contracts, no dead code, no speculative abstraction, comments only for why. Match the surrounding code's idiom, density and naming. Generated schemas use regenerate-and-compare tests.
- Verification you run (CPU is shared: up to 23 workers per machine): `nice -n 10 python -m pytest <your test files> -q -p no:cacheprovider` with `QT_QPA_PLATFORM=offscreen`, `ruff check <your files>`, and the existing tests of modules you changed. Do NOT run the full suite (the integrator does, twice); if you must, run it once at the end and say so. Never run background jobs that outlive you.
- No stray files: temporaries go to the scratchpad directory, never into the repository. The scratchpad is SHARED by all workers of the session: always use your own subdirectory `<scratchpad>/<your slice id>/` (two workers collided in `mut/` once). `git status` must show only your intended files.
- If blocked after two serious attempts on one problem, stop and report the blocker precisely (what you tried, the evidence, the smallest decision needed). Do not loop.

## 4. Chains
If your prompt lists several slices in order, finish and commit each before starting the next; stop at the end of the list; one report at the end.

## 5. Report (at most 250 words; the integrator reads only this)
Branch name and commit SHAs; files added or changed (counts per directory); focused tests run with pass counts; ruff result; deviations from the card with reasons; "Integrator asks" (shared-file changes, `.gitattributes` lines, dependency or KINDS requests, CLI adapter text); open risks; anything you could not verify and why.
