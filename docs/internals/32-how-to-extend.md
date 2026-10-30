# 32. How to extend PatchTrace

Concrete recipes for the four common extensions: a CLI verb, a panel, a tool or engine adapter, and a spec with its tests. Each recipe names the files, the contract that makes it safe, and the checks to run. Read first: `AGENTS.md`, `CLAUDE.md`, `docs/plans/worker-brief.md` (the rules for a slice), `docs/modules.md`. Architecture background: [20](20-architecture.md), [23](23-gui-framework.md). Previous: [31](31-decisions-and-tradeoffs.md).

## 0. Before any extension

1. **Fetch the current state.** `git fetch origin main`, check open PRs and their checks, and do not reuse stale snapshot facts. Parallel contributors are active; never overwrite another branch (`CLAUDE.md`).
2. **Spec first** when an interface or persisted contract changes: edit `docs/specs/` (and `docs/specs/REGISTRY.md` for a new number), then code.
3. **Frozen shared files**: `ui.py`, `tooltips.py`, `panel_manifest.py`, `cli.py`, `tools/frozen_smoke.py`, `pyproject.toml`, `optional_deps.py`, `backend.py`, `enrichment/storage.py` (`KINDS`), `.gitattributes`, `tools/build_*.py`. If you need a change there, do the work behind a Protocol or stub and list it as an "Integrator ask" in your report.
4. **Invariants** ([31](31-decisions-and-tradeoffs.md)): never execute a target, no silent network, no fabricated evidence, no averaged scores, unknown is not negative, additive contracts only.
5. **Verification** you run: `QT_QPA_PLATFORM=offscreen python -m pytest <your files> -q -p no:cacheprovider`, `python -m ruff check <your files>`, plus the tests of modules you touched. Generate schemas after a contract edit.

## 1. Add a CLI verb (`cli_commands/`)

A verb is one file, `src/patchtrace/cli_commands/<verb>.py`, at most about 25 lines, that exports `COMMAND`. The file name is the verb (`build_env.py` becomes `build-env`); the name must match `[a-z][a-z0-9-]{1,23}` and must not be one of the built-ins in `cli.COMMANDS`. Real example (`cli_commands/kev.py`):

```python
"""`patchtrace kev`: the CISA Known Exploited Vulnerabilities catalog (adapter over `kev.cli`, GUI plan 8.12)."""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..kev.cli import add_parser  # function-level: listing the verbs imports no feature
    return add_parser(sub)


def _run(args, cancel):
    from ..kev.cli import run
    return run(args, cancel)


COMMAND = CliCommand('kev', 'CISA KEV catalog: status, plan, fetch, import, lookup', _build, _run)
```

Rules (`cli_commands/__init__.py`):

- The adapter is **stdlib only at module level**; it imports its feature inside `_build` and `_run`, so `patchtrace --help` loads nothing. Discovery imports every file to read its `summary` (1 to 80 printable ASCII characters).
- Put the logic in your Qt-free package: `<package>/cli.py` with `add_parser(sub) -> ArgumentParser` and `run(args, cancel: threading.Event) -> int`. Import `CANCELLED, ENVIRONMENT, NO_RESULTS, OK, RUNTIME, CliError` and `emit` from `patchtrace.cli_commands` (or `patchtrace.cli`). Never import Qt in a CLI path.
- Parse with `argparse`; add `--json` ("emit exactly one JSON document on stdout"); set `command_label` so the envelope names the verb. Output uses the `enrichment-cli/1` envelope via `emit(args, command, status, result, warnings, text)`. Diagnostics and any "request:" line go to stderr.
- Exit codes: 0 success; 2 invalid arguments, configuration or consent; 3 runtime failure or partial; 4 a legitimate empty result; 5 cancelled. Raise `CliError(code, message)` for 2 and 3. Decide partial semantics in your spec (SPEC-44 section 8 documents the inconsistencies of older verbs; new verbs reject inert flags with exit 2).
- Anything that can reach the network takes an exact `--consent-hosts` list and prints the request first ([17](../guide/17-privacy-and-network.md)).
- A broken file is listed as `unavailable (could not be loaded)` and exits 3 without hiding other verbs.
- PyInstaller: `tools/pyinstaller_hooks/hook-patchtrace.cli_commands.py` collects every `cli_commands/[!_]*.py` and **fails the build** if one is missing; no manual hidden-import is needed. `tools/frozen_smoke.py` check A1 then asserts `--help` for every command in the frozen build.
- Tests: add `tests/test_<verb>_cli.py` using the pattern of `tests/test_cli_registry.py`, `tests/test_kev_cli.py`; assert `test_headless_entry_never_imports_qt` still passes; document the verb in `docs/specs/cli-umbrella.md` section 5 and update `docs/cli-reference.md` (no generator script is committed; it was produced from `argparse`).

## 2. Add a panel (`PanelSpec`)

1. **Spec and view model first.** Write the pure view model in your package (frozen dataclasses from stored records, every string passed through `gui.text.sanitize_text`; no Qt, no I/O). Example shapes: `nway/view_model.py`, `pilot/read_model.py`, `secondary/evidence_view.py`.
2. **Declare the panel** in `<package>/panel.py`, importing no Qt:

```python
from ..gui.registry import PanelContext, PanelController, PanelSpec
from ..tooltips import TooltipEntry

TIPS = {
    'series.dock': TooltipEntry('Dock with one tab for each series.json you opened.', 'Why it exists.',
                                'Read-only; closing a tab changes no project data.', 'Where the data comes from.',
                                'Open a series.json from the File menu.'),
    'series.action': TooltipEntry('Show or hide the Series panel.', 'Keeps stored chain hypotheses next to the workspace.',
                                  'Toggles the dock.'),
}

def _factory(ctx: PanelContext) -> PanelController:
    from ..ui_series import SeriesController      # Qt is imported only when the factory runs
    return SeriesController(ctx)

PANEL = PanelSpec(id='series', title='Series', factory=_factory, area='bottom', tips=TIPS)
```

3. **Match the manifest slot.** `panel_manifest.MANIFEST` already reserves id, area, tab group and shortcut for the planned panels (`ManifestEntry('rules', 'patchtrace.rules.panel', _rules, 'right', None, 'Ctrl+Shift+R')`). Your spec's area, tab group and shortcut must equal the slot; a placement change is a one-line edit by the integrator. A new panel needs a new `ManifestEntry` (shared file: integrator ask). Shortcut form is `Ctrl+Shift+<letter>` and must not collide with `RESERVED`/`FRAMEWORK` keys.
4. **Write the controller** in `ui_<feature>.py`, subclassing `gui.qt.docks.ControllerBase`. Override only the hooks you need: `project_changed(key)`, `selection_changed(match_id)`, `busy_changed`, `capabilities_changed`, `theme_changed(tokens)`, `show_anchor(anchor) -> NavResult`, `shutdown()`. Talk to the window only through `ctx.project` (read), `ctx.mutate`, `ctx.nav` and `ctx.shell` (tasks, settings, theme, announce, notice, copy_text, choose_file); never import `MainWindow`, `ui.py` or another feature.
5. **Threads and widgets.** Run work with `ctx.tasks.submit(channel, fn)` (latest wins; worker gets a snapshot, returns a value); use `VirtualTable`, `StateView`, `PlainLabel`, chips and `compose_selections` rather than hand-rolling. Every state of a panel (no project, idle, loading, partial, stale, error, too-large, cancelled...) gets words from `gui/state.py`.
6. **Text and claims.** Tooltip ids start with `<panel id>.` and include `.dock` and `.action`; choose a claims profile (`CLAIMS_NEUTRAL`, or `CLAIMS_PAIRING` for pairing panels). Declare `requires` (`project`, `tool:...`), `anchors_in`/`anchors_out`, `commands`.
7. **Gates.** `patchtrace panels check` (no display) must report no conflicts; add the panel module to the Qt-import-free tests (`tests/test_ui_m3_docks.py::test_panel_specs_import_no_qt`); write offscreen Qt tests with `qt_support`; run `python tools/qt_gate.py --repeat 5 tests/test_ui_<feature>.py`; confirm `test_no_new_top_level_window` and the `ui.py` ceiling still pass (you never edit `ui.py` for a panel).

## 3. Add a tool or engine adapter

**Static tool (capa/FLOSS/diec pattern, `intelligence/tools/`).** One module per tool with: a config dataclass; `probe(config, cancel, runner)` that verifies version and the options PatchTrace will pass; `build_argv(...)` returning a fixed argv (no shell, no user text in flags); `prepare(...)`; `classify_exit(...)`; and a strict result parser (`pydantic` strict, frozen, `extra='forbid'`) that maps the tool's document to `tool-evidence/1` records with canonical module-relative addressing (`normalize.py`). Wire it in `common.ENGINES`/`PROFILES`, `runner.py` and `cli.py`. Pin the executable SHA-256 in `intelligence/tools/pins.py` **and** `tools/intel_tools_pin.json` (a test keeps them equal); an unpinned build is `unsupported` unless `--<tool>-accept-untested`, and is recorded as untested. Spawn only through `process.py`/`jobs.run_process` with a private scratch copy of the artifact. Add fixtures from real tool runs on **synthetic** PEs, never Microsoft binaries. Store results through `store.py` (reserved kinds, never derived).

**Secondary match engine (`secondary/`).** Implement the `EngineAdapter` Protocol: `probe(job_env, cancel) -> Capability`, `argv(cap, job)`, `run(cap, job) -> RawResult` (via `job.runner`, which is `jobs.run_process`), `parse(raw, cap, job) -> SecondaryMatchSet | None`; register it in `build_registry` and `DISPLAY_ORDER`. Untrusted output (SQLite, protobuf, JSON) gets a hardened reader and a capped worker. Spawn through the runner only; take the child environment from `engine_env.py`.

**Unified source (`unified/`).** Add a `SourceSpec` row and a `Family` with its dependency tags to `unified/registry.py` (D-08) and an adapter in `unified/sources/`; if it reads the same upstream data as an existing family, share the joining tag so it is one component. The source never adds a number to fusion; map its native vocabulary to tiers and evidence classes (`GHIDRIFF_TYPES`, `BINDIFF_STEPS` are the model).

**Checklist for any adapter.** Bound every read and every output; make cancellation work; store provenance (tool, version, argv digest, input hashes); report `unavailable`/`unsupported` honestly; add a hostile-input test; add a `live-*` workflow only for real-tool acceptance and record `passed|failed|blocked` through `record_live_status`.

## 4. Add a spec and its tests

1. **Pick a number.** Take the next free SPEC number in `docs/specs/REGISTRY.md`; never reuse one; check `docs/specs/INDEX.md` and `docs/specs/non-goals.md` (do not partly implement a deferred item under another name, NG-R2).
2. **Write the spec** under `docs/specs/` (or an integration plan under `docs/specs/program-e/`): scope and basis commit, verified current behaviour with file and line citations, requirements with MUST/SHOULD, contracts and limits (numbers in one place), error codes (`PT-<AREA>-*` with fixed message templates), tags for decisions, proposals and unverified items, acceptance and test plan, and the registry row. Mark what is planned.
3. **Contracts.** Strict pydantic, frozen, versioned `name/N`; additive changes only; add a schema generator under `tools/` and a regenerate-and-compare test; add fixtures with LF endings and list new fixture directories in `.gitattributes` (integrator ask).
4. **Tests first (red, then green)** for each requirement: hermetic, deterministic, short parametrize ids, `>=` timings, no sleeps, injected openers/runners, a `network_guard` check for anything near a socket, `HOSTILE` strings for any text sink, a no-Qt import test for pure packages.
5. **Record evidence.** Append a block headed `### [<slice id>:<name>]` to `docs/modules.md`, `tasks/todo.md` and `docs/qa.md` (append-only, never reflow) with commands, counts, versions and a "Not verified here" list; update the status line of the spec you built from.
6. **Report** in at most 250 words: branch, files changed, tests with pass counts, ruff result, deviations with reasons, Integrator asks, open risks, anything you could not verify.

## 5. Common mistakes (each has bitten before)

- Importing Qt, `pydantic` or a feature at the top of a `cli_commands` adapter or a `panel.py`.
- A worker thread that touches a Qt object, the service, or a SQLite connection; or a `TaskRunner` collected off the GUI thread.
- A new persisted field without a default, or a new kind added to `KINDS` by a feature branch.
- A fixture with CRLF endings on Windows, a YAML plain scalar containing `: `, a parametrize id that is a huge string.
- Treating a mocked tool test as live evidence, or a skipped live check as passed.
- Putting `[skip ci]` in a commit message you want to count for a release, or changing `.github/workflows/` in the commit you expect to publish.
