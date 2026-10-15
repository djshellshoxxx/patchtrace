# 23. The GUI framework

How the single main window hosts independent panels: the registry, the host and its lifecycle, background tasks, shared widgets, theming, and how the pieces are tested. Spec of record: `docs/specs/program-e/GUI-integration-plan.md` (sections 7 to 10); user view: [13](../guide/13-panels-and-layout.md). Built by slices F0 to F9 (ledger D, merged in PR #58 at `21a005e`). Previous: [22](22-engines-and-fusion.md). Next: [24](24-acquisition-and-enrichment.md).

## The shape

```
ui.py  MainWindow (one QMainWindow; legacy workspace; PanelHost seam: 1 constructor line + hooks)
  |
  +-- gui/qt/host.py  PanelHost  --- builds dock shells from panel_manifest.MANIFEST
  |       |  ports: ProjectPort, MutationPort, NavigationPort, ShellPort  (gui/ports.py)
  |       +-- docks.py (PanelDock, ControllerBase)   layout.py (save/restore)   commands.py (View menu, F6)
  |       +-- palette.py (Ctrl+Shift+P)   announce.py   tasks.py (TaskRunner)   settings.py   theme.py
  |
  +-- <package>/panel.py       PANEL = PanelSpec(...)         pure, no Qt
  +-- ui_<feature>.py          Controller(ControllerBase)     Qt, built by the spec's factory
gui/ (pure)  registry.py, anchors.py, capabilities.py, state.py, text.py, shortcuts.py, table_spec.py,
             projection.py, graph_view.py, pair_text.py, tips.py, theme_math.py, cli.py
```

`gui/` imports no Qt, no `ui*.py` and no feature package (`test_gui_core_isolation.py`). `ui.py` is a frozen shared file: it may only gain seam lines, and a test caps its length (`test_gui_host_seam.py`, `UI_LINES_BEFORE_F5 = 3142` plus a transitional ceiling that only goes down; the file is 3,077 lines at `21a005e`).

## PanelSpec and the manifest

A feature declares a `PanelSpec` (frozen dataclass, `gui/registry.py`):

| Field | Meaning |
|---|---|
| `id`, `title` | id matches `[a-z][a-z0-9_]{1,23}` and is append-only (a retired id stays reserved); title at most 32 characters |
| `factory(ctx) -> PanelController` | runs once on the GUI thread at first show; builds every widget; must start no thread and read no disk |
| `area`, `tabify_with` | `left`, `right`, `top`, `bottom` or `none` (no dock: cards, chips, banners); optional tab group |
| `shortcut` | must be `Ctrl+Shift+<letter>`; collisions with `RESERVED`/`FRAMEWORK` keys fail the lint |
| `requires` | capability ids (`project`, `tool:capa`, ...) the host checks; a missing one shows a reason, not an empty pane |
| `claims` | wording profile (`CLAIMS_NEUTRAL`, `CLAIMS_PAIRING`) that bans probability or vulnerability wording in panel text |
| `tips`, `tip_templates`, `extra_tip_prefixes` | tooltip entries; ids must start with `<panel id>.` |
| `commands`, `teach` | palette/menu commands; guide topics (E-5, deferred) |
| `anchors_in`, `anchors_out` | anchor kinds the panel can open and can emit |
| `default_visible`, `eager`, `minimum_em`, `contract` | first-run visibility; build at startup (the evidence panel is eager because it owns the engine probe); minimum size in em; spec contract version |

`panel_manifest.MANIFEST` reserves id, area, tab group and shortcut of **every** planned panel, built or not (14 entries). A loader imports its module inside its body: an absent module (or package above it) means *not built* and is hidden from menus; any other exception is a defect that `patchtrace panels check` reports. Feature builders never edit the manifest; they add `<package>/panel.py` and the integrator changes placement. Limits: at most 32 panels (`MAX_PANELS`).

`gui/registry.lint` (behind `panels check`) verifies ids, shortcut form and collisions, tab groups, tooltip prefixes, claims wording, forbidden imports (`PySide6`, `shiboken6`, `networkx`, `rapidfuzz`, `pygments`, `yara`, `yara_x` and the `ui*` modules) and that a built spec agrees with its slot. It runs without a display.

## Host lifecycle

1. `PanelHost(window)` at window construction loads the manifest and creates a hidden **dock shell** per built spec (a fraction of a millisecond each; nothing of the feature imported yet).
2. Menus are built after the shells: the View menu (toggles per spec group, Theme submenu, Reset layout, Command palette, Next/Previous panel, Navigate back/forward).
3. First show builds the panel through its factory. A factory exception becomes a visible state ("could not be created: PT-GUI-FACTORY ...") and never stops other panels. `eager` panels build at once.
4. Hooks the window calls: `project_changed`, `selection_changed` (debounced 120 ms), `update_controls`, `restore_layout`, `shutdown`. A hidden panel keeps its results and is told about a project change when next shown.
5. Anchors: `AnchorRef(kind, key, side, run_id, label)` is a value, never a callback. `AnchorRouter` checks currency, finds the one handler (code kinds `function`/`match` go to the main window's code panes via the `@code` pseudo panel) and returns a `NavResult` (`shown`, `not-found`, `stale`, `ambiguous`, `blocked`). History keeps 50 entries (Alt+Left/Right).
6. `shutdown` cancels and joins every worker (`JOIN_SECONDS = 5`) before Qt objects go away.
7. `PanelHost.self_check()` (used by `--self-test`) imports every manifest module and builds every panel once.

Layout persistence is `QSettings` only: `layout/schema` (bump only when a dock id is renamed or removed), `layout/state` (at most 64 KiB) and `layout/state_sha256`; a blob is trusted only when all three agree (`PT-GUI-LAYOUT`). Per-panel settings live under `<panel id>/` with validated getters (`PanelSettings`: type, range, enum membership, length).

## Tasks and threads (`gui/qt/tasks.py`)

`TaskRunner.submit(channel, fn)` runs `fn(token, report)` on a daemon thread. Rules:

- **Latest wins per channel**: submitting on a busy channel cancels and supersedes the earlier task; a superseded result is never delivered.
- The worker is pure with respect to Qt, the service and SQLite: it gets an immutable snapshot built on the GUI thread and returns a value. Results, errors (`TaskFailure`) and progress return on the GUI thread through one queued bridge slot, progress throttled to 10 Hz (latest wins).
- `CancelToken` is a `threading.Event` with `checkpoint()` (sleeps 1 ms after every 2 ms of CPU work so repaint stays smooth) and `raise_if_cancelled()`.
- `lane(name, init, close)` is a long-lived worker whose state (for example read-only SQLite connections) is opened, used and closed on that one thread.
- Ownership rule (to-do T15): every Qt object is created, used and freed on the GUI thread. A runner dropped or collected off the GUI thread can crash in Shiboken, so live runners sit in a module registry until `shutdown`. Legacy `QThread` registries (`_LIVE_THREADS` in `ui_series`, `ui_inspection`, `ui_engine_setup`, `ui_bundle_setup`) are adopted into the same shutdown until migrated.

## Shared widgets

| Widget | Module | Notes |
|---|---|---|
| `VirtualTable` | `table.py`, `table_spec.py` | cost depends on visible rows, not total (cap 100,000 rows); `prepare_table` runs in the worker and the model swaps a pointer; filters via a row predicate; TSV copy neutralises spreadsheet formula prefixes |
| `CodeDiffView` / `compose_selections` | `codediff.py`, `pair_text.py` | two panes from a `PairText` (both sides padded, hunks marked); `compose_selections` is the **one writer of extra selections** per `QPlainTextEdit`, with one list per layer |
| `GraphCanvas` | `canvas.py`, `graph_view.py` | `QGraphicsView` with stock items only (no Python `paint()`); up to 2,000 nodes and 8,000 edges; always secondary to a text table; no minimap |
| `StateView` / `NoticeStrip` | `state_view.py`, `state.py` | twelve states with words (`no-project`, `idle`, `loading`, `refreshing`, `ready`, `partial`, `stale`, `blocked`, `error`, `too-large`, `unsupported`, `cancelled`) and a fixed precedence; copy is ASCII |
| Chips | `chips.py` | text + ASCII glyph + shape, colour redundant; one drawing routine for widget and table delegate |
| `PlainLabel`, `plain_view` | `labels.py` | untrusted text never reaches rich-text guessing; every string passes `sanitize_text` |
| Command palette | `palette.py` | child popup of the main window, not a window; 50 results |
| `StatusAnnouncer` | `announce.py` | the only sender of accessibility announcements (a forbidden-API grep enforces it); polite coalesced, assertive for blocking errors |
| `Metrics` | `metrics.py` | em-based sizes from the font, never pixel constants |

## Theming (`theme.py`, `theme_stylesheet.py`, `gui/theme_math.py`)

`ThemeTokens` (surface, text, accent, focus ring, border, warning, hunk tints, chip colours) in two variants, `dark` and `system`; `build_stylesheet(DARK)` must equal `ui.DARK_STYLE` (golden test). `system` removes the stylesheet and reads the palette. High contrast is **automatic**: while the platform contrast preference is `HighContrast`, tokens come from the palette, fills and tints are dropped, `high_contrast=True`. `SystemPrefs` is the seam tests replace with a simulated provider; reduced motion is observed and emitted (`motion_changed`). `contrast_problems(tokens)` and tests guard 4.5:1 text and 3:1 non-text ratios.

## Tooltips and text safety

`tooltips.py` is the semantic registry (stable ids, never visible text; entries plus templates, 1,090 lines at `21a005e`). `gui/tips.py` adds idempotent registration for panel tips and `apply_tip`. `gui/text.sanitize_text` is the one gate: control, bidi, zero-width and surrogate code points go; length is bounded (`LABEL_LIMIT`, `VIEW_LIMIT`). Claims profiles are checked by tests over all registered text.

## Testing the GUI

- **Pure tests, no display**: `tests/test_gui_core_*.py` (registry, manifest, lint, shortcuts, state, text, anchors, ports, projection, capabilities, isolation, theme math, CLI) run anywhere; `patchtrace panels check` is the gate every feature PR runs.
- **Qt tests offscreen** with `QT_QPA_PLATFORM=offscreen`, `pytest-qt` (`qtbot`), and `tests/qt_support.py`: shared hostile-string params (`HOSTILE`: `<b>pwn</b>`, `<img src=x onerror=1>`, `\x1b[31m`, bidi overrides, null bytes, ...), settings fixtures, `join_gui_threads`, and legacy-thread detection. Test ids are short and explicit because Windows limits `PYTEST_CURRENT_TEST` to 32,767 characters.
- **`tools/qt_gate.py`** (the `qt_gate`): repeats the GUI test files (`test_gui_*.py`, `test_ui_*.py`, `test_evidence_ui.py`, `test_tooltips.py`) N times **in one pytest session** with `--keep-duplicates` and `PYTHONFAULTHANDLER=1`, so a teardown SIGABRT from a destroyed running `QThread` prints every thread's stack and a surviving thread is caught. Exit status is pytest's; signal deaths print `ABORT`. Typical use: `python tools/qt_gate.py --repeat 20 tests/test_gui_tasks.py` or `--repeat 5` over all GUI files. Results are recorded in `docs/qa.md` per slice (for example 5 repeats over all GUI files: 5,665 passed with F5; 6,465 with the GUI2 follow-through). **No workflow file invokes it today**; `docs/qa.md` carries the proposed CI step text for the integrator.
- **Not yet measured**: NVDA/Narrator behaviour, DPI scaling, and a real Windows run of the panel host are open (ledger D, M22).

## Known limits

Planned panels (Search, Graph, Strings, Capabilities, Build environment, Rules, KB, KEV, Guide) have manifest slots but no code; the Capabilities panel, KB wizard and KEV dock depend on unmerged branches (ledger D). Qt code colouring (`ui_codetext.py`) and the Build-facts tab (`ui_pemeta.py`) are built but not attached to the main window or the Files dock yet. `unified/enabled` has no Setup control. See [99](../guide/99-open-doc-questions.md).
