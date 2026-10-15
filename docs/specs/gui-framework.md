# GUI framework: panel registry, projection, anchors, theme, tooltips and CLI extensions (SPEC-54)

Status: partial, 2026-10-14. Owner: GUI core (`src/patchtrace/gui/`, `cli_commands/`, `panel_manifest.py`, `tooltips.py`). This file states the contract that the pure, Qt-free core already enforces, and marks the planned Qt host layer. It is derived from `docs/specs/program-e/GUI-integration-plan.md` (the plan, not the contract) and checked against the code on `work/a`. It changes no code. `[planned]` = not in `src/` today; `[proposal]` = recommended default where the code does not decide.

Built and tested: `gui/{registry,anchors,projection,capabilities,state,text,shortcuts,theme_math,ports,cli}.py`, `cli_commands/{__init__,panels}.py`, `panel_manifest.py`, `tooltips.py` (tests `tests/test_gui_core_*.py`, `tests/test_tooltips.py`). Not built: any `PanelSpec` (all 14 manifest slots resolve to "not built": no `panel.py` exists), the Qt layer `patchtrace/gui/qt/` (host, `ThemeTokens`, `StatusAnnouncer`, `a11y_audit`, task runner), the layout and theme settings. `ui.py` is not a panel host today.

## 0. Scope and non-goals

In scope: how a feature declares a dock panel, how the window reserves and loads panels, how panels point at each other, how text, state, theme colours and tooltips are made safe, and how a CLI verb is added. Non-goals: the content of any panel (each has its own spec), the Qt widgets of the host (`[planned]`), accessibility rules beyond what this core enforces (`docs/specs/accessibility-baseline.md`, SPEC-45), settings persistence (`docs/specs/app-settings.md`, SPEC-43), the umbrella CLI (`docs/specs/cli-umbrella.md`, SPEC-44).

Product invariants that bind this layer: one main window (a panel is a dock, never a window); pure models stay free of Qt; panels never import `MainWindow`, `ui.py` or another feature (`gui/ports.py:3`); text from tools, advisories and files is untrusted and always passes `sanitize_text`; no number is shown as vulnerability confidence.

## 1. Panel registry and manifest

1.1 A panel is a frozen `PanelSpec` (`gui/registry.py:133`) exported as `PANEL` from the feature's `panel.py`. Its `factory(PanelContext) -> PanelController` MUST run once on the GUI thread at first show, build all widgets, start no thread and read no disk. Specs compare by identity.

1.2 `PanelContext` carries the spec and exactly four ports: `ProjectPort` (read-only: `key`, `project`, `busy`, `artifact_paths`, `match_index`), `MutationPort` (`annotate`, `review_match`; the only way a panel changes the project), `NavigationPort` (`select_match`, `reveal_lines`, `show_raw_offset`, `show_pair`, `navigate`, `focus_panel`, `back`, `forward`) and `ShellPort` (`tasks`, `settings`, `theme`, `status`, `announce`, `notice`, `copy_text`, `choose_file`, `spotlight`). `WindowPort` is their union for legacy code. All run on the GUI thread (`gui/ports.py`).

1.3 `PanelController` hooks: `widget`, `focus_target`, `project_changed`, `selection_changed`, `busy_changed`, `capabilities_changed`, `theme_changed`, `show_anchor`, `shutdown`. The Qt base class is to supply no-ops `[planned]`.

1.4 The manifest (`panel_manifest.py`) reserves one `ManifestEntry(id, module, load, area, tabify_with, shortcut)` per planned panel, built or not. Today 14 slots: evidence, unified, search, graph, strings, capabilities, build_env, rules, kb, kev, leads, guide, series, files. Builders never edit the manifest; a placement change is a one-line integrator edit. A built spec MUST agree with its slot on area, tab group and normalized shortcut (rule `placement`).

1.5 Ids: `^[a-z][a-z0-9_]{1,23}$`, append-only (a retired id stays reserved). Areas: `left right top bottom none` (`none` = no dock; no shortcut, no tab group). Limits (`gui/registry.py:32-53`): 32 panels, title 32, accessible name 80, description 160, 100,000 table rows, clipboard 16 KiB, graph 500/2,000 nodes/edges default and 2,000/8,000 maximum, 200,000 code characters, `focus_order >= 100` (built-in regions use 10/20/30/90), `contract == 1`.

1.6 Derived names: dock objectName and tip id `<id>.dock`; View-menu action `<id>.action`; accessible name `"<title> panel"`; settings prefix `<id>/`; tip prefix `<id>.`.

1.7 Loading (`load_manifest`): each loader runs in isolation. A `ModuleNotFoundError` for the expected module or a package above it means `not_built`; any other exception is recorded by class name only (never a message) and does not stop the others; a non-`PanelSpec` result is `NotAPanelSpec`. The loader polls a `cancelled` callable before each entry. Loading a spec module MUST NOT newly import Qt, PySide6, PyQt, networkx, rapidfuzz, pygments, yara, yara_x, `patchtrace.ui`, `patchtrace.ui_*` or `patchtrace.gui.qt.*` (`FORBIDDEN_ROOTS`; reported per panel).

1.8 Lint rules (`lint`, codes `PT-GUI-MANIFEST`, `PT-GUI-TIPS`, `PT-GUI-CAP`; message text is sanitized to 200 characters):

| Rule | Checks |
|---|---|
| count, id, duplicate-id, area, module | at most 32; id grammar; unique; known area; module inside `patchtrace` with identifier parts |
| none-dock, shortcut, reserved-shortcut, duplicate-shortcut | `none` has no dock options; panel shortcut is `Ctrl+Shift+<letter>`; not in `RESERVED` or `FRAMEWORK`; unique |
| tabify | target exists, is not itself, is not itself tabbed, shares the area |
| spec-id, contract, title, placement, focus-order, requires, anchors | per built spec: id equals slot; contract 1; title 1-32 plain characters; placement equals slot; focus order; capability ids valid; anchor kinds known |
| tip-required, tip-prefix, tip-extra-prefix, tip-entry, tip-conflict, tip-duplicate | docked panels declare `<id>.dock` and `<id>.action`; tip ids start with the panel prefix or a declared extra prefix that ends in a dot and belongs to no other panel; What/Why/Effect non-empty and without `<` or `>`; no id is both tip and template or re-registered with different text; no What line repeats another's |
| command-id, command-duplicate, command-title, command-shortcut, command-reserved, command-taken | command ids start with the panel prefix and are unique; title 1-80; shortcuts are single chords not reserved or taken |
| teach-id, teach-duplicate, teach-empty, teach-meaning, teach-steps, teach-step | teach topics: prefixed unique ids, meaning 1-300 characters, at most 4 steps of 1-200 |
| claims | every title, tip, command and teach text is swept through the panel's `ClaimsProfile` |
| imports | forbidden modules newly imported while loading |

A built panel that emits an anchor kind no built panel handles is a warning, not a finding (`CODE_KINDS` are handled by the main window).

## 2. Capabilities and states

2.1 A panel names what it needs in `requires`. Valid ids: `project`, `run`, `idle`, `tool:<capa|floss|diec|yara-x>`, `engine:<bindiff|rzdiff>`, `feature:<flag>`, `os:windows`. The tool and engine lists are closed on purpose (`gui/capabilities.py`). The host answers each with a `CapabilityState(kind, reason, remedy_command)`, `kind` in `available missing unsupported unchecked policy`. `check` returns the first blocker in `requires` order, with code `PT-GUI-CAP`; an unknown id blocks. A `remedy_command` is displayed, never run; probing that runs a program is an explicit user action and never happens in this core.

2.2 Panel states (`gui/state.py`): `no-project idle loading refreshing ready partial stale blocked error too-large unsupported cancelled`, with fixed ASCII copy. Precedence when several apply: no-project, unsupported, blocked, error, too-large, cancelled, stale, partial, loading, refreshing, ready, idle. A blank panel is never the way to say "nothing found". `partial` copy states that missing evidence is unknown, not disagreement. `loading` applies only to a first load. Interpolated values are sanitized; a worker failure crosses threads as the exception class only (`TaskFailure`, code `PT-GUI-TASK`), and a failed factory shows `PT-GUI-FACTORY` without touching other panels.

2.3 Notices (`NoticeModel`): key `^[a-z][a-z0-9_.-]{0,63}$`, level `caution|notice`, scope `project|session`, text 1-400 characters, never modal. Chips (`ChipSpec`): text plus a 1-2 character ASCII glyph plus a shape (`round square diamond dashed`); the colour token is redundant. `chip_collisions` reports chips sharing (glyph, shape) in one table.

## 3. Projection and navigation

3.1 `ProjectKey(root, project_id, revision, run_id, older_sha256, newer_sha256)` identifies everything that makes an on-screen result current; `identity()` is `(root, project_id)`. It is a `NamedTuple` because consumers index it.

3.2 `MatchIndex` maps a function id to the `(match_id, side)` hits of the key's run; matches of other runs are ignored and no run id gives an empty index. More than one hit is ambiguous: callers offer candidates, never the first. `MatchIndexCache` keeps one index and rebuilds when the key changes.

3.3 `AnchorRef(kind, key, side, run_id, label, origin, revision)` is a value, never a callback. Kinds (closed): `function match string import address capability rule build_fact advisory_phrase cve kb cwe`. `key` is 1-256 opaque characters; `side` is `older|newer|both|None` and always explicit; equality is on kind, key, side and run; `label`, `origin` and `revision` are not compared. `pinned(key)` fills run and revision.

3.4 `NavResult.status` is one of `shown not-found stale ambiguous blocked`, with codes `PT-GUI-NAV-NOTFOUND`, `-STALE`, `-AMBIGUOUS` (at most 20 candidates), `-BLOCKED`. There is no fallback target: a stale, missing, ambiguous or unhandled anchor says so and navigates nowhere.

3.5 `is_stale`: true when the project is gone, the anchor's run differs, or its revision differs from the current one (a manual correction and an orientation swap both bump the revision). `locate_match` resolves `function` and `match` anchors against the index; an explicit side that does not hold the function is a miss, not a guess.

3.6 `AnchorRouter.navigate`: stale check, then the one handler declared for the anchor's kind (built from the specs' `anchors_in`), then the host's `show`. Only a `shown` result enters history. `NavHistory` keeps the newest 50; a new destination drops the forward trail; Alt+Left and Alt+Right move through it.

3.7 Shortcuts (`gui/shortcuts.py`): sequences compare in one canonical spelling (`Ctrl+Alt+Shift+Meta+<key>`), so `ctrl+shift+e` and `Shift+Ctrl+E` collide. `RESERVED` holds the main window's keys and `FRAMEWORK` holds Ctrl+Shift+P (palette), F6/Shift+F6 and Alt+Left/Right. `ShortcutTable.claim` reports the current owner and changes nothing on a collision.

## 4. Text safety and claims

4.1 `sanitize_text(value, limit=200, multiline=False)` is the one gate for every label, status line, announcement and tooltip value: bounded (ellipsis when cut), idempotent, encodable. It removes C0 controls except kept breaks, DEL, C1 controls, lone surrogates, bidi controls and Unicode line and paragraph separators; single-line mode turns a run of breaks and tabs into one space so a newline cannot forge a second line; multiline mode keeps tabs and `\n`. It never HTML-escapes: Qt plain-text sinks do not interpret markup and rich-text sinks escape separately.

4.2 `ClaimsProfile(banned_stems, banned_words, allowed_phrases)`: stems match word starts, words match whole words, case-insensitive, after sanctioned negations are removed. Presets: `CLAIMS_PAIRING` (bans probab-, likelihood, vulnerab-, exploit and the words "confidence %", safe, secure, fixed, verified, proven, certain; allows "not a vulnerability assessment", "not vulnerabilities", "not a probability") for function-pairing panels, and `CLAIMS_NEUTRAL` (the default). Panels with advisory vocabulary (KB, KEV) define their own profile.

## 5. Theme and contrast

5.1 Colours are `#rrggbb` strings; `contrast_ratio` is the WCAG relative-luminance ratio (1.0 to 21.0, symmetric). Thresholds: `TEXT_CONTRAST = 4.5` (text) and `NON_TEXT_CONTRAST = 3.0` (borders, focus ring, chip outlines). `ensure_contrast(color, background, fallback)` is the runtime guard: it returns the colour only when it reaches the minimum, else the fallback.

5.2 `[planned]` `ThemeTokens` with variants `dark` (default, stylesheet byte-identical to `ui.DARK_STYLE`) and `system`; high contrast follows the OS preference automatically (stylesheet removed, state carried by text, glyph and border); metrics recomputed on font, DPI, style and palette change. Contrast tests run on every token pair and variant. Redundant encoding (text, glyph, shape, position) is mandatory; no red/green-only pairs.

## 6. Tooltips and accessible names

6.1 `tooltips.py` is a pure registry (no Qt import). `TooltipEntry(what, why, effect, source, availability)`; `REGISTRY` holds static ids, `TEMPLATES` dynamic ones. `tooltip(id)` and `template(id, **values)` return escaped rich text; `plain_description` and `template_description` return plain text. Unknown ids raise `KeyError`. `EXEMPT_IDS` is `action.new` and `action.open`.

6.2 Dynamic values pass `clean_value`: control characters removed, capped at 200 characters plus an ellipsis, and the final text HTML-escaped once.

6.3 `apply_tooltip(target, id, name=None, **values)` sets tooltip and what's-this; on actions also the status tip; on widgets also the accessible description (the plain text on one line); and sets the objectName to `name` or the id only when it is still empty.

6.4 Every control of a panel is keyed by a stable tip id under the panel's prefix. Docks and View-menu actions are required to have tips (rule `tip-required`).

6.5 `[planned]` Accessible description = the What line (at most 160 characters) with the full text in what's-this; `StatusAnnouncer` is the only sender of screen-reader announcements (polite; assertive only for blocking errors); `a11y_audit(root)` enforces names of at most 80 characters, roles and Tab order. Specified in SPEC-45; not built.

## 7. CLI-extension registry

7.1 A verb is one file `cli_commands/<verb>.py` exporting `COMMAND = CliCommand(name, summary, build, run)`. The file name is the verb with `_` as `-`; `name` MUST equal it and match `^[a-z][a-z0-9-]{1,23}$`; `summary` is 1-80 printable ASCII characters; `run(args, cancel) -> int`. The package is stdlib only, with no Qt.

7.2 Discovery lists module names without importing them (`pkgutil`), then imports each to read its `COMMAND`. A module whose verb is built in (`cli.COMMANDS`), duplicated, malformed or that raises is recorded by exception class and listed as `unavailable (could not be loaded)`; it never hides other verbs. `register_all` builds the full parser only for the invoked verb and bare listings for the rest, so `--help` loads no feature. Invoking a broken verb raises `CliError(RUNTIME, "PT-CLI-COMMAND: ...")` (exit 3).

7.3 Adapters import only the package and stdlib at module level and load their feature inside `build` and `run` (`cli_commands/panels.py` is the model, 17 lines). Output uses the `enrichment-cli/1` envelope via `emit`; exit codes 0 ok, 2 invalid argument, 3 runtime or load failure, 4 no results, 5 cancelled.

7.4 `patchtrace panels list|check [--json]` (`gui/cli.py`) is the display-free gate every feature PR runs. `list` prints one row per slot (state `built|not-built|error`); `check` adds the lint findings as `conflicts`. Exit 3 if any spec failed to load (wins over 2), 2 on findings, 4 when no panel is built, 5 cancelled, else 0. Today `panels check` returns 4 because no panel exists.

## 8. Error codes

`PT-GUI-MANIFEST`, `PT-GUI-TIPS`, `PT-GUI-CAP`, `PT-GUI-TASK`, `PT-GUI-FACTORY`, `PT-GUI-NAV-NOTFOUND|STALE|AMBIGUOUS|BLOCKED`, `PT-CLI-COMMAND`. `PT-GUI-LAYOUT` (invalid saved layout falls back to defaults plus a status line) is `[planned]` with the layout settings.

## 9. Test and acceptance plan

| Rule | Covered by | Gap |
|---|---|---|
| 1.1-1.8 registry, manifest, lint | `tests/test_gui_core_registry.py`, `test_gui_core_manifest.py`, `test_gui_core_isolation.py`, `test_gui_core_lint.py` | no real `PanelSpec` has been linted end to end |
| 2 capabilities and states | `test_gui_core_capabilities.py`, `test_gui_core_state.py` | host-side capability answers |
| 3 projection, anchors, shortcuts | `test_gui_core_projection.py`, `test_gui_core_anchors.py`, `test_gui_core_shortcuts.py`, `test_gui_core_ports.py`; per-feature `test_intel_anchors.py`, `test_unified_anchors.py` | router wired into a real window |
| 4 text and claims | `test_gui_core_text.py` | none known |
| 5.1 contrast | `test_gui_core_theme_math.py` | 5.2 token tests need `ThemeTokens` |
| 6 tooltips | `test_tooltips.py` (needs the Qt window fixture) | 6.5 `StatusAnnouncer`, `a11y_audit` |
| 7 CLI registry | `test_gui_core_cli.py` | verb discovery under PyInstaller (hook `[planned]`) |

Windows-only and owner-only gates (screen-reader pass with NVDA and Narrator, high-contrast and DPI checks, clean-machine launch) are listed in `docs/specs/accessibility-baseline.md` and never count as done here.

## 10. Open questions (recommended defaults)

1. Should `ui.py` host panels through a thin `gui/qt/` layer or stay as is while panels land one by one? Default `[proposal]`: add `gui/qt/` as the plan says; `ui.py` gains only a host call, never panel code.
2. Should the closed capability tool and engine lists be derived from the engine registry? Default `[proposal]`: keep closed until a second source of truth exists; a typo must fail lint.
3. Where do the PyInstaller hidden-import hooks for `cli_commands` live? Default `[proposal]`: `tools/pyinstaller_hooks/`, owned by the packaging slice.
