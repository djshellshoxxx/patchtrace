# GUI integration plan: panel registry, shared widgets and threading for the single main window (Program E, track GUI)

Status: research plan, 2026-10-14, base `d972125` (`prep/program-e`); slice F1 (pure core) built 2026-10-14, see `docs/modules.md` [GUI-F1:core]; slice F4 (VirtualTable) built 2026-10-14, see [F4:virtual-table]. Author: E-1 GUI-architecture researcher (documents only). Labels: [S] read from source at the cited tag and lines, [D] documentation text, [M] measured here (PySide6 6.12.0, CPython 3.13.16 although the project targets 3.12, Linux x86-64, offscreen, one machine; scripts were scratch and are not committed; every number is a budget to re-measure on Windows CI), [U] unverified. Inputs read: AGENTS.md, CLAUDE.md, program-e-roadmap.md, modules.md, todo.md, `ui.py`, `ui_evidence.py`, `ui_engine_setup.py`, `ui_series.py`, `ui_inspection.py`, `tooltips.py`, the UI tests, specs `ui.md`, `multi-engine-evidence-panel.md`, `unified-engine/07-ui-and-cli.md`, `workbench/*`, `kb-patch-search-ui-cli-contract.md`, the C6 research and troubleshooting notes, and, read-only and for alignment only, the sibling plans present on 2026-10-14 (CAP, DIE, KB, KEV, LBL, PIL, WB1-WB3, YRX in the integration checkout, WBQ in its worker's tree); their drafts may have changed since. Slice F1b (section 8.12, the CLI-extension registry) is built (2026-10-14, Linux evidence only; Windows frozen build pending CI): see `docs/modules.md` `[F1b:cli-registry]`; the hook guard is generalised so an empty registry builds.

## 1. Verdict and scope

- Build `patchtrace.gui`: a Qt-free core (registry, ports, anchors, state model, capability gating, text safety, shortcut table, manifest-lint CLI) plus a Qt layer (`PanelHost`, `TaskRunner`, `StatusAnnouncer`, theme tokens, six shared widgets, command palette) and one explicit manifest `panel_manifest.py` that reserves a slot for every planned panel. Next to it, a directory-based CLI-extension registry (`cli_commands/<verb>.py` plus one PyInstaller collect hook, 8.12) so that no track edits `cli.py` either.
- After ONE `ui.py` seam (12 call sites, expected net +9 lines, budget +15; slice F5) no later track edits `ui.py`, `tooltips.py`, `tests/test_tooltips.py` or the manifest: a feature adds a pure `<package>/panel.py` (`PANEL`) and a Qt `ui_<feature>.py`. Today six feature plans carry fallback `ui.py` seams of about 100 lines in total (WB2 25, PIL 20 + 15, DIE 12, CAP 12, WBQ 10, YRX 8) on top of SPEC-31 S4's 25, all aimed at the same call sites.
- Decisions: dock shells eager, content lazy; Python-thread `TaskRunner` (not QThread subclasses, not QThreadPool); announcements through `QAccessibleAnnouncementEvent` because Qt's name-change path does not reach unfocused labels on Windows; short accessible descriptions; system colours under Windows high contrast; layout through `saveState` with an integrity envelope and a reset command.
- Not building: plugin discovery or dynamic imports (frozen build), a second window system, QML or WebEngine, a docking library, new dependencies or Qt modules, a theme editor, graph layout algorithms (feature tracks own them), any combined score.

## 2. Sources and facts

Prefixes (all retrieved 2026-10-14; the canonical doc.qt.io and learn.microsoft.com pages are blocked from this sandbox, the same text lives in these repositories): `Q`=https://raw.githubusercontent.com/qt/qtbase/v6.12.0/ ; `MS`=https://raw.githubusercontent.com/MicrosoftDocs/win32/docs/desktop-src/ ; `MD`=https://raw.githubusercontent.com/MicrosoftDocs/windows-dev-docs/docs/hub/apps/design/accessibility/ ; `SD`=https://raw.githubusercontent.com/MicrosoftDocs/sdk-api/docs/sdk-api-src/content/ ; `NV`=https://raw.githubusercontent.com/nvaccess/nvda/master/ (no tag resolvable: github.com pages return 403) ; `WG`=https://raw.githubusercontent.com/w3c/wcag/main/understanding/ ; `WI`=https://raw.githubusercontent.com/w3c/wcag2ict/main/.

| # | Claim | Source | Retrieved | Conf. |
|---|---|---|---|---|
| F1 | `saveState(version)` stores toolbar and dock layout keyed by unique `objectName`; `restoreState` returns False and changes nothing on a version mismatch | Q src/widgets/widgets/qmainwindow.cpp L1150-1225 | 2026-10-14 | high |
| F2 | Qt's own security note: pass `restoreState` only blobs produced by this or a compatible app version, never downloaded, synced or foreign data (the nested layout tree is not bounds-checked) | same file L231-249 | 2026-10-14 | high |
| F3 | `restoreDockWidget` restores a dock created after `restoreState`. [M]: it works only when the dock was NOT first passed to `addDockWidget` (then area, tab group, floating and hidden state come back; False = no saved placement); if `addDockWidget` came first it returns True but leaves the default placement. Docks missing from the blob keep their defaults, docks missing now do not disturb the rest, empty/truncated/mismatched blobs return False; an unnamed `QToolBar` makes `saveState` warn and store less | same file L1012-1023; scratch exp_dock_state, exp_dock_lazy, exp_unnamed_toolbar | 2026-10-14 | high |
| F4 | The Windows plugin instantiates only the UI Automation backend; default DPI awareness is PerMonitorV2; widget accessibility is compiled into QtWidgets (no `plugins/accessible` in the 6.12 wheel [M]) | Q src/plugins/platforms/windows/qwindowsintegration.cpp L105,L199; src/widgets/accessible/qaccessiblewidgetfactory.cpp | 2026-10-14 | high |
| F5 | UIA patterns Qt serves: Window, Text(+2), Value, RangeValue, Toggle, Selection(+2), SelectionItem, Table, TableItem, Grid, GridItem, Invoke, ExpandCollapse. NOT served: Scroll/ScrollItem, VirtualizedItem/ItemContainer (Microsoft's virtualization patterns), Transform, Dock, MultipleView, Annotation, LegacyIAccessible, Drag/Drop | Q src/plugins/platforms/windows/uiautomation/qwindowsuiamainprovider.cpp L296-395; MS WinAuto/uiauto-implementingvirtualizeditem.md, uiauto-implementingitemcontainer.md | 2026-10-14 | high |
| F6 | Name-change events reach UIA only for combo boxes and the focused element, so C6's "empty accessible name, `setText` announces" is silent for an unfocused status label | same provider L176-190 | 2026-10-14 | high |
| F7 | `QAccessibleAnnouncementEvent` (since 6.8; Polite/Assertive) maps to `UiaRaiseNotificationEvent` (Polite = ProcessingAll, Assertive = ImportantAll); needs Windows 10 1709+; ignored until a UIA client has queried and while nobody listens. `QAccessible::Alert` only plays a Windows system sound in this backend (L110-112), so it is not a speech path. PySide6 6.12 exposes the announcement event and `QAccessible.setActive` but NOT `installUpdateHandler` [M] | Q .../qwindowsuiaaccessibility.cpp L72-165, qwindowsuiamainprovider.cpp L233-262, src/gui/accessible/qaccessible.cpp L470-492; SD uiautomationcoreapi/nf-uiautomationcoreapi-uiaraisenotificationevent.md | 2026-10-14 | high |
| F8 | NVDA subscribes to notification events when IUIAutomation5 exists and speaks `displayString` for the foreground app; it uses UIA for any window with a server-side provider (Qt classes are not in its bad list); its object description is FullDescription else HelpText, with a setting to switch descriptions off (default [U]). Narrator's handling of notification events is [U] (manual row M20) | NV source/UIAHandler/__init__.py L625-632,L1203-1290; source/NVDAObjects/UIA/__init__.py L1931-1933,L2528-2551; user_docs/en/userGuide.md L3380 | 2026-10-14 | high (master) |
| F9 | Qt text mapping: UIA Name = `accessibleName`, else same-parent buddy QLabel, else group title; FullDescription = `accessibleDescription` falling back to `toolTip`; HelpText = `whatsThis`. [M] registry: the whole flat tooltip sits in `accessibleDescription` today (206 entries: median 234 chars/36 words, p90 416, max 765); the "What" line alone has median 60, max 149. UIA AutomationId = `accessibleIdentifier` when set (QWidget property since 6.9; the PySide6 6.12.0 setter works [M]), else a dotted chain of objectNames and class names that is unstable for unnamed widgets | Q src/widgets/accessible/qaccessiblewidget.cpp L322-356; provider L593-676, L559-562; src/widgets/kernel/qwidget.cpp L11889-11908; src/gui/accessible/qaccessiblebridgeutils.cpp L75-95; scratch tip_lengths | 2026-10-14 | high |
| F10 | [M] accessible tree: dock = Pane named by its title with Close/Float buttons (Press action, not focusable); QGraphicsView = Client with 1 child; QTableView = Table + Column/RowHeader + Cell named by `AccessibleTextRole`; the Qt-created dock tab bar has empty objectName, TabFocus, PageTabList; table cells are created lazily and cached per visited cell | scratch exp_a11y_tree, exp_dock_children, exp_dock_tabbar; Q src/widgets/accessible/itemviews.cpp L518-640 | 2026-10-14 | high |
| F11 | `QStyleHints.accessibility()` (6.10) exposes `contrastPreference` and `motionPreference` (6.12) with change signals [M PySide6]; Windows high contrast uses `SPI_GETHIGHCONTRAST`, forces `colorScheme()` to Unknown and fills the palette from `GetSysColor`. Microsoft: map all colours to one foreground/background pair, drop background images | Q src/gui/kernel/qaccessibilityhints.cpp L40-90, src/plugins/platforms/windows/qwindowstheme.cpp L311-360,L652-683,L1281-1287, src/corelib/global/qnamespace.qdoc L834-856; MS WinAuto/high-contrast-parameter.md | 2026-10-14 | high |
| F12 | PerMonitorV2 apps are told of DPI changes and must re-evaluate cached DPI data; Qt re-fonts on `DevicePixelRatioChange`; rounding policy PassThrough [M] | MS hidpi/high-dpi-desktop-application-development-on-windows.md L49-63,L195; Q src/widgets/kernel/qwidget.cpp L9381-9384 | 2026-10-14 | high |
| F13 | WCAG2ICT: 4.1.3 Status Messages applies to software through platform accessibility services; 1.4.11 applies as written to author-drawn components; 1.4.4 resizing follows platform capability | WI comments-by-guideline-and-success-criterion.md L253,L334,L1257; WG 21/status-messages.html | 2026-10-14 | med-high |
| F14 | Microsoft keyboard guide (Windows 7 era, not updated): Tab order rules, arrows move inside a group only, all interactive UI must be keyboard accessible, Ctrl+Shift+letter is the "less frequent command" tier, Ctrl+Tab cycles tabs; F6 pane cycling is not stated there [U]. Microsoft test recipe: Tab sequence, arrows in composites, contrast, high-contrast theme, Narrator (Caps Lock+arrows; developer mode Ctrl+Caps Lock+F12), table headers; tools Accessibility Insights for Windows, Inspect, AccScope | MS uxguide/inter-keyboard.md; MS WinAuto/accessibility-testingtools.md; MD accessibility-testing.md L90-124 | 2026-10-14 | medium |
| F15 | `~QThread` aborts while the thread runs; `QThreadPool::tryTake` has an ABA caveat with auto-delete | Q src/corelib/thread/qthread.cpp L446-474, qthreadpool.cpp L326-343 | 2026-10-14 | high |
| F16 | Qt 6.12 builds the Windows Vista/11 styles as plugin `qmodernwindowsstyle`; the repo's QtGui hook keeps only listed plugins, so which widget style the frozen build renders (and whether OS dark mode can apply) is [U] | Q src/plugins/styles/modernwindows/CMakeLists.txt; tools/pyinstaller_hooks/hook-PySide6.QtGui.py | 2026-10-14 | medium |
| F17 | Pins and licences: PySide6 and shiboken6 6.12.0 `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`; pytest-qt 4.5.0 MIT; Qt sources `LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`; NVDA GPL-2.0-or-later with exceptions (read for behaviour, nothing copied); PyInstaller 6.22.3 (already pinned) `GPL-2.0-or-later WITH Bootloader-exception`, its pkgutil runtime hook Apache-2.0 (read from the installed wheel, nothing copied); MicrosoftDocs content CC-BY-4.0, samples MIT; W3C repos W3C Document License. No new dependency and no new Qt module (QtCore, QtGui, QtWidgets only); `pip --only-binary=:all:` unaffected. Provisioning: none for the framework; optional tools (capa, FLOSS, diec, YARA-X) are provisioned by their own tracks | package metadata, `copying.txt`, repo LICENSE files | 2026-10-14 | high |
| F18 | Blocked here (403 or ENOTFOUND, not retried): doc.qt.io, code.qt.io, learn.microsoft.com, www.w3.org, github.com pages, api.github.com, nature.com, www.inf.ufrgs.br, jfly.uni-koeln.de. Okabe-Ito/Wong palette values and Machado CVD matrices are therefore [U]. In-repo precedent: `docs/research/phase-c/multi-engine-evidence-ui.md` (proxy-sort and thread findings, re-confirmed in 8.4 and 8.5) | proxy status | 2026-10-14 | - |
| F19 | PyInstaller 6.22.3 (the repo pin): `collect_submodules(pkg, on_error=...)` imports the named package in an isolated subprocess and lists its modules with `pkgutil.iter_modules` without importing non-package modules; the default `on_error="warn once"` only warns when that import fails; the pkgutil runtime hook makes `iter_modules` list modules embedded in the PYZ. [M] toy freeze (Linux, about 7 s per build, `--paths` plus `--additional-hooks-dir` as in both build scripts): without a hook, verbs found by `pkgutil` at run time are silently absent (exit 2, `invalid choice`); with a 3-line hook the frozen output equals the source output and a verb module with a bad import fails at run time with exit 3; a registry package that fails to import fails the build with `on_error='raise'` but only warns, and ships a crashing exe, with the default; `collect_submodules` returns `[]` with no error at all when it cannot resolve the package (here an editable install of another tree shadowed `--paths`), even with `on_error='raise'`, hence the non-empty guard in the hook (8.12); the real `patchtrace.cli` frozen without Qt (about 17 s) with the final hook lists, runs and answers `--help` for the prototype verbs like the source; cold start 78-83 ms in every toy variant | PyInstaller 6.22.3 wheel `PyInstaller/utils/hooks/__init__.py` L567-690 and `PyInstaller/hooks/rthooks/pyi_rth_pkgutil.py`; `tools/build_windows.py` L31-43, `tools/build_linux.py` L55-56; scratch toyfreeze | 2026-10-14 | high on Linux, Windows [U] |

## 3. Standalone baseline versus PatchTrace value

- Qt alone gives `QDockWidget`, `saveState` and per-feature plumbing. Today that means five `QThread` base classes (`Worker`, `InspectionThread`, `SeriesLoadThread`, `_WorkerThread`, `TaskThread`) with four module-level live-thread sets (`ui._DISCOVERY_THREADS` and a `_LIVE_THREADS` in each of `ui_evidence`, `ui_series`, `ui_engine_setup`), three `PlainLabel` copies, three sets of settings helpers, one global tooltip dict, a test that lists every UI root by hand, and competing planned `ui.py` seams (SPEC-31 S4 <= 25 lines, the KB wizard and the intelligence pane <= 12 each, queued behind S4). Each feature alone ships a panel that cannot open another's finding, announce, or share the pair, orientation and staleness rules. The CLI has the same shape: 13 planned verbs would each edit the same four places in `cli.py`, the `COMMANDS` list of `tools/frozen_smoke.py` and two lists in `tests/test_acceptance_smoke.py` (8.12).
- PatchTrace adds one context (older/newer pair, run, revision, staleness), one navigation fabric (anchors), central enforcement of the evidence rules (no averaged numbers, unknown is not negative, plain text, banned claim wording), accessibility and performance gates inherited by every panel, and zero `ui.py` conflicts.
- Workflows (each is a test in section 5): (1) leads row -> string -> function -> exact lines in the NEWER pane -> Alt+Left returns; (2) advisory phrase -> search hit -> call-graph neighbourhood -> code; (3) capability delta -> unified change fact -> evidence dock; (4) teacher step "open Strings and select the new string" runs the same commands the analyst finds in the palette.

## 4. Cross-feature links

The framework neither produces nor interprets findings; it routes `AnchorRef` values (a GUI projection of the FAB anchor fabric) and publishes `project_changed`, `selection_changed`, visibility and announcements.

| Anchor kind | Produced by | Opened by (handler) | Absent or stale behaviour |
|---|---|---|---|
| function, match | search, graph, strings and capabilities attribution, leads, unified, evidence, series | main window: `select_match` + `reveal_lines` (code panes) | not in this run -> "Not found in run {id}"; split/merged -> candidate list, never the first |
| string | strings, search, KB (quoted advisory text) | strings panel (select), search (query) | present on one side only -> shown labelled "absent in older/newer" (absent is unknown, not a negative vote) |
| import/API, address | files (PE), raw view, strings, capa | files panel, raw view go-to | unreadable artifact -> blocked state with the error code |
| capability | capabilities (capa), unified change facts | capabilities panel | tool missing -> BlockedState with remedy |
| rule | rules (YARA-X) | rules panel, search | rule pack stale -> stale banner |
| build_fact | build_env (DIE) | build_env panel, evidence noise note | unknown packer or compiler stays "unknown" |
| advisory_phrase, cve, kb, cwe | KB workflow, KEV, CSAF | kb panel, kev panel (`cve`), search (pre-filled query), leads | offline cache only; fetch needs explicit consent; stale snapshot labelled |

## 5. Synergy test

`tests/test_gui_synergy.py::test_anchor_chain_leads_to_code_and_back`, synthetic: `ProjectService.sample` plus three fake registered panels (`leads`, `strings`, `search`: real `PanelSpec`s with fake factories), no feature code needed. Expected outputs:

1. The leads row carries `AnchorRef('string', 's:7f3a', side='newer', run_id=R)`; Enter -> the router builds `strings` lazily (factory called once), shows its dock, focuses its table and selects `s:7f3a`; `NavResult.status == 'shown'`.
2. The strings action "Show containing function" emits `AnchorRef('function', fid, 'newer')`; the navigator selects match M (filters cleared with the visible message "Navigator filters were cleared to show this function."), `reveal_lines` selects original lines 12-14 in the NEWER pane only, and exactly one polite announcement is sent: "Showing newer function sub_1000, lines 12 to 14".
3. Alt+Left returns to strings, Alt+Right to the code; history length 3.
4. A manual match correction bumps the revision; the same anchor now returns `stale` with "The project changed after this link was created. Open it again from the source panel." and navigates nowhere. Swapping orientation also yields `stale`.
5. A hostile label made of `<img src=x onerror=1>{0}` followed by the bidi override U+202E passes leads -> palette -> status bar -> announcement; every sink shows literal sanitized text (the override is stripped; labels are `PlainText`; tooltip and rich-capable sinks receive escaped text, so `Qt.mightBeRichText` is false for them).
6. After a restart the layout is restored with strings visible and leads hidden.

Alone, leads cannot show code, strings cannot show lines and search cannot choose an orientation; together the chain reaches the exact old/new lines with provenance and a way back.

## 6. Traps and guards

| Trap | Guard |
|---|---|
| A blank panel when a tool or run is missing reads as "no findings" | `StateView` blocked, unsupported and idle states are mandatory; `test_panel_never_blank` per state; copy says unknown versus none |
| Stale data looks live | `ProjectKey` (root, id, revision, run, SHA pair) plus generation; stale banner, navigation disabled, "Copy provenance" carries STALE |
| Colour-only status; high contrast ignored by a hard-coded stylesheet | chips = text + ASCII glyph + shape; HC removes the stylesheet and fills; contrast tests per variant; unique (glyph, shape) per table |
| Status never spoken (F6) or announcement spam | `StatusAnnouncer` is the only sender (grep test), coalesced >= 1.5 s, progress never announced, sender injected in tests, manual NVDA and Narrator rows |
| Long descriptions spoken on every focus (F9) | `apply_tooltip` sets `accessibleDescription` to the What line (<= 160); the full text stays in toolTip and whatsThis |
| Proxy sort, `ResizeToContents`, rich text, `terminate`, parented QThread | forbidden-API grep over `ui*.py` and `gui/**` (list in 8.9) |
| CPU-bound Python in a worker freezes repaint (up to x40 [M]) | subprocess or `token.checkpoint()`; switch interval 1 ms; repaint-under-load test |
| Late result applied to the wrong project; abort on close | per-channel generation, Python threads (no QThread to destroy), `shutdown()` joins, teardown matrix x20 |
| Workers touching widgets or SQLite | immutable request built on the GUI thread; `MutationPort` is GUI-thread only; `test_worker_never_touches_widgets` |
| Restoring a corrupt or foreign layout (F2) | blob only from per-user QSettings, <= 64 KiB, SHA-256 envelope, schema int, try/except, Reset command; never read from a project, import or report |
| Unnamed docks, toolbars and dock tab bars break layout and audits (F3, F10) | host names them; `qtlog` test for "objectName not set" |
| Shortcut collisions (Escape = cancel job, Alt+Up/Down overloaded) | `ShortcutTable` plus a test over every QAction; Escape reserved; the palette owns its own Escape |
| Navigation silently lands on a similar target | explicit `NavResult` statuses; ambiguous -> candidates; filters cleared only with a visible message |
| A panel factory exception kills the window | host try/except -> error `StateView` `PT-GUI-FACTORY` (class name only) |
| Dynamic import breaks the frozen build; heavy libraries loaded at start | panels: explicit manifest with function-level imports, ban on `import_module` and `__import__` in `gui/`; `--self-test` calls `self_check()`; spec modules must import in < 100 ms without networkx, rapidfuzz, pygments or yara. CLI verbs (8.12) are the one directory-discovered exception, made safe by the collect hook and the A1 loop |
| Arrow-key selection storms start N tasks | host debounces `selection_changed` 120 ms; panels use latest-wins channels |
| Hidden panels burn CPU; floating panels lose shortcuts | `test_hidden_panels_do_no_work`; manual row M27 |
| Claim drift ("confidence %", "safe", "fixed") or advisory text treated as truth | per-panel `ClaimsProfile` sweep over every string the pure view-model emits; attribution line "listed by {source}" |
| Assuming platform dark mode in the frozen build (F16) | dark = app stylesheet; the `system` variant only follows what the active style supports |
| A discovered CLI verb missing from the frozen exe silently disappears (`invalid choice`, F19) | collect hook with `on_error='raise'`; A1 of `frozen_smoke` over `names()`; hook-parity test |
| A generic `args.action` rule would change the `cache` envelope (`cache` has a positional `action`, `cli.py` L93) | keep the set `{acquire, series, secondary}`; verbs name themselves through `command_label` |
| A verb module that imports Qt or heavy libraries slows or breaks every headless call | adapters import only `.` and the stdlib at module level (AST test); only the invoked verb builds its parser; subprocess no-Qt test over `names()` |

## 7. Contracts

All GUI values are frozen `dataclass(slots=True)` in the pure package, not Pydantic models (deliberate deviation from the brief: they are in-process view values that are never persisted or imported, so validation would add cost without a trust boundary; the repo splits the same way, Pydantic in `secondary/contracts.py` and `models.py`, frozen dataclasses in `secondary/evidence_view.py`). Additive changes only (new fields with defaults); `PanelSpec.contract = 1` is checked by the lint.

| Type | Fields |
|---|---|
| `AnchorRef` | `kind` (closed: function, match, string, import, address, capability, rule, build_fact, advisory_phrase, cve, kb, cwe), `key` (<= 256, opaque, from the producer), `side` (older/newer/both/None, explicit), `run_id`, `label` (sanitized <= 200), `origin` (panel id); equality on (kind, key, side, run_id). Amended by FAB-0 (2026-10-14): the fabric's ten kinds are the names above verbatim (`match` and `address` stay GUI-only); `AnchorRef.from_fabric(anchor, run_id, origin)` is a pure function. |
| `NavResult` | `status` (shown, not-found, stale, ambiguous, blocked), `message`, `candidates` (<= 20 `AnchorRef`), `code` (`PT-GUI-NAV-*`) |
| `ProjectKey` | `root, project_id, revision, run_id, older_sha256, newer_sha256`; `.identity()` = first two (same as C6 `WindowPort.key`) |
| `PanelSpec`, `PanelController`, `PanelContext` | 8.2 |
| `CommandSpec` | `id, title, tip_id, shortcut, group, keywords, enabled() -> Availability, run()` |
| `CliCommand` | `name` (`^[a-z][a-z0-9-]{1,23}$`; the file name with `_` -> `-`; unique; not in `cli.COMMANDS`), `summary` (<= 80 ASCII), `build(subparsers) -> ArgumentParser`, `run(args, cancel) -> int`; 8.12 |
| `CapabilityState` | `kind` (available, missing, unsupported, unchecked, policy), `reason` (<= 200), `remedy_command` |
| `StateModel`, `NoticeModel` | `kind, text, detail, actions`; notice: `key, level` (caution, notice), `text` (<= 400), `detail`, `dismissible`, `scope` (project, session) |
| `TeachTopic` | `id` (`<panel id>.<slug>`), `meaning` (<= 300), `next` (<= 4 steps of <= 200), `commands` (command ids) |
| `ChipSpec` | `key, glyph` (ASCII), `text, shape` (round, square, diamond, dashed), `token` (ok, change, caution, info, muted, alt, error, plain) |
| `Progress`, `TaskFailure` | `stage` (<= 80), `done`, `total` (None = indeterminate), `message` (<= 200); `code='PT-GUI-TASK'`, `exception_class` only |
| `ColumnSpec`, `TableSpec`, `PreparedTable`, `PairText`, `GraphNodeView`, `GraphEdgeView` | 8.4 |
| `ClaimsProfile` | `banned_stems`, `banned_words`, `allowed_phrases`; presets `CLAIMS_PAIRING` (= C6 `BANNED` with its whitelisted negations) and `CLAIMS_NEUTRAL`; KB and KEV define their own |

Error codes: `PT-GUI-MANIFEST` (duplicate id or shortcut, prefix mismatch, bad area: the lint fails, runtime logs and skips the panel), `PT-GUI-FACTORY`, `PT-GUI-LAYOUT` (invalid blob -> defaults plus status), `PT-GUI-TIPS` (id outside prefix, duplicate What, conflicting re-registration), `PT-GUI-CAP`, `PT-GUI-NAV-NOTFOUND|STALE|AMBIGUOUS|BLOCKED`, `PT-GUI-TASK`, `PT-GUI-GRAPH-TOO-LARGE`, `PT-GUI-TABLE-TOO-LARGE`, `PT-CLI-COMMAND` (a verb module failed to import or declares an invalid, duplicate or built-in-clashing command: that verb becomes a stub that exits 3 and never hides the others).

Persisted state is QSettings only (no enrichment kind, sidecar or cache key): `layout/schema` (int, starts at 1; bumped only when a dock id is renamed or removed), `layout/state` (QByteArray <= 64 KiB), `layout/state_sha256`, `theme/variant` (dark or system), `gui/palette/recent` (<= 8 command ids); per-panel keys live under `<id>/` through `PanelSettings` (typed getters with range, enum and length checks; corrupt value -> default; never credentials; no untrusted string > 256 chars). Existing keys stay valid: `desktop/*`, `evidence/*`, `engines/bindiff/*`, `series/geometry`, `recent/*`, `analysis/profile`. Cache key inputs: none persisted; `MatchIndex` is an in-memory cache keyed by `ProjectKey`; a `PreparedTable` is never cached.

Limits (constants in `gui/registry.py`): 32 panels; id `^[a-z][a-z0-9_]{1,23}$`, append-only (retired ids stay reserved); title <= 32; accessible name <= 80; description <= 160; label or status <= 200; table 100,000 rows; clipboard 16 KiB; graph 500 nodes and 2,000 edges by default (maximum 2,000 and 8,000); code view 200,000 chars; notice 400 chars; progress 10 Hz; announcement gap 1.5 s; selection debounce 120 ms; join timeout 5 s; navigation history 50; palette results 50.

## 8. CLI and GUI

### 8.1 CLI
`patchtrace panels list|check [--json]` (`gui/cli.py`, no Qt; registered by the adapter `cli_commands/panels.py` of the registry in 8.12, so F1 does not edit `cli.py`; `enrichment-cli/1` envelope). `list` prints id, title, area, tabify, shortcut, requires and built or not-built. `check` loads the manifest and applies every `PT-GUI-MANIFEST` rule (unique ids and shortcuts, tip prefixes, claims profile, no Qt import, import-cheap). Exit 0 ok; 2 invalid argument or manifest error; 3 a spec module raised on import; 4 no panel built; 5 cancelled. Example result: `{"contract":"enrichment-cli/1","command":"panels check","status":"ok","result":{"panels":[{"id":"evidence","state":"built","area":"right","shortcut":"Ctrl+Shift+E","requires":["project"]},{"id":"graph","state":"not-built"}],"conflicts":[]},"warnings":[]}`. This is the display-free collision gate every feature PR runs.

### 8.2 Panel registry contract
Manifest: `src/patchtrace/panel_manifest.py` (pure; top level so that `from .search.panel import PANEL` resolves) holds one entry per panel, pre-populated by F1 with 14 stubs named after the tooltip prefixes the feature plans already use (evidence, unified, search, graph, strings, capabilities, build_env, rules, kb, kev, leads, guide, series, files) written as `def _x(): from .pkg.panel import PANEL; return PANEL`. Function-level imports are lazy at runtime and are found by PyInstaller's bytecode scan at any nesting level (existing precedent: `ui.open_series`; the scan rule itself is [U], not re-fetched, so the frozen `self_check()` in 8.8 is the proof). `ModuleNotFoundError` whose `.name` is exactly the expected module means "not built" (hidden from menus, listed by `panels list`); any other exception is `PT-GUI-MANIFEST`. Default placement (hidden at first run unless a spec sets `default_visible`): right = evidence [unified and build_env tabbed], kb [kev tabbed], rules; bottom = graph [strings and capabilities tabbed], search, series, files; left = leads, guide. Most feature plans tab their dock with Evidence on the right (WB3, CAP, YRX, KEV, PIL); a right column with six or more tabbed docks is crowded at KB's 560 px minimum width, so wide result tables go to the bottom (a one-line manifest edit, open question 13). The `<id>/geometry` keys those plans propose are dropped: `layout/state` stores dock and floating geometry.

```python
@dataclass(frozen=True, slots=True)
class PanelSpec:                                    # gui/registry.py, no Qt import
    id: str; title: str
    factory: Callable[[PanelContext], PanelController]
    area: Literal['left', 'right', 'top', 'bottom', 'none'] = 'right'   # 'none' = no dock (cards, chips, banners, tips)
    tabify_with: str | None = None                  # join another panel's Qt dock-tab group
    shortcut: str | None = None; focus_order: int = 100; group: str = 'Panels'
    requires: tuple[str, ...] = (); claims: ClaimsProfile = CLAIMS_NEUTRAL
    tips: Mapping[str, TooltipEntry] = field(default_factory=dict)
    tip_templates: Mapping[str, TooltipEntry] = field(default_factory=dict)
    extra_tip_prefixes: tuple[str, ...] = ()        # for tips outside '<id>.', e.g. 'viewer.'; never another spec's prefix
    commands: tuple[CommandSpec, ...] = (); teach: tuple[TeachTopic, ...] = ()
    anchors_in: frozenset[str] = frozenset(); anchors_out: frozenset[str] = frozenset()
    default_visible: bool = False; eager: bool = False; minimum_em: tuple[int, int] = (40, 14); contract: int = 1

class PanelController(Protocol):                    # all hooks optional (base class supplies no-ops)
    def widget(self) -> QWidget | None: ...         # None for area='none' (headless controller)
    def focus_target(self) -> QWidget | None: ...
    def project_changed(self, key: ProjectKey | None) -> None: ...
    def selection_changed(self, match_id: str | None) -> None: ...
    def busy_changed(self, busy: bool) -> None: ...
    def capabilities_changed(self) -> None: ...
    def theme_changed(self, tokens: ThemeTokens) -> None: ...
    def show_anchor(self, anchor: AnchorRef) -> NavResult: ...
    def shutdown(self) -> None: ...                 # idempotent
```

A feature's pure `panel.py` (example; the Qt module is imported only when the factory runs):

```python
def _factory(ctx):
    from ..ui_search import create_panel            # function-level: lazy at run time, visible to PyInstaller
    return create_panel(ctx)
PANEL = PanelSpec(id='search', title='Search', factory=_factory, area='bottom', shortcut='Ctrl+Shift+F',
                  requires=('project',), tips=TIPS, anchors_in=frozenset({'function', 'string'}),
                  anchors_out=frozenset({'function', 'string'}))
```

| `PanelSpec` field | Rule |
|---|---|
| `id`, `title` | id forever unique, named like the tooltip prefix the feature plans already use; dock objectName `<id>.dock` (also its tip id, as the existing `evidence.dock`), tooltip prefix `<id>.`, settings prefix `<id>/`, toggle action `<id>.action`; title in sentence case <= 32, accessible name "<title> panel" |
| `area` | `left`, `right`, `top`, `bottom`; `none` = a contribution without a dock (the DIE card, the LBL calibration line, WBQ code tips): no shell, shortcut or toggle, but tips, commands, teach topics, anchors and a headless controller (`widget()` is None; `eager=True` when it must see `project_changed`) still work, so such features never edit `tooltips.py` |
| `factory` | called once on the GUI thread at first show (or at start when `eager=True`, used by evidence only); builds every widget eagerly (hidden when not applicable), sets names and tips; starts no thread and reads no disk |
| `shortcut`, `focus_order` | `Ctrl+Shift+<letter>` unique per window, pre-assigned in the stubs (E evidence, U unified, F search, G graph, T strings, A capabilities, B build_env, R rules, K kb, X kev, L leads, H guide; P is the palette). The plans for KB, CAP and KEV all ask for K: KB keeps it, CAP takes A, KEV takes X, and `panels check` fails the next duplicate; F6 order: built-in regions 10/20/30/90, panels 100+ |
| `requires` | capability ids, all `available`, else the panel opens in BlockedState with reason and remedy (never hidden): `project`, `run`, `idle`, `tool:<name>` (capa, floss, diec, yara-x), `engine:<name>` (bindiff, rzdiff), `feature:<flag>`, `os:windows`; a probe that executes a program is an explicit action, never automatic |
| `tips`, `tip_templates` | pure `TooltipEntry` dicts whose ids start `<id>.` (or a declared `extra_tip_prefixes` entry that no other spec or existing registry id uses); `<id>.dock` and `<id>.action` are required unless `area='none'`; registered idempotently into `tooltips.REGISTRY` by the host and by the test fixture; framework-owned ids live under `gui.*` (`gui.palette`, `gui.palette_list`, `gui.state_retry`, `gui.state_copy`, `gui.state_setup`, `gui.reset_layout`, `gui.cycle_panels`, `panels.dock_tabs`, `menu.view`) |
| `commands` | `CommandSpec`s for menu and palette; the host adds Show/Hide, Focus, Float/Dock and Move to left, right, top, bottom (keyboard parity: the dock buttons are not focusable [M F10]) |
| `anchors_in/out`, `teach` | anchor kinds handled and emitted (the lint warns about kinds nobody handles); `TeachTopic(id, meaning, next, commands)` for E-5 with `id` = `<panel id>.<slug>` (the plans use three styles today: DIE `build.*`, CAP `cap.*`, YRX `teach.rules.*`; they adopt this one), `meaning` <= 300 chars, `next` <= 4 steps of <= 200 chars, `commands` = command ids; data only, claims-swept |

Lifecycle:

| State | Trigger | Host does | Panel must |
|---|---|---|---|
| registered | manifest load | hidden dock shell with placeholder (0.3 ms [M]), toggle action, shortcut, tips; no Qt module of the feature is imported | nothing |
| available or blocked | `capabilities_changed` | evaluates `requires`, updates the action's Availability text | when built, show BlockedState |
| constructed | first show, command, or eager | `factory(ctx)` inside try/except, `dock.setWidget` | build widgets, no I/O, no tasks |
| active | visible | `project_changed(key)` if dirty, replays `selection_changed` and `busy_changed` | start loads through `ctx.tasks` channels |
| hidden | closed or tab not current | nothing | stop timers, mark dirty, keep results |
| shutdown | `closeEvent` or `aboutToQuit` | `save_layout`, controllers' `shutdown()`, `tasks.shutdown()` (joins <= 5 s) | start nothing new |

`factory` receives `PanelContext(spec, project, mutate, nav, shell)`, one object per port below (`ctx.tasks`, `ctx.settings`, `ctx.theme` and `ctx.announce` are shortcuts into `shell`). `WindowPort` stays as the union of the four ports for legacy code.

Ports (`gui/ports.py` Protocols; Qt adapter `MainWindowPort`; `ui_evidence.WindowPort` becomes a subclass for compatibility): `ProjectPort` (read-only: `key()`, `project()`, `busy()`, `artifact_paths()`, `match_index()` = function id -> match and side, built once per key); `MutationPort` (`annotate`, `review_match`; GUI thread, through `ProjectService`); `NavigationPort` (`select_match(id, clear_filters=False)`, `reveal_lines(function_id, start, end)` where the function id already fixes the side, as `_function_offsets` does today, `show_raw_offset(side, offset)`, `show_pair(older, newer, label)`, `navigate(anchor)`, `focus_panel(id)`, `back()`, `forward()`); `ShellPort` (`status`, `announce`, `notice(key, NoticeModel | None)` = the strip above the central workspace that the DIE pre-flight banner needs, `settings`, `theme`, `tasks`, `copy_text` <= 16 KiB, `choose_file`, reserved `spotlight(tip_id)` for E-5). Panels import only `gui.ports`, `gui.qt.*` and their own package, never `MainWindow`, `ui.py` or another feature (import test).

Navigation (`AnchorRouter`, pure): stale check against `ProjectKey` -> handler by kind (declared in `anchors_in`) -> the host builds and shows the panel -> `show_anchor` -> `NavResult`. There is no fallback target; ambiguous returns candidates; history holds 50 entries (Alt+Left, Alt+Right). Copy: not-found "Not found in run {id}: {label}."; ambiguous "{n} candidates match {label}. Choose one."; blocked "{Title} is unavailable: {reason}"; stale as in section 5.

### 8.3 Host behaviour
Layout persistence:
1. `PanelHost(window)` runs before `_build_actions` and creates only shells: one hidden dock per built spec (Closable, Movable, Floatable; all areas), laid out at its default area and tab group.
2. `restore_layout()` (end of `__init__`, when menus, toolbar and workspace exist): names the main window and any unnamed toolbar (`toolbar.<slug>`), applies the theme, wraps the central widget with the `NoticeStrip` (`takeCentralWidget()` then `setCentralWidget(wrapper)`; children stay valid and `saveState` is unaffected [M]; no extra `ui.py` line), installs the View menu (inserted before the action named `menu.help`, found by objectName, not by text), builds `eager` controllers, validates `layout/schema`, size and SHA-256, then calls `restoreState(blob, LAYOUT_SCHEMA)` inside try/except after the existing `restoreGeometry`. Failure -> defaults and the status "Panel layout could not be restored; defaults were used."
3. A panel that becomes available later is created without `addDockWidget`, passed to `restoreDockWidget`, and given its default area only when that returns False [M F3].
4. `shutdown()` and `aboutToQuit` save `saveState` plus SHA-256; nothing else is stored per panel except through `PanelSettings`.
5. Qt-created dock tab bars are named `panels.dock_tabs` and given a tooltip on `tabifiedDockWidgetActivated`; `setAnimated(False)` when `motionPreference == ReducedMotion`.

Menus and commands:
- View menu: panel toggles grouped by `group`; Theme (Dark, System; high contrast is automatic); Reset panel layout (clears `layout/*`, status "Panel layout reset to defaults." and an announcement); Command palette (Ctrl+Shift+P); Cycle panels (F6, Shift+F6).
- The palette is a transient modal popup that is a child of the main window (not a window): search box plus list built from panel commands and every QAction in the menus and toolbars; disabled commands stay listed as "(unavailable: reason)" taken from the tooltip Availability line; substring filter on title and keywords (no fuzzy dependency); Enter runs, Esc closes; the result count is announced politely after 300 ms idle.
- Reserved shortcuts today (collision test input): Ctrl+N, Ctrl+O, Ctrl+S, Ctrl+E, Ctrl+I, Ctrl+R, F1, F5, Escape, Alt+Up, Alt+Down, plus Ctrl+Shift+E, which stays the evidence dock toggle (`ui_evidence.py` L1311) and is claimed by the `evidence` spec.

Focus and keyboard: F6 visits navigator (10), code (20), findings (30), visible panels by `focus_order`, diagnostics (90) through `focus_target()`; floating docks are activated and raised. The Tab order inside a panel is declared by the panel and verified by `test_tab_order_matches_declared`. Every function is reachable without a mouse; nothing is hover-only.

### 8.4 Shared widgets
| Widget | Contract and limits |
|---|---|
| `VirtualTable` (`table.py`) | `ColumnSpec(key, title, unit, width_em, text, sort_key, chip, accessible, tip_id)`, `TableSpec(row_key, search_text, default_order, tip_prefix)`. `prepare_table(spec, rows, token)` runs in the WORKER (strings, sort keys, search keys, order); `VirtualTableModel.set_prepared()` swaps pointers. Model-owned filter and sort over an index list (stable, None last, persistent indexes follow, selection kept by `row_key`), early-return `data()`, fixed row height `max(2*lineSpacing+6, 28)`, hidden vertical header, no ResizeToContents; Enter or double-click -> `activated_key`, Ctrl+C -> TSV <= 16 KiB, Space -> detail pane; more than 100,000 rows -> too-large state; columns may change with every `set_prepared` (the YRX builds-by-rules grid). Flat tables only: grouped or tree models (CAP `CapabilityTreeModel`, the WB2 call tree) and paged models (WB1 `fetchMore`) stay feature-owned and must pass the same `assert_lazy_model` gate (open question 14). [M] 6 columns: first paint, sort and filter each need <= 7 x visible cells x 1.2 + 20 `data()` calls, independent of N (840 at 120 cells); 10k rows reset 29 ms, sort 12 ms, filter 6 ms; 100k rows reset 235 ms when prepared on the GUI thread (so prepare in the worker), sort 49 ms, filter 13 ms. Baseline `QSortFilterProxyModel` sort on display strings: 1.0 s at 10k (255k calls), 12.4 s at 100k (3.2M calls) |
| `ChipSpec`, `ChipDelegate`, `ChipLabel` (`chips.py`) | text + ASCII glyph + shape always; fill from a theme token (the C6 palette becomes tokens ok, caution, info, muted, alt; `error` is new and never used for conflicts; `plain` = outlined bold text with no fill, the KEV badge, so no colour implies severity); high contrast = system pair + border style, no fill; features own their glyph tables (C6 `= ! 1 ? +`, SPEC-31 `= ~ ? ! # - + .`), unique per (glyph, shape) within a table; `AccessibleTextRole` "Verdict: Contested"; tooltip through a template |
| `StateView` (`state_view.py`) | kinds no-project, idle, loading, refreshing, ready, partial, stale, blocked, error, too-large, unsupported, cancelled; precedence error > stale > partial > ready, loading only before first content; buttons Retry, Copy details, Open setup built eagerly and named per panel ("Retry loading Search"); one status label with an EMPTY accessible name (read when focused) while changes go through `StatusAnnouncer`. `NoticeStrip` (same file): the window-level strip above the central workspace for `NoticeModel`s (DIE pre-flight, calibration scope), one wrapped line with Details and Dismiss, hidden when empty, dismissal remembered per project or session, never modal; consent pages (KEV inline, KB plan review) stay feature-owned (open question 15) |
| `PlainLabel`, `SafeTextView` (`labels.py`) | PlainText, links off, `sanitize_text` on every set (C0/C1, bidi, NUL, U+2028/9 stripped; 200 chars for labels, 4,000 for views), selectable only by explicit flag, middle-elide with an escaped tooltip; replaces the three copies (aliases stay) |
| `CodeDiffView` (`codediff.py`) | two read-only `QPlainTextEdit` fed aligned lines plus `line_map` (original -> aligned); `compose_selections(view, layer, selections)` is the only writer of `setExtraSelections` (layers diff < search < anchor < mark, so WB1 hits, WB2 jump targets and WBQ marks never overwrite hunks); it works on any `QPlainTextEdit`, so WBQ S9 and WB1 can adopt it on the existing panes before M4 moves the four `setExtraSelections` sites of `ui.py` (L2059, L2138, L2589, L2641) to it; `next_hunk`, `previous_hunk`, `hunk_changed`, `reveal(side, start, end)`, `sync_scroll`, header with provenance and Copy; 200,000-char cap with an explicit truncation notice; optional highlighter slot for the WBQ design (windowed `QSyntaxHighlighter` parented to the document, visible blocks +/- 80, constant block state, model installed before `setPlainText`; WBQ measured +11 and +150 ms at 6.5k and 65k lines against +99 and +1,046 ms for a full highlighter); `ThemeTokens` carry the pane base and hunk colours and `theme_math.ensure_contrast()` is the runtime guard WBQ describes (below 4.5:1 falls back to the text colour); names "Older artifact code" and "Newer artifact code" kept; never QTextBrowser or HTML |
| `GraphCanvas` (`canvas.py`) | `QGraphicsView` over immutable node and edge views; ceilings are constructor arguments (default 500 nodes and 2,000 edges, framework maximum 2,000 and 8,000, else `PT-GUI-GRAPH-TOO-LARGE`); above 500 nodes only stock Qt items (no Python `paint()`); antialiasing off above 200 items; level of detail by zoom (marks below 0.15, boxes below 0.5, labels from 0.5), zoom clamp 0.05-8, `setMinimumRenderSize(1.0)`, optional minimap; a scene is replaced by swapping in a new one and `deleteLater` on the old; layout is supplied by the feature; keyboard (arrows = nearest node in that direction, Enter activates, Space selects, +/- zoom, 0 fits); `node_focused` -> polite announcement because scene items are invisible to UIA [M F10]; the feature must also supply the textual adjacency table. [M] 500/2,000: build 13-55 ms, first paint 41-75 ms, repaint 11-44 ms; 2,000/8,000: build 84-86 ms, first paint 99-141 ms, repaint when fitted 74 ms (stock items) or 130 ms (Python paint), 24-29 ms at 100%; `scene.clear()` 30-40 ms against 1.4 ms to swap plus 14 ms deferred delete |

State copy (ASCII, plain text): no-project "Open a project to use {title}."; idle "{title} has no results yet. {hint}"; loading "Loading {noun}..."; refreshing "Refreshing {noun}..."; partial "Partial result: {reasons}. Missing evidence is unknown, not disagreement."; stale "{title} is stale: {reason}. It is shown for reference only." [Refresh]; blocked "{title} is unavailable: {reason} {remedy}" [Open setup]; error "{title} could not be loaded: {code}: {message}. Earlier results are unchanged." [Retry] [Copy details]; too-large "Too many rows to display ({n}). Narrow the filter."; cancelled "Cancelled. Earlier results are unchanged."; factory failure "{title} could not be created: PT-GUI-FACTORY: {ExceptionClass}. Other panels are unaffected." Notice strip: region "Notices", buttons "Details" and "Dismiss" named "Show notice details" and "Dismiss notice"; a dismissed notice stays dismissed for its scope and returns only when its text changes. Palette: placeholder "Type a command..."; empty "No matching command."

### 8.5 Worker and thread pattern
| Option | Per task [M] | Hazard | Verdict |
|---|---|---|---|
| `QThread` subclass + registry (status quo: five base classes, four registries) | 425 us | process abort if destroyed while running (F15); parent, registry and `deleteLater` rules; proven by the 20x gates | keep until migrated; adopted into the same shutdown and fixture |
| `QThreadPool` + `QRunnable` | 155 us | not a QObject, so a signal holder deleted mid-run raises `RuntimeError: Signal source has been deleted` in the worker; no join or registry; `tryTake` ABA (F15) | rejected |
| Python `threading.Thread` + GUI-owned bridge `QObject` | 181 us | a late emit into a deleted bridge raises RuntimeError (caught); nothing to destroy; teardown x20: 0 stuck threads | chosen; a QThread executor with the same API is the fallback if Windows CI shows a non-Qt-thread problem [U] |

Rules:
1. `TaskRunner.submit(channel, fn, on_result, on_error, on_progress)` with `fn(token, report) -> R`, pure with respect to Qt, the project service and SQLite; inputs are immutable snapshots built on the GUI thread.
2. One generation per channel: submit bumps it and sets the previous token; the bridge slot (a bound method on a queued connection, never a lambda) drops older generations.
3. Results are applied, and anything persisted is written, only in GUI-thread callbacks; a callback exception becomes a status line (re-raised in tests). Worker exceptions cross as `TaskFailure(exception class)` only.
4. Progress is throttled to 10 Hz, latest wins, final always. [M] 100,000 unthrottled emits took 3.2 s to drain and delayed a 10 ms GUI timer by up to 98 ms.
5. Cancel is cooperative (`CancelToken(threading.Event)`: `is_set`, `__call__`, `raise_if_cancelled`, `checkpoint`); child processes only through `jobs.run_process` (kills the tree); no `terminate`.
6. `shutdown()` sets every token and joins each for <= 5 s; threads are daemon so a hung worker cannot block exit; a closed flag stops late emits. Hidden panels may finish a running task but apply nothing until shown.
7. GIL [M]: a CPU-bound pure-Python worker made a 1,218-call table repaint go from 6.5 ms to 274 ms median (max 565) at the default 5 ms switch interval; GIL-releasing work (sqlite3, hashlib) did not (6.7 ms). Mitigations measured: `token.checkpoint()` sleeping 1 ms after every 2 ms of CPU work gives repaint median 11 ms, p95 20 ms at about 78% worker throughput (unthrottled p95 was 210 ms); `sys.setswitchinterval(0.001)` alone gives p95 81 ms at 73%; both together add nothing. So: heavy Python work runs in a subprocess or calls `checkpoint()` in its loop, and `runtime.install()` sets the 1 ms switch interval once as insurance.
8. Long-lived readers (WB1's search reader owns read-only SQLite segment connections): `TaskRunner.lane(name, init, close)` starts one daemon thread whose `init()` runs on that thread, so the state never crosses threads (`sqlite3` raises `ProgrammingError` on a connection used from another thread [M]). Requests run FIFO, or latest-only with `coalesce=True`; generations, tokens, the bridge and `shutdown()` (which closes the state on the lane thread after the running request) follow rules 2-6. [M] 1,000 point queries: 149 us per request, delivered on the GUI thread (thread per task: 181 us at 300 tasks, 1.5 ms per task when 1,000 are started back to back).

### 8.6 Theming
- `ThemeTokens` (frozen): surface, surface_alt, text, text_muted, accent, focus_ring, border, chip fills. Variants: `dark` (default; stylesheet text byte-identical to `ui.DARK_STYLE`, golden test) and `system` (no stylesheet, platform palette; follows OS light or dark only when the active style supports it [U F16]).
- High contrast is automatic: when `styleHints().accessibility().contrastPreference() == HighContrast` (F11; `contrastPreferenceChanged` is handled) the stylesheet is removed, tokens come from `QPalette`, custom painting uses `option.palette`, chip fills are dropped and state is carried by text, glyph and border style. `PaletteChange` and `ThemeChange` re-emit `theme_changed`.
- DPI: no pixel constants in custom painting; `Metrics` (em, row height, gaps) is recomputed on `FontChange`, `DevicePixelRatioChange`, `StyleChange`, `PaletteChange` (F12); stylesheet px are logical px. The code font size setting (8-28) is unchanged; platform text scaling is not assumed.
- Colour-blind safety is redundant encoding (text + glyph + shape + position), contrast tests on every token pair and variant (text 4.5:1, borders and focus ring 3:1; WCAG 1.4.3 and 1.4.11 [F13]) and no red/green-only pairs. A CVD simulation test stays optional until the matrices are verified [U F18].

### 8.7 Accessibility
| Finding | Consequence and rule |
|---|---|
| UIA only, fixed pattern set (F4, F5) | Table, Grid, Selection, Value and Invoke work; there are no virtualization or scroll patterns: keep a status summary and a filter, hide the vertical header, put units in `AccessibleTextRole`, never depend on "read all" for large tables |
| Name changes reach UIA only when focused (F6); `Alert` is a sound only (F7) | every asynchronous message goes through `StatusAnnouncer` (`QAccessibleAnnouncementEvent`; Polite, Assertive only for blocking errors; target = status bar; sender injected in tests). Ten feature plans (KB, PIL, WB1, WB2, DIE, CAP, KEV, YRX, LBL, WBQ) rely on C6's "empty accessible name, `setText` announces" and DIE also cites `Alert`: all switch to `ctx.announce` |
| Description = FullDescription else HelpText, median 234 chars (F8, F9) | `apply_tooltip(..., accessible='what')`: description = the What line <= 160 chars; `whatsThis` keeps the full text |
| Dock = Pane; Close and Float exposed but not focusable [M F10] | per-panel commands for show, hide, float and move are the keyboard path |
| QGraphicsView exposes 1 child [M F10] | textual adjacency table plus node announcements |
| Dock tab bar unnamed; splitter unnamed; buddy names only for same-parent labels | host names tab bars; splitters are named "Panel divider"; `labelled(field, text)` creates a sibling label, buddy and explicit name |

What NVDA and Narrator need: name, role, state, a short description and the value on every control; table headers and position; focus events as the current cell moves; announcements for asynchronous completion; stable Tab order and visible focus; no hover-only or mouse-only function; high-contrast support. `a11y_audit(root)` enforces: R1 every focusable widget has a name <= 80 chars that is a noun phrase without a role word or final period and is unique among siblings (good: "Function name filter"; bad: "Search edit box."); R2 description = What line <= 160; R3 sampled table cells have `AccessibleTextRole` and the vertical header is hidden or named; R4 status labels keep an empty name; R5 shortcuts are unique; R6 the declared tab order holds; R7 only allowed top-level windows exist (main window, floating docks, modal dialogs, popups); R8 state buttons are named per panel; R9 every control with a tip id has `accessibleIdentifier` equal to it, unique in the window (the UIA AutomationId that Accessibility Insights and UIA scripts select by; WB1 already plans this). Verification tools: Accessibility Insights for Windows (Live Inspect, FastPass), Inspect, AccScope, Narrator developer mode (F14). Not verifiable here: real NVDA or Narrator output, high contrast, DPI, the frozen style plugin. Linux AT-SPI and Orca are not a gate for the Windows alpha and were not tested [U].

### 8.8 Testability
- Stack: pytest-qt 4.5, `QT_QPA_PLATFORM=offscreen`, a per-test `QSettings(IniFormat, tmp_path)`. `tests/qt_support.py` (F2) provides fixtures `settings` and `main_window`; autouse `join_gui_threads` (joins `TaskRunner` and the legacy registries, fails if any survive, flushes DeferredDelete with `sendPostedEvents(None, DeferredDelete)`); `assert_lazy_model(factory, sizes=(10_000, 100_000))` (call ceilings exact, time 5x slack); `a11y_audit`; `HOSTILE` strings (the C6 list, short explicit ids for Windows); `RecordingAnnouncer`; `slot_timer`; `top_level_windows(app)`. `contrast_ratio` moves to pure `gui/theme_math.py` (re-exported by `ui_evidence`).
- Gates: pure tests including subprocess `test_gui_core_has_no_qt` and `test_panel_specs_import_cheaply`; the teardown matrix (close while loading x5, project switch mid-task, GC of a started worker, bridge deleted while running, shutdown with a hung worker); `tools/qt_gate.py --repeat 20` lists the GUI test files 20 times in ONE pytest session with `--keep-duplicates` and `PYTHONFAULTHANDLER=1` (the method the `docs/qa.md` rows already use): Linux PR job 20x, Windows PR job 5x, nightly 20x on both; `data()` call gates at 10k and 100k; a hostile-text sweep over every panel x every state; `test_ui_seam_budget`; the forbidden-API grep; contrast per variant; `test_no_new_top_level_window`.
- Announcement tests inject the sender because PySide6 cannot install an accessibility update handler [M F7]. Layout tests: round trip, missing, new and lazy dock, version mismatch, corrupt and oversize blob, reset, and no Qt "objectName not set" warning (`qtlog`).
- `host.build_all_for_test()` builds every manifest panel in blocked and ready states, so `tests/test_tooltips.py` never lists roots by hand again. Frozen: `--self-test` runs `window.panels.self_check()` (imports every manifest module, builds each panel once), extending smoke check A4.

### 8.9 Performance
| Item | Budget (re-measure on Windows) |
|---|---|
| Startup | 12 dock shells <= 10 ms [M 3.9]; `restoreState` <= 10 ms [M 2.3]; `MainWindow()` growth <= 25 ms over the 58 ms baseline [M]; panel first build <= 150 ms (EvidencePanel takes 11-23 ms [M]) |
| GUI-thread callbacks | median <= 16 ms, max <= 50 ms, none > 100 ms (`slot_timer`) |
| Tables | the 8.4 budgets; reset = pointer swap after the worker prepared; 10k rows <= 64 MiB (`tracemalloc`); frozen slots rows, no per-row QObject, no `QTableWidget` or `QStandardItemModel` above 200 rows |
| Background load | repaint p95 with a `checkpoint()` worker <= 5x idle median + 20 ms |
| Idle and fan-out | hidden panels: 0 active timers and 0 foreground tasks; selection debounce 120 ms; progress 10 Hz |
| Forbidden APIs (grep test) | `QSortFilterProxyModel`, `lessThan`, `ResizeToContents`, `resize*ToContents`, `setHtml`, `setMarkdown`, `TextFormat.RichText` (not `mightBeRichText`, which `ui.py` legitimately cites), `.terminate(`, `processEvents(` outside tests, `QThread(` with a parent, thread-signal lambdas, `QRunnable`, `QThreadPool`, `importlib` or `__import__` in `gui/` and the manifest (`import_module` is allowed only in `cli_commands/__init__.py`, 8.12), `QAccessible.updateAccessibility` outside `announce.py`, `sys.setswitchinterval` outside `runtime.py`. The test carries a counted baseline allowlist produced at F5 (today only two small `QTableWidget` calls, `resizeColumnsToContents` at `ui.py` L563 and `ui_inspection.py` L118); counts may only shrink and new code gets none |

### 8.10 `ui.py` seam and migration
Baseline 3,119 lines at `d972125`. Final seam after F5 and F8: 12 call sites, expected net +9 lines, budget +15 (`test_ui_seam_budget` allows at most 3,134 lines and no feature name in `ui.py`); F5 alone leaves the evidence hooks in place, so its transitional ceiling is +25.

```text
imports (L62):                     from .gui.qt.host import PanelHost       # replaces the EvidenceController import
__init__ (before _build_actions):  self.panels = PanelHost(self)            # shells only, no widgets
_build_navigator:                  layout.addWidget(self.panels.navigator_stack(self.navigator), 1)   # returns the navigator until a panel claims the view switch
current_match():                   override = self.panels.match_override()  /  if override is not None: return override
refresh() end:                     self.panels.project_changed()            # replaces the 2-line hasattr hook
select_match():                    self.panels.selection_changed(self.current_match())
update_controls():                 self.panels.update_controls()            # replaces the 2-line hasattr hook
restore_preferences() end:         self.panels.restore_layout()
closeEvent():                      self.panels.shutdown()
new show_external_pair(older_text, newer_text, label)   # +10: clears hunks, offsets and selections, truncates at MAX_VIEW_CHARS
new reveal_lines(function_id, start_line, end_line)     # +15, returns the code view or None; replaces two duplicated 13-line blocks in jump_signal and jump_evidence (-20)
new show_raw_offset(side, offset)                       # +3, extracted from raw_goto_offset (L2653-2677); the 'address' anchor and WB3 "Open in hex" call it
```

Other existing files that change (each inside one slice): `tooltips.py` (`register_tooltips`, `apply_tooltip(accessible='what')`), `__main__.py` (+3 lines self-check), `cli.py` (7 touched lines, net +3, slice F1b, 8.12), `ui_evidence.py`, `ui_engine_setup.py`, `ui_series.py`, `ui_inspection.py`, `tests/test_tooltips.py`, `tests/test_evidence_ui.py`, `tests/test_ui_engine_setup.py`, `tests/test_ui_series.py`; `.github/workflows/qa-windows.yml` gets the repeat job from the integration owner (the F5 builder hands over the job text, as C3 did for its CI steps).

Migration steps:
- M0 (F5): the host coexists with the untouched `EvidenceController`; manifest stubs only.
- M1 (F8): evidence. Pure `secondary/evidence_panel.py` (`id='evidence'`, right, Ctrl+Shift+E, `CLAIMS_PAIRING`, `eager=True`). `EvidenceController(ctx)` no longer creates the dock, the menu entry or the geometry (the host does; legacy `evidence/geometry` is read once as fallback). `WindowPort` and the thread, label and settings helpers become aliases of the `gui` versions. Tests change `window.evidence` -> `window.panels.controller('evidence')` and the seam-test regex; acceptance = the existing C6 and G suites otherwise unchanged, plus 20x.
- M2 (F8): remove the remaining `hasattr(self, 'evidence')` hooks and the menu lookup by the text 'Analysis'.
- M3 (F9): `SeriesWindow` -> `series` dock (a tab per opened `series.json`; `series/geometry` retired) and the File overview dialog -> `files` dock (`ui.py` loses about 65 lines). Until then both are recorded exceptions to "one main window".
- M4 (optional, last): the main code panes -> `CodeDiffView`.
- Modal task dialogs (New, Acquisition, Setup, Export, Context, Correct match, KB wizard) stay `QDialog.exec()` children of the main window; their results always land in a dock.

### 8.11 PySide6 pitfalls the framework encodes
| Pitfall | Evidence | Encoded in |
|---|---|---|
| Lambdas on thread signals do not guarantee GUI-thread delivery | C6 research item 13 [M] | bound-method slots with an explicit queued connection |
| Emitting after the sender QObject died raises `RuntimeError: Signal source has been deleted` | [M] | the bridge wrapper catches it; the closed flag |
| Destroying a running QThread aborts | F15 | Python threads for new code; legacy registry kept |
| `QLabel`, tooltips and `QMessageBox` default to AutoText: `<b>x</b>` renders | C6 research item 15 [M] | `PlainLabel`, escaped tooltip templates, `sanitize_text` |
| Proxy sort calls `data()` per comparison and re-sorts on reset | [M 12.4 s at 100k] | model-owned order; forbidden-API grep |
| `ResizeToContents` costs about 40k `data()` calls regardless of N | C6 research item 7 | fixed widths from font metrics |
| Vertical header exposes RowHeader accessibles | F10 | hide or name it (R3) |
| `restoreDockWidget` after `addDockWidget` is a silent no-op; unnamed toolbars | [M F3] | host algorithm 8.3 steps 1-3 |
| Offscreen `QAccessible.isActive()` is False; no update handler | [M F7] | injected sender |
| `processEvents` does not run DeferredDelete at loop level 0 | C6 research item 14 | `sendPostedEvents(None, DeferredDelete)` in the fixture |
| Exceptions in virtual overrides are captured by pytest-qt (PySide6 >= 6.5.2) | C6 research section 8 | no broad `except` in `data()` or paint |
| A window stylesheet overrides the palette (hard-coded colours ignore high contrast) | F11 | the theme manager clears it in HC mode |

### 8.12 CLI-extension registry (`cli_commands/`, slice F1b)
Thirteen new verbs are planned (unified, patch, panels, search, graph, strings, kb, kev, intelligence, build-env, rules, pe-meta, calibration; CAP adds `intel-tools pairs` to T0's verb) and each plan budgets a `cli.py` hook of about 6 lines (LBL 8). Each hook edits the same lines: `COMMANDS` (`cli.py` L16), the parser chain in `_parser()`, `HANDLERS` (L817), `_command_name` (L821), `COMMANDS` in `tools/frozen_smoke.py` (L37) and the lists at `tests/test_acceptance_smoke.py` L41 and L52. With the registry a verb is one file and none of those lines is edited again.

```python
# src/patchtrace/cli_commands/__init__.py  (<= 90 lines, stdlib only, no Qt; the only `import_module` call in the code base)
@dataclass(frozen=True, slots=True)
class CliCommand:
    name: str      # file build_env.py -> 'build-env'; ^[a-z][a-z0-9-]{1,23}$; unique; not in cli.COMMANDS
    summary: str   # <= 80 ASCII characters, listed by `patchtrace --help`
    build: Callable[[_SubParsersAction], ArgumentParser]   # adds the full parser (it may add an `action` level)
    run: Callable[[Namespace, threading.Event], int]       # exit 0/2/3/4/5; raise CliError for 2 and 3
def discover() -> tuple[dict[str, CliCommand], dict[str, str]]   # (verbs, {file: exception class}); sorted; _private.py skipped
def names() -> tuple[str, ...]                                    # cli.COMMANDS + discovered: the one list for smoke and tests
def register_all(sub, invoked: str | None) -> None                # full parser for `invoked`, bare listing parsers for the rest
# re-exported for adapters: CliError, emit (= cli._emit, the enrichment-cli/1 envelope), OK, ENVIRONMENT, RUNTIME, NO_RESULTS, CANCELLED

# src/patchtrace/cli_commands/search.py  (an adapter, <= 25 lines; module level imports only `.` and the stdlib)
def _build(sub):
    from ..search.cli import add_parser        # function-level: listing verbs imports nothing heavy
    return add_parser(sub)
def _run(args, cancel):
    from ..search.cli import run
    return run(args, cancel)
COMMAND = CliCommand('search', 'full-text search over a project', _build, _run)
```

The `cli.py` seam is 7 touched lines, net +3 (cap +6, `test_cli_seam_budget`); the seven built-in verbs and their parsers stay byte-identical:
```text
def _parser(argv=()):                    # was _parser()
    ...                                  # built-in verbs unchanged
    from .cli_commands import register_all                 # new
    register_all(sub, argv[0] if argv else None)           # new, just before `return parser`
main():          args = _parser(argv).parse_args(argv)     # was _parser()
                 return (getattr(args, 'handler', None) or HANDLERS[args.command])(args, cancel)   # was HANDLERS[args.command](args, cancel)
_command_name(): base = <the existing expression>; return getattr(args, 'command_label', None) or base   # one added line
```

`register_all` builds the full parser only for the invoked verb (`argv[0]`), adds a bare parser (name and summary) for every other verb so `patchtrace --help` lists them, and sets `handler` and a default `command_label` (the verb; a nested leaf parser may set `command_label='kb index import'`). A module that fails to import, or declares a bad, duplicate, over-long or built-in name, stays listed as "unavailable (could not be loaded)" and, when invoked, exits 3 with "PT-CLI-COMMAND: {verb} could not be loaded ({ExceptionClass})" before argparse sees its arguments, so one broken file never hides the others and its `--help` fails the A1 check loudly. The generic `args.action` rule is not used: `cache` has a positional `action` (L93) but its envelope says `cache`, so the set `{acquire, series, secondary}` stays. Hidden worker verbs stay actions under their feature verb (`secondary _binexport-worker`, `cli_binexport.py` L40), so there is no `hidden` flag.

Frozen build: verbs are found at run time by `pkgutil.iter_modules`, which PyInstaller's bytecode scan cannot see, so one hook is added (F19; `build_windows.py` and `build_linux.py` already pass `--additional-hooks-dir tools/pyinstaller_hooks` and `--paths src`):
```python
# tools/pyinstaller_hooks/hook-patchtrace.cli_commands.py  (6 lines with the docstring)
from PyInstaller.utils.hooks import collect_submodules
hiddenimports = collect_submodules('patchtrace.cli_commands', on_error='raise')   # a registry that fails to import fails the build
if len(hiddenimports) < 2:   # collect_submodules returns [] WITHOUT an error when it cannot resolve the package (F19)
    raise RuntimeError('patchtrace.cli_commands collected no verb modules; refusing to build an exe without them')
```

The guard matters because the isolated child resolves `patchtrace` like any process: if an editable install of another tree shadows `--paths src`, `collect_submodules` returns an empty list even with `on_error='raise'`. The builds are meant to run from an editable install of the tree being built (`build_windows.py` points to `pip install -e '.[dev]'`); the guard turns any other situation into a failed build instead of an exe without verbs. `tools/frozen_smoke.py` derives `COMMANDS = names()` (an import and the assignment, replacing the literal at L37), so A1 runs `--help` for every discovered verb and an unbundled or broken verb (exit 2 or 3) fails the Windows CI step; `docs/qa.md` L111 "all seven commands" becomes "every registered command". Directory discovery is right here and an explicit manifest is right for panels: a verb is configured by nothing but its name, which the file name makes unique (two tracks cannot claim one verb without a visible git conflict), whereas panels share one screen and need central shortcuts, areas and focus order, and a missing verb fails an A1 check in seconds while a missing panel would just look absent. Budgets: registry <= 90 lines (prototype 70 [M]), adapter <= 25, `cli.py` net +3 (856 -> 859 [M]; cap +6), hook 6, smoke and test files 2 touched lines each; `names()` over 30 verbs 8 ms [M] (budget 25 ms, 5x CI slack); frozen cold start unchanged at 78-83 ms in the toy [M]. Not built: entry-point or third-party plugins and discovery outside the package (offline and frozen invariants), a `hidden` flag, migration of the seven built-ins (open question 16).

Tests (`tests/test_cli_registry.py`, 13 prototyped green): discovery over a temporary package (valid, broken import, duplicate or built-in clash, bad name, over-long summary, `_private` skipped); `names()` order; top-level help lists every summary; only the invoked verb's `build` runs; the standard envelope and a nested `command_label`; a broken verb exits 3 with and without `--help` while the others still run; the built-in envelope names stay (`cache` is not `cache status`); `test_cli_seam_budget` (`cli.py` <= baseline + 6, `COMMANDS` unchanged, registry <= 90 lines); an AST check that adapters have <= 25 lines and import only `.` and the stdlib at module level; hook parity with the directory (PyInstaller's isolated child needs `PYTHONPATH=src`); `names()` over 20 fake verbs; the existing no-Qt `--help` subprocess test parametrized by `names()`; `test_every_cli_command_is_covered_by_the_smoke_list` unchanged (it now proves `cli.COMMANDS` plus the registry equal the parser's choices); and a nightly toy-freeze test (the F19 experiment, about 7 s). [M] Prototyped in a scratch copy of the tree (nothing committed): the 12 acceptance-smoke tests (10 plus 2 new verbs) and 172 CLI-related tests pass, the same 172 as before the seam; the real `patchtrace.cli` frozen without Qt (about 17 s) lists, runs and answers `--help` for the new verbs like the source and keeps the built-ins.

## 9. Slice plan

Order: F0, F1 and F1b in parallel (F1b is 1 day and lets every track add a CLI verb without touching `cli.py`) -> F2 (its first commit, `tests/qt_support.py`, merges after about half a day) -> F3 and F4 start; F2, F3, F4 run in parallel -> F5 (single owner of every shared file) -> F6a, F6b, F7, F8 in parallel -> F9. Critical path about 11 working days elapsed (F1 1.5 + F2 first commit 0.5 + F3 2 + F5 3 + F8 2 + F9 2; F1b is off it) and 20.5 builder-days in total. Feature tracks can add CLI verbs from day 1 (F1b merged), write their pure `panel.py`, view-models and specs from day 1.5 (F1 merged) and their Qt panels from about day 7 (F5 merged); widgets arrive as F3, F4 and F6 land. Every slice: ruff clean, red then green tests, full suite twice, Qt test files 20x, no stray files, a `docs/modules.md` row.

| Slice | Scope | Exclusive files | Deps | Tier (reason) | Size | Gate | Fallback |
|---|---|---|---|---|---|---|---|
| F0 | apply the section 10 doc amendments and module rows | the docs listed in section 10 only | - | Haiku (mechanical) | 0.5 d | link check | builders append their rows |
| F1 | pure core: anchors, projection (`MatchIndex`), ports, registry and lint, capabilities, state, text and claims, theme_math, shortcuts, `gui/cli.py`, manifest with 14 stubs, adapter `cli_commands/panels.py` | `src/patchtrace/gui/{__init__,anchors,projection,ports,registry,capabilities,state,text,theme_math,shortcuts,cli}.py`, `panel_manifest.py`, `cli_commands/panels.py`, `tests/test_gui_core_*.py` | none (the adapter needs F1b; fallback: a 6-line `cli.py` hook) | Sonnet (pure, spec-driven) | 1.5 d, ~900 LOC + 700 test | hypothesis on `sanitize_text`, ids and manifest; no-Qt subprocess; CLI exits 0/2/3/4/5; full suite x2 | move `projection` to F5 |
| F1b | CLI-extension registry (8.12): `CliCommand`, discovery, lazy parsers, `emit`, the `cli.py` seam, collect hook, derived smoke and test lists | `src/patchtrace/cli_commands/__init__.py`, `cli.py` (7 touched lines, net +3), `tools/pyinstaller_hooks/hook-patchtrace.cli_commands.py`, `tools/frozen_smoke.py` (2 touched lines), `tests/test_acceptance_smoke.py` (2 touched lines), `tests/test_cli_registry.py` | none | Sonnet (small and spec-driven; prototyped and the frozen-build facts measured, F19 and 8.12) | 1 d, ~70 LOC + ~150 test | the registry tests of 8.12; `test_cli_seam_budget`; full suite x2; frozen smoke A1 over `names()` (Windows CI, reported separately) | leave `cli.py` alone: every track keeps its own 6-line hook |
| F2 | Qt runtime: `TaskRunner` with `lane`, `CancelToken`, legacy-registry adoption, `PanelSettings`, `StatusAnnouncer`, `Metrics`, `runtime`, `qt_support`, `qt_gate` | `gui/qt/{__init__,tasks,settings,announce,metrics,runtime}.py`, `tests/qt_support.py`, `tools/qt_gate.py`, `tests/test_gui_{tasks,announce,settings}.py` | F1 | Sonnet; Opus review only if the 20x gate aborts | 2 d, ~700 LOC + 800 test | teardown matrix x20 with faulthandler; repaint under load; progress flood; worker never touches widgets; lane state opened and closed on the lane thread | QThread executor behind the same API |
| F3 | labels, `StateView` and `NoticeStrip`, chips, `ThemeTokens` (dark) and stylesheet builder, `gui/tips.py` | `gui/qt/{labels,state_view,chips,theme}.py`, `gui/tips.py`, tests | F1, F2 (`qt_support` commit) | Sonnet | 2 d | dark stylesheet equals `DARK_STYLE`; contrast; hostile text; per-state copy; `a11y_audit` | high-contrast drawing moves to F7 |
| F4 | `VirtualTable` | `gui/qt/table.py`, tests | F1, F2 (`qt_support` commit) | Sonnet (C6 reference code exists) | 2 d, ~500 LOC | 10k and 100k call and time gates; selection, sort, filter, keyboard, copy cap | copy-adapt the C6 model |
| F5 | host and seam: `PanelHost`, docks, layout, commands, palette, `MainWindowPort`, `ui.py` seam, `tooltips.py`, `test_tooltips.py` generalisation, `__main__.py` self-check, CI repeat job text for the integration owner | `gui/qt/{host,docks,layout,commands,palette}.py`, `ui.py`, `tooltips.py`, `__main__.py`, `tests/test_gui_host*.py`, `tests/test_tooltips.py` | F1, F2, F3 | Sonnet (capable); Opus only for a demonstrated blocker (CLAUDE.md cost rule) | 3 d | all of 8.8 for the host; seam budget; layout suite; full suite x2; 20x | ship without the palette |
| F6a | `CodeDiffView` with `compose_selections` | `gui/qt/codediff.py`, tests | F3 | Sonnet | 1.5 d | caps, layers, hunk API, truncation, hostile text, a stub windowed highlighter attaches and survives `setPlainText` | defer the highlighter slot |
| F6b | `GraphCanvas` | `gui/qt/canvas.py`, tests | F3 | Sonnet | 1.5 d | 500/2,000 and 2,000/8,000 budgets, level of detail, scene swap, keyboard, announcements, too-large error | table-only first release |
| F7 | theme variants: system, automatic high contrast, chip HC drawing, reduced motion, View > Theme | `gui/qt/theme.py` (+ `theme_stylesheet.py`), tests | F3, F5 | Sonnet | 1.5 d | simulated contrast provider; contrast per variant; manual M22 | dark and HC only |
| F8 | migration M1 and M2 | `secondary/evidence_panel.py`, `ui_evidence.py`, `ui_engine_setup.py`, `ui.py` (removals), the listed tests | F5 | Sonnet | 2 d | C6 and G suites unchanged otherwise, 20x | keep both paths for one release |
| F9 | migration M3 (series and files docks) | `ui_series.py`, `ui_inspection.py`, `ui.py` (removals), pure `series` and `files` specs, tests | F5, F8 | Sonnet | 2 d | `test_no_new_top_level_window`; series and overview suites | postpone to beta |

Feature builder contract (CLI after F1b, panels after F5; what every other Program E track does):
1. Pure `<package>/panel.py` exporting `PANEL`, with its `TIPS`, anchors and `requires`; a Qt `src/patchtrace/ui_<feature>.py` with `create_panel(ctx)` built from `gui.qt` widgets; pure view-model and service modules as today (the UI holds no analysis state).
2. Tests `tests/test_ui_<feature>*.py` on `tests/qt_support.py`: every state, hostile text, `a11y_audit`, `data()` gates for tables, teardown, anchors in and out.
3. Never edit `ui.py`, `tooltips.py`, `tests/test_tooltips.py` or `panel_manifest.py`; append docs rows under a unique heading. Run `patchtrace panels check` and the 20x gate; report open manual gates separately.
4. CLI: a verb is `src/patchtrace/cli_commands/<verb>.py`, an adapter of <= 25 lines over the feature's own Qt-free `<package>/cli.py`; never edit `cli.py`, `tools/frozen_smoke.py` or `tests/test_acceptance_smoke.py` (`names()` feeds them) and never add a pyinstaller hook for it.

## 10. Amendments required, test and QA plan

| File | Section | Change |
|---|---|---|
| `docs/specs/multi-engine-evidence-panel.md` | 1.8, 5.3.6, 8, 15; new 17 | status rule: the label name-change event reaches UIA only when focused (F6), use `StatusAnnouncer`; the thread registry is `gui.qt.tasks`; the seam is `PanelHost`; add "Migration M1" |
| `docs/specs/unified-engine/07-ui-and-cli.md` | 2, 8, 9 | seam replaced by the registry (`PanelSpec(id='unified', tabify_with='evidence')`; `match_override`, `navigator_stack`, `show_external_pair` come from F5); tooltip ids via spec `tips`; threads via `TaskRunner` |
| `docs/specs/ui.md` | new paragraph | panels, themes, palette, F6, layout reset, announcements, the ASCII glyph rule, modal dialogs versus docks, the two recorded exceptions |
| `docs/specs/series-window.md`, `gui-preflight-inspection.md` | architecture | migrate to docks (M3) |
| `docs/specs/workbench/README.md`, `kb-patch-search-ui-cli-contract.md` | integrator | "single workbench dock" becomes independent registry panels; the KB wizard stays a modal dialog, results go to docks |
| `docs/modules.md` | append `### [GUI:framework]` | rows: gui pure core (`gui/{anchors,projection,ports,registry,capabilities,state,text,theme_math,shortcuts,cli}.py`, `panel_manifest.py`), gui.qt runtime (`tasks,settings,announce,metrics,runtime`), widgets (`labels,state_view,chips,table,codediff,canvas,theme`), host (`host,docks,layout,commands,palette`), each with dependencies and tests |
| `docs/qa.md`, `tasks/todo.md` | append; `qa.md` L111 | the gates above and the manual rows; "A1 `--help` for all seven commands" -> "for every registered command (`names()`)" |
| `docs/specs/windows-acceptance-and-milestone-builds.md` | 3 | add M19-M28 below |
| `docs/plans/program-e-roadmap.md` | 5 | "tooltips and accessibility names registered" = `panels check` and `a11y_audit` pass |
| `docs/plans/phase-d-build-coordination.md` | 1 (L23) | `ui.py`, `tooltips.py`, `tests/test_tooltips.py` and `panel_manifest.py` are frozen after F5, and `cli.py` and the `COMMANDS` lists of `tools/frozen_smoke.py` and `tests/test_acceptance_smoke.py` after F1b (the per-track hook budgets become obsolete); "CLI: new command = own dispatcher module + a hook of at most 6 lines in `cli.py`" -> "a new verb = `cli_commands/<verb>.py`" |
| `docs/plans/unified-engine-plan.md` L41, `unified-engine/01-architecture.md` L162, `07-ui-and-cli.md` L91, `kb-patch-search-ui-cli-contract.md` L10 and C02, `workbench-search-graph-floss-implementation.md` L126 | CLI | "`COMMANDS += (...)` plus dispatch" and "reserve commands" become the adapters `cli_commands/{unified,patch,search,graph,strings}.py` (the file is the reservation); `unified` may merge its S0b hook first (the registry ignores it) and move later |
| the eleven sibling plans (CAP, DIE, KB, KEV, LBL, PIL, WB1, WB2, WB3, WBQ, YRX) | 8, 9, 10 (CLI hook) | each "hook of at most 6 lines in `cli.py`" and each `frozen_smoke` `COMMANDS` line becomes one adapter file; PIL's `intelligence` hook (K2) may merge first and move later |
| `docs/specs/program-e/{KB,PIL,WB1,WB2,DIE,CAP,KEV,YRX,LBL,WBQ}-integration-plan.md` | 8 (accessibility) | ten plans rely on "empty accessible name, `setText` announces" and DIE also on `Alert`: use `ctx.announce` (F6, F7); drop the `<id>/geometry` keys (the host stores layout); dock objectName is `<id>.dock` |
| `{KB,CAP,KEV}-integration-plan.md` | 8 (shortcut) | all three ask for Ctrl+Shift+K: KB keeps K, CAP uses A, KEV uses X (fixed in the manifest stubs) |
| `CAP-integration-plan.md` | 8, 9 (CAP-6a) | ids `capabilities.*`, teach `cap.*` -> `capabilities.*`; `create_panel(ctx)` in `ui_capabilities.py`; the `tooltips.py` block and the 12-line seam become `PANEL.tips`; the tree model stays feature-owned (open question 14) |
| `DIE-integration-plan.md` | 8, 9 (D5, D7) | id `build_env`; `buildenv/group_last` -> `build_env/group_last`; teach `build.*` -> `build_env.*`; `PreflightBanner` posts through `ctx.shell.notice`; `area='none'` until the card moves into a dock; `tooltips_buildenv.py` becomes `PANEL.tips` |
| `YRX-integration-plan.md`, `WB2-integration-plan.md` | 8 (placement) | "page or tab in the shared Workbench dock" -> independent panels `rules` and `graph`; YRX `rules_dock` -> `rules.dock` and `teach.rules.*` -> `rules.*`; WB2 may build its diagram on `GraphCanvas` (its 2,000-node stock-item cap equals the framework maximum; the edge ceiling of 8,000 is ours) |
| `WB1-integration-plan.md` | 8 (assumed panel interface) | `PanelHost.register(PanelSpec(...))` -> `PANEL = PanelSpec(..., requires=('project',))` in `search/panel.py`; `ProjectPort.navigate(locator)` -> `NavigationPort.navigate(AnchorRef)`; `ThreadRegistry` -> `ctx.tasks.lane`; `ShortcutPolicy.claim` -> the manifest; `accessibleIdentifier` = tip id is rule R9 |
| `WB3-integration-plan.md` | 8, 10 (A5, A7, A8) | `show_raw_offset` and the line reveal are in the F5 seam; `register_entries` (A7) is replaced by `PANEL.tips`; the `cli.py` hook (A8) stays with the track |
| `PIL-integration-plan.md` | 8, 10 | `reveal_location(match_id, side, s, e)` = `reveal_lines(function_id, s, e)`; the 20-line seam is replaced by the registry; "visible when a project opens" needs `default_visible` (open question 13) |
| `LBL-integration-plan.md`, `WBQ-integration-plan.md` | 8 | LBL edits `EvidencePanel` while F8 rewrites the controller half of `ui_evidence.py` (the second to merge rebases); WBQ attaches its highlighter to the existing panes through the `compose_selections` and highlighter-slot contracts and its PE panel becomes a tab of `files` (F9) |
| code | see 8.10 and 8.12 | the files listed there; for the CLI registry: `cli.py` (7 touched lines), `tools/frozen_smoke.py` and `tests/test_acceptance_smoke.py` (2 touched lines each) and the new hook `tools/pyinstaller_hooks/hook-patchtrace.cli_commands.py` |

Test plan: no Microsoft binaries and no network; fixtures are `ProjectService.sample`, fake panels, synthetic row generators and the hostile list. Goldens: the dark stylesheet, the state copy table, sorted `panels list --json` (LF through `.gitattributes` for `tests/fixtures/gui/*`). Properties (hypothesis): `sanitize_text` is idempotent, control-free and bounded; manifest validation over random ids and shortcuts; `VirtualTableModel` sort is stable and its filter equals a naive filter; the layout blob round-trips. Windows pitfalls (roadmap checklist plus Qt): CRLF goldens, short parametrize ids, `>=` on the 15.6 ms monotonic clock and `waitUntil` instead of sleeps, wheels-only installs, hermetic tests, `QSettings` IniFormat in tests (the native format is the registry), file dialogs through a module-level function, floating docks closed through `qtbot.addWidget`, offscreen has no UIA or DPI.

Manual or live gates (blocked here, reported separately, never counted as done): M19 NVDA walk (panel names, table reading with units, one announcement per completed search, no description flood); M20 Narrator (Caps Lock+arrows, developer mode Ctrl+Caps Lock+F12, table headers, notification speech); M21 keyboard-only walk (Tab, F6, palette, move a panel without the mouse); M22 each Windows contrast theme (chips legible, focus visible); M23 layout persistence including a floating panel on a second monitor and Reset; M24 100/150/200% and moving between monitors (no clipped chips or rows); M25 Accessibility Insights for Windows FastPass and Live Inspect per panel; M26 a 100k-row table under Narrator (no hang); M27 panel shortcuts while a panel is floating; M28 inspect `PySide6/plugins/styles` in `file-inventory.json` of the frozen package and record which style renders.

## 11. Open questions (a default for each; none blocks the build)

1. FAB's anchor kinds may differ from the closed tuple in `gui/anchors.py`: default = one constant tuple, FAB adapts through `AnchorRef.from_fabric`; nothing else changes. Amended by FAB-0 (2026-10-14): they do not differ; the ten fabric kinds are the names of this tuple verbatim (`match` and `address` stay GUI-only), and `AnchorRef.from_fabric(anchor, run_id, origin)` is a pure function.
2. Flip `accessibleDescription` to the What line for the ~200 existing controls? Default yes in F5 (no test asserts the old text); row M19 confirms; one flag reverts.
3. Default theme for new installs: keep `dark`; `system` is opt-in; high contrast is automatic. A `light` variant is not in the alpha.
4. Command palette in v1: yes, minimal (substring filter, no fuzzy library).
5. Process-wide `sys.setswitchinterval(0.001)`: yes, one constant in `runtime.py`, documented trade-off (worker throughput about -27% [M]).
6. Python-thread `TaskRunner` instead of QThread: yes; the QThread executor is the fallback if Windows CI disagrees.
7. Series window and File overview migration timing: after the first feature wave (F9); until then they are recorded exceptions.
8. Modal dialogs for consented workflows (KB wizard): allowed as children of the main window; results must land in a dock.
9. F6 for panel cycling: yes (a Windows convention, [U] in Microsoft sources); the palette command is always available.
10. CVD simulation test: skip until the Okabe-Ito and Machado sources are reachable from an allowed host; the WBQ plan already validated Machado matrices against `colorspacious` 1.1.2 (MIT) in a test file, so reuse them once merged instead of writing a second set.
11. All [M] numbers come from Linux and CPython 3.13: the F2, F4 and F5 gates re-measure on Windows CI and widen ceilings only with data.
12. Who runs M19-M28 (a named tester on a clean Windows 11 profile): owner decision; they stay `not-run` until recorded. The numbers are provisional: other plans may claim M19 or higher, and the owner renumbers when merging.
13. Default placement and visibility: PIL wants Leads visible when a project opens and most plans tab their dock with Evidence on the right. Default: everything hidden on first run, wide tables at the bottom (8.2); a placement change is one manifest line.
14. Tree, grouped and paged models (CAP, WB2 tree, WB1 `fetchMore`): default feature-owned on the same `assert_lazy_model` gate; promote a `VirtualTreeModel` into the framework when a second panel needs identical code.
15. Consent UIs (KEV inline page, KB plan review, WB3 emulation consent): default feature-owned, modal dialogs allowed (8); each shows the exact request, hosts and size and focuses Cancel by default; promote a shared `ConsentView` when two panels share most of it.
16. Move the seven built-in verbs (and `unified` after S0b) into `cli_commands/`? Default no: they work, share the `common`, `profiled` and `cached` parser helpers, and moving them only risks the `enrichment-cli/1` envelopes; only new verbs use the registry. The registry's frozen behaviour on Windows is [U] until the A1 loop passes in CI.
