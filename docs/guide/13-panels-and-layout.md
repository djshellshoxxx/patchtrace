# 13. Panels, layout, themes and keyboard use

PatchTrace has **one main window**. New features are docks or tabs inside it, never separate application windows (NG-R1 in `docs/specs/non-goals.md`). Dialogs for consented workflows stay modal; their results go to docks. The framework is described in [23](../internals/23-gui-framework.md); this chapter is the user's view.

## The workspace

The central area is fixed: function matches on the left, paired code in the middle, findings and review on the right, and the job log below, separated by splitters. Window size, splitter positions, code font size and scroll-sync are remembered in OS settings. The window opens at 1440 x 900 and has a minimum of 960 x 640.

Around it sit **docks**, one per feature panel. Each dock can be shown or hidden from the **View** menu (grouped by panel group), floated, moved to another side, or tabbed with another dock by dragging.

## Which panels exist today

`patchtrace panels list` is the live answer. At the time of writing (main at `21a005e`): 14 reserved, **5 built**, 9 not built.

| Panel | State | Default area | Shortcut | Opens with |
|---|---|---|---|---|
| Engine evidence (`evidence`) | built, created eagerly | right | Ctrl+Shift+E | View menu |
| Unified (`unified`) | built, needs a project; tabbed with Engine evidence | right | Ctrl+Shift+U | View menu |
| Leads (`leads`) | built | left | Ctrl+Shift+L | View menu |
| Files (`files`) | built, needs a project | bottom | none | Project > File overview, or View menu |
| Series (`series`) | built | bottom | none | Project > Series window..., or View menu |
| Search (`search`) | **planned** | bottom | Ctrl+Shift+F | not available |
| Graph (`graph`) | **planned** | bottom | Ctrl+Shift+G | not available |
| Strings (`strings`) | **planned** (tabbed with Graph) | bottom | Ctrl+Shift+T | not available |
| Capabilities (`capabilities`) | **planned** (tabbed with Graph) | bottom | Ctrl+Shift+A | not available |
| Build environment (`build_env`) | **planned** (tabbed with Evidence) | right | Ctrl+Shift+B | not available |
| Rules (`rules`) | **planned** | right | Ctrl+Shift+R | not available |
| KB (`kb`) | **planned** | right | Ctrl+Shift+K | not available |
| KEV (`kev`) | **planned** (tabbed with KB) | right | Ctrl+Shift+X | not available |
| Guide (`guide`) | **planned** | left | Ctrl+Shift+H | not available |

Source: `src/patchtrace/panel_manifest.py`. A panel that is not built is hidden from the menus. Several of the planned panels have working headless verbs ([16](16-cli-reference.md)) but no dock yet. The Series and Files panels are read-only views; the Series dock keeps one tab per opened `series.json` ([14](14-series.md), [15](15-files-and-pe-overview.md)).

A dock whose `requires` is not met (for example Files and Unified need an open project) stays openable but shows its state in words rather than a blank pane. Panel shortcuts always have the form **Ctrl+Shift+<letter>**; the registry rejects any other form and any collision with the main-window keys.

## Layout commands

| Command | Where | Effect |
|---|---|---|
| Show / hide a panel | View menu, or its Ctrl+Shift shortcut, or the palette | toggles the dock |
| Reset panel layout | View menu | clears the stored layout, restores defaults and announces it |
| Command palette | **Ctrl+Shift+P** (View menu) | searchable list of every panel command and every menu action; at most 50 results; disabled commands show the reason |
| Next / previous panel | **F6** / **Shift+F6** | cycles focus: navigator, code, findings, visible panels, diagnostics |
| Navigate back / forward | **Alt+Left** / **Alt+Right** | steps through your last 50 jumps between panels and code |
| Per-panel commands | palette | Show/Hide, Focus, Float or dock, Move to left/right/top/bottom |

The dock title-bar buttons are not keyboard-focusable, so every panel gets the same four actions in the palette. A panel can jump to a thing in another panel through an **anchor** (function, match, string, import, address, capability, rule, build fact, advisory phrase, CVE, KB or CWE); the result is `shown`, `not-found`, `stale`, `ambiguous` or `blocked`, and a stale link says "The project changed after this link was created. Open it again from the source panel."

The layout is stored in OS settings (`layout/schema`, `layout/state` capped at 64 KiB, and a SHA-256). If the stored blob does not validate, defaults are used and the status line says so (error code `PT-GUI-LAYOUT`). Panel content is built lazily the first time a dock is shown.

## Keyboard reference

| Keys | Action |
|---|---|
| Ctrl+N / Ctrl+O / Ctrl+S | New / Open / Save |
| Ctrl+E | Export |
| Ctrl+R | Rank changes |
| Ctrl+I | Interpret selection (opens the preview first) |
| F5 | Run comparison |
| Esc | Cancel job |
| F1 | Workflow and dependencies (help) |
| Alt+Up / Alt+Down | Previous / next difference |
| Alt+Left / Alt+Right | Navigate back / forward |
| F6 / Shift+F6 | Next / previous panel region |
| Ctrl+Shift+P | Command palette |
| Ctrl+Shift+E, U, L (built) | Engine evidence, Unified, Leads |
| Ctrl+Shift+F, G, T, A, B, R, K, X, H (planned) | reserved for the planned panels above |

The main-window keys are literals in `src/patchtrace/ui.py`; `gui/shortcuts.py` lists them as reserved so a panel cannot claim one. Menus have no Alt-letter mnemonics yet (SPEC-45 audit).

## Themes, high contrast, motion

**View > Theme** offers **Dark** (the default look) and **System** (removes the stylesheet and reads colours from the platform palette). The choice is stored as `theme/variant`.

**High contrast is automatic.** While the platform asks for it (`Qt.ContrastPreference.HighContrast`), colours come from the system palette whatever you chose, chip fills and code-diff tints are dropped, and state is carried by text, glyph and border. The Theme menu then shows a disabled note: "High contrast is on: Windows settings decide the colours". **Reduced motion** from the platform is honoured. The dark token set is checked for contrast ratios by tests (text at least 4.5:1, non-text 3:1; `gui/theme_math.py`).

## Accessibility behaviour

- **Not colour alone.** Every status chip carries text, an ASCII glyph and a shape. Glyphs are plain ASCII.
- **Announcements.** Asynchronous status messages (a run finished, a layout reset) go through one announcer (`StatusAnnouncer`, `ctx.announce`), polite by default and assertive only for blocking errors, because a label's name change reaches Windows UI Automation only while the label is focused. Polite messages are coalesced (latest wins).
- **Plain text for untrusted data.** Function names, strings, advisory text and tool output are shown as plain text; control, bidirectional and zero-width characters are removed or replaced (`hostile_text.py`).
- **Tooltips.** Every functional control has a tooltip from the semantic registry (`tooltips.py`) with What, Why, Effect, Source and Availability. A disabled control states why.
- **Sizes follow the font.** Panel metrics derive from the widget's font (`gui/qt/metrics.py`), not pixel constants, so a larger code font or system font scales the layout. Code font size 8 to 28 points in Setup.
- **Keyboard.** Everything reachable with the mouse is reachable from the keyboard through the palette and F6; tab order is set in the evidence panel and engine setup.

**Known gaps (from the SPEC-45 audit at `fd6cdba`, not re-measured since):** 54 controls in the legacy modules had no explicit accessible name, eight "Browse..." buttons share one name, there are no menu mnemonics, no localisation (all text is literal English), and DPI-change and screen-change handlers are partial. Windows acceptance with NVDA and Narrator, and DPI scaling, are **not done** (ledgers A and D list them as open). Treat the accessibility baseline as in progress. Spec: `docs/specs/accessibility-baseline.md`.

Next: [14 Series](14-series.md).
