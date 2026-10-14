# Accessibility, keyboard, DPI and localization baseline (SPEC-45)

Status: draft, 2026-10-14. Documents only: this file changes no code and no other file. SPEC-45 is a proposed number (`docs/specs/REGISTRY.md` section 1, rule 6); section 11 gives the registry row.

Basis: `main` = `fd6cdba` (GitHub REST, 2026-10-14; the worktree HEAD is the same commit). Open PRs at that time: #40, #41, #43 (docs) and #51 (draft, research). By title, none touches the GUI files named here `[inf]`: the diffs were not read.

Tags: `[decision]` taken; `[proposal]` for the owner to confirm; `[inf]` my inference, not run here; `[unverified]` not confirmed (host blocked, or not read). Source tags `[Q1]` to `[Q10]`, `[M1]` to `[M3]` and `[W1]` are listed in section 14.

## 0. Scope

This file is the application-wide floor: rules that every window, dialog and panel meets, existing or new. It does not restate the panel framework, which is `docs/specs/program-e/GUI-integration-plan.md` section 8 (8.2 registry, 8.6 theming, 8.7 accessibility, 8.8 testability, 8.11 Qt pitfalls). Evidence-panel rules are in `docs/specs/multi-engine-evidence-panel.md` 1.7 and 1.8; tooltip acceptance is in `docs/specs/gui-preflight-inspection.md` Part A. Gate tracking: `docs/qa.md:142` (C8) and `docs/specs/program-e/E6-test-performance-beta-plan.md` section 7, rows O1 to O3. Audit card: `docs/audits/spec-gaps-20261014.md` section 5 row 11, and the app-wide row of section 1c.

Access: on 2026-10-14 the egress proxy answered 403 to CONNECT for `doc.qt.io`, `learn.microsoft.com` and `www.w3.org`. They were not retried or routed around. The Qt and Microsoft facts below come from the upstream source files on `raw.githubusercontent.com`, at the pinned Qt tag and in the Microsoft docs repository; the documentation pages are generated from the same sources `[inf]`. The documentation URLs appear only as `[unverified]` pointers. Research rules: `docs/plans/program-e-research-brief.md` section 3.

## 1. Current state (read at fd6cdba)

| Area | What exists | Gap |
|---|---|---|
| Tooltip registry | `src/patchtrace/tooltips.py:64` REGISTRY, `:1006` TEMPLATES; `apply_tooltip` `:1088-1107` sets toolTip, whatsThis, statusTip, accessibleDescription (`:1104-1105`) and objectName (`:1106-1107`) | never sets an accessible name; objectName is not the Qt accessible identifier |
| Names | 11 explicit `setAccessibleName` calls in `ui.py` (`:735`, `:1637-1680`, `:1759`, `:1767`); `ui_evidence.py:603-871` names the evidence panel; `ui_engine_setup.py:343-346` `_control()` sets tip and name from `ACCESSIBLE_NAMES` | 54 controls with no name in the audited modules (section 2) |
| Status text | empty names by design: `ui_evidence.py:680`, `ui_engine_setup.py:260`, `:282` | no announcer: `src/` sends no Qt accessibility event |
| Keyboard | tab chains `ui_engine_setup.py:322-324`, `ui_evidence.py:882-885`; focus policy `ui_engine_setup.py:202` | no tab chain in `ui.py`; a key-driven test only at `tests/test_evidence_ui.py:237`; a tab-order assertion only at `tests/test_ui_engine_setup.py:479` |
| Shortcuts | `ui.py:1531-1539` `_action()` takes key text; keys at `ui.py:1542-1559`, `:1735-1736`; `ui_evidence.py:1311` | no registry; keys are literals in two modules |
| Mnemonics | none: menu titles at `ui.py:1567`, `:1575`, `:1578`, `:1582` have no `&` | no Alt-letter access to menus |
| Theme | one theme: `DARK_STYLE` `ui.py:95-116`, applied to the whole window at `ui.py:1522` | window stylesheet overrides the palette; no high-contrast path; no handler for a palette or contrast change |
| Font and size | `font-size: 12px` `ui.py:96`; `font-size: 20px` `ui.py:107`; metric-based sizes at `ui_evidence.py:620`, `:888-895`, `ui_engine_setup.py:253`, `:321` | 24 fixed-pixel size calls in `ui.py` (D4) |
| DPI | no `QT_ENABLE_HIGHDPI_SCALING`, `QT_SCALE_FACTOR`, `AA_*` or DPI manifest outside `docs/` (grep) | Qt 6 default applies (D1) |
| Screen change | start-up clamp only, `ui.py:3105-3117` | no handler for DPR, screen or palette change; `ui_evidence.py:897-900` handles `FontChange` only |
| Icons | no `QIcon` or `QPixmap` in `src/patchtrace` (grep) | none |
| Localization | no `tr(`, `QTranslator`, `QLocale` or `QCoreApplication` in `src/patchtrace` (grep) | all user text is literal |
| Tests | names: `tests/test_evidence_ui.py:266`, `tests/test_ui_engine_setup.py:461-472`; badge contrast `tests/test_evidence_ui.py:453-465`; every main-window control has a tooltip, `tests/test_tooltips.py:188`; `tests/test_evidence_ui.py:349` is DPI-named but checks row height against the font | `tests/test_tooltips.py:105-111` (`audit()`) asserts a description and an objectName on each control it visits, never a name; no test asserts a name on `MainWindow` or on a `ui.py` dialog |

## 2. Gap audit (2026-10-14)

Three things give a control its name. An explicit name (`[Q4]` `qwidget.cpp:11818-11834`, read in `[Q3]` `qaccessiblewidget.cpp:322-326`). The visible text of a QPushButton, QCheckBox, QRadioButton or QAction. The text of a QLabel whose buddy is the control, found among the control's siblings (`[Q3]` `:43-55`, `:332-334`). `QFormLayout.addRow(text, field)` creates that buddy (`[Q5]` `qformlayout.cpp:1340-1351`).

Method: an AST scan of direct Qt constructor calls in `ui.py`, `ui_evidence.py`, `ui_series.py`, `ui_inspection.py`, `ui_engine_setup.py`, `ui_bundle_setup.py` and `tooltips.py`, matched against same-variable `setAccessibleName`. Every flagged line was then read by hand. The script is in the session scratchpad and is not committed. Helper-created widgets and subclasses were found by reading and are counted separately.

| Module | Flagged | No name | Named by buddy or own text |
|---|---|---|---|
| `ui.py` | 55 | 34 (32 flagged, plus 2 `ArtifactPathEdit` subclass fields), and 10 `plain_view()` viewers | 20 by form buddy; 3 by own text (`:780`, `:1429`, `:1532`) |
| `ui_series.py` | 11 | 9 (`:202`, `:205`, `:207`, `:212`, `:215`, `:226`, `:237` x2, `:255`) | 2 status labels (`:221`, `:230`): empty by rule, not announced |
| `ui_evidence.py` | 1 | 1 (splitter `:728`) | none |
| `ui_engine_setup.py` | 4 | 0 | the 4 hits are named by `_control()`: scan false positives |
| other GUI modules | 0 | 0 | none |

Unnamed `ui.py` controls:
- No label relation (25): `:325`, `:333`, `:368`, `:986`, `:1288`, `:1355`, `:1598`, `:1599`, `:1611`, `:1704`, `:1709`, `:1713`, `:1718`, `:1741`, `:1782`, `:1788`, `:1790`, `:1796`, `:1809`, `:1817`, `:1821`, `:1828`, `:1831`, `:2799`, `:2815`.
- Nested in a row container whose label is the container's buddy, so the field has no buddy (9): `ArtifactPathEdit` at `:232` and `:233`, and `:234`, `:354`, `:764`, `:1000`, `:1001`, `:1002`, `:1414`.
- Helper `plain_view()` viewers (10; the helper at `ui.py:159-164` sets no name): `:192`, `:375`, `:1043`, `:1290`, `:1291`, `:1292`, `:1439`, `:1618`, `:1758`, `:1804`.

Other findings:
- Eight buttons share the name "Browse…" (`ui.py:244` x3, `:359`, `:1012` x3, `:1420`): one name, eight targets.
- The detector checkbox is named "enabled" on every row (`ui.py:763`).
- Accessible descriptions carry all five tooltip fields, flattened, rather than the What line the GUI plan asks for (GUI plan 8.7). `plain_description()` renders What, Why, Effect, Source and Availability (`tooltips.py:30-37`, `:1054-1056`), and `apply_tooltip` sets that text (`:1099`, `:1104-1105`).
- `plain_tip()` returns HTML (`ui.py:144-146`). It is passed to `setToolTip` on two `PlainLabel`s (`ui.py:591`, `:1995`). Qt uses the tooltip as the description when none is set (`[Q3]` `:336-341`), so these two would expose markup `[inf: not run]`.

## 3. Accessible names and roles

R-N1 MUST every focusable control has an explicit name, set with `setAccessibleName`: at most 80 characters, a noun phrase, unique among its siblings, and naming its target (GUI plan 8.7, R1). Exempt: QPushButton, QCheckBox, QRadioButton and QAction whose visible text is the name. Form-row buddies stand in for the name only in code that exists today (section 12, question 3); new code sets the name. UI Automation exposes it as the `Name` property `[M3]` (line 33).
R-N2 MUST names be unique within a window. The eight "Browse…" buttons and the per-row "enabled" boxes fail this. The target goes into the name, for example "Browse for the older artifact".
R-N3 MUST every name, description and tooltip be user-visible text that goes through the string module (section 10). Qt's docs say accessible names and descriptions have to be localized `[Q4]` `:11832`, `:11864`.
R-N4 MUST status text that changes at run time keep an empty name, so that `setText` raises `NameChanged` (`ui_evidence.py:680` documents this). Its text is announced through one announcer (GUI plan 8.7). Qt 6.12 provides `QAccessibleAnnouncementEvent`, with a Polite default `[Q6]` `:654-660`. Nothing in `src/` sends one, so the status labels at `ui_series.py:221`, `:230` and `ui_engine_setup.py:260`, `:282`, and the evidence status label (comment at `ui_evidence.py:680`), stay silent on completion.
R-N5 MUST an accessible description be one plain line of at most 160 characters: the What line (GUI plan 8.7). Today it is the full five-field text (section 2). Tips reach widgets only through `apply_tooltip`, never as a raw `setToolTip(plain_tip(...))` (`ui.py:591`, `:1995`).
R-N6 SHOULD a registry-backed control set `QWidget.accessibleIdentifier` to its registry id `[Q4]` `:11889-11898` ("since 6.9"), as well as `objectName` (`tooltips.py:1106-1107`). The mapping to the UIA AutomationId on Windows is `[unverified]` and is checked at AX-M3.
R-N7 MUST every table and list have a name, and every table have visible headers and cell text roles (GUI plan 8.7, R3). Unnamed today: `ui.py:333`, `:1355`, `:1796`, `:1809`, `:2799`, `:2815`; `ui_series.py:237` (x2).
R-N8 MUST every splitter be named "Panel divider" and every tab bar be named (GUI plan 8.7). Unnamed today: `ui.py:986`, `:1288`, `:1598`, `:1599`, `:1741`; `ui_series.py:255`; `ui_evidence.py:728`.
R-N9 MUST a control's role follow its stock Qt class. A custom-painted item sets `Qt.AccessibleTextRole` (GUI plan 8.7).

## 4. Keyboard-only operation

K1 MUST every command be reachable from the keyboard, by a menu, toolbar, focusable control or registry shortcut. A mouse-only function is not allowed (evidence panel 1.8).
K2 MUST each window and dialog declare its focus chain with `QWidget.setTabOrder` over every focusable control. The call needs both widgets in one window `[Q4]` `:7029-7037`. Chains exist only at `ui_engine_setup.py:322-324` and `ui_evidence.py:882-885`; the `ui.py` windows use Qt's default order.
K3 MUST every focusable control show a visible focus indicator. `DARK_STYLE` (`ui.py:95-116`) has no `:focus` rule, so the platform style supplies the indicator `[inf]`. Checked at AX-M4.
K4 MUST no keyboard trap: Escape closes popups and dialogs without losing typed input `[W1]` 2.1.1 and 2.1.2 `[unverified]`.
K5 SHOULD menu titles and dialog labels carry access keys (`&`). None do today (`ui.py:1567-1582`).
K6 MUST dialogs built by `dialog_buttons()` (`ui.py:167-173`) keep the standard OK and Cancel keys `[inf]`.
K7 MUST each dock and panel have keyboard commands for show, hide, float and move (GUI plan 8.7, "Dock = Pane"). Close and Float are not focusable today, per that finding.

## 5. Shortcut registry

S1 MUST one module own every shortcut: identifier, key sequence, `Qt.ShortcutContext`, owning panel, enabled rule and tooltip identifier. Only that module calls `setShortcut` or builds a `QShortcut`. A QAction's default context is `WindowShortcut` `[Q8]` `:367-371`; the contexts are `WidgetShortcut`, `WindowShortcut`, `ApplicationShortcut` and `WidgetWithChildrenShortcut` `[Q7]` `:1322-1327`. Today twelve keys are set in three places: Ctrl+N, Ctrl+O, F5, Escape, Ctrl+I, Ctrl+E, Ctrl+S, F1 and Ctrl+R (`ui.py:1542-1559`); Alt+Down and Alt+Up (`ui.py:1735-1736`); Ctrl+Shift+E (`ui_evidence.py:1311`).
S2 MUST no two enabled shortcuts share a key sequence in one context. A test fails on a duplicate (GUI plan 8.7, R5).
S3 MUST a window-scope shortcut not take a key that a focused text field needs. Escape is bound to Cancel job at `ui.py:1550` with window scope, and is enabled only while a job runs (`ui.py:2988`, `:3025`). `[inf]` While enabled, Escape can cancel a job while a text field has focus, unless the field refuses the key. A test covers it.
S4 MUST no single letter or digit be a shortcut. Function keys and Ctrl or Alt combinations only.
S5 SHOULD use a standard key where one exists (`QKeySequence.StandardKey`, as `ui_evidence.py:461` does for Copy). The Windows mapping is `[unverified]`.
S6 SHOULD each shortcut appear in its registry tooltip's What line, so sighted and screen-reader users get the same words.

## 6. Contrast and themes

T1 MUST text meet 4.5:1 against its background, or 3:1 for large text, in every theme variant `[W1]` 1.4.3 `[unverified]`. The project's badge test uses the same thresholds (`tests/test_evidence_ui.py:461-465`).
T2 MUST boundaries needed to identify a control (field borders, focus ring, badge outlines) meet 3:1 against adjacent colours `[W1]` 1.4.11 `[unverified]`.
T3 MUST keep the measured baseline. The ratios below for `DARK_STYLE` pairs were computed on 2026-10-14 with the WCAG 2.x relative-luminance formula (script in the scratchpad, not committed; black on white = 21.00 as a check).

| Pair (`ui.py:95-116`) | Ratio | Rule | Result |
|---|---|---|---|
| `#d9e1ec` text on `#161b22` | 13.12 | 4.5 | pass |
| `#97a7ba` muted label on `#161b22` (`:108`) | 7.04 | 4.5 | pass |
| `#d9e1ec` text on button `#253040` (`:99`) | 10.11 | 4.5 | pass |
| `#f1fcff` selected list item on `#21424c` (`:106`) | 10.32 | 4.5 | pass |
| `#6c7684` disabled button text on `#253040` (`:102`) | 2.90 | exempt while disabled `[W1]` `[unverified]` | record |
| `#3b4a5c` button border on `#161b22` (`:99`) | 1.91 | 3.0 | FAIL (T2) |
| `#303b49` text field border on `#10151c` (`:103-104`) | 1.61 | 3.0 | FAIL (T2) |

T4 MUST colour never be the only carrier of state (GUI plan 8.6; evidence panel section 0, rule 7).
T5 MUST the window honour Windows High Contrast. `ui.py:1522` applies `DARK_STYLE` to the whole window unconditionally, so the hard-coded colours stay in high contrast. The GUI plan lists the palette override as a Qt pitfall (8.11). The contrast-preference API is named in GUI plan 8.6 and is `[unverified]` here.
T6 MUST no fixed pixel font size for user text. `font-size: 12px` (`ui.py:96`) and `font-size: 20px` (`ui.py:107`) do not follow the Windows text setting. The code font size (`ui.py:1030`, `:3101-3103`) is the only user-set size. GUI plan 8.6 states that stylesheet pixels are logical pixels `[unverified]` here.
T7 SHOULD colour literals move to one token module (GUI plan 8.6, `ThemeTokens`), and new widget modules contain no hex literal. `ui.py:98` also hard-codes a toolbar colour.

## 7. What automated tests can and cannot prove

- Names and descriptions are testable offscreen with `QAccessible.queryAccessibleInterface(w).text(QAccessible.Text.Name)`. Precedent: `tests/test_ui_engine_setup.py:471`. Tests assert names, never announcements.
- Contrast is testable as a pure function over token pairs (precedent: `tests/test_evidence_ui.py:453-465`).
- Scale: Qt documents `QT_SCALE_FACTOR` as a global factor for all windows `[Q1]` `:168-171`. The offscreen platform takes `logicalDpi` per screen `[Q10]` `:113-128`, `:258-259`, and the per-screen factor is `logicalDpi / logicalBaseDpi` `[Q1]` `:159-161`. `[inf]` A test can therefore emulate 120, 144 and 192 DPI. Each route needs a red test before anything relies on it.
- Offscreen cannot prove NVDA or Narrator output (`QAccessible.isActive()` is False offscreen, `docs/qa.md:142`), DPI rendering, high contrast, or a move between monitors.

## 8. DPI and monitors

D1 MUST keep Qt 6's default high-DPI scaling. It is always on in Qt 6, and only `QT_ENABLE_HIGHDPI_SCALING=0` opts out `[Q1]` `:137-141`. Qt does not round scale factors by default `[Q1]` `:175-176`. Nothing in the repository sets an opt-out, `QT_SCALE_FACTOR` or an `AA_` flag (section 1).
D2 MUST the frozen Windows build run Per-Monitor V2. The Qt 6.12 Windows plugin defaults to `PerMonitorVersion2` `[Q2]` `:199` unless `dpiawareness=` is given `[Q2]` `:170-171`, and it logs the effective awareness under a debug category `[Q2]` `:215-217`. AX-M5 records that log line. In Per-Monitor V2 the window is told of each DPI change and is not bitmap-scaled `[M1]` ("Per-Monitor and Per-Monitor (V2) DPI Awareness").
D3 MUST layouts hold at 100, 125, 150 and 200 percent (DPI 96, 120, 144 and 192, `[M2]` table). New layout code uses font metrics, the pattern at `ui_evidence.py:620` and `:888-895` and `ui_engine_setup.py:253` and `:321`.
D4 SHOULD move the fixed-pixel sizes: 24 in `ui.py` (lines 190, 224, 317, 376, 984, 1281, 1345, 1409, 1520, 1521, 1614, 1674, 1720, 1800, 1801, 1806, 1810, 1811, 1823, 1830, 1854, 2789, 2802, 2803) and one in `ui_series.py:282`. The start-up clamp at `ui.py:3112-3113` uses the available screen and stays.
D5 MUST the window re-lay out when it moves to a monitor of another scale. Qt's Windows window applies the suggested geometry from `WM_DPICHANGED` `[Q9]` `:2151-2176`. No handler in `src/` reacts to a DPR, screen or palette change (section 1), so AX-M5 is the only check that would show a clipped layout.
D6 MUST no 1x-only bitmaps. `src/patchtrace` has no `QIcon` or `QPixmap` today. A new icon is vector, or ships at 1.25, 1.5 and 2 times scale.
D7 MUST the start-up clamp be the only main-window size rule for now. `ui.py:3112-3113` caps the minimum size, 960 by 640 (`ui.py:1521`), to the available screen, once, at start-up. `[proposal]` The owner decides whether a 1366 by 768 panel at 125 percent must show the full UI; AX-M5 records the answer.

## 9. Manual acceptance walk

Every row below is an owner or Windows-only gate that automated tests cannot close. The sandbox has no Windows desktop and no assistive technology, so every gate is open. Record each result in `docs/qa.md`: app build SHA, Windows build, display scale, theme, assistive-technology name and version, date, and pass or fail per step. The gates map to C8 (`docs/qa.md:142`) and to E6 rows O2 and O3.

| Gate | Owner-run steps | Pass criteria |
|---|---|---|
| AX-M1 NVDA (version recorded) | Main window menus, toolbar, Setup, Evidence dock and Series window: Tab through each; run a sample job, cancel it, reopen | every control speaks name, role and state; no unnamed control reached; start, done, failed and cancelled are announced |
| AX-M2 Narrator (Windows build recorded) | same scope and steps, in Narrator scan mode | same as AX-M1 |
| AX-M3 Accessibility Insights for Windows | FastPass on each window; Inspect on each registry-backed control | no failure; Inspect shows name, role and identifier (R-N6) `[unverified]` tool version and assessment names |
| AX-M4 Keyboard only | no mouse for all menus, dialogs, panels and jobs | no trap; focus visible at every step; order matches K2 |
| AX-M5 DPI | 100, 125, 150 and 200 percent on one display; move a window between a 100 percent and a 150 percent monitor; read the awareness log (D2) | no clipped or hidden control; window stays usable; log shows Per-Monitor V2 |
| AX-M6 High contrast | Windows High Contrast black and white themes | every window readable; no state carried by colour alone |

## 10. Localization

L1 `[decision]` English-only in the alpha. There is no translation layer (section 1), and all copy is English.
L2 `[proposal]` One module owns all user-visible text: labels, button and action text, menu and tab titles, status text, accessible names and tooltip text. Proposed name `src/patchtrace/ui_text.py`, new; no existing file changes in the first slice. Widget modules import keys from it. A lint test fails on a string literal in a `ui*.py` module passed to `setText`, `setToolTip`, `setTitle`, `setAccessibleName`, `setPlaceholderText` or `QAction(`.
L3 `[proposal]` Keys are stable identifiers such as `menu.project` and `browse.older_artifact`, with English values. When a translation ships, the module wraps `QCoreApplication.translate`; widgets do not change.
L4 `[proposal]` The `tooltips.py` REGISTRY keeps its identifiers. Its text moves into the module in a later slice, because `tooltips.py` is shared and its changes go through the integrator.

## 11. Integrator asks

- Add this row to `docs/specs/REGISTRY.md`, Table A. `tests/test_spec_registry.py` fails for any file under `docs/specs/` that REGISTRY does not cite by its backticked path (REGISTRY section 1, rule 7).

```text
| `docs/specs/accessibility-baseline.md` | SPEC-45 (title) | SPEC-45 (proposed) | draft | none; owners are ui.py, ui_evidence.py, ui_engine_setup.py, tooltips.py | Application-wide floor; AX-M1 to AX-M6 open (owner, Windows) |
```

- Numbering: REGISTRY section 1, rule 4 names SPEC-41 as the next free number, and `docs/specs/program-e/GDE-integration-plan.md` proposes SPEC-41. The owner keeps SPEC-45, as requested and marked proposed, or picks SPEC-41.
- No other file was edited. The fixes in sections 3 to 8 touch `ui.py` and `tooltips.py`, which the worker brief lists as shared files (`docs/plans/worker-brief.md`, section 3, on `origin/claude/instance-b-features`). They go to the integrator as separate slices.

## 12. Open questions (default in brackets)

1. Number: SPEC-45 as requested, or SPEC-41 under REGISTRY rule 4 [SPEC-45, marked proposed; owner confirms].
2. English-only for the alpha [yes, L1].
3. Form-row buddy names on existing controls [allowed until a test enforces R-N1; new code sets names].
4. A 1366 by 768 panel at 125 percent [keep the clamp, D7; owner confirms at AX-M5].

## 13. Items marked [unverified]

- `[W1]` WCAG 2.2 normative text. w3.org returned 403, and the upstream `w3c/wcag` understanding path tried returned 404. The thresholds (4.5:1, 3:1) and SC numbers used here are the project's own tested values (`tests/test_evidence_ui.py:461-465`), not the standard text.
- `[Q-doc]` `doc.qt.io/qt-6/highdpi.html` and `accessible.html` returned 403. The facts used come from the Qt 6.12 source.
- `[M-doc]` The `learn.microsoft.com` pages returned 403. The facts used come from the MicrosoftDocs/win32 source files. The source path of the high-contrast page was not found.
- The UIA AutomationId mapping of `accessibleIdentifier` on Windows (R-N6).
- Form-row buddy names at run time: source read, not run (R-N1).
- Escape reaching the window shortcut through a focused QLineEdit (S3); the focus outline under `DARK_STYLE` (K3); and markup exposure through `plain_tip` (section 2). All `[inf]`.
- Stylesheet pixels are logical (T6), and the contrast-preference API name (T5): both are GUI plan 8.6 statements, not re-verified in qtbase here.
- Tool and assistive-technology versions (AX-M1 to AX-M3) are not pinned.

## 14. Sources (all retrieved 2026-10-14)

- `[Q1]` https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/gui/kernel/qhighdpiscaling.cpp
- `[Q2]` https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/plugins/platforms/windows/qwindowsintegration.cpp
- `[Q3]` https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/widgets/accessible/qaccessiblewidget.cpp
- `[Q4]` https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/widgets/kernel/qwidget.cpp
- `[Q5]` https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/widgets/kernel/qformlayout.cpp
- `[Q6]` https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/gui/accessible/qaccessible.h
- `[Q7]` https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/corelib/global/qnamespace.h
- `[Q8]` https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/gui/kernel/qaction.cpp
- `[Q9]` https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/plugins/platforms/windows/qwindowswindow.cpp
- `[Q10]` https://raw.githubusercontent.com/qt/qtbase/v6.12.0/src/plugins/platforms/offscreen/qoffscreenintegration.cpp
- `[M1]` https://raw.githubusercontent.com/MicrosoftDocs/win32/docs/desktop-src/hidpi/high-dpi-desktop-application-development-on-windows.md (learn.microsoft.com/en-us/windows/win32/hidpi/high-dpi-desktop-application-development-on-windows)
- `[M2]` https://raw.githubusercontent.com/MicrosoftDocs/win32/docs/desktop-src/hidpi/wm-dpichanged.md (learn.microsoft.com/en-us/windows/win32/hidpi/wm-dpichanged)
- `[M3]` https://raw.githubusercontent.com/MicrosoftDocs/win32/docs/desktop-src/WinAuto/uiauto-uiautomationoverview.md (learn.microsoft.com/en-us/windows/win32/winauto/uiauto-uiautomationoverview)
- `[W1]` https://www.w3.org/TR/WCAG22/ `[unverified]`: not reached (proxy 403, 2026-10-14)
