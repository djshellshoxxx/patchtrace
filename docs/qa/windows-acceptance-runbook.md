# Windows acceptance runbook (C8 and the manual part of RB-05)

Status: draft runbook, 2026-11-04, written at base `9451d7e`. Nobody has run it yet. Every result in the receipt (section 6) is `not-run`.

This is the operator procedure. A named tester follows it on a clean Windows 11 profile to run and record every manual gate for accessibility, DPI, contrast and screen readers. The check tables are not copied here. They stay in the specs, and each step names the row it serves:

- M01 to M28: [Windows acceptance spec, section 3](../specs/windows-acceptance-and-milestone-builds.md#3-manual-acceptance-checklist-clean-windows-11-profile), which has the steps, the expected results and the record table.
- AX-M1 to AX-M6: [SPEC-45, section 9](../specs/accessibility-baseline.md#9-manual-acceptance-walk), with the rules it checks in sections 3 to 8 (R-N, K, S, T and D).
- Draft steps and the known Qt bugs: [Qt accessibility research, sections 2 and 3](../research/qt-accessibility-windows.md#3-recommended-manual-checklist-steps).
- What NVDA and Narrator need, and the gate list: [GUI plan 8.7](../specs/program-e/GUI-integration-plan.md#87-accessibility) and the manual-gate paragraph at the end of section 10 of that plan.
- The open tracker lines: the C8 paragraph of [docs/qa.md](../qa.md) and [tasks/todo.md](../../tasks/todo.md). Section 5 maps each line to a step.

RB-05 is the release-blocker row "clean Windows GUI analyst journey". It is defined, with the receipt template that section 6 follows, in `docs/plans/release-blockers.md` on branch `docs/post-consolidation-gap-analysis-20261030`. That file is not on this base, so it is not linked here.

## 1. Scope and the evidence rule

**Automated evidence never stands in for a manual gate.** The automated gates run offscreen. They have no UI Automation client, no screen reader, no real DPI and no high contrast ([SPEC-45 section 7](../specs/accessibility-baseline.md#7-what-automated-tests-can-and-cannot-prove)). A green automated run is a prerequisite. It goes in the receipt's `automated` block and never sets an M or AX result. The automated gates are:

- [`tools/journey_gate.py`](../../tools/journey_gate.py): the RB-05 analyst journey, offscreen, with a fake backend. It runs in the `qa` job of [`qa-windows.yml`](../../.github/workflows/qa-windows.yml) on both operating systems.
- [`tools/qt_gate.py`](../../tools/qt_gate.py): the GUI test files repeated in one session (`qt-gate` job; the Windows leg runs 5 repeats).
- `python -m patchtrace panels check` (`qa` job): manifest slot, shortcut and spec conflicts.
- G3 ([`tests/test_gui_theme_variants.py`](../../tests/test_gui_theme_variants.py)): the real `QtSystemPrefs` notifies on an application palette change, and the System variant re-reads its tokens from the new palette. Offscreen ignores `QStyleHints.setColorScheme`, so the OS light and dark switch is checked only by hand, at R-CM5.
- Reduced motion: [`theme.py`](../../src/patchtrace/gui/qt/theme.py) turns off the menu, combo, tooltip and tool box animations when Qt reports reduced motion. `src/` has no custom animation, so no other motion code exists to check. R-CM1 checks what Windows actually delivers.

Recording rules (spec section 3):

- A result is `pass`, `fail` or `not-run`, and the default is `not-run`. Never prefill a pass.
- Never copy a result to a new SHA. Each build gets a fresh copy of the receipt from this file, never from an earlier record.
- A `fail` links an issue and states what was observed. A step that was not performed stays `not-run`, with the reason in its notes.
- A gate id (M or AX) is a pass only when every step that lists it is a pass. Steps marked "C8 only" close tracker lines and no gate id.

Keystrokes come only from repository sources, and each one is cited where it is used. Any other keystroke, settings path or tool path is marked **[unverified]**. Confirm it on the test machine before the run, and write what worked in the step's notes.

Out of scope:

- Live engines: real BinDiff `bindiff.exe` (tracker line 151) and assembly from a real SPEC-31 `insns.text` (line 422).
- Windows CI runs and timing budgets (lines 422, 508 and 696). These are automated, belong to the `qa` and `qt-gate` jobs, and are recorded with their run URL.
- The IME rows that research section 2 proposes. They have no M id yet.

## 2. Prerequisites

1. **Machine**: the clean profile from spec section 3, Setup 1 and 2: Windows 11 x64, no Python, Java, Ghidra or Ghidriff, and Defender real-time protection on.
2. **Displays**: two monitors whose scale can be set to 100 % and 150 %, for M23, M24 and AX-M5. With only one monitor, the monitor-move parts stay `not-run` and the notes say why.
3. **Assistive technology**: install NVDA and Accessibility Insights for Windows. Narrator is part of Windows.
4. **Package**: get the ZIP of the build under test. Verify its SHA-256 with the PowerShell block in [spec section 1.3](../specs/windows-acceptance-and-milestone-builds.md#13-verification-after-each-release). Extract the whole ZIP to `%USERPROFILE%\Downloads\PatchTrace` (spec section 3, Setup 3).
5. **Panel list**: in PowerShell, from the package folder, run `.\PatchTrace.exe panels list` and keep its output. It names every panel with its area, its tabbed partner and its `Ctrl+Shift+<letter>` shortcut. R-SR1, R-KB3 and R-FD1 use it. Whether the verb answers in the frozen build is **[unverified]**. If it does not, list the panels from the View menu.
6. **Data**:
   - Most steps use the built-in Sample (M02).
   - M14 and M15 need a configured native runtime, as their spec rows say.
   - M26 needs a project with a 100,000-row table. That is the table cap: above it the GUI shows the too-large state ([`tests/test_gui_table.py`](../../tests/test_gui_table.py)). No repository tool builds such a project for the frozen app on a clean profile, so record where the project came from.
   - Without the data a step needs, that step stays `not-run` with the reason.
7. **Evidence to keep** (research section 3): a screen recording or audio notes, the NVDA log, the Narrator developer-mode tree export and the Accessibility Insights reports. Keep the files outside the repository and link each one from the receipt.

## 3. Run header

Fill these in before the first step. They go to the receipt's top-level keys and its `run` and `assistive_tech` blocks.

| Field | Where to read it | Receipt key |
|---|---|---|
| Windows build | `winver` (spec section 3, Setup 2) | `run.windows_build` |
| Display scale | Per monitor. Settings, System, Display **[unverified]** | `run.scale` |
| Monitors | Count, with each monitor's scale and resolution | `run.monitors` |
| Theme | The Windows theme or contrast theme at the start | `run.theme` |
| App SHA | The 40-character commit. Take it from the release notes `Commit:` line (spec section 4). The EXE version resource `Comments` reads `Unsigned build of commit <sha>` ([`check_windows_exe.py`](../../tools/check_windows_exe.py)). Read it with `(Get-Item .\PatchTrace.exe).VersionInfo.Comments` **[unverified]** | `head_sha` |
| ZIP SHA-256 | The `Get-FileHash` value from prerequisite 4 | `artifact_sha256` |
| Qt and PySide6 | `dependency-versions.json` in the package folder (spec section 1.3) | `run.pyside6` |
| NVDA version | NVDA's About dialog **[unverified]** | `assistive_tech.nvda` |
| Narrator build | The same as the Windows build | `assistive_tech.narrator_build` |
| Accessibility Insights version | The tool's About dialog **[unverified]** | `assistive_tech.accessibility_insights` |
| Tester and date | The tester's full name, and the date as ISO 8601 | `run.tester`, `run.date` |

## 4. Procedures

Each step names the gate ids it serves. Where this text and a spec row differ, the spec row's expected result wins, and the difference is a finding.

Panel names below are the manifest titles, and shortcuts come from [`gui/shortcuts.py`](../../src/patchtrace/gui/shortcuts.py) and the panel list:

| Panel | Shortcut |
|---|---|
| Engine evidence | Ctrl+Shift+E |
| KB and CVE | Ctrl+Shift+K |
| Leads | Ctrl+Shift+L |
| Calls | Ctrl+Shift+G |
| Search | Ctrl+Shift+F |
| Build environment | Ctrl+Shift+B |

### 4.1 Screen readers (M19, M20, AX-M1, AX-M2)

Every asynchronous message goes through `StatusAnnouncer`, as a polite `QAccessibleAnnouncementEvent` aimed at the status bar. Only blocking errors are assertive (GUI plan 8.7). Qt drops announcements until a UI Automation client has queried the app (research section 2), so the first announcement after launch is checked at R-SR8.

#### R-SR1 NVDA panel walk (M19, AX-M1)
1. Start NVDA. **[unverified]**: the start key. Research section 3 gives Insert or Caps Lock as the NVDA modifier and marks it [U].
2. Start `PatchTrace.exe` and open the Sample.
3. Using Tab and the arrow keys (spec M19), walk these:
   - the main-window menus and toolbar
   - the Setup dialog
   - every panel in the panel list (show a hidden panel from the command palette, Ctrl+Shift+P)
   - the Series window
4. For each panel, note whether its name is spoken, and the name, role and state of each control. Note any unnamed control, whether the dock tab names of tabbed panels are spoken, and whether splitters read as "Panel divider" (SPEC-45 R-N8).

Expected: spec M19 and the first AX-M1 criterion. A description is one line, the What line of at most 160 characters, and is not read in full on every focus (GUI plan 8.7, R2).

#### R-SR2 NVDA search and results table (M19)
1. In Search (Ctrl+Shift+F), run one search.
2. Move through the results with the arrow keys.
3. Read the table role and the row and column position with NVDA object navigation. **[unverified]**: the key (research section 3 marks it [U]).

Expected: exactly one announcement when the search completes, not one per progress tick. Each cell is read with its unit and its column header, and the vertical header is silent (research section 3).

#### R-SR3 Job announcements (AX-M1)
1. On the Sample, start Run comparison (F5).
2. Cancel the job with Escape (Cancel job).
3. Reopen the project with Ctrl+O. The keys come from `RESERVED` in [`gui/shortcuts.py`](../../src/patchtrace/gui/shortcuts.py).

Expected: start, done, failed and cancelled are each announced once (AX-M1). Without a native runtime the job may stop at the backend check. Record which states were reached. A state that was not reached is noted in the step's notes, and the step stays `not-run` until every state has been heard.

#### R-SR4 Status label (C8) and the two engine-setup status lines (M19, AX-M1)
1. Show Engine evidence (Ctrl+Shift+E) and change what it shows: select another match row, or press Refresh.
2. Open the BinDiff setup section of engine setup, press Probe BinDiff, then press Validate .BinExport files.

Expected: each new text of the status line is spoken once without moving focus. The status line is the `evidence_status` label. It keeps an empty accessible name so that `setText` announces; see [`ui_evidence.py`](../../src/patchtrace/ui_evidence.py) and SPEC-45 R-N4. The same holds for `engine_setup_probe_status` and `engine_setup_validation_status` (tracker line 151).

#### R-SR5 Notice strip (M19)
1. Bring up a window notice. KB and CVE (Ctrl+Shift+K) posts its coverage notice once leads are loaded, and Build environment (Ctrl+Shift+B) posts its banners.
2. Tab to the strip, then press Details, then Dismiss.

Expected: the notice text is spoken once when it appears. The strip is named "Notices", and its buttons are read as "Show notice details" and "Dismiss notice" ([`state_view.py`](../../src/patchtrace/gui/qt/state_view.py)). A dismissed notice stays silent until its text changes. If neither panel shows a notice on the Sample, the step stays `not-run` and the notes say so.

#### R-SR6 'Line changes' label (M19)
1. Open a changed function pair in the code panes.
2. Put the caret in the older pane and move it with the Up and Down arrows over changed and unchanged lines.
3. Step with Alt+Down and Alt+Up (Next and Previous difference, `RESERVED`).

Expected: the label named `Line changes` ([`codetext_view.py`](../../src/patchtrace/codetext_view.py), `LABEL_NAME`) speaks its sentence once each time the sentence changes. It does not repeat an unchanged sentence, and it says nothing on a line with nothing to report. Colour and underline are not announced; this sentence is the spoken equivalent.

#### R-SR7 KB, Leads and Calls status lines (M19)
1. KB and CVE (Ctrl+Shift+K): load the panel. Each change of its state strip text is spoken once.
2. Leads (Ctrl+Shift+L): press Prepare leads, then Refresh. The headline (`leads.headline`) is announced once per change, and the error state L5 is announced assertively, interrupting speech ([`ui_leads.py`](../../src/patchtrace/ui_leads.py)).
3. Calls (Ctrl+Shift+G): focus the graph. Move between nodes with the arrow keys, open one with Enter, and zoom with + and - ([`canvas.py`](../../src/patchtrace/gui/qt/canvas.py)). Each focused node is announced politely (tracker line 508).

Expected: each status text is spoken once, and unchanged text is not repeated.

#### R-SR8 Narrator walk (M20, AX-M2)
1. Start Narrator with Ctrl+Win+Enter (research section 3).
2. Move with Caps Lock+arrows (spec M20). **[unverified]**: the scan-mode key.
3. Turn on developer mode with Ctrl+Caps Lock+F12 to read the UIA tree (spec M20). Export the tree **[unverified]**.
4. Straight after launch, make the first announcement happen, for example by opening the Sample. Confirm that it is spoken (research section 4, item 3).
5. Repeat R-SR1 to R-SR7 under Narrator, reading each panel's table headers.
6. Make one notification happen, for example an export with Ctrl+E, and confirm that it is spoken once.
7. Move focus into a second panel and back.

Expected: spec M20 and AX-M2. A pass under one reader never stands for the other (research section 2).

### 4.2 Keyboard (M21, M27, AX-M4)

#### R-KB1 Keyboard-only walk (M21, AX-M4)
1. Unplug the mouse or turn off the touchpad (research section 3).
2. Tab through every control of every panel, the menus, the Setup dialog and the Series window. **[unverified]**: the key that reaches the menu bar.
3. Open one native file dialog from a Browse button, and close it with Escape.
4. Cycle the panels with F6 and Shift+F6 (spec M21). The order is: navigator, code, findings, the visible panels by focus order, diagnostics ([`host.py`](../../src/patchtrace/gui/qt/host.py), `cycle_focus`).
5. Open the palette with Ctrl+Shift+P (spec M21). Run "Focus <Title> panel" and "Show <Title> panel" or "Hide <Title> panel" ([`commands.py`](../../src/patchtrace/gui/qt/commands.py)).
6. Move one panel with the palette command "Move <Title> panel to the <area>".
7. Start a job. Press Escape with a text field focused, and record whether the job is cancelled (SPEC-45 S3).
8. In each popup and dialog, check that Escape closes it without losing typed input (SPEC-45 K4).

Expected: spec M21 and AX-M4. Every control is reachable, there is no trap, and focus is visible at every stop (K3). The declared tab orders of engine setup and Engine evidence hold (K2).

#### R-KB2 Main-window shortcuts (AX-M4)
Press each key and check that it runs its command. The keys are in [`gui/shortcuts.py`](../../src/patchtrace/gui/shortcuts.py), `RESERVED` and `FRAMEWORK`:

| Key | Command |
|---|---|
| Ctrl+N | New |
| Ctrl+O | Open |
| Ctrl+S | Save |
| Ctrl+E | Export |
| Ctrl+I | Interpret selection |
| Ctrl+R | Rank changes |
| F1 | Workflow and dependencies |
| F5 | Run comparison |
| Escape | Cancel job |
| Alt+Up and Alt+Down | Previous and Next difference |
| Alt+Left and Alt+Right | Navigate back and forward |

Expected: each key does the command it names. Record any key that does nothing, or does something else.

#### R-KB3 Panel shortcuts while floating (M27)
1. Float each panel that has a shortcut in the panel list with the palette command "Float or dock <Title> panel".
2. Press its `Ctrl+Shift+<letter>` and the shortcut of one other panel, first with the floating panel focused and then with the main window focused.

Expected: spec M27.

### 4.3 Contrast and motion (M11, M22, AX-M6)

Run this whole group with Settings, Accessibility, Visual effects, Animation effects off. Tracker line 530 names the page, and research section 3 marks the path [U], so it is **[unverified]**.

#### R-CM1 Visual effects off (M22)
1. Turn animation effects off before launch.
2. Open a menu, a combo box popup and a tooltip.

Expected: nothing animates or fades in. Whether Windows passes this setting to Qt's motion preference is open (research section 5, question 1). Record what is seen.

#### R-CM2 High contrast on and off while running (M11)
1. Settings, Accessibility, Contrast themes (spec M11). Apply a contrast theme while PatchTrace runs. **[unverified]**: the toggle shortcut Left Alt+Left Shift+PrtScn (research section 3).
2. Tab through the main controls.
3. Turn the contrast theme off again.

Expected: spec M11. The window drops its dark stylesheet and takes the contrast palette without a restart (GUI plan 8.6). View, Theme shows the disabled note "High contrast is on: Windows settings decide the colours" ([`theme.py`](../../src/patchtrace/gui/qt/theme.py)). Turning contrast off brings back the chosen variant.

#### R-CM3 Every contrast theme, every panel (M22)
1. For each contrast theme that Windows lists, show every panel. Tracker line 530 names Aquatic, Desert, Dusk and Night sky; record the actual list.

Expected: spec M22. Chips stay legible through text, glyph and shape. The focus ring is visible. No hard-coded colour remains. Code-diff hunks are marked by underline, not by tint (`system_tokens`).

#### R-CM4 Black and white high contrast (AX-M6)
1. Repeat R-CM3 for the darkest and the lightest contrast theme. **[unverified]**: which Windows 11 themes match SPEC-45's "black" and "white". Name the themes used.

Expected: AX-M6. The main window, Setup, Series, floating panels and dialogs are all readable, and no state is carried by colour alone (SPEC-45 T4).

#### R-CM5 OS light and dark with the System variant (M22)
1. Choose View, Theme, System.
2. Switch the Windows app mode between light and dark while PatchTrace runs. **[unverified]**: the settings path.
3. Repeat the switch with View, Theme, Dark.

Expected: under System, the colours follow without a restart when the active style supports it (GUI plan 8.6 marks this [U]). Under Dark, nothing changes. This is the only check of the OS colour-scheme signal, because offscreen cannot raise it (section 1, G3).

### 4.4 DPI and monitors (M08 to M10, M24, AX-M5)

In each of R-DP1 to R-DP4:
- Set the display scale (spec M08), launch, open the Sample, use every main tab and show every panel.
- Look at the chips in Leads, KB and CVE, Unified and Engine evidence, and at the code-diff hunk rows.

Expected in each: the matching spec row, with no clipped label, chip or hunk row (SPEC-45 D3).

#### R-DP1 100 percent (M08, AX-M5)
Scale 100 %.
#### R-DP2 125 percent (AX-M5)
Scale 125 %. SPEC-45 D3 and AX-M5 include it; spec section 3 does not.
#### R-DP3 150 percent (M09, AX-M5)
Scale 150 %.
#### R-DP4 200 percent (M10, AX-M5)
Scale 200 %. No control is hidden.

#### R-DP5 Monitor moves and layout restore (M24, AX-M5)
1. With one monitor at 100 % and one at 150 %, move the main window between them.
2. Float a panel and move it to the other monitor.
3. Quit and relaunch (tracker line 520: layout restore across DPI changes).
4. If a 1366 by 768 display at 125 % is available, record whether the full UI shows. This is the owner question in SPEC-45 D7.

Expected: spec M24 and AX-M5. The window stays usable after each move, and the restored layout fits the screen.

#### R-DP6 DPI awareness log (AX-M5)
1. Record the effective DPI awareness of `PatchTrace.exe`. SPEC-45 D2 says Qt's Windows plugin logs it under a debug category (`qwindowsintegration.cpp`, lines 215 to 217). No repository source names the category or how to turn it on, so this is **[unverified]**. A second reading is Task Manager, Details, the DPI awareness column **[unverified]**.

Expected: Per-Monitor V2 (SPEC-45 D2). Keep the log line or a screenshot.

#### R-DP7 Code text glyphs (C8 only)
1. At 100 % and at 200 %, open a changed function pair in the code panes.
2. Check that bold tokens keep their column in Consolas (bold advance width).
3. Check that default-ignorable characters are drawn visibly (`ShowDefaultIgnorables`).
4. Check that the syntax foreground colours are visible on a hunk row.
5. Check that chip glyphs render, with no empty boxes.

Expected: each check holds. Keep a screenshot of each scale. A pixel probe tool is **[unverified]**; compare by eye if none is available.

### 4.5 Accessibility Insights (M25, AX-M3)

#### R-AI1 FastPass on every window and panel (M25, AX-M3)
1. Run Accessibility Insights for Windows FastPass on the main window, the Setup dialog, the Series window and each panel (spec M25).

Expected: spec M25 and AX-M3. Results are recorded per panel, with no unexplained failure.

#### R-AI2 Live Inspect: AutomationId equals accessibleIdentifier (AX-M3)
1. With Live Inspect, read Name, ControlType and AutomationId on registry-backed controls. Each one sets `accessibleIdentifier` to its tip id ([`gui/tips.py`](../../src/patchtrace/gui/tips.py), `apply_tip`).
2. Check at least `gui.notice_details`, `gui.notice_dismiss` and `gui.notice_text` on the Notices strip, plus the action buttons of Leads and of KB and CVE.

Expected: AutomationId equals the tip id and is unique in its window (SPEC-45 R-N6; GUI plan 8.7, R9). Every mismatch is recorded. SPEC-45 lists the Windows mapping itself as unverified, so this step is its first check.

### 4.6 Large table (M26)

#### R-LT1 100,000-row table under Narrator (M26)
1. With Narrator running, open the project from prerequisite 6 and focus the large table.
2. Sort with Alt+Down (ascending), Alt+Up (descending) and Alt+Backspace (default order) on the current column. Move the column with Left and Right ([`table.py`](../../src/patchtrace/gui/qt/table.py), `sort_current_column`).
3. Filter, then move through cells with the arrow keys.
4. With a stopwatch, time the first focus into the table (research section 2: QTBUG-100997).

Expected: spec M26. Nothing hangs, and cells are read on focus. Record the focus latency.

### 4.7 Style plugin (M28)

#### R-SP1 Frozen style plugin (M28)
1. Open `file-inventory.json` in the package folder with a text editor.
2. Record every entry under `PySide6/plugins/styles`.
3. Note which style renders. **[unverified]**: how to tell the styles apart by eye.

Expected: spec M28.

### 4.8 Frozen-EXE dock smoke

#### R-FD1 Frozen-EXE dock smoke (C8 only)
1. Start `PatchTrace.exe` from the extracted package, not from a source checkout, and open the Sample.
2. Show every panel in the panel list.
3. Float one panel and dock it again. Move one panel.
4. Choose View, Reset panel layout ([`commands.py`](../../src/patchtrace/gui/qt/commands.py)).
5. Quit and relaunch.

Expected: every panel shows either its content or its blocked state, with no error dialog, no traceback and no console window. The frozen `--self-test` (spec A4) builds each panel only offscreen; this step is the check on a real screen.

### 4.9 Other section 3 checks (M01 to M07, M12 to M18, M23)

These rows belong to the same clean-profile run and the same receipt, and their steps are in the spec table.

#### R-OT1 Launch, Sample, files, raw views and tooltips (M01, M02, M03, M04, M05, M06, M07)
Run spec rows M01 to M07 as written.
#### R-OT2 Resize, export, cancel, close, file lock, restart and Unicode path (M12, M13, M14, M15, M16, M17, M18)
Run spec rows M12 to M18 as written. M03, M04 and M18 are repeated from a OneDrive-synced folder when one is available (spec section 3, Setup 3).
#### R-OT3 Layout persistence (M23)
Run spec row M23 as written. Reset must also be announced: check it under NVDA.

## 5. Crosswalk (tracker line to runbook step)

Line numbers were read at base `9451d7e` and will drift. The heading column is the stable anchor.

| Tracker line | Heading | Open item | Runbook steps |
|---|---|---|---|
| `tasks/todo.md:56` | `Windows Setup release track (PR #95, 2026-10-17)` | Clean Windows GUI acceptance of the alpha ZIP: File overview, raw views, tooltips, DPI | R-OT1, R-DP1 to R-DP4 |
| `tasks/todo.md:73` | `C6 multi-engine evidence panel (2026-10-14)` | C8: status label announced by NVDA and Narrator; DPI at 125, 150 and 200 % and glyph fonts; contrast against the live palette; frozen-EXE dock smoke | R-SR4, R-SR8, R-DP2 to R-DP4, R-DP7, R-CM2, R-CM3, R-CM5, R-FD1 |
| `tasks/todo.md:151` | `[G:bindiff-gui-setup]` | Native file dialogs, DPI layout of the section, the two status lines, keyboard-only walk (real `bindiff.exe` is a live-engine gate, out of scope) | R-KB1, R-DP2 to R-DP4, R-SR4, R-SR8 |
| `tasks/todo.md:422` | `[WBQ-S7:codetext-core]` | "Line changes" read by NVDA and Narrator, DPI, high contrast, bold advance in Consolas, `ShowDefaultIgnorables` glyphs (Windows CI and the 200 KB budget are automated; real `insns.text` is out of scope) | R-SR6, R-SR8, R-DP1 to R-DP4, R-DP7, R-CM2, R-CM3 |
| `tasks/todo.md:505` | `[GUI-F3:widgets]` | Status strip and notice strip under Narrator or NVDA; chip shapes at 100 to 200 % | R-SR5, R-SR7, R-SR8, R-DP1 to R-DP4 |
| `tasks/todo.md:508` | `[F6b:graph-canvas]` | Screen-reader output for node announcements (the 500/2,000 and 2,000/8,000 budget timings are `tests/test_gui_graph_view.py` on the Windows `qa` job) | R-SR7, R-SR8 |
| `tasks/todo.md:520` | `[GUI-F5:host]` | Palette, F6 order, dock tab names and notice strip under Narrator or NVDA; layout restore across DPI changes | R-KB1, R-SR1, R-SR5, R-SR8, R-DP5 |
| `tasks/todo.md:526` | `[F8:evidence-migration]` | M19 NVDA walk and M21 keyboard walk of the migrated panel | R-SR1, R-SR4, R-KB1 |
| `tasks/todo.md:530` | `[F7:theme]` | M22 contrast themes, animation effects off, OS light and dark with the System variant, chip and hunk legibility at 100 to 200 % | R-CM1, R-CM3, R-CM5, R-DP1 to R-DP4 |
| `tasks/todo.md:687` | `[WBQ-S6-S9:qt-modules]` | "Line changes" read by NVDA and Narrator, DPI, high contrast, bold advance in Consolas, syntax foreground on a hunk row | R-SR6, R-SR8, R-DP1 to R-DP4, R-DP7, R-CM2, R-CM3 |
| `tasks/todo.md:696` | `[PIL-C2:leads]` | Status lines announced through UIA, NVDA and Narrator; chips in high contrast and at 200 % (Windows CI is automated) | R-SR7, R-SR8, R-AI2, R-CM3, R-DP4 |

## 6. Receipt (RB-05, manual part)

This follows the RB receipt template.

1. Copy the block below fresh for each build, and fill it in during the run.
2. Paste the filled copy into [docs/qa.md](../qa.md) under a heading that names the date and the first 12 characters of the SHA.

`outcome` becomes `PASS`, `FAIL`, `INSUFFICIENT_DATA` or `BLOCKED` only after the run. The template has no word for "not yet run", so `not-run` holds that place. A zero-evaluated receipt is never a pass.

```yaml
gate: RB-05
part: manual
repository: djshellshoxxx/patchtrace
head_sha: ''
workflow_run_id: ''
job_ids: []
platform: Windows 11 x64, clean profile
artifact_sha256: ''
run: {windows_build: '', scale: '', monitors: '', theme: '', pyside6: '', tester: '', date: ''}
assistive_tech: {nvda: '', narrator_build: '', accessibility_insights: ''}
automated: {journey_gate_run: '', qt_gate_run: '', panels_check_run: ''}
case_count: 34
evaluated_count: 0
passed_count: 0
failed_count: 0
unknown_count: 0
cancelled_count: 0
outcome: not-run
results:
  M01: {result: not-run, steps: [R-OT1], evidence: '', notes: ''}
  M02: {result: not-run, steps: [R-OT1], evidence: '', notes: ''}
  M03: {result: not-run, steps: [R-OT1], evidence: '', notes: ''}
  M04: {result: not-run, steps: [R-OT1], evidence: '', notes: ''}
  M05: {result: not-run, steps: [R-OT1], evidence: '', notes: ''}
  M06: {result: not-run, steps: [R-OT1], evidence: '', notes: ''}
  M07: {result: not-run, steps: [R-OT1], evidence: '', notes: ''}
  M08: {result: not-run, steps: [R-DP1], evidence: '', notes: ''}
  M09: {result: not-run, steps: [R-DP3], evidence: '', notes: ''}
  M10: {result: not-run, steps: [R-DP4], evidence: '', notes: ''}
  M11: {result: not-run, steps: [R-CM2], evidence: '', notes: ''}
  M12: {result: not-run, steps: [R-OT2], evidence: '', notes: ''}
  M13: {result: not-run, steps: [R-OT2], evidence: '', notes: ''}
  M14: {result: not-run, steps: [R-OT2], evidence: '', notes: ''}
  M15: {result: not-run, steps: [R-OT2], evidence: '', notes: ''}
  M16: {result: not-run, steps: [R-OT2], evidence: '', notes: ''}
  M17: {result: not-run, steps: [R-OT2], evidence: '', notes: ''}
  M18: {result: not-run, steps: [R-OT2], evidence: '', notes: ''}
  M19: {result: not-run, steps: [R-SR1, R-SR2, R-SR4, R-SR5, R-SR6, R-SR7], evidence: '', notes: ''}
  M20: {result: not-run, steps: [R-SR8], evidence: '', notes: ''}
  M21: {result: not-run, steps: [R-KB1], evidence: '', notes: ''}
  M22: {result: not-run, steps: [R-CM1, R-CM3, R-CM5], evidence: '', notes: ''}
  M23: {result: not-run, steps: [R-OT3], evidence: '', notes: ''}
  M24: {result: not-run, steps: [R-DP5], evidence: '', notes: ''}
  M25: {result: not-run, steps: [R-AI1], evidence: '', notes: ''}
  M26: {result: not-run, steps: [R-LT1], evidence: '', notes: ''}
  M27: {result: not-run, steps: [R-KB3], evidence: '', notes: ''}
  M28: {result: not-run, steps: [R-SP1], evidence: '', notes: ''}
  AX-M1: {result: not-run, steps: [R-SR1, R-SR3, R-SR4], evidence: '', notes: ''}
  AX-M2: {result: not-run, steps: [R-SR8], evidence: '', notes: ''}
  AX-M3: {result: not-run, steps: [R-AI1, R-AI2], evidence: '', notes: ''}
  AX-M4: {result: not-run, steps: [R-KB1, R-KB2], evidence: '', notes: ''}
  AX-M5: {result: not-run, steps: [R-DP1, R-DP2, R-DP3, R-DP4, R-DP5, R-DP6], evidence: '', notes: ''}
  AX-M6: {result: not-run, steps: [R-CM4], evidence: '', notes: ''}
steps:
  R-SR1: {result: not-run, evidence: '', notes: ''}
  R-SR2: {result: not-run, evidence: '', notes: ''}
  R-SR3: {result: not-run, evidence: '', notes: ''}
  R-SR4: {result: not-run, evidence: '', notes: ''}
  R-SR5: {result: not-run, evidence: '', notes: ''}
  R-SR6: {result: not-run, evidence: '', notes: ''}
  R-SR7: {result: not-run, evidence: '', notes: ''}
  R-SR8: {result: not-run, evidence: '', notes: ''}
  R-KB1: {result: not-run, evidence: '', notes: ''}
  R-KB2: {result: not-run, evidence: '', notes: ''}
  R-KB3: {result: not-run, evidence: '', notes: ''}
  R-CM1: {result: not-run, evidence: '', notes: ''}
  R-CM2: {result: not-run, evidence: '', notes: ''}
  R-CM3: {result: not-run, evidence: '', notes: ''}
  R-CM4: {result: not-run, evidence: '', notes: ''}
  R-CM5: {result: not-run, evidence: '', notes: ''}
  R-DP1: {result: not-run, evidence: '', notes: ''}
  R-DP2: {result: not-run, evidence: '', notes: ''}
  R-DP3: {result: not-run, evidence: '', notes: ''}
  R-DP4: {result: not-run, evidence: '', notes: ''}
  R-DP5: {result: not-run, evidence: '', notes: ''}
  R-DP6: {result: not-run, evidence: '', notes: ''}
  R-DP7: {result: not-run, evidence: '', notes: ''}
  R-AI1: {result: not-run, evidence: '', notes: ''}
  R-AI2: {result: not-run, evidence: '', notes: ''}
  R-LT1: {result: not-run, evidence: '', notes: ''}
  R-SP1: {result: not-run, evidence: '', notes: ''}
  R-FD1: {result: not-run, evidence: '', notes: ''}
  R-OT1: {result: not-run, evidence: '', notes: ''}
  R-OT2: {result: not-run, evidence: '', notes: ''}
  R-OT3: {result: not-run, evidence: '', notes: ''}
limitations:
  - Offscreen automated gates are recorded under automated and never set a manual result
  - Live engines, Windows CI and timing budgets are outside this receipt
reviewed_by: ''
```
