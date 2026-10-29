# Qt 6 / PySide6 accessibility on Windows (UI Automation, NVDA, Narrator, high contrast)

Research note, not a contract. Scope: the Windows standalone alpha and GUI plan section 8.7 ([GUI plan](../specs/program-e/GUI-integration-plan.md)). Linux AT-SPI and Orca are out of scope.

Access conventions: `[Q6.12]` = Qt 6.12.0 source fetched 2026-10-15 from `https://raw.githubusercontent.com/qt/qtbase/v6.12.0/<path>`. `[Q-prev]` = retrieved 2026-10-14 by the GUI plan research (section 2 there, F1-F17), not re-fetched today. `[WEB]` = web search snippet, 2026-10-15. `[U]` = unverified. Official canonical doc.qt.io and learn.microsoft.com pages were not fetched directly today; the Qt 6.12 announcement class docs appear as `https://doc.qt.io/qt-6/qaccessibleannouncementevent.html` in search results only.

## 1. Verified facts

### 1.1 Announcements (QAccessibleAnnouncementEvent)
- The class exists in Qt 6.12.0: `QAccessibleAnnouncementEvent(QObject*, const QString&)` and `(QAccessibleInterface*, const QString&)`, default politeness `Polite`, with `politeness()`/`setPoliteness()`. [Q6.12] `src/gui/accessible/qaccessible.h` (around L654-682), fetched 2026-10-15.
- Windows routing: the event type `QAccessible::Announcement` is dispatched to `QWindowsUiaMainProvider::raiseNotification`. [Q6.12] `src/plugins/platforms/windows/uiautomation/qwindowsuiaaccessibility.cpp` L131-133, fetched 2026-10-15.
- Politeness mapping: `Assertive` maps to `NotificationProcessing_ImportantAll`, everything else (Polite) to `NotificationProcessing_All`; the call is `UiaRaiseNotificationEvent(provider, NotificationKind_Other, processing, message, activityId)`. The event's `accessibleInterface()` must resolve to a provider or nothing is raised. [Q6.12] `src/plugins/platforms/windows/uiautomation/qwindowsuimainprovider.cpp` L233-262, fetched 2026-10-15.
- Events are ignored before the first UIA request and while accessibility is being activated (the backend comment at `qwindowsuiaaccessibility.cpp` L117-118). [Q6.12] same file, fetched 2026-10-15. Consequence: offscreen tests cannot exercise this path (already in GUI plan 8.11).
- `QAccessible::Alert` plays a Windows system sound only (`playSystemSound(alertSound(...))`, same file L110-112). [Q6.12] fetched 2026-10-15; not a speech path. Confirms GUI plan F7.
- Minimum OS for `UiaRaiseNotificationEvent`: Windows 10 1709 [Q-prev, MS sdk-api docs, retrieved 2026-10-14; re-check `https://learn.microsoft.com/windows/win32/api/uiautomationcore/nf-uiautomationcore-uiaraisenotificationevent` [U today].
- PySide6 6.12.0 binding: `QAccessibleAnnouncementEvent` is declared in `sources/pyside6/PySide6/QtGui/typesystem_gui_common.xml` (`<object-type name="QAccessibleAnnouncementEvent"`), fetched 2026-10-15 from `https://raw.githubusercontent.com/pyside/pyside-setup/v6.12.0/sources/pyside6/PySide6/QtGui/typesystem_gui_common.xml`. Confirms the class is bound.
- PySide6 binding search: `setActive` and `installUpdateHandler` were NOT found in that typesystem file (both halves read, about 155,900 characters, fetched 2026-10-15). This contradicts the GUI plan's statement that 6.12 exposes `QAccessible.setActive`; see section 4. `installUpdateHandler` absence is consistent with GUI plan F7 and the injected-sender design. [U] whether a binding for `setActive` exists in a different typesystem file.
- Known limitation of the QObject constructor: a non-QObject item (for example a row in a model) needs its own `QAccessibleInterface`; a Qt maintainer's advice on the interest list is to build the event from the item's interface [WEB, lists.qt-project.org/pipermail/interest/2024-June/039745.html, accessed 2026-10-15].

### 1.2 Contrast, colour scheme and motion
- `QStyleHints::colorScheme()` (property since Qt 6.5; setting is only a hint, not supported on all platforms). [Q6.12] `src/gui/kernel/qstylehints.h` L60-61, L111, fetched 2026-10-15; the "not all platforms" note [WEB, doc.qt.io/qt-6.12/qstylehints.html, accessed 2026-10-15].
- `QStyleHints::accessibility()` returns `QAccessibilityHints`, which carries `contrastPreference` and `motionPreference`, each with a change signal `contrastPreferenceChanged` / `motionPreferenceChanged`. [Q6.12] `src/gui/kernel/qaccessibilityhints.cpp` L10-27 and L55-86, fetched 2026-10-15.
- Versions: `accessibility()` and `contrastPreference` since Qt 6.10; `motionPreference` since Qt 6.12 [WEB, doc.qt.io/qt-6.12/qstylehints.html and the QAccessibilityHints dev snapshot, accessed 2026-10-15; the 6.12 release page was not read directly].
- Windows high contrast: `SPI_GETHIGHCONTRAST`, `colorScheme()` becomes Unknown, palette filled from `GetSysColor`; Microsoft guidance is to map every colour to one foreground/background pair and drop background images [Q-prev F11, qwindowstheme.cpp L311-360, L652-683, L1281-1287 and MS WinAuto high-contrast-parameter.md, retrieved 2026-10-14].
- Motion: Qt 6.12 exposes a motion preference, but the Windows source path that fills it (the "Show animations in Windows" setting) was not verified today [U].

### 1.3 Widget accessibility tree (QTableView, QPlainTextEdit, tab bars, docks, QGraphicsView)
- Table views: `QAccessibleTable` wraps `QAbstractItemView`; selection modes for rows and columns are implemented there. [Q6.12] `src/widgets/accessible/qaccessiblewidgets.cpp`... item-view code in `src/widgets/accessible/itemviews.cpp` (selection L272-342), fetched 2026-10-15. Cell and header tree (Table, Column/RowHeader, Cell named by `AccessibleTextRole`, lazy and cached per visited cell): [Q-prev F10, itemviews.cpp L518-640, scratch experiments, retrieved 2026-10-14].
- QPlainTextEdit: `QAccessiblePlainTextEdit` exists and is the `QAccessibleTextWidget` path for plain text. [Q6.12] `src/widgets/accessible/qaccessiblewidgets.cpp` L100-105, fetched 2026-10-15.
- QTextEdit: rich-text accessibility is a separate class (`QAccessibleTextEdit`). [Q6.12] same file L184-206. Not used by PatchTrace (plain text rule).
- Dock widgets: exposed as Pane named by title, with Close and Float buttons (Press action, not focusable). [Q-prev F10, scratch exp_dock_children, retrieved 2026-10-14]. Dock tab bar: empty objectName, TabFocus, PageTabList [Q-prev F10, scratch exp_dock_tabbar, 2026-10-14].
- QGraphicsView: exposed as Client with one child. [Q-prev F10, retrieved 2026-10-14]. Not re-verified in 6.12 today [U for the current child count].
- Accessible name and description come from `accessibleName`, buddy label, group title; description from `accessibleDescription` else `toolTip`; HelpText from `whatsThis`; AutomationId from `accessibleIdentifier` (QWidget property since 6.9) else a dotted chain of objectName/class names. [Q-prev F9, qaccessiblewidget.cpp L322-356, provider L593-676, retrieved 2026-10-14]. The provider code for name and description was not re-fetched on 2026-10-15.

### 1.4 DPI
- Qt 6 defaults to per-monitor DPI awareness V2 on Windows; `qt.conf` `dpiawareness` or the platform argument `windows:dpiawareness` can change it [WEB, Chinese doc.qt.io/qt-6/zh/highdpi.html and the Qt 5.15 High DPI page, accessed 2026-10-15; English Qt 6 page not read, so [U] on exact wording]. Q-prev F4 also states PerMonitorV2 default with the Windows plugin instantiating only the UIA backend [Q-prev, qwindowsintegration.cpp L105,L199, retrieved 2026-10-14].
- `QT_ENABLE_HIGHDPI_SCALING=0` is the only environment opt-out; OS scale factor still applies [WEB, qhighdpiscaling.cpp comments in code.qt.io qtbase 6.4 tree, accessed 2026-10-15].

### 1.5 IME
- Bug reports cover Windows IME preedit behaviour for text widgets, not screen-reader output specifically [WEB, accessed 2026-10-15]: QTBUG-98915 (QPlainTextEdit, Japanese IME fires `contentsChange` per keystroke before `toPlainText()` changes; open) at bugreports-test.qt.io/browse/QTBUG-98915; QTBUG-42344 (pre-edit text disappears on focus change; Hiragana IME) at bugreports.qt-project.org/browse/QTBUG-42344; QTBUG-40402 (pre-edit appears in another widget; closed as fixed); QTBUG-56767 (composed text visible in a password field; closed as fixed).
- Input-method-enabled flag honoured on Windows was a 2014 patch proposal (QTBUG-40691 attachment) [WEB, accessed 2026-10-15]; whether it is in 6.12 is [U].

## 2. Known bugs and workarounds

| Issue | Evidence | Workaround for PatchTrace |
|---|---|---|
| Focused list or table content not read by NVDA or Narrator after the MSAA-to-UIA switch (Qt 5.11) | QTBUG-91029 (QListWidget, both readers silent; worked in 5.9.3), QTBUG-90897 (Narrator reads window name but not focused child); both [WEB, accessed 2026-10-15]; status of each ticket not checked [U] | Manual rows M19 and M20 must include focused table cell speech; do not claim M19 from a single reader |
| Table row navigation and focus issues with Narrator/NVDA | QTBUG-70996 is QtQuick TableView, not QTableView [WEB]; QTBUG-100997: first click on a row stalls on large QTableView because the UIA main provider scans every child to find focus (Qt 6.2 regression, performance) [WEB, bugreports-test.qt.io/browse/QTBUG-100997] | Keep 100k-row manual gate (M-series "100k table under Narrator"); measure focus latency, not just speech; the model-owned order and `data()` call gates in the GUI plan keep row count small per focus change [Q-prev] |
| Announcement not spoken unless a UIA client has queried and while accessibility is active | Q6.12 `qwindowsuiaaccessibility.cpp` L117-118 | Announce only after startup; manual check that the first announcement after launch is spoken |
| Alert is a sound, not speech | Q6.12 L110-112 | Use `StatusAnnouncer` (GUI plan 8.7) for every message |
| Name changes on an unfocused label are not spoken | Q-prev F6 | Same as above |
| IME composition emits per-keystroke changes, pre-edit text leaks on focus change | QTBUG-98915, QTBUG-42344 [WEB] | Do not announce text changes in editable fields; treat search boxes and editors as plain text; test a Japanese IME row manually (M-series extension, section 3) |
| Windows contrast: stylesheets override palette | Q-prev F11 | Drop the window stylesheet in high-contrast mode (GUI plan 8.11) |

## 3. Recommended manual checklist (steps)

Record each step as pass, fail or not-run with Windows build, Qt version, PySide6 version, NVDA version, Narrator build, theme name and monitor DPI. Automated tests do not count here. Commands below are common Windows and NVDA defaults; those marked [U] must be confirmed on the test machine before the run.

Setup
1. Install the frozen alpha on Windows 10 1709+ or Windows 11. Record `winver`.
2. Note display scale (100/150/200%) and monitor count.
3. Start the app with no project, then with a sample project that has at least 2,000 table rows.

NVDA walk (M19)
1. Start NVDA (default modifier Insert or Caps Lock) [U exact setting].
2. Press Tab from the main window through every panel. Expect each panel name, role and state (for example "Function name filter, edit"). Report any unnamed control.
3. Run one search. Expect exactly one announcement when the search completes, not one per progress tick.
4. In the results table, move with arrow keys. Expect cell text with its unit and the column header. Confirm the vertical header is silent.
5. Report any description read on every focus (description must be the What line, <= 160 chars).
6. Use the NVDA object navigation key to read the table role and row/column position [U key name].

Narrator walk (M20)
1. Start Narrator with Ctrl+Win+Enter. Use Caps Lock+arrows to move.
2. Turn on developer mode with Ctrl+Caps Lock+F12 to read the UIA tree (GUI plan F14 source, MS testing docs [Q-prev, retrieved 2026-10-14]).
3. Walk each panel; confirm table headers read with each cell.
4. Trigger one notification (for example an export complete). Confirm it is spoken once.
5. Repeat step 3 with a sample of focus changes into a second panel and back.

Keyboard-only walk (M21)
1. Unplug the mouse or disable touchpad for the run.
2. Tab through all panels; F6 and Shift+F6 cycle panels; Ctrl+Shift+P opens the palette; move a floating panel without the mouse.
3. Confirm focus is visible on every stop (2 px outline or equivalent).

Windows high contrast (M22)
1. Settings > Accessibility > Contrast themes (or press Left Alt+Left Shift+PrtScn to toggle) [U shortcut].
2. For each installed contrast theme (list varies by Windows build [U]): open every panel. Check text contrast, chip legibility (chips must use text + glyph + shape), focus ring, and that no hard-coded colours remain.
3. Switch between dark and high contrast while the app runs. Expect the palette to refresh without restart.
4. Record `QStyleHints.accessibility().contrastPreference` values in the log if a debug build is available [U].

Motion (new, no current row)
1. Settings > Accessibility > Visual effects > Animation effects off [U path].
2. Confirm the app shows no animated transitions (if any are added). Report `motionPreference` if a debug log exposes it [U].

DPI and monitor (M-series, 100/150/200% and monitor moves)
1. At each scale, check labels are not clipped and tables show full headers.
2. Move the window between a 100% and a 150% monitor. Confirm no text overlap and no crash.

IME (new row, Japanese or Chinese IME)
1. Enable the IME. In the search field and in one QPlainTextEdit, type a composed string.
2. Confirm pre-edit text stays in the field and is not announced per keystroke.
3. Commit the text. Confirm one announcement only if the app announces it.

Accessibility Insights (M-series)
1. Run Accessibility Insights for Windows FastPass on the main window and each panel; record failures.
2. Use Live Inspect to confirm AutomationId equals `accessibleIdentifier` for each tip id (GUI plan R9).

Evidence to keep: screen recording or audio notes, the NVDA log, the Narrator developer-mode tree export, the theme name, the Accessibility Insights report. Mark any step not run as `not-run`, never done.

## 4. Corrections to GUI plan 8.7

1. Plan 8.7 says "PySide6 6.12 exposes ... `QAccessible.setActive`". Today's fetch of the 6.12.0 PySide typesystem did not find `setActive` (or `installUpdateHandler`) in the whole file. Change the claim to: `setActive` is unverified in the binding [U]; keep the injected sender either way. Also confirm `QAccessible.isActive`/`setActive` exist in the 6.12 header (not found in `src/gui/accessible/qaccessible.h`, fetched 2026-10-15; the search may need the .cpp).
2. Plan 8.7 row F7 says `QAccessibleAnnouncementEvent` "needs Windows 10 1709+". Keep, but cite Microsoft's UiaRaiseNotificationEvent page directly (not re-fetched today).
3. Add to the Windows "not verifiable here" list: announcements are dropped unless a UIA client is active; manual M20 must include a first-announcement check after launch.
4. Add QTBUG-100997 (large QTableView focus stall, Qt 6.2) to the 100k-row gate: the gate must measure focus latency, not only `data()` counts.
5. Add IME rows (QTBUG-98915, QTBUG-42344) to the manual plan; plan 8.7 does not mention IME.
6. Motion: plan says reduced motion is not implemented anywhere; Qt 6.12 exposes `motionPreference`, so a test can read it. Windows source for it is [U].
7. DPI: plan F4 states PerMonitorV2 default. Verified only through a Chinese translation and code comments; English Qt 6 highdpi page should be cited before the Windows gate relies on it.

## 5. Open questions

1. Does Qt 6.12 Windows fill `motionPreference` from "Show animations in Windows"? [U]
2. Is `QAccessible::setActive`/`isActive` bound in PySide6 6.12.0? (typesystem check negative; check the `QtGui` pyi stubs.) [U]
3. Current status of QTBUG-91029, QTBUG-90897, QTBUG-98915, QTBUG-100997 on bugreports.qt.io (not checked today).
4. QGraphicsView child count and naming in 6.12 (only 6.x scratch experiments from 2026-10-14 exist).
5. Does NVDA announce `UiaRaiseNotificationEvent` with `NotificationProcessing_All` when the app is in the foreground only? [U]
6. Narrator handling of notification events (GUI plan F8 says [U]; still [U]).
7. Exact Windows high-contrast theme list and shortcut on the target Windows build.
8. Whether `accessibleIdentifier` (6.9+) is kept when the widget is recreated by `saveState`/`restoreState` (not checked).
