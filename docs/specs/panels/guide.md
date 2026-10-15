# Guide panel (deferred stub)

Status: proposed implementation contract, documentation only. Baseline: branch `claude/instance-d-gui`, commit `d15e16be7f19798cd6419c313b16dc54a3467ac4`, observed through GitHub. No code, tests, benchmarks or applications were run. UNVERIFIED: runtime compatibility, Windows behaviour, upstream versions, licences and URLs quoted by the integration plans. Repository identifiers below are verified against those documents unless explicitly labelled proposed or UNVERIFIED. Proposed view fields and command ids are requirements for the implementation, not claims that they already exist.

Authority: direct task constraints and `docs/plans/worker-brief.md`; `docs/specs/gui-framework.md` for pure contracts; actual `src/patchtrace/panel_manifest.py` for placement; the feature integration plan for domain semantics. Older plan seams into `ui.py`, shared tooltip edits, ad hoc worker registries and per-dock geometry are replaced by the existing panel framework. This document does not authorize shared-file changes.

## 1 Purpose and analyst question

Stub only, explicitly deferred by PROMPT1. Analyst question: "Is contextual teaching available in this build?" The answer is a static availability statement. The guide does not interpret the selected function, generate lessons, call AI or implement a help browser. Existing help and docs remain their own product surface.

## 2 Identity

guide/panel.py PANEL; lazy factory ui_guide.create_panel(ctx), proposed UNVERIFIED module/function until implemented. id guide,title Guide,left,no tab group,Ctrl+Shift+H,focus_order200,default_visibleFalse,requires(),CLAIMS_NEUTRAL. All hooks are no-op except widget/focus_target/theme_changed/shutdown; project and selection changes cause no work. Preserve the reserved manifest slot; do not register another help dock.

## 3 Data contract

Proposed pure guide/view_model.py::deferred_view()->GuideStubView. Frozen slotted fields: state Literal['blocked']; title Literal['Guide']; text str<=200; detail str<=400; no project ids, target content, URLs or persisted schema. Fixed text is the row in section5. No service calls. No database, filesystem or network reads. No TeachTopic consumption until the deferred phase has a complete spec.

## 4 Layout

StateView with plain heading, static status, one selectable plain-text detail and Copy status. No table columns, sorting, filters, graph, code panes or lessons. Detail: "Panel tooltips explain current controls. Contextual lessons and step-by-step guidance are deferred. This panel does not inspect or interpret your comparison." Keep readable wrapping in a40em by14em minimum region. Empty-cell text is inapplicable because the stub has no cells.

## 5 States

| State | Trigger | Exact on-screen copy | Remedy button | Screen-reader announcement |
|---|---|---|---|---|
| blocked/deferred | First show or any project state | Contextual guide is deferred in this build. Use the existing help and control tooltips. | Copy status | Contextual guide is deferred in this build. Use the existing help and control tooltips. |

No loading, empty result, stale, retry or analysis-error state is fabricated. Factory failure remains the host's PT-GUI-FACTORY state, not a custom lesson failure.

## 6 Interactions

guide.action toggles dock. guide.copy_status copies heading,status and static detail, at most1KiB, LF plain text. Ctrl+C in selected detail copies selected static text; context menu Copy status uses the same command. No Run, Download, Next lesson, external link or Retry action. Escape returns focus through host navigation without cancelling comparison. F6/Shift+F6 remain panel cycling.

## 7 Navigation

anchors_in={}, anchors_out={}. show_anchor returns NavResult.blocked('Guide','contextual lessons are deferred'). It must never mark an anchor shown without content. No project identity or history entry is created.

## 8 Threads

No tasks, lanes, timers or worker threads. shutdown idempotently detaches view listeners. There is no progress display. project_changed and selection_changed do not perform reads. Theme changes update existing widgets on the GUI thread.

## 9 Settings

No guide/ settings in this phase. Layout belongs to the host. No saved lesson position, recent queries, project content or consent. This is deliberate deferred scope, not a missing implementation.

## 10 Tooltips

### `guide.dock`

Accessible name: "Guide panel".

What: Read the status of the deferred contextual guide.

Why: Keep planned teaching separate from current evidence.

Effect: Stub only; no lessons or automatic analysis.

Source: GUI manifest guide slot and the task's deferred scope.

### `guide.action`

Accessible name: "Show Guide".

What: Show or hide the deferred Guide panel.

Why: Make the reserved panel reachable by keyboard.

Effect: Toggles the dock; Ctrl+Shift+H.

Source: Panel registry.

### `guide.status`

Accessible name: "Guide availability".

What: Read why the contextual guide has no lessons in this build.

Why: Avoid presenting unfinished content as available help.

Effect: Read-only; no project information is sent or generated.

Source: Deferred Guide implementation status.

### `guide.copy_status`

Accessible name: "Copy Guide status".

What: Copy the guide's deferred status.

Why: Record the limitation when planning work.

Effect: Clipboard only; no project data.

Source: Static deferred-status copy.

## 11 Accessibility

For every control enumerated in section 10, set its accessible identifier to the tooltip id, its accessible name to the quoted name in that entry, and its description to that entry's What line (at most 160 characters). Static section headings are plain labels with explicit buddies for inputs. Nonfocusable status labels have an empty accessible name; `ctx.announce` is the only asynchronous speech path. Announce state entry using section 5's exact announcement once, not on each progress tick. Result counts are polite; a blocking error is assertive. Debounce selection announcements and maintain the framework's 1.5-second speech gap.

Each composite has one Tab stop; arrows move inside tables, lists and trees. Space transfers focus to detail, Enter activates the explicit primary action, and context menus are reachable by Menu or Shift+F10. Show visible focus with a two-logical-pixel equivalent border measured from theme metrics. F6 and Shift+F6 remain host panel cycling. All pointer actions have a command or keyboard route. Group labels, table headers, positions, side, units, missing reasons and chip words appear in AccessibleTextRole. Empty cells use the literal text in section 4 rather than silence. Keep focus and selection by stable key across filtering or announce when the row leaves the view.

Use `ThemeTokens` for dark, system and automatic high contrast. Text contrast is at least 4.5:1, focus and boundaries at least 3:1. In high contrast remove custom fills and use system palette, words, ASCII glyphs and border shapes. A glyph or colour alone never encodes state. Reduced motion disables animated transitions and automatic scrolling; navigation uses an immediate reveal. Font, style, palette and DPI changes recompute em widths and row heights. Test actual NVDA, Narrator and multi-monitor DPI on Windows separately; offscreen assertions do not close those gates.


Tab order: selectable detail then Copy status. State label has an empty accessible name and one polite announcement when the dock first shows; subsequent project/selection events produce no announcement. The dock/action/status/copy names are defined in section10. No timed or animated content.

## 12 Performance budgets

UNVERIFIED future gate: factory<=30ms, zero I/O, zero timers, zero foreground tasks, static text<1KiB, retained widget memory<=1MiB above the host shell. No table benchmarks are applicable.

## 13 Security/privacy

Never execute, install or load a target binary. Read hash-checked project copies as data. Do not fabricate missing code, observations or provenance. Preserve conflicts; unknown contributes no negative vote; shared-origin observations count once. Never average engines' scores or present an uncalibrated number as vulnerability confidence. Older and newer remain explicit after every swap. Models, providers and adapters stay separate from Qt. Persisted records change additively only; a changed derived view never rewrites raw evidence. No Microsoft-derived binary, PDB or Winbindex label enters git; no GPL/AGPL implementation is copied. Ghidriff remains a separate unmodified component.

All file, advisory, rule and tool text is hostile input: bound before formatting, use `sanitize_text`, use plain-text widgets, and escape separately for any rich tooltip or report sink. Strip controls and bidi formatting; preserve an explicitly labelled escaped representation when exact text matters. Do not interpret a data value as an action, path, shell fragment, URL to fetch or HTML. Clipboard operations are explicit, LF, plain text and at most 16 KiB; truncation is announced and includes provenance. No credentials in settings, logs or copy blocks. No automatic browser opening.


Network hosts:none. The stub reads no project or target data, stores no new evidence and opens no URLs. It does not consume advisory text or model output.

## 14 Test plan

Required, not run: test_guide_deferred_copy_exact; test_guide_no_project_or_selection_read; test_guide_no_tasks_or_timers; test_guide_no_navigation_claims; test_guide_manifest_left_h; test_guide_tip_names_complete; test_guide_theme_and_reduced_motion; test_guide_copy_contains_no_project_data. Run no tests in this task. Manual Windows: keyboard focus, static announcement, high contrast and DPI readability of the stub; no lesson acceptance is implied.

## 15 Open questions

1. When to implement lessons? Default defer until a separate owner-approved teaching contract defines topic identity, source freshness and action routing.
2. Link to a bundled help index now? Default no extra control; use existing application help. A later requirement can add one with exact local-resource provenance.
3. Consume TeachTopic now? Default no; feature specs can declare their own teach data, but this stub does not pretend to render it.
