# GDE R2: teaching and guidance in tools (evidence and design recommendations)

Track GDE (Program E, E-5), charter item 8 "Teachable". Author: research worker R2, 2026-10-14. Document only; no source changed.

## 0. Method and evidence status (read first)

- Rules: primary sources only (peer-reviewed papers, standards, official docs). No blogs, videos, forums, AI summaries.
- **Retrieval limitation.** On 2026-10-14 every external host (w3.org, doc.qt.io, learn.microsoft.com, ghidra.re, docs.binary.ninja, hex-rays.com, doi.org, arxiv.org) was unreachable from this sandbox (curl: proxy CONNECT 403; WebFetch: ENOTFOUND). **No source below was re-fetched.** Every citation is from the author's prior knowledge of the primary source, with bibliographic data given so a reviewer can verify it. Tag meaning: `[unverified]` = not retrieved, bibliographic details believed correct; `[unverified-detail]` = the source exists but a specific number or UI detail may be wrong. The "retrieved" column therefore reads `not retrieved (host blocked 2026-10-14)`. A reviewer with network access should close these before the E-5 spec is frozen; section 9 lists which decisions depend on which claim.
- Decisions resting on repository facts read from the tree are marked `[repo]`.
- Product constraints used: deterministic, not AI-assisted; single main window; no target binary execution; offline by default; strict-JSON imports; pure domain separate from Qt; tooltips already keyed by stable semantic IDs `[repo: src/patchtrace/tooltips.py]`; each feature must expose "what this means / what to do next" hooks `[repo: program-e-roadmap.md charter 8]`; every lesson step must link to a real feature `[repo: roadmap E-5 gate]`.

## 1. Learning science: what the evidence supports

| # | Claim | Source (bibliographic) | Retrieved | Conf. |
|---|---|---|---|---|
| L1 | Problem solving by means-ends search imposes high cognitive load that competes with schema acquisition; reducing extraneous load helps novices | Sweller, J. (1988). Cognitive load during problem solving: effects on learning. Cognitive Science 12(2):257-285. doi:10.1207/s15516709cog1202_4 | not retrieved | `[unverified]` high |
| L2 | Worked-example effect: novices learn more from studying solved examples than from solving the same problems | Sweller & Cooper (1985). Cognition and Instruction 2(1):59-89 | not retrieved | `[unverified]` high |
| L3 | Expertise reversal: guidance that helps novices becomes redundant or harmful for more expert learners; fade it | Kalyuga, Ayres, Chandler, Sweller (2003). Educational Psychologist 38(1):23-31 | not retrieved | `[unverified]` high |
| L4 | Fading worked steps backward (remove last solution steps first) eases the transition from example study to problem solving; self-explanation prompts improve transfer | Renkl & Atkinson (2003). Educational Psychologist 38(1):15-22; Renkl, Atkinson, Maier, Staley (2002), J. Experimental Education 70(4):293-315 `[unverified-detail]` | not retrieved | `[unverified]` med-high |
| L5 | Scaffolding: the tutor takes over parts of the task the learner cannot yet do and withdraws as competence grows | Wood, Bruner, Ross (1976). J. Child Psychology and Psychiatry 17(2):89-100 | not retrieved | `[unverified]` high |
| L6 | Minimal guidance (pure discovery) is less effective than guided instruction for novices; debate concerns how much, not whether | Kirschner, Sweller, Clark (2006). Educational Psychologist 41(2):75-86 (opposing view: Hmelo-Silver, Duncan, Chinn 2007, 42(2):99-107) | not retrieved | `[unverified]` high |
| L7 | Distributed (spaced) practice beats massed practice; the optimal gap grows with the desired retention interval | Cepeda, Pashler, Vul, Wixted, Rohrer (2006). Psychological Bulletin 132(3):354-380 | not retrieved | `[unverified]` high |
| L8 | Retrieval practice (testing effect) improves long-term retention more than restudy | Roediger & Karpicke (2006). Psychological Science 17(3):249-255 | not retrieved | `[unverified]` high |
| L9 | Step-based tutors approach human-tutor effect sizes; answer-based tutors are weaker; feedback granularity matters | VanLehn (2011). Educational Psychologist 46(4):197-221 | not retrieved | `[unverified]` high |
| L10 | Two-loop structure: outer loop selects tasks, inner loop gives step-level feedback and on-demand hints | VanLehn (2006). The behavior of tutoring systems. IJAIED 16(3):227-265 | not retrieved | `[unverified]` high |
| L11 | Learners "game the system" by clicking through hints to the bottom-out answer; correlates with poor learning | Baker, Corbett, Koedinger (2004). Detecting student misuse of intelligent tutoring systems. ITS 2004, LNCS 3220 `[unverified-detail]`; Aleven, Roll, McLaren, Koedinger (2016). Help helps, but only so much. IJAIED 26:205-223 `[unverified-detail]` | not retrieved | `[unverified]` med |

Implications:

1. Start each skill with a **worked example** (the app shows the move on the synthetic fixture; the learner studies it), then **completion problems** (fade backward: the learner does the last step), then **full tasks** (L2, L4). Never open with an empty "find the bug" task (L6).
2. **Fade support by learner evidence, not by time** (L3, L5). Evidence is deterministic: steps completed unaided, hint depth used.
3. **Spacing and retrieval** (L7, L8): short optional review prompts asking the learner to *do* the move again on a different fixture, on a fixed expanding schedule. No notification pop-ups.
4. **Hint ladder with a free orientation rung and a marked bottom-out** (L11): the last rung reveals the answer but records the step as `shown`, never `completed`.
5. **Cognitive load** (L1): one goal per step, one highlighted target at a time, plain sentences. About 60 words per rung maximum `[design choice, not an evidence figure]`.

## 2. ITS architecture, reduced to what is deterministic

Classic ITS: domain model, learner model, tutoring model, interface (VanLehn 2006).

| ITS part | Classic technique | Verdict for PatchTrace |
|---|---|---|
| Step checking | Cognitive Tutors model tracing (Anderson, Corbett, Koedinger, Pelletier 1995, J. Learning Sciences 4(2):167-207 `[unverified]`) | **Adopt reduced**: declarative predicates over an app-state snapshot (5.3). No rule engine, no learning. |
| Authoring | Example-tracing tutors (Aleven, McLaren, Sewall, Koedinger 2009, IJAIED 19(2):105-154 `[unverified-detail]`); authoring survey (Murray 1999, IJAIED 10:98-129 `[unverified]`) | **Adopt the principle**: content is data, tested by replay (section 8). |
| Constraint checking | Accept any state satisfying constraints (Mitrovic & Ohlsson 1999, IJAIED 10:238-256 `[unverified-detail]`) | **Adopt for open steps**: several routes reach a good state (search, call graph, table); the predicate states the *end condition*, not the route. |
| Learner model | Bayesian Knowledge Tracing (Corbett & Anderson 1995, UMUAI 4:253-278 `[unverified]`) | **Reject**: fitted parameters, no calibration data, false precision (conflicts with the rule against uncalibrated numbers). Use a transparent counter model. |
| Hint generation | Next-step hints from traced state | **Static ladder per step**, state-conditioned *selection* by rules (5.5). No generated prose. |
| Outer loop | Mastery-based task selection | **Fixed prerequisite DAG of lessons**; learner chooses; the guide suggests by rule. |

Deterministic means: same pack + same snapshot sequence + same injected clock gives identical step states, hints and review schedule. No randomness, no wall-clock reads in the engine, no network, no model calls.

## 3. HCI and accessibility guidance

| # | Claim | Source | Retrieved | Conf. |
|---|---|---|---|---|
| H1 | WCAG 2.2 is a W3C Recommendation (2023-10-05; later edition 2024-12) | W3C, WCAG 2.2, https://www.w3.org/TR/WCAG22/ | not retrieved | `[unverified]` high |
| H2 | SC 2.2.1 Timing Adjustable, 2.2.2 Pause, Stop, Hide: no auto-dismiss or auto-advance the user cannot extend or stop; moving content over 5 s needs a pause control | WCAG 2.2, 2.2.1, 2.2.2 | not retrieved | `[unverified]` high |
| H3 | SC 2.4.11 Focus Not Obscured (Minimum), AA, new in 2.2: a focused component must not be entirely hidden by author-created content | WCAG 2.2, 2.4.11 | not retrieved | `[unverified]` high |
| H4 | SC 2.1.1 Keyboard, 2.1.2 No Keyboard Trap | WCAG 2.2, 2.1.1, 2.1.2 | not retrieved | `[unverified]` high |
| H5 | SC 1.4.13 Content on Hover or Focus: dismissible (Esc), hoverable, persistent | WCAG 2.2, 1.4.13 | not retrieved | `[unverified]` high |
| H6 | SC 2.5.8 Target Size (Minimum), AA: at least 24x24 CSS px (spacing exceptions) | WCAG 2.2, 2.5.8 | not retrieved | `[unverified]` high |
| H7 | SC 3.2.6 Consistent Help (A); SC 3.3.7 Redundant Entry (A) | WCAG 2.2, 3.2.6, 3.3.7 | not retrieved | `[unverified]` high |
| H8 | SC 4.1.3 Status Messages (AA); 1.4.1 Use of Color; 1.4.3 and 1.4.11 contrast | WCAG 2.2, 4.1.3, 1.4.1, 1.4.3, 1.4.11 | not retrieved | `[unverified]` high |
| H9 | WCAG is written for web content; EN 301 549 clause 11 applies WCAG-derived criteria to non-web software | ETSI EN 301 549 v3.2.1 (2021), clause 11 | not retrieved | `[unverified-detail]` med |
| H10 | Qt exposes widgets to assistive technology via QAccessible (UI Automation on Windows, AT-SPI on Linux); standard widgets are accessible by default; set accessibleName/accessibleDescription on custom or icon-only controls; custom widgets need a QAccessibleInterface; notify with `QAccessible::updateAccessibility()` | Qt 6 docs, "Accessibility", https://doc.qt.io/qt-6/accessible.html | not retrieved | `[unverified]` high |
| H11 | `setAccessibleName/Description`, `setFocusPolicy`, `setTabOrder`, `QShortcut`, `QToolTip`, `QWhatsThis` are the stock Qt building blocks for labels, keyboard access and contextual help | Qt for Python 6 docs, PySide6.QtWidgets, https://doc.qt.io/qtforpython-6/ | not retrieved | `[unverified]` high |
| H12 | `Qt::WA_TransparentForMouseEvents`, child-widget overlays and `QStateMachine` exist; lesson logic still lives outside Qt (testability, modularity rule) | Qt 6 docs: Qt::WidgetAttribute; "The State Machine Framework" | not retrieved | `[unverified]` high |
| H13 | Microsoft Fluent/WinUI: TeachingTip is a non-modal, targeted, dismissible callout for just-in-time instruction; use sparingly; never for information the user cannot get elsewhere | Microsoft Learn, "Teaching tip", https://learn.microsoft.com/windows/apps/design/controls/dialogs-and-flyouts/teaching-tip (exact path unconfirmed) | not retrieved | `[unverified-detail]` med-high |
| H14 | Microsoft Windows accessibility: keyboard accessibility, UI Automation names/roles, high-contrast, text scaling | Microsoft Learn, "Accessibility in Windows apps" | not retrieved | `[unverified-detail]` med |
| H15 | Training wheels: blocking advanced functions for novices helps early learning (Carroll & Carrithers 1984, Comm. ACM 27(8):800-806 `[unverified-detail]`); the active-user paradox: users skip manuals and learn by doing (Carroll & Rosson 1987) | peer-reviewed | not retrieved | `[unverified]` med |

Consequences:

- **Non-modal everywhere** (H2, H4, H13). No `exec()` dialogs. A tour is a dock widget plus an optional click-through overlay and one small card.
- **Never obscure the focused control** (H3): the card flips to the side that keeps the target and keyboard focus visible and is keyboard-movable.
- **No timers dismiss or advance** (H2). Advancing happens only on *observed completion* and is announced (H8).
- **Esc dismisses the card; Help > Guide reopens** (H5, H7) in a fixed menu position and one fixed dock tab.
- **Status via accessibility** (H8, H10): each step change updates the card's accessible name, emits an alert/name-changed event and writes a visible status line. State by text and icon shape, not color alone.
- **Targets >= 24x24 px** (H6); text follows system font scale; verify high-contrast (H14).
- **Highlight, do not block** (H15 reading): PatchTrace disables nothing in guided mode (analyst control); training-wheels gating is rejected.

## 4. Comparable products (official documentation only; not retrieved, re-verify)

| Product | What official docs show | Takeaway | Source | Conf. |
|---|---|---|---|---|
| Ghidra (NSA, Apache-2.0) | Distribution carries a GhidraClass tree (beginner/intermediate/advanced slides and exercises), built-in Help with context-sensitive F1 help, a "Tips of the Day" start-up dialog | Teaching material is separate from the tool; no in-tool step checking. Context help keyed to component IDs matches our tooltip-ID pattern | https://github.com/NationalSecurityAgency/ghidra (Ghidra/Documentation, GhidraDocs/GhidraClass) | `[unverified-detail]` |
| Binary Ninja (Vector 35) | User docs with Getting Started and per-feature guides | Docs-side learning only | https://docs.binary.ninja | `[unverified-detail]` |
| IDA (Hex-Rays) | Documentation, F1 help, academic/education licensing | External documentation | https://docs.hex-rays.com | `[unverified-detail]` |
| picoCTF (CMU) | Chapman et al. (2014), "picoCTF: A Game-Based Computer Security Competition for High School Students", USENIX 3GSE 2014: tiered challenges, hints, story frame, flag-string checking | Graded difficulty and hints work motivationally; flag strings are answer-based, the weaker feedback type (L9) | https://www.usenix.org/conference/3gse14 | `[unverified]` med-high |
| CTFd (Apache-2.0) | Docs describe hints that can cost points, prerequisite gating of challenges, static/regex flags | Confirms hint cost + prerequisite DAG + value check. We swap "flag string" for "app-state predicate" and drop point costs | https://docs.ctfd.io | `[unverified-detail]` |

None of these checks completion from the live state of the real analysis tool. PatchTrace can, using its own anchors and findings on a synthetic known-answer pair.

## 5. Recommended architecture

```
lessons/*.json (versioned data) --validate--> LessonPack (Pydantic, pure)
GuideHook registry (features register) ------+
AppStateSnapshot (frozen dataclass, built by an adapter from the real app)
                         |
   GuideEngine (pure: step state machine + predicate evaluator + hint selector)
                         |
   GuideProgressStore (versioned JSON/SQLite)      Qt adapter: dock + coach card + overlay
```

Package `guide/` (pure: `models.py`, `predicates.py`, `engine.py`, `hints.py`, `review.py`, `store.py`, `registry.py`) and `ui_guide.py` (Qt only). `guide/` imports no Qt and no feature internals `[repo: modularity rule]`; features reach it through `GuideHook` registration and the anchor fabric only.

### 5.1 Lesson data model (strict JSON, additive versioning)

Strict JSON `[repo: AGENTS.md]`, Pydantic `extra="forbid"`, `schema_version: "guide-lesson/1"` (additive only), content hash stored with progress so edited lessons invalidate stale progress explicitly.

```
LessonPack  {schema_version, pack_id, pack_version, title, locale, fixture_ref, lessons[]}
Lesson      {lesson_id, title, summary, skill_ids[], prerequisites[lesson_id],
             est_minutes, mode: worked|completion|task, steps[], review_items[]}
Step        {step_id, title, goal (one sentence), why (what this means),
             target: TargetRef, show_me: ShowMe|null,
             done_when: Predicate, hints: Hint[1..4],
             skippable: bool, requires_hooks: hook_id[]}
TargetRef   {hook_id, anchor?: AnchorSelector}
AnchorSelector {kind: function|string|import|capability|rule|build_fact|
                advisory_phrase|cve|kb|cwe, match: fixture_expected|exact|selected, value?}
Hint        {rung: 1..4, kind: orient|point|procedure|reveal, text, when?: Predicate}
ShowMe      {action_id (declared hook action only)}
Predicate   {op: all|any|not|eq|ge|in|exists, args | {probe, value}}   # closed vocabulary, no eval
ReviewItem  {item_id, skill_id, prompt, done_when, fixture_ref}
```

Predicates use a **closed JSON vocabulary** evaluated by `predicates.py`; never `eval`, never user code. Text is plain strings, escaped at render (reuse the tooltip control-character stripping, length cap and escaping `[repo: tooltips.py]`); advisory or binary-derived strings shown in steps are bounded and escaped.

### 5.2 Step state machine

States: `locked` (prerequisites unmet), `ready`, `active`, then one of `completed_unaided`, `completed_with_hint`, `shown` (bottom-out used), `skipped`, `blocked` (required hook unavailable, e.g. optional engine missing). Transitions are pure: `next_state(step_state, event, snapshot)`; events: `snapshot_changed`, `hint_requested`, `show_me`, `skip`, `reset`. A step is completed **only** on `snapshot_changed` with `done_when` true. "Next" navigates without changing completion status. `blocked` shows the hook's exact availability reason and never counts as done.

### 5.3 Completion detection from app state, without AI

1. The app builds an `AppStateSnapshot` of named, typed, read-only **probes**, e.g. `selected_function(side)`, `visible_panel(id)`, `active_tab(dock)`, `search_query(panel)`, `selected_anchor(kind)`, `pinned_anchors`, `has_pair`, `finding_count(channel)`, `orientation`, `export_done(kind)`, `note_exists(anchor)`. A probe is registered by the feature that owns it.
2. The Qt adapter recomputes on owning signals (selection changed, panel shown, job finished), **not on a timer**, coalesced to one evaluation per event-loop turn. Target: all active predicates under 2 ms on a 100k-row session because probes read cached view-model state `[design target]`.
3. Open goals use end-state predicates (constraint style): `eq(selected_pair, fixture.expected.changed_pair)`. The expected value is fixture data committed with the pack, never computed by the guide.
4. Honest progress: each completion stores `observed_at` (injected clock) and the satisfying snapshot hash, so replay shows why it was marked done.

### 5.4 Guide hooks and anchors from features

Each feature track ships `guide_hooks.py` (charter item 8):

```
GuideHook {hook_id "wb.strings.delta", feature_id, title,
           means: plain text, <= 280 chars,
           next: [hook ids that usually follow],
           tooltip_ids: [...],                 # existing stable semantic IDs [repo]
           probes: [ProbeSpec{name, type}],
           actions: [navigate|select|open_panel with typed params],
           anchor_kinds_emitted: [...], anchor_kinds_consumed: [...],
           availability: probe|null }
```

Consumption rules: (a) `target.hook_id` must exist or the pack fails validation (enforces "every step links to a real feature"); (b) the card's "What this means" = `Step.why` + `GuideHook.means`, so feature owners own semantics and lesson authors only sequence them; (c) `AnchorSelector` resolves through the FAB Protocol (`resolve(kind, value) -> location`), never by importing a feature; (d) the highlight target is found by tooltip id / accessible name, never by position or visible text; (e) an unavailable hook yields `blocked` with the hook's own message, and CI fails if a shipped lesson's required hook is not registered in the frozen build.

### 5.5 Hint ladder (rule-selected, static text)

1. **orient** (free): restates the goal and where this information lives. No highlight.
2. **point**: highlights the target control or region via the hook; names the panel, not the click.
3. **procedure**: exact action sequence including the keyboard route, without naming the answer item.
4. **reveal**: names the expected item; offers "Show me" (only declared navigate/select actions, never writes); the step becomes `shown`.

Selection: learner-initiated, one rung per request. A rung's optional `when` predicate swaps in a *common-misstep* variant when the snapshot matches a known wrong state (for example the selected pair is an unchanged neighbor: "These sides have identical code; check the delta column."). Misstep rules are authored data, tested by fixtures. An optional, off-by-default idle offer proposes rung 1 in the status line only (no auto-open, H2). The guide never prevents any feature use (analyst control).

### 5.6 Fading and learner model (counters, no probabilities)

Per skill: `attempts`, `unaided`, `with_hint`, `shown`, `last_practiced`, `box`. Rule (L3, L4): first exposure uses `worked`; after one unaided completion offer `completion`; after two, `task`. Learner can always override. Display counters verbatim ("Completed unaided 2 times, with hints 1 time"), never a mastery percentage.

### 5.7 Spaced review

Leitner boxes, injected clock, date granularity: 1, 3, 7, 21, 60 days `[illustrative, direction per L7; not fitted; keep as pack data]`. Unaided success moves up; `shown` or hint at rung >= 3 returns to box 1. Due items appear as a count on the Guide tab ("2 review items due"), opt-in, never a pop-up, each on a **different fixture** than learned on (L8 transfer). Progress is local only, resettable ("Reset guide progress") and exportable as strict JSON.

### 5.8 Qt realization (single main window)

- `GuideDock(QDockWidget)`: lesson list, step list (state icon plus text), goal, "What this means", hint button "Hint (1/4)", "Show me", "Skip", "Reset step". Explicit tab order; every button has `accessibleName`; reachable at Help > Guide.
- `CoachCard(QFrame)`: child of the main window (not top-level, not `QDialog`), one at a time, anchored to the target resolved by tooltip id; Esc dismisses; Tab leaves; repositions on resize or dock move; placement avoids the focus rectangle (H3).
- `HighlightOverlay(QWidget)` with `WA_TransparentForMouseEvents`: outline plus corner marks (shape, not color alone); no pulsing by default (H2).
- Step change updates accessible name and emits an alert event plus a visible status line (H8, H10).

## 6. Content strategy

- Curriculum follows the product workflow: (1) open a pair, older/newer orientation; (2) triage: where to look first, channels explained; (3) one click to code; (4) delta not inventory: strings, imports, capabilities, unknown versus absent; (5) provenance and staleness; (6) advisory, CVE, KB anchors; (7) rules and export. One skill per lesson (L1).
- RE-domain pedagogy is the concern of the sibling research worker R1; this document constrains structure only.
- Lessons run on **synthetic committed fixtures** with a known answer `[repo: specs/known-answer-corpus.md]`; no Microsoft-derived binaries or PDBs. Lessons state judgment limits explicitly (uncalibrated score is not confidence; missing is unknown).
- Ownership: one `pack_id` per theme; `pack_version` recorded in release notes; human review of lesson text (Opus writes, Sonnet validates per roadmap `[repo]`).

## 7. Recommendations (numbered for the E-5 spec)

7.1 **Model**: adopt 5.1 as the starting contract `guide-lesson/1`, strict JSON, closed predicate vocabulary, additive-only evolution.
7.2 **Step truth**: completion only via `done_when` over `AppStateSnapshot`, with `observed_at` and snapshot hash.
7.3 **Honest status taxonomy**: `completed_unaided`, `completed_with_hint`, `shown`, `skipped`, `blocked` are distinct, shown as text plus icon, counted separately. A lesson with any `shown` step reads "Completed with answers revealed", not "Completed".
7.4 **Hint ladder**: four rungs, learner-initiated, no point-cost UI (CTF cost pattern does not transfer to a professional tool), bottom rung marks `shown`.
7.5 **Fade**: counter rules in 5.6, always overridable.
7.6 **Hooks**: every feature track ships `guide_hooks.py` with `means`, tooltip ids, probes and an availability probe. Validation fails on unknown hook, hook without `means`, or a predicate probe name not registered.
7.7 **Anchors**: steps point to anchors by `AnchorSelector` through the FAB Protocol; the guide never creates anchors, notes, rules or exports on the learner's behalf; "Show me" is navigate/select only.
7.8 **UI**: dock plus non-modal card plus click-through overlay; no timed dismiss or advance; no focus trap; accessible names and alerts.
7.9 **Spacing**: opt-in, in-panel count only, fixed schedule, different fixture.
7.10 **Privacy and offline**: progress local, exportable, resettable; no telemetry; a test greps `guide/` imports for `socket`, `urllib`, `http`, `requests`.
7.11 **Performance**: event-driven snapshots, 2 ms predicate budget, no polling timer.
7.12 **E-5 slices** (each mergeable alone): (a) `guide/models.py` plus schema and validation tests; (b) predicates, engine, store; (c) hook registry plus per-track `guide_hooks.py` (each owned by that track); (d) Qt dock, card, overlay; (e) first lesson pack (orientation) on a synthetic fixture; (f) review scheduler; (g) remaining packs.

## 8. Test and fixture design

1. **Pack validation (pure)**: generated JSON schema with drift check `[repo: AGENTS.md]`; red/green tests rejecting unknown fields, unknown predicate op, duplicate step ids, missing prerequisite, lesson-DAG cycle, non-increasing hint rungs, over-length text; control characters stripped or escaped.
2. **Snapshot replay fixtures**: `tests/fixtures/guide/<lesson>/<case>.json` holds an ordered list of `AppStateSnapshot` objects plus expected per-step transitions and hint outputs. Cases per lesson: golden path (unaided), hint path (each rung), wrong-turn path (misstep variant), reveal path (`shown`), blocked path, reorder path (different route, same end state still completes).
3. **Determinism property**: replaying twice, and with shuffled probe key order, gives identical output; a test fails if `time` or `random` is imported in `guide/` (only `review.py`, via the injected clock, may use dates).
4. **Real-state integration**: per shipped lesson, drive the real app offscreen on the synthetic pair, perform the golden path through hook actions, assert each `done_when` turns true in the real snapshot adapter. This prevents lesson rot when a feature changes; hermetic, no network, not a mocked-backend claim.
5. **Hook coverage**: iterate lessons x steps x `requires_hooks`; assert registration and that `tooltip_ids` exist in `tooltips.py`.
6. **Qt offscreen tests** (20x repeat gate `[repo]`): overlay click-through (QTest click reaches the widget beneath); card never covers the focused widget at three window sizes; Esc dismisses; Tab leaves; accessible names non-empty; alert emitted; `QApplication.topLevelWidgets()` count unchanged; closing the main window mid-tour does not abort.
7. **Store**: migration, content-hash invalidation, reset, strict-JSON export round-trip, review schedule table test with injected dates (`>=` for coarse clocks, short explicit parametrize ids per Windows pitfalls `[repo]`).
8. **Copy golden**: all hint and card text of a pack snapshotted so edits are reviewed.

## 9. Decisions that depend on unverified claims

| Decision | Depends on | If claim fails |
|---|---|---|
| Worked-example first, backward fading | L2, L4 | Harmless; `mode` stays configurable |
| Static ladder, bottom-out marked `shown` | L11 | Low risk; honest status is a product rule anyway |
| Fixed Leitner intervals | L7, L8 | Intervals are pack data; tune freely |
| No timed dismiss/advance | H2 | Conservative regardless |
| Non-obscuring card, 24 px targets | H3, H6 | Check wording; low cost |
| Alert and name-change events | H10 | Verify `QAccessible::Alert` in the pinned PySide6; fall back to status label plus accessible-name change |
| TeachingTip analogy | H13 | Informational only |
| Comparable products | Section 4 | Informational only; no dependency |

## 10. Anti-patterns to reject

1. **Modal blockers**: dialogs or overlays that capture input; "finish the tour first" gates.
2. **Fake progress**: completion on "Next", on elapsed time, or on a panel merely being open when the goal is a result; mastery percentages without a model. Progress bars count observed completion only, broken down by status.
3. **Answer-string checking** when app state can be checked.
4. **Counting `shown` as completed.**
5. **Auto-advancing or auto-dismissing coach marks**; moving or pulsing highlights without pause.
6. **Gating features** (training wheels) in a professional tool: the guide suggests, never gates.
7. **Generated text**: any LLM or template-synthesized hints; lesson text is authored, reviewed and hashed.
8. **Positional or label-matching targets**: break on layout or translation; use stable semantic ids.
9. **Stale lessons** naming controls that no longer exist; prevented by hook validation and the real-state test.
10. **Real or Microsoft-derived data in lessons**, executing any sample, or network calls from the guide (all product invariants).
11. **Color-only state, small targets, tooltips that vanish on hover-out** (WCAG 1.4.1, 2.5.8, 1.4.13).
12. **Uncalibrated number presented as confidence** in lesson copy; lessons repeat the honesty rules ("unmatched or missing means unknown").
13. **Lessons that write analyst data** (notes, rules, exports) without the analyst's explicit action.

## 11. Open questions (defaults given; none blocks)

1. Progress storage: default JSON sidecar under app data with `schema_version`; revisit when FAB storage lands.
2. User-importable packs: default ship-only in v1; later import via the same strict-JSON validator.
3. Localization: English only, `locale` reserved.
4. Mandatory rungs: default rungs 1, 2, 4 for `worked`/`completion`, all four for `task`.
5. Card `means` reuses the tooltip entry's `why` text when present, to avoid divergent explanations. Default yes.
6. Verification debt: a reviewer with network access should fetch each `[unverified]` URL before the E-5 spec is frozen (section 9 shows what changes).
