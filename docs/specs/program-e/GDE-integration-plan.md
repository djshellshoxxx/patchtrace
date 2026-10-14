# GDE integration plan: deterministic guided-RE teacher (`guide/`, contract `guide-lesson/1`)

Track GDE (Program E, E-5, charter item 8 "Teachable"). Author: GDE spec worker, 2026-10-14. Documents only. Inputs: `docs/research/gde/R1-expert-patch-diffing-workflows.md`, `R2-teaching-and-guidance-in-tools.md`, the code on this branch (base `02c492d`, includes main `67e5a6c`). Proposed spec id: next free number per `docs/specs/REGISTRY.md` (SPEC-41 at the snapshot); cite by path until the owner confirms.

## 1. Verdict and scope

- **Build**: a pure, Qt-free teacher: lesson packs (strict JSON, `guide-lesson/1`), a closed predicate vocabulary evaluated over a read-only `AppStateSnapshot`, a four-rung static hint ladder, honest step statuses, a `guide_hooks` registration contract every feature track ships, anchor resolution through a Protocol (`AnchorSink`), a transparent counter-based learner model, a CLI (`guide validate|list|show|replay|progress`) and, later, a dock + non-modal card in the single main window through the panel registry.
- **Not built**: any AI/LLM/template-generated text (lesson text is authored, reviewed, hashed); Bayesian knowledge tracing or any mastery percentage; point-cost hints; feature gating ("training wheels"); modal tours; timers that advance or dismiss; telemetry; user-imported packs (v1 ships packs only); lessons that write analyst data; any use of real or Microsoft-derived binaries.
- **Hard dependency order**: domain/engine/CLI slices need nothing but `tooltips.py` ids and the committed sample; the panel needs the GUI panel registry (GUI track); anchor-based steps need FAB. Until then `AnchorSink` has one interim adapter over stored matches.
- **Initial lesson set** (section 9) uses only features that exist on `main` today; steps for capa/FLOSS/DiE/KB/workbench/unified are written as `blocked`-until-hook-registered stubs in a second pack, not in the shipped first pack.

## 2. Sources and facts

Retrieved 2026-10-14 unless stated. `search` = confirmed from web-search result snippets of the named host or a paper index (the sandbox resolves no hosts for WebFetch: `getaddrinfo ENOTFOUND` for w3.org, doc.qt.io, learn.microsoft.com, arxiv.org). Confidence: H = official/primary host snippet; M = bibliographic data confirmed by PubMed/DOI/index, content not read; L = not reachable.

| claim | source URL | retrieved | confidence / tag |
|---|---|---|---|
| WCAG 2.2 became a W3C Recommendation on 2023-10-05; 2.4.11 Focus Not Obscured (Minimum) and 2.5.8 Target Size (Minimum, 24x24 CSS px, with spacing/equivalent/inline/UA/essential exceptions) are Level AA | https://www.w3.org/WAI/standards-guidelines/wcag/new-in-22/ ; https://www.w3.org/TR/WCAG22/ | 2026-10-14 | M (search snippets of w3.org/WAI "What's New"; normative TR page not fetched). Upgraded from `[unverified]` to `[verified-snippet]`. Note: a snippet mixed up the labels of 2.4.11/2.4.12, so quote the TR text before freezing |
| 2.2.2 Pause, Stop, Hide (A): auto-moving content longer than 5 s needs pause/stop/hide; 2.1.2 No Keyboard Trap (A); 1.4.13 Content on Hover or Focus (AA: dismissible, hoverable, persistent) | https://www.w3.org/TR/WCAG22/ | 2026-10-14 | L-M: only secondary checklists returned; **still `[unverified]`** |
| 2.2.1 Timing Adjustable, 3.2.6 Consistent Help, 3.3.7 Redundant Entry, 4.1.3 Status Messages, 1.4.1, 1.4.3, 1.4.11 | https://www.w3.org/TR/WCAG22/ | not reached | `[unverified]` (R2 H2, H7, H8 carried over) |
| Qt: custom widgets may subclass `QAccessibleInterface` (plugin or compiled in); `QAccessibleWidget`/`QAccessibleObject` are convenience bases; `QAccessible::updateAccessibility()` takes a `QAccessibleEvent`; events are to be sent after the change; `Alert` event exists | https://doc.qt.io/qt-6/qaccessible.html ; https://doc.qt.io/qt-6.5/qaccessiblewidget.html ; https://doc.qt.io/qtforpython-6/PySide6/QtGui/QAccessibleEvent.html | 2026-10-14 | M-H (doc.qt.io snippets). Upgraded |
| Qt 6.8 added `QAccessibleAnnouncementEvent` + `AnnouncementPoliteness` (screen-reader announcements); the repo pins `PySide6==6.12.0` (`pyproject.toml`) so it is available | https://doc.qt.io/qt-6/qaccessibleannouncementevent.html | 2026-10-14 | M (snippet; default politeness stated only by translated pages: **verify in the pinned wheel at build time**). Replaces R2's "verify `QAccessible::Alert`" fallback with a preferred API |
| Linux AT-SPI is active only when the DBus `IsEnabled` and `ScreenReaderEnabled` properties are true (or `QT_LINUX_ACCESSIBILITY_ALWAYS_ON`) | https://doc.qt.io/qt-6/accessible.html (search result) | 2026-10-14 | M. Consequence: Linux CI cannot observe a11y events without forcing the env var; tests assert accessible name/description strings, not the AT bridge |
| `accessibleName`/UIA mapping on Windows; QAccessible "stock" statement that standard widgets are accessible by default | https://doc.qt.io/qt-6/accessible.html | not confirmed | `[unverified]` (search did not return the mapping text) |
| Microsoft Learn "Teaching tip": semi-persistent flyout for contextual info and teaching tasks; transient so not for errors/important status; keep brief; avoid showing too often; light-dismiss or explicit close; test every UI configuration | https://learn.microsoft.com/windows/apps/design/controls/dialogs-and-flyouts/teaching-tip | 2026-10-14 | M-H (path confirmed by search result; R2 H13 path was "unconfirmed", now confirmed). The word "non-modal" does **not** appear in the snippets; PatchTrace states non-modality as its own rule |
| Sweller 1988, Cognitive Science 12(2):257-285, doi:10.1207/s15516709cog1202_4: means-ends problem solving competes with schema acquisition | https://doi.org/10.1207/s15516709cog1202_4 | 2026-10-14 | M (abstract via index) |
| Sweller & Cooper 1985, Cognition and Instruction 2(1):59-89, doi:10.1207/s1532690xci0201_3: worked examples beat problem solving in algebra | https://doi.org/10.1207/s1532690xci0201_3 | 2026-10-14 | M |
| Kalyuga, Ayres, Chandler, Sweller 2003, Educational Psychologist 38(1):23-31: expertise reversal (guidance effective for novices loses or reverses effect for experienced learners). Author order differs between repositories; volume/pages agree | https://www.doi.org/10.1007/S10648-007-9054-3 (related review); https://ro.uow.edu.au/edupapers/136 | 2026-10-14 | M |
| Renkl & Atkinson 2003, Educational Psychologist 38 (special issue): fade problem-solving elements into example study; backward fading removes the last step first (the backward-fading detail is from a secondary review) | https://asu.elsevierpure.com/en/publications/structuring-the-transition-from-example-study-to-problem-solving--2 | 2026-10-14 | M; pages 15-22 and "2002 vs 2003" for the companion study **unverified** |
| Wood, Bruner, Ross 1976, J Child Psychol Psychiatry 17(2):89-100, doi:10.1111/j.1469-7610.1976.tb00381.x (origin of scaffolding) | https://pubmed.ncbi.nlm.nih.gov/932126/ | 2026-10-14 | H (PubMed record) |
| Kirschner, Sweller, Clark 2006, Educational Psychologist 41(2):75-86: guided instruction outperforms minimal guidance (a persuasive, contested argument; Hmelo-Silver et al. 2007 reply not re-checked) | https://www.davidlewisphd.com/courses/EDD8121/readings/2006-Kirschner_et_al.pdf (copy) | 2026-10-14 | M |
| VanLehn 2011, Educational Psychologist 46(4):197-221: answer-based vs step-based vs substep-based tutors; reported effect sizes ~0.31 (answer-based, from Kulik&Kulik), ~0.76 (step-based), ~0.79 (human) | secondary slides/papers (https://quality.mit.edu/files/2012/01/Quality-Symposium-Kurt-VanLehn.pdf) | 2026-10-14 | M for bibliography, **L for the figures**: sources disagree (0.40 vs 0.32 for substep). Do not quote numbers in lesson copy or docs |
| Roediger & Karpicke 2006, Psychological Science 17(3):249-255, doi:10.1111/j.1467-9280.2006.01693.x (testing effect) | https://doi.org/10.1111/j.1467-9280.2006.01693.x | 2026-10-14 | M-H |
| Cepeda, Pashler, Vul, Wixted, Rohrer 2006, Psychological Bulletin 132(3):354-380, doi:10.1037/0033-2909.132.3.354 (distributed practice) | https://digitalcommons.usf.edu/psy_facpub/1771/ | 2026-10-14 | M (metadata only) |
| Baker, Corbett, Koedinger 2004, ITS 2004, LNCS 3220:531-540 (gaming the system, help abuse) | https://learninganalytics.upenn.edu/ryanbaker/BCKR2005Final.pdf (author site) | 2026-10-14 | M (bibliography); Aleven et al. 2016 IJAIED 26:205-223 **unverified** |
| Brumley, Poosankam, Song, Zheng, "Automatic Patch-Based Exploit Generation is Possible", IEEE S&P 2008, pp. 143-157, doi:10.1109/SP.2008.17; patch + original program, five Microsoft programs | https://users.ece.cmu.edu/~dbrumley/pdf/Brumley%20et%20al._2008_Automatic%20Patch-Based%20Exploit%20Generation%20is%20Possible%20Techniques%20and%20Implications.pdf | 2026-10-14 | H (paper host appears in results). R1 S4 upgraded from M |
| Haq & Caballero survey (arXiv 1909.11424), Kim et al. TSE 2022 (arXiv 2011.10749), DeepBinDiff NDSS 2020, MSRC Exploitability Index, CISA KEV, BinDiff manual, rz-diff book, CWE-416, PE format, DYNAMICBASE, /GS | as in R1 section 1 | not re-fetched | carry R1's tags unchanged; lessons cite none of them for a number |
| Corbett & Anderson 1995 BKT, Anderson et al. 1995 Cognitive Tutors, Mitrovic & Ohlsson 1999, Murray 1999, Aleven 2009, Carroll & Carrithers 1984, picoCTF 3GSE 2014, CTFd docs, Ghidra/Binary Ninja/IDA docs, ETSI EN 301 549 | R2 sections 2, 3, 4 | not re-fetched | `[unverified]`; none is a decision input (BKT is *rejected*; training wheels *rejected*) |
| Repo facts: `PySide6==6.12.0`, Python >= 3.12; `tooltips.py` registry keyed by stable ids with `apply_tooltip` (sets toolTip, whatsThis, statusTip, accessibleDescription, objectName); only `ui.py` lines 728 and 1616-1646 call `setAccessibleName`; `EvidenceController` adds a right-area, initially hidden `QDockWidget` with `toggleViewAction()`; CLI envelope `enrichment-cli/1`, exit codes 0/2/3/4/5; `sample.create_sample` builds a deterministic synthetic project | `src/patchtrace/{tooltips,ui,ui_evidence,cli,sample}.py`, `pyproject.toml` | read 2026-10-14 | H (code) |

**Verification tally**: upgraded from `[unverified]`: WCAG 2.2 recommendation date and 2.4.11/2.5.8, Qt `updateAccessibility`/custom `QAccessibleInterface`/Alert, Qt 6.8 announcement events, Teaching-tip path and content, Sweller 1988, Sweller & Cooper 1985, Wood/Bruner/Ross, Roediger & Karpicke, Cepeda et al. (metadata), Kirschner et al., Brumley et al. Everything else keeps its tag (full table in section 10.3).

## 3. Standalone baseline versus PatchTrace value

- **Standalone**: Ghidra ships separate GhidraClass slides/exercises and context help; IDA and Binary Ninja ship documentation (R2 s4, all `[unverified]`). CTF platforms (picoCTF, CTFd) check answer strings. None checks completion from the live state of the analysis tool.
- **PatchTrace adds**: (a) step completion computed from the application's own state on a committed synthetic known-answer pair (end-state predicates, any route); (b) the same stable ids already used for tooltips (`tooltips.py`) address UI targets, so copy and lessons cannot drift; (c) each feature owns the "what this means" text of its hook, so the teacher cannot contradict the tool; (d) honesty rules of the product (missing is unknown, uncalibrated is ordinal, older/newer explicit) become taught, testable steps; (e) pitfalls P-01..P-42 from R1 become rule-fired, testable misstep hints.
- **Workflows enabled**: guided first comparison (open sample, verify orientation, rank, read, record a reviewed finding, export); a "why did the score not decide it" lesson; a "unknown is not removed" lesson on unmatched functions; later, per-track lessons on capa/strings/KB as hooks land.

## 4. Cross-feature links

The guide **consumes** anchors and hooks; it emits only local progress records, never anchors, notes, rules, findings or exports.

| item | direction | kinds | other track | how |
|---|---|---|---|---|
| `GuideHook` registration (`guide_hooks.py` per feature) | consume | hook ids | every feature track (UE, KB, WB1-3, CAP, DIE, YRX, KEV, PIL, FAB, GUI) | feature ships `HOOKS: tuple[GuideHook, ...]` and calls `register_hooks()`; guide never imports feature internals |
| `AnchorSelector` -> location | consume | function, string, import, capability, rule, build_fact, advisory_phrase, cve, kb, cwe | FAB | through `AnchorSink.resolve(kind, value, side)`; interim adapter resolves `function` only from stored matches |
| tooltip ids | consume | `action.*`, `nav.*`, `evidence.*`, `series.*`, `export.*`, `overview.*` | GUI | target lookup by `objectName == tip_id` (set by `apply_tooltip`) and `tooltip_ids` validation against `tooltips.REGISTRY` |
| probes | consume | `selected_match`, `visible_panel`, `finding_count` ... | owning feature | feature registers `ProbeSpec`; snapshot adapter fills values on the owning signals |
| `means` text | consume | hook field, <= 280 chars | owning feature | shown on the card as "What this means" with `Step.why` |
| progress records | emit (local) | `guide-progress/1` | none | per-user JSON sidecar, not an evidence anchor, not in the project file |
| pitfall ids (R1 P-nn) | emit (as `misstep.pitfall` on hints) | stable string | LBL/QA | lets QA grep that each pitfall has a lesson hint |

## 5. Synergy test

Scenario `GDE-SYN-1` (committed, synthetic): project from `sample.create_sample` (functions: `read_item` modified, ratio 0.58, bounds guard added; `get_version` modified, ratio 0.94, constant 1 -> 2; `report_invalid_index` added; `debug_dump` deleted).

Lesson `L03-rank-and-choose` step `S3` goal: "select the change that most likely adds a safety check". Channels alone: (a) the ranking channel (`Rank changes`, `nav.order` = attention) puts `read_item` first but shows an ordinal score only; (b) the code viewer alone shows both diffs; (c) a bare checklist cannot tell if the learner looked. Combined: the engine marks `S3` `completed_unaided` only when `eq(selected_match.name, fixture.expected.security_candidate)` **and** `eq(match_order, "attention")` **and** `exists(ranking_result)`; selecting `get_version` first triggers the misstep hint ("This pair differs by one constant; compare the added branch in the other pair"). Expected outputs, asserted in `tests/test_guide_replay.py`: golden path -> `S3 completed_unaided`, lesson `completed_unaided`; hint path (rungs 1-3 requested then completes) -> `completed_with_hint`; reveal path -> `shown`, lesson label "Completed with answers revealed"; wrong-turn path -> misstep variant shown exactly once per entry into that state; route-independence (select via table, via search box) -> same end status; `blocked` path (evidence-dock lesson without engines) -> `blocked` with the hook's own reason, never `completed`.

## 6. Traps and guards

| trap | guard |
|---|---|
| Fake progress (complete on Next, elapsed time, panel merely open) | completion only from `done_when` over a snapshot; `Next` navigates only; test `test_next_never_completes` |
| Answer revealed counted as success | `shown` is its own status, never aggregated into "completed"; lesson label changes; review box resets |
| Teacher contradicts the tool | `means` owned by the feature hook; lessons cannot override it; copy golden |
| Lesson rot after UI change | hook validation + `tooltip_ids` validation + real-state offscreen golden-path test per shipped lesson (fails the build) |
| Teaching false precision | lesson copy lint: forbids "confidence", "%", "probability" next to score words unless inside a quoted warning; every score step restates "ordinal, not vulnerability confidence" |
| Untrusted text in cards (function names, advisory phrases) | all dynamic values go through `tooltips.clean_value` semantics: control strip, 200-char cap, `PlainText` labels, never `RichText`/`setHtml` |
| Highlight hides focused control (WCAG 2.4.11, `[verified-snippet]`) | card placement picks the side not overlapping the focus rectangle; test at three window sizes |
| Keyboard trap / modal gate (2.1.2 `[unverified]`) | no `exec()`, no `Qt.WindowModal`; Esc dismisses card; Tab leaves; `Help > Guide` reopens |
| Auto-dismiss / pulsing (2.2.2 `[unverified]`) | no `QTimer` anywhere in `guide/` or `ui_guide.py`; static outline; test greps imports |
| Click-through into hint rungs ("gaming the system", Baker 2004) | one rung per explicit request; rung 4 marks `shown`; counters shown verbatim |
| Guide mutates analyst data | "Show me" executes only declared `navigate|select|open_panel` actions; actions are typed, no write verbs exist in the vocabulary; test enumerates the action enum |
| Network/telemetry | import-lint test on `guide/`: no `socket`, `urllib`, `http`, `requests`, `ssl`; progress stays local |
| Nondeterminism | engine takes injected `now`; no `random`, no wall clock; shuffled probe key order test |
| Stale progress after lesson edit | progress stores `lesson_hash`; mismatch -> progress for that lesson shown as "lesson changed, restart" and archived, never silently reapplied |
| Real/Microsoft data in lessons | fixtures are only `sample.py` outputs and hand-written JSON; the existing corpus guard test covers `tests/fixtures/guide/` |

## 7. Contracts

All models Pydantic v2, `extra="forbid"`, frozen, strict JSON load (reject NaN, duplicate keys, > 1 MiB per pack file). Additive-only versioning: unknown `schema_version` major -> `PT-GUIDE-VERSION`. Generated JSON Schemas under `docs/schemas/guide/` with the drift check from AGENTS.md.

### 7.1 Package layout (`src/patchtrace/guide/`, no Qt, no feature imports)

`models.py` (records), `limits.py`, `predicates.py`, `engine.py`, `hints.py`, `snapshot.py` (AppStateSnapshot, ProbeSpec), `registry.py` (hooks, probes), `anchors.py` (`AnchorSink` Protocol + `NullAnchorSink`), `validate.py`, `store.py` (progress), `review.py` (Leitner), `packs/` (data: `*.json`), `cli.py`. Qt side: `ui_guide.py` only (section 8).

### 7.2 `guide-lesson/1` records

```
LessonPack  {schema_version:"guide-lesson/1", pack_id, pack_version:int, title, locale:"en", fixture_ref, lessons:Lesson[1..24]}
Lesson      {lesson_id, title, summary<=240, skill_ids[1..4], prerequisites:lesson_id[<=4],
             est_minutes:1..30, mode:"worked"|"completion"|"task", steps:Step[1..14], review_items:ReviewItem[<=6]}
Step        {step_id, title<=80, goal<=200 (one sentence), why<=400, target:TargetRef,
             show_me:ShowMe|null, done_when:Predicate, hints:Hint[1..4], skippable:bool,
             requires_hooks:hook_id[<=6], pitfalls:string[<=4]   # R1 ids "P-18"; informational, linted against R1 catalogue
TargetRef   {hook_id, tooltip_id|null, anchor:AnchorSelector|null}
AnchorSelector {kind: function|string|import|capability|rule|build_fact|advisory_phrase|cve|kb|cwe,
                match: fixture_expected|exact|selected, value:string<=200|null, side: older|newer|either}
Hint        {rung:1..4, kind:orient|point|procedure|reveal, text<=420 (about 60 words), when:Predicate|null,
             misstep:string|null}
ShowMe      {action_id}                      # must be declared by target.hook_id
Predicate   {op, args}                        # section 7.3
ReviewItem  {item_id, skill_id, prompt<=240, done_when:Predicate, fixture_ref}   # fixture_ref != lesson fixture_ref
```

Rules: rung numbers strictly increasing, rung 1 `orient`, last rung `reveal`; `worked`/`completion` lessons may omit rung 3 (open question 4 default); ids `[a-z0-9._-]{1,48}`, unique per pack; prerequisite graph acyclic; text fields NFC-normalised, control characters rejected (not stripped) at validation, stripped again at render. Limits in `limits.py`: pack <= 1 MiB, 64 predicate nodes per tree, depth <= 6, 200 steps per pack.

### 7.3 Closed predicate vocabulary

`Predicate = {op, args}` with exactly these ops; no regex, no arithmetic beyond comparison, no string functions, no user code, no references to wall time.

| op | args | semantics |
|---|---|---|
| `all`, `any` | `Predicate[1..8]` | conjunction / disjunction |
| `not` | `Predicate` | negation (unknown stays unknown: see below) |
| `eq`, `ne` | `{probe, value}` or `{probe, fixture}` | equality of a probe with a literal (str/int/bool) or a fixture expected value |
| `ge`, `le` | `{probe, value:int}` | integer comparison |
| `in` | `{probe, values:literal[<=16]}` | membership |
| `exists` | `{probe}` | probe value is present and not `unknown` |
| `count_ge` | `{probe, value:int}` | length of a list-valued probe |

`fixture` references `fixture.expected.<dotted.path>` in the pack's fixture file (never computed by the guide). Evaluation is three-valued (`true|false|unknown`): a probe that is unavailable or unregistered yields `unknown`; `unknown` never satisfies a `done_when` and never counts as a negative vote (project invariant). `not(unknown) = unknown`.

### 7.4 AppStateSnapshot and probes (`snapshot.py`)

`AppStateSnapshot {seq:int, probes: Mapping[str, ProbeValue]}`, `ProbeValue = str|int|bool|tuple[str,...]|Unknown`, frozen, canonical-JSON hashable (reuse `enrichment.identity` canonicalisation for `snapshot_hash`). `ProbeSpec {name, value_type, owner_feature, description<=160, hint_for_authors}`. Probe names are `feature.name` (`nav.selected_match_name`). A snapshot may contain only registered probes; unknown keys are dropped and counted (`PT-GUIDE-PROBE` at validation time, not at run time).

### 7.5 Hooks (`registry.py`)

```
GuideHook {hook_id "nav.rank", feature_id, title<=60, means<=280, next:hook_id[<=6], tooltip_ids:str[<=8],
           probes:ProbeSpec[<=12], actions:HookAction[<=6], anchor_kinds_emitted[], anchor_kinds_consumed[],
           availability_probe:str|null, unavailable_text<=200}
HookAction {action_id, verb: navigate|select|open_panel, params_schema}   # no write verbs
```

Obligations on a feature track (charter 8; added to every track's "done" checklist): ship `<package>/guide_hooks.py` exporting `HOOKS`; every `tooltip_ids` entry exists in `tooltips.REGISTRY`; every probe is implemented by the feature's window adapter; `means` states what the feature output means and its limits; frozen smoke imports the module. Registration is explicit (`guide.registry.register(HOOKS)` in `guide/bootstrap.py`, a list of dotted module names loaded with `importlib` and each guarded; a module that fails to import yields hook state `unavailable`, never a crash).

### 7.6 Anchor port

```
class AnchorSink(Protocol):
    def resolve(self, kind: str, value: str | None, side: str) -> AnchorResolution: ...
@dataclass(frozen=True) class AnchorResolution { status: "found"|"absent"|"unknown"|"unsupported", location: str|None, label: str|None }
```

`absent` is only returned when the source is complete; incomplete sources return `unknown`. The guide never calls `emit`; the name `AnchorSink` is kept because the FAB contract is where it will converge (open question 3: FAB may rename it; only `anchors.py` changes). Interim `MatchAnchorSink` (in `ui_guide.py`'s adapter module, not in `guide/`): `function` -> a match id by exact symbol name in the open project; other kinds -> `unsupported`. A step whose target kind is `unsupported` is `blocked` with copy "This step needs a feature that is not available in this build." Highlight target resolution order: `tooltip_id` -> `objectName` lookup in the main window; failing that, `blocked`. Never by position or visible text.

### 7.7 Step state machine and statuses

`StepStatus`: `locked`, `ready`, `active`, `completed_unaided`, `completed_with_hint`, `shown`, `skipped`, `blocked`. Events: `snapshot_changed(snapshot)`, `hint_requested`, `show_me`, `skip`, `reset_step`, `hook_availability_changed`. Transition function `next_state(state, event, snapshot, now)` is pure. Rules: a step becomes `completed_*` only on a `snapshot_changed` where `done_when` is `true`; `completed_with_hint` if any rung >= 2 was requested; `shown` once rung 4 or "Show me" was used and stays `shown` even if the learner then does the action (the record keeps `observed_at` of the later satisfaction as `satisfied_after_reveal`); `skipped` and `blocked` never count as done; `reset_step` clears the step but not the attempt counters. Lesson roll-up: all steps `completed_unaided` -> "Completed"; any `completed_with_hint` and no `shown` -> "Completed with hints"; any `shown` -> "Completed with answers revealed"; any `skipped`/`blocked` -> "Incomplete". Each completion stores `{observed_at (injected clock), snapshot_hash, rung_max}`.

### 7.8 Hint ladder

Rung kinds `orient` (free, restates goal and where the information lives, no highlight), `point` (highlights target, names the panel not the click), `procedure` (exact actions incl. keyboard route, without naming the answer), `reveal` (names the expected item, offers Show me, marks `shown`). Request is learner-initiated, one rung per request. A rung's `when` predicate selects the misstep variant; selection order: variants whose `when` is `true` (first in file order) else the plain rung. Misstep text is data, tested by replay fixtures. Optional idle offer (default off): status-line text only ("Hint available: F6 then H"); no timer, it is evaluated on the next snapshot change after the preference is on and a monotonic gap measured from the injected clock.

### 7.9 Progress store and learner counters (`store.py`, `review.py`)

`guide-progress/1` JSON under `QStandardPaths.AppDataLocation/guide/progress.json` (resolved by the Qt adapter and passed in as a path; the pure store takes a `Path`), atomic write via temp file + `os.replace`, size cap 256 KiB, strict load; corrupt file -> renamed `.corrupt-<n>` and a fresh store (prior data preserved, matching the repo's preserve-prior policy). Fields: `schema_version, pack_hashes{pack_id:sha256}, lessons{lesson_id:{lesson_hash, steps{step_id:{status, observed_at, snapshot_hash, rung_max}}}}, skills{skill_id:{attempts, unaided, with_hint, shown, last_practiced, box}}, review_due`. Counters displayed verbatim ("Completed unaided 2 times, with hints 1 time"), never a percentage. Fading rule: first exposure `worked`; one unaided completion offers `completion`; two offer `task`; learner can always override (Kalyuga 2003, Renkl & Atkinson 2003: direction only, thresholds are design defaults). Review (opt-in): Leitner boxes with intervals 1, 3, 7, 21, 60 days from pack data `review_schedule_days` (illustrative, not fitted); unaided success moves up one box; `shown` or rung >= 3 returns to box 1; each review item uses a different fixture than the lesson. "Reset guide progress" and strict-JSON export are explicit analyst actions.

### 7.10 Error codes (`PT-GUIDE-*`)

`PT-GUIDE-SCHEMA` (strict parse), `PT-GUIDE-VERSION`, `PT-GUIDE-LIMIT`, `PT-GUIDE-DUP` (duplicate id), `PT-GUIDE-PREREQ` (missing/cyclic), `PT-GUIDE-HOOK` (unknown hook / missing `means`), `PT-GUIDE-PROBE` (unregistered probe or type mismatch), `PT-GUIDE-ACTION` (undeclared Show-me action), `PT-GUIDE-TIP` (unknown tooltip id), `PT-GUIDE-TEXT` (control char, over length, forbidden phrase), `PT-GUIDE-FIXTURE` (missing fixture key), `PT-GUIDE-STORE` (progress unreadable), `PT-GUIDE-REPLAY` (golden mismatch). Cache keys: none needed (no derived cache); lesson identity = `lesson_hash` = SHA-256 of canonical JSON of the lesson plus `pack_version`. No enrichment-store kind: progress is per user, not per project evidence.

## 8. CLI and GUI

### 8.1 CLI (`guide/cli.py` + a <= 6-line hook in `cli.py`, as `intel-tools` did; envelope `enrichment-cli/1`, exit 0 ok, 2 invalid args/pack, 3 runtime failure, 4 no results (e.g. no lessons match), 5 cancelled)

| command | behaviour |
|---|---|
| `guide validate [--pack FILE|--all] [--json]` | full validation of section 10.1 incl. hook, probe and tooltip registry checks; exit 2 on any `PT-GUIDE-*` |
| `guide list [--json]` | packs, lessons, prerequisite order, hook availability per lesson |
| `guide show LESSON [--json]` | steps, goals, hint text (for copy review) |
| `guide replay FILE|--all [--json]` | replays snapshot fixtures; exit 3 on mismatch with the first differing transition |
| `guide progress show|export|reset [--confirm]` | local store; `reset` requires `--confirm` |

CLI never imports Qt and never starts the desktop. `guide replay` is the headless QA workhorse (no GUI needed for lesson regression).

### 8.2 GUI (slice G4+, through the GUI track's panel registry; this is the design the registry entry must satisfy)

- **Placement**: `GuideDock(QDockWidget)`, `objectName='guide.dock'`, right dock area (tabified with the evidence dock when both are shown), initially hidden, features closable/movable/floatable as `EvidenceDock`; opened by `Help > Guide` (fixed menu position, `toggleViewAction()`), plus a status-bar "Guide" entry. Floating is allowed by Qt but the dock remains owned by `MainWindow`: no top-level window of our own (test: `QApplication.topLevelWidgets()` count unchanged by opening, stepping and closing).
- **Dock widgets**: lesson list (`QListView`, model `LessonListModel`), step list (`QListView`, `StepListModel`: state icon + status text, never colour alone), goal label, "What this means" (`PlainText`), buttons `Hint (n/4)`, `Show me`, `Skip`, `Reset step`, status line (`QLabel`, live text), review count label ("2 review items due"; text only, no pop-up), `Reset guide progress`. Models read frozen view-models from `guide.engine`; the dock holds no lesson logic.
- **CoachCard**: `QFrame` child of the main window (never `QDialog`, never `Qt.Popup`), one at a time, anchored beside the resolved target, repositions on resize/dock move/`QEvent.Move`, flips side to avoid the focus rectangle; contains the same goal/means/hint text; Esc dismisses (sets the card hidden for the current step only); Tab leaves; no focus steal on show (`Qt.WA_ShowWithoutActivating` not needed for child; do not call `setFocus` on show).
- **HighlightOverlay**: transparent `QWidget` child with `WA_TransparentForMouseEvents`, draws outline + corner marks (shape, not colour), static, `prefers-reduced-motion` irrelevant because there is no animation. Contrast >= the existing `DARK_STYLE` accent against its background (check 3:1 non-text contrast, 1.4.11 `[unverified]`).
- **Accessibility**: every dock control gets `setAccessibleName` and (via `apply_tooltip`) `accessibleDescription`; explicit `setTabOrder`; on each step change the adapter (1) updates the card's accessible name to "Step n of m: <title>, <status>", (2) sends a `QAccessibleAnnouncementEvent` (Qt >= 6.8, pinned 6.12.0, `[verified-snippet]`; fall back to a name-change event + the visible status line if unavailable), (3) updates the visible status line. Status messages follow WCAG 4.1.3 `[unverified]` intent. Targets >= 24x24 px (2.5.8, `[verified-snippet]`); text honours the system font scale. Windows screen-reader behaviour (UIA via Qt) and DPI scaling are **blocked external acceptance**: Linux CI asserts strings and event construction, not an AT bridge (AT-SPI needs the DBus flags, section 2).
- **Tooltips**: new ids registered in `tooltips.REGISTRY` by the dock slice (additive): `guide.dock`, `guide.lessons`, `guide.steps`, `guide.hint`, `guide.show_me`, `guide.skip`, `guide.reset_step`, `guide.review`, `guide.reset_progress`, `guide.card`; each with What/Why/Effect, e.g. `guide.show_me`: What "Show the expected item in the application." Why "Lets you see the answer and continue." Effect "Selects or opens only; changes nothing in your project. The step is recorded as Answer shown, not Completed." The existing tooltip audit test must pass.
- **States and exact copy**: empty (no project): "Open a project or load the synthetic sample to start a lesson. [Load sample]" (button calls the existing sample action); loading packs: "Loading lessons..."; pack error: "Lessons could not be loaded: <code>. Details are in Diagnostics." (never blocks the app); blocked step: "Not available in this build: <hook unavailable_text>"; `shown` row: "Answer shown"; lesson done with reveals: "Completed with answers revealed".
- **Qt pitfalls**: (1) never parent a card to a widget that can be destroyed mid-tour (parent is the main window; delete target references on `destroyed`); (2) snapshot recomputation is connected to owning signals with `Qt.QueuedConnection` and coalesced to one evaluation per event-loop turn using a single-shot zero-delay `QTimer`-free pattern: a boolean "dirty" flag and `QMetaObject.invokeMethod(..., Qt.QueuedConnection)` (no `QTimer` in the guide's code, see traps); (3) never read widget state from a worker thread; (4) never call `QToolTip` for the card (tooltips vanish on hover-out, 1.4.13 `[unverified]`); (5) `restoreGeometry` of the dock follows `EvidenceController`'s settings key pattern (`guide/geometry`); (6) closing the main window mid-tour must not abort (20x repeat).
- **Model/view and scale**: lesson and step models hold <= 24 lessons x 14 steps, so no virtualization is needed; the guide never touches the 100k-row match model, it only reads cached probe values published by `ui.py`/`ui_evidence.py` adapters (O(1) per probe). Budget: evaluating all active predicates <= 2 ms (design target), measured by a replay benchmark with 64-node predicates, not asserted as a hard CI limit on Windows (coarse clocks).
- **Offscreen tests** (`tests/test_ui_guide.py`, `QT_QPA_PLATFORM=offscreen`, 20x repeat gate): overlay click-through (QTest click reaches the button below); card never intersects the focused widget at 3 window sizes; Esc dismisses; Tab leaves card; accessible names non-empty and status text equals announced text; `topLevelWidgets()` unchanged; main window close mid-tour; real-state golden path per shipped lesson driven through hook actions on `sample.create_sample` (hermetic, no network, not a mocked-backend claim).

## 9. Initial lesson set (built only against features on `main`; confirmed in code 2026-10-14)

Confirmed present: Sample project (`MainWindow.open_sample`, `action.sample`), Swap orientation (`action.swap_orientation`), File overview/PE comparison (`show_file_overview`, `overview.*`), Rank changes Ctrl+R (`rank_action`, `action.rank_changes`, `nav.order`, `nav.signals`), navigator filters (`nav.search`, `nav.category_filter`, `nav.review_filter`), code viewer with modes, hunk navigation and sync scroll (`viewer.*`, `nav.previous_hunk`, `nav.next_hunk`), findings review/notes/bookmarks (`findings.*`), evidence dock (`evidence.*`, shows Unknown/Single engine states), series window (`series.*`, needs a series directory), Export with preview (`export.*`). **Not on main** (no GUI; do not teach): capa/FLOSS/DiE (CLI/adapters only: `intel-tools`), KB-CVE, patch search, workbench (strings/call graph/search), unified engine UI, YARA-X, KEV. Hooks for these are written by their tracks later.

| lesson id | skill | mode | features exercised (hooks) | key predicate (end state) | R1 pitfalls taught |
|---|---|---|---|---|---|
| `L01-first-comparison` | orientation | worked | sample, project label, navigator (`app.sample`, `nav.list`) | `eq(app.project_is_sample,true)` and `eq(project.orientation_explicit,true)` | P-06 |
| `L02-triage-the-files` | artefact triage | completion | file overview (`overview.table`) | `eq(overview.visible,true)` and `exists(overview.compared_field_count)` | P-07, P-09, P-10 (state limits only) |
| `L03-rank-and-choose` | where to look first | task | Rank changes, order switch, `nav.signals` | `eq(nav.order,"attention")` and `eq(nav.selected_match_name, fixture.expected.security_candidate)` | P-19, P-23, P-26 |
| `L04-read-one-change` | read a change | worked -> completion | code viewer, hunks, sync scroll | `ge(viewer.hunks_visited,2)` and `eq(viewer.representation,"decompiled")` | P-27, P-30 |
| `L05-unmatched-is-unknown` | unknown vs removed | completion | navigator category filter (added/deleted), match review | `eq(nav.category_filter,"deleted")` and `eq(nav.selected_match_name, fixture.expected.deleted_candidate)` | P-18 |
| `L06-record-your-reasoning` | review and notes | task | finding detail, evidence refs, review status, note | `eq(findings.selected_review_status,"accepted")` or `rejected`, `count_ge(findings.note_count,1)` (the learner performs the save; guide never writes) | P-31, P-32, P-33, P-40 |
| `L07-second-opinion-states` | evidence channels | completion | evidence dock | `eq(evidence.visible,true)` and `exists(evidence.verdict_label)`; step blocked until the dock hook is registered; copy explains Unknown/Single engine, never "wrong" | P-19, P-22, P-36 |
| `L08-share-what-you-found` | provenance and export | completion | Export dialog preview | `eq(export.preview_visible,true)` (stops at preview; the learner decides to write) | P-40, P-41 |

Excluded on purpose: series lesson (needs a multi-project fixture; added when SPEC-09b live path is open), anything needing Ghidra/BinDiff/rz-diff executables, KEV/CVE lessons. A second, **disabled-by-default** `stubs` pack lists future lessons (strings delta, capability delta, KB anchors) with `requires_hooks` that do not yet exist; it validates only in `--allow-missing-hooks` mode and never ships in the frozen build. Authoring: Opus drafts text, Sonnet validates (roadmap), human review of the copy golden.

Fixture `tests/fixtures/guide/sample-expected.json`: `{"security_candidate":"read_item","trivial_candidate":"get_version","deleted_candidate":"debug_dump","added_candidate":"report_invalid_index"}`; it is cross-checked against `sample.sample_diff` in a test so the fixture cannot drift from the sample.

## 10. Slice plan, amendments and QA

### 10.1 Pack validation rules (slice G1/G2)

Schema (7.2) + limits; unique ids; prerequisite DAG; rung monotonicity; hook exists and has `means`; every `done_when` probe registered with matching type; `Show me` action declared by the target hook; `tooltip_ids` exist; anchors' kinds are in the FAB vocabulary; text lint (no control chars, NFC, over-length, forbidden phrases: "confidence", "%", "proof of exploit", "vulnerable" outside an explicit negation template); fixture keys resolvable; each lesson has a worked/completion/task ordering consistent with `mode`; every R1 pitfall id referenced exists in `guide/data/pitfalls.json` (copied from R1 section 5 with its status `taught|not-yet`).

### 10.2 Slices (each mergeable alone; no two builders edit one file)

| slice | scope | exclusive files | deps | tier | size | acceptance gate | fallback |
|---|---|---|---|---|---|---|---|
| G0 | this spec merged; REGISTRY row; modules.md rows | `docs/specs/program-e/GDE-integration-plan.md` -> spec file, doc edits per 10.3 | none | Haiku | S | `tests/test_spec_registry.py` | none |
| G1 | models, limits, predicates (three-valued), snapshot, generated schemas | `src/patchtrace/guide/{__init__,models,limits,predicates,snapshot}.py`, `docs/schemas/guide/*`, `tests/test_guide_models.py`, `tests/test_guide_predicates.py` | none | Sonnet | M | red/green rejects unknown field/op, depth/node limits, NaN, unknown tri-state truth tables; schema drift check | hand-written validator without Pydantic generics |
| G2 | engine, hints, registry, validate, anchors port, store, review | `guide/{engine,hints,registry,anchors,validate,store,review}.py`, `tests/test_guide_engine.py`, `test_guide_validate.py`, `test_guide_store.py`, `test_guide_review.py`, `tests/fixtures/guide/replay/*.json` | G1 | Sonnet | L | replay fixtures (golden/hint/wrong-turn/reveal/blocked/reorder), determinism with shuffled keys, import lint (no time/random/net), store migration/corruption/reset, Leitner table with injected dates (`>=`, short parametrize ids) | split store into G2b |
| G3 | CLI `guide ...` + 6-line `cli.py` hook, `bootstrap.py` | `guide/cli.py`, `guide/bootstrap.py`, `tests/test_guide_cli.py`; **`cli.py` hook owned by the integration owner** | G2 | Sonnet | S | envelope `enrichment-cli/1`, exits 0/2/3/4/5, subprocess no-Qt-import test | emit JSON only |
| G4 | first pack + fixture + hook files for existing features | `guide/packs/core-1.json`, `guide/data/pitfalls.json`, `tests/fixtures/guide/sample-expected.json`, `src/patchtrace/guide_hooks_core.py` (hooks for sample, nav, viewer, findings, overview, export, evidence), `tests/test_guide_pack_core.py` | G2, G3 | Opus writes copy; Sonnet wiring | M | `guide validate --all` clean; copy golden; fixture-vs-sample cross-check; every `tooltip_ids` entry exists | ship L01-L04 only |
| G5 | snapshot adapter (`MainWindow` probes) | `src/patchtrace/ui_guide_adapter.py` (reads `WindowPort`-style accessors), `tests/test_ui_guide_adapter.py`; **one accessor hook in `ui.py` owned by the GUI-panel-registry track** | G4, GUI registry | Sonnet | M | offscreen: driving the real window to the golden state flips each lesson's `done_when`; no polling timer | read-only property reads only |
| G6 | dock, card, overlay, tooltips, a11y | `src/patchtrace/ui_guide.py`, new ids appended to `tooltips.py` (single owner for the append), `tests/test_ui_guide.py` | G5, GUI registry | Sonnet; a11y review Opus only if two attempts fail | L | section 8.2 test list at 20x repeat; tooltip audit; frozen smoke imports `ui_guide` | dock without overlay (card only) |
| G7 | per-track hooks and lessons as tracks land (strings, capa, KB, unified, FAB anchors) | each track's `guide_hooks.py` + its own pack file | tracks, FAB | Sonnet per track | S each | hook coverage test: every registered hook has `means`, tips, probes | `stubs` pack stays disabled |
| G8 | spaced review UI + progress export UI | `ui_guide.py` extension (same owner as G6) | G6 | Sonnet | S | review count text; reset/export tests | CLI-only review |

Order: G0 -> G1 -> G2 -> G3 -> G4 (G5 and G6 wait for the GUI panel registry; G1-G4 can run now and merge without any GUI).

### 10.3 Amendments required (applied by the integration owner)

1. `docs/specs/REGISTRY.md`: add the spec file as SPEC-41 (proposed) once promoted from `program-e/`; `tests/test_spec_registry.py` excludes `program-e/` until then.
2. `docs/modules.md`: add rows `guide` (models, predicates, engine, hints, registry, validate, anchors, store, review, cli; pure, depends on stdlib/pydantic/`enrichment.identity`) and `guide UI` (`ui_guide.py`, `ui_guide_adapter.py`; Qt, depends on guide, tooltips).
3. `docs/plans/program-e-roadmap.md` charter item 8 and gate "Feature done": add "ships `guide_hooks.py` with `means`, tooltip ids, probes; `guide validate --all` green"; add GDE track row source/build status.
4. `src/patchtrace/cli.py`: `COMMANDS` gains `'guide'` plus the dispatch hook (same pattern as `intel-tools`).
5. `src/patchtrace/tooltips.py`: append `guide.*` ids (G6); `exempt` list unchanged.
6. `tasks/todo.md`: slices G0-G8 with owners; `docs/qa.md`: blocked-external rows below.
7. Feature specs of tracks FAB (anchor vocabulary + `AnchorSink` alias), GUI (panel registry entry type "guide dock"), WB/CAP/KB/UE (a "Guide hooks" subsection).

### 10.4 Unverified residue (what remains `[unverified]`)

| item | status | what to do |
|---|---|---|
| WCAG 2.2.1, 2.2.2, 2.1.2, 1.4.13, 3.2.6, 3.3.7, 4.1.3, 1.4.1/1.4.3/1.4.11 normative text | `[unverified]` (checklists only) | reviewer with w3.org access reads the TR before freeze; designs are conservative anyway |
| WCAG 2.2 / 2.4.11 / 2.5.8 | `[verified-snippet]` | quote TR text; one snippet mislabelled 2.4.11/2.4.12 |
| Qt `accessibleName` -> UIA mapping text, standard widgets accessible by default | `[unverified]` | read doc.qt.io accessibility page; Windows screen-reader pass is owner acceptance |
| `QAccessibleAnnouncementEvent` default politeness | `[verified-snippet]` partial | check in pinned PySide6 6.12.0 wheel in G6 |
| ETSI EN 301 549 clause 11, Carroll & Carrithers 1984, Carroll & Rosson 1987, picoCTF 3GSE 2014, CTFd, Ghidra/Binary Ninja/IDA teaching material, Corbett & Anderson 1995, Anderson et al. 1995, Mitrovic & Ohlsson 1999, Murray 1999, Aleven et al. 2009/2016, Hmelo-Silver et al. 2007 | `[unverified]` | none is a decision input; keep as background or drop |
| VanLehn 2011 effect-size figures; Renkl & Atkinson page numbers; Kirschner 2006 as settled science | figures `[unverified]`, bibliography verified | never quote figures in lesson text |
| Leitner intervals 1/3/7/21/60 days | design default, not evidence | pack data; owner may change |
| R1 S5, S6, S10, S12, S14 (BinDiff manual text, CWE-416, DiE/FLOSS pages, PE format/ASLR/GS pages) and R1 `[practice, unverified]` stages | `[unverified]` | lessons L01-L08 cite none; no lesson may state them as fact |
| R1 S1/S2 numeric claims | M | not used |

### 10.5 Test and QA plan

- **Pure** (Linux+Windows CI): schema drift; table-driven predicate truth tables incl. unknown propagation; replay goldens per lesson (`tests/fixtures/guide/replay/<lesson>/<case>.json`: ordered snapshots + expected transitions/hints/roll-up); property: replay twice and with shuffled key order is identical; `guide/` import lint (`time`, `random`, `socket`, `urllib`, `http`, `requests`, `ssl`, `PySide6`, `patchtrace.ui*`) ; progress store crash-point tests (kill between temp write and replace leaves prior file); copy golden of all hint/card text; fixture-vs-`sample.sample_diff` cross-check.
- **Offscreen Qt** (G5/G6): section 8.2; 20x repeat without abort; tooltip audit; frozen smoke.
- **Windows pitfalls checklist**: CRLF (`.gitattributes` for `guide/packs/*.json`, fixtures and goldens, since hashes are over canonical JSON not file bytes, but golden text compare must be newline-neutral), short explicit parametrize ids, `>=` for coarse monotonic clocks (injected clock avoids it), no YAML (JSON only), wheels-only (no new dependency), hermetic.
- **Blocked external acceptance (reported separately, never counted done)**: Windows screen reader (Narrator/NVDA) reading step announcements, DPI/high-contrast/text-scaling pass, keyboard-only walk-through on a real Windows desktop, any lesson run with real third-party engines, owner usability review of lesson copy.
- **Beta scripted scenario (E-6)**: scripted run of L01-L08 on the sample via `guide replay` plus the offscreen golden path; the human tutorial feel stays owner acceptance.

## 11. Open questions (defaults given; none blocks)

1. Progress storage: per-user JSON under app data (default) vs inside the project file. Default: per-user, because lessons are not project evidence; revisit when FAB storage lands.
2. User-importable packs: default ship-only in v1; later import via the same validator with a consent step.
3. Anchor port name: default `AnchorSink` until the FAB contract names it; only `guide/anchors.py` changes.
4. Mandatory rungs: default rungs 1, 2, 4 for `worked`/`completion`, all four for `task`.
5. Card `means` reuses the tooltip entry `why` when the hook sets `means_from_tooltip`: default yes, to avoid divergent explanations.
6. Localisation: English only; `locale` reserved.
7. Idle hint offer: default off.
8. Should the guide expose `guide.progress` as a probe for features ("learner is in a lesson")? Default no; features must behave identically with the guide closed.
9. Spec number: default SPEC-41 (proposed); cite by path until confirmed.
