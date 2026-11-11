# Related-evidence panel (FAB-6)

Status: proposed implementation contract, 2026-10-15, written from the code at `claude/instance-d-gui` `da7d2db` and `docs/specs/program-e/FAB-integration-plan.md` s7 and s8. Nothing here is built. No ChatGPT draft exists for this panel. Facts below were read in `src/patchtrace/fabric/*.py` and `src/patchtrace/gui/anchors.py`; anything not read is marked UNVERIFIED. Authority: `docs/plans/worker-brief.md`, `docs/specs/gui-framework.md`, the FAB plan for domain semantics.

## 1 Purpose and analyst question

"What else is known about this function (or any anchor I select) from independent sources?" The panel lists the anchors the project's fabric holds for the selected pair or function, each with how many independent origins support it. It adds no evidence, no score, no ranking and no sum. Missing evidence is unknown, not negative.

## 2 Identity

- Package module `src/patchtrace/fabric/panel.py` exporting `PANEL`; Qt module `src/patchtrace/ui_related.py` with `RelatedController(ControllerBase)` (pattern: `pilot/panel.py` and `ui_leads.py`).
- `PanelSpec(id='related', title='Related evidence', area='bottom', tabify_with='leads', shortcut='Ctrl+Shift+J', requires=('project',), anchors_in=<kinds below>, anchors_out=<kinds below>)`.
- The manifest has no slot for it (`src/patchtrace/panel_manifest.py` lists 14). The integrator adds one line before the build: `ManifestEntry('related', 'patchtrace.fabric.panel', _related, 'bottom', 'leads', 'Ctrl+Shift+J')` plus a `_related()` loader. `python -m patchtrace panels check` arbitrates the shortcut; if it conflicts, pick another `Ctrl+Shift+<letter>` that `gui/shortcuts.py` does not reserve and update FAB plan Q6.
- Kinds handled and emitted: the fabric kinds `function, string, import, capability, rule, build_fact, advisory_phrase, cve, kb, cwe` (`fabric/contracts.py` `Kind`). `gui/anchors.py` `ANCHOR_KINDS` additionally has `match` and `address`, which the fabric does not store. Do not claim `cve`/`match` in `anchors_in`: the Leads panel owns them (`AnchorRouter` keeps one handler per kind). Register `anchors_in` for the other kinds this panel can show; Enter on a row ROUTES the anchor to its owning panel through `ctx.nav.navigate`, it does not handle it.

## 3 Data contract

Read only; nothing is persisted by this panel except what FAB-4 already persists on request (pins).

- Reader: `AnchorReader` (`fabric/ports.py`): `find(project_key, AnchorQuery{kind?, key?, side?, role?, subject?, producer?, offset, limit}) -> AnchorPage{items, total}`; `get(project_key, anchor_id)`; `resolve(project_key, kind, value, side)`. Real implementation: `fabric/store.py::EnrichmentAnchorStore(enrichment)` (also exposes `batches(project_key)` -> `BatchStatus` rows with `readable`, `skipped`, stale flag, and `digest(project_key)`). Pins: `fabric/pins.py::EnrichmentPinStore` implementing `PinPort` (`pin`, `unpin`, `pins`).
- Page size 500 (`FabricLimits` F-09). `project_key` is the persisted project id (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`); the GUI `ProjectKey.identity()` supplies it.
- Pure module to create: `fabric/view_model.py` with frozen slotted dataclasses `RelatedRow(anchor_id, kind, label, side, role, role_glyph, witnesses_text, producers_text, accessible, search)`, `RelatedView(state, rows, total, skipped, stale_batches)` and functions `build_view(page, batches, pins) -> RelatedView`, `row_for(anchor, registry) -> RelatedRow`, `detail_text(anchor) -> str`, `copy_text(anchor) -> str` (TSV, at most 16 KiB), `witness_phrase(anchor, registry)`. Independence uses `fabric/origins.py::independent_count` and `anchor_components`, never the raw witness count. Names are proposals (UNVERIFIED against future code); reuse an existing equivalent if one appears.
- Add `AnchorRef.from_fabric(anchor) -> AnchorRef` in `src/patchtrace/gui/anchors.py` (does not exist: `grep -rn from_fabric src` is empty). Mapping: `kind` equal; `key` = fabric `key` (1-256 characters; both sides use the same limit, `KEY_LIMIT` 256 and F-06 200); `side` = fabric side, with fabric `none` -> `None`; `label` = display witness label; `origin` = producer of the first witness in producer order; `run_id` and `revision` from `AnchorRef.pinned(ProjectKey)`. A fabric anchor of `role='hint'` or `'stated'` must still route as itself (a hint is not found evidence). Test it for all ten kinds and for sanitised labels. This file is GUI core, not a feature file: list it under "Integrator asks".

## 4 Layout

One `VirtualTable` (`gui/qt/table.py`) over `gui/table_spec.py` columns: Kind, Label, Side, Role (chip with glyph and text: `+` observed, `i` stated, `?` hint; `gui/qt/chips.ChipLabel`; `chip_collisions` must report none), Witnesses ("2 independent of 3"), Producers. Order is the canonical `find` order; no score column. Above the table: a filter combo (Kind) and a text filter. Below: a read-only detail pane (`SafeTextView`) and buttons Copy, Pin/Unpin (only for rows of the current orientation), Go to. A `StateView` plus `NoticeStrip` carry the framework states. Minimum size (40, 14) em.

## 5 States (framework copy from `gui/state.py`; panel text below)

| State | Trigger | Text |
|---|---|---|
| no-project | no project | framework copy |
| loading | `find` page in flight | framework copy |
| ready | rows present | table |
| empty | no anchors for the subject | "Nothing else is known about this function yet. Run capabilities, strings or build tools to add evidence. Missing evidence is unknown, not a negative result." |
| partial | some batches unreadable or skipped | framework partial copy plus "n anchors skipped" from `BatchStatus.skipped` |
| stale | a batch's guard moved or its origins digest is not the registry's | rows still shown with a "stale" chip (a stale batch is out of date, not wrong, FAB plan s7) |
| error | `FabricError` | message with the `PT-FAB-*` code; no raw exception text |
| too-large | more rows than the 100,000 table cap | framework copy; ask for a narrower kind filter |

There is no blocked state of its own (`requires=('project',)`).

## 6 Interactions

Arrows move rows; Enter or double-click routes the anchor (`ctx.nav.navigate(AnchorRef.from_fabric(anchor))`); Space opens the detail pane; Ctrl+C copies the selected rows as TSV (framework behaviour, capped). Pin writes one `anchor-pin` event through `PinPort.pin(project_key, anchor, note='', via='related')`; Unpin writes `unpin`. A pin of an anchor made for the other orientation is refused by the store (`PT-FAB-ORIENTATION`): disable the button and say why. Notes are plain text of at most 2 KiB.

## 7 Navigation

Selection of a match in the main window arrives through `selection_changed(match_id)`; the controller looks up the pair's subject (`pair:` key via `fabric/ids.py::pair_key`; a `pair:` subject also matches its member `image:` subjects) and reloads. `show_anchor(AnchorRef)` accepts any fabric kind, filters the table to the anchor's kind and key and selects the row, or returns `NavResult.not_found` with the framework copy (exact strings are the constructors in `gui/anchors.py`, see `docs/plans/panels-build-plan.md` s2.1 on `origin/chatgpt/panels-1`). Ambiguity returns candidates (at most `MAX_CANDIDATES`), never the first.

## 8 Threads

Loading runs through `ctx.tasks` on a lane stored on the controller (one name, created once). The worker receives the immutable project key and queries; the project database connection is thread-bound, so the GUI thread opens the `EnrichmentAnchorStore` and passes read results or does paging with small GUI-thread slices (decide in the first test: UNVERIFIED which of the two the enrichment store permits; follow `ui_leads.py`, which reads pointer rows on the GUI thread). A generation counter drops late results after a project or selection change.

## 9 Settings

Prefix `related/`: `related/kind` (filter), nothing else. Geometry belongs to the host layout.

## 10 Tooltips (`PANEL.tips`; ids: `related.dock`, `related.action`, `related.table`, `related.filter_kind`, `related.search`, `related.detail`, `related.copy`, `related.pin`, `related.goto`; templates: `related.role`, `related.witnesses`)

Each entry has What / Why / Effect, no `<` or `>`. Required wording:
- `related.dock`: What "Dock listing what other tools and advisories say about the selected function." Why "Shows where independent evidence agrees." Effect "Read-only; it does not rank functions or show likelihood."
- `related.role` (template): What "Role {role}." Why "Observed was found in this code; stated comes from an advisory or catalog; a hint is something to look for." Effect "Read-only; a hint was not found here."
- `related.witnesses` (template): What "{n} witnesses from {m} independent origins." Why "Witnesses that share an origin count once." Effect "Read-only."
Teach topic ids: `fabric.origin.once`, `fabric.role.hint`, `fabric.related.unknown`. Detail pane text: "Seen by {n} witnesses from {m} independent origins: {producers}. Witnesses that share an origin count once."; hint: "A hint is something to look for; it was not found here."; stated: "A statement comes from an advisory or catalog; by itself it says nothing about this code." Claims profile: neutral plus the banned-word sweep used by `tests/test_kev_view_model.py::test_copy_has_no_banned_claims` (no "probability", "confidence", "likely", "proven", "safe").

## 11 Accessibility

One Tab stop for the table; names "Related evidence panel", "Related evidence table", "Kind filter"; cell accessible text such as "Imports RtlULongAdd, newer, observed, 2 independent origins of 3 witnesses"; chips carry glyph and text, colour is redundant; `a11y_audit` from `tests/qt_support.py` must return no findings. Manual NVDA/Narrator pass stays OPEN.

## 12 Performance budgets

Pure `build_view` for 100,000 synthetic anchors in a test with an upper bound recorded in `docs/qa.md` when first measured (do not invent the number); table `data()` lazy gate at 10,000 and 100,000 rows via `assert_lazy_model`; filter response measured the same way. First paint after the first page only.

## 13 Security and privacy

Labels and facets are untrusted: pass through `sanitize_text`; render as plain text (`PlainLabel`, `SafeTextView`); never HTML. Pin notes are analyst text, stored locally only. No network, no tool run, no target execution.

## 14 Test plan

Write first:
- `tests/test_fabric_view_model.py`: `test_independent_count_not_witness_count`, `test_hint_row_is_not_found`, `test_stale_batch_rows_flagged_not_hidden`, `test_skipped_anchors_counted`, `test_copy_text_capped_16_kib`, `test_hostile_label_is_plain_text`, `test_100k_anchor_view`.
- `tests/test_gui_anchors_fabric.py` (or in `tests/test_gui_core_anchors.py`): `test_from_fabric_all_ten_kinds`, `test_from_fabric_side_none`, `test_from_fabric_label_sanitised`.
- `tests/test_related_panel.py`: spec equals manifest slot; importing `patchtrace.fabric.panel` imports no Qt (subprocess, needs the package installed).
- `tests/test_ui_related.py`: every state, late result dropped after a project switch, Pin disabled for wrong orientation, tooltip registry coverage, `a11y_audit`, lazy table gate, no new top-level window.
Commands: `PYTHONPATH=src QT_QPA_PLATFORM=offscreen python -m pytest -q -p no:cacheprovider tests/test_fabric_*.py tests/test_related_panel.py tests/test_ui_related.py tests/test_gui_host_seam.py tests/test_tooltips.py`; `python -m patchtrace panels check`; `python tools/qt_gate.py --repeat 20 tests/test_ui_related.py`. CI: workflow `qa-windows.yml` (jobs `qa`, `qt-gate`). Integrator edits that must ship in the same PR: the manifest line, `built` set in `tests/test_gui_host_seam.py`, the dock tuple in `tests/test_tooltips.py`.

## 15 Open questions

1. Shortcut `Ctrl+Shift+J` and tab group `leads` (FAB plan Q6, default as written).
2. Does the producer ever need to publish `absent`? No for v1 (FAB plan Q2).
3. Whether the GUI thread or a worker pages the enrichment store (section 8): decide by a first failing test.
4. Whether to show the panel for projects with zero published batches or hide the action: default show, with the empty state.
