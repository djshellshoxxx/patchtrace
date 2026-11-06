# Dockable workspace proposal

**Status: draft / proposed; no implementation or release acceptance is claimed.**
Proposed alias: **SPEC-DW-01**; cite this path until the alias is confirmed.

This is a compact reconciliation of the [original proposal in PR #183](https://github.com/djshellshoxxx/patchtrace/blob/ed70e6ddac449a42f843f1c60aa878416ab31727/docs/specs/DOCKABLE-WORKSPACE-SPEC.md), whose source observations used `a04f5a299a8d4afef023261e52e08d14678cf1e7`. The baseline below was rechecked at candidate #235, `ccfe175d44a70947203c75bbd033a9a9e2633f0f`, on 2026-11-06. That candidate is not an assertion about an accepted mainline or installed package. The [reconciliation record](../research/workspace-docs-reconciliation-20261106.md) and [source receipt](../research/workspace-docs-reconciliation-20261106-sources.json) retain the original commit, file hashes and dispositions. This document is an adaptation, not a byte-preserved import.

## 1. Outcome and boundaries

Make the core work areas independently movable, tabbed, floating and hideable, with a simpler starting arrangement. Existing functionality remains reachable. A layout changes presentation; it does not change analysis settings, selected engines, project data, permissions or consent.

The existing [panel and layout guide](../guide/13-panels-and-layout.md), [keyboard help](../help/49-keyboard-and-command-navigation.md) and [layout recovery help](../help/50-panel-layout-and-recovery.md) describe the present framework. The proposed core extraction, presets and durable workspace envelope below are future work. The full historical proposal remains available for its detailed D0-D6 slices and DW-01-DW-18 acceptance fixtures.

## 2. Baseline observed in the candidate source

| Concern | Observed source and consequence |
|---|---|
| Core workspace | [`MainWindow._build_workspace`](../../src/patchtrace/ui.py) still builds horizontal matches/code/findings splitters and a vertical diagnostics area. The code pair has its own splitter. These core sections are not separate `PanelSpec` docks. |
| Existing feature panels | The [manifest](../../src/patchtrace/panel_manifest.py) has 14 reserved slots. Thirteen referenced declaration modules are present; `guide` is absent. This is source availability, not packaged or native GUI acceptance. [`fabric/panel.py`](../../src/patchtrace/fabric/panel.py) exists but is not registered in that manifest. |
| Registry and shells | [`gui/registry.py`](../../src/patchtrace/gui/registry.py) caps the registry at 32 panels and uses stable IDs. [`PanelDock`](../../src/patchtrace/gui/qt/docks.py) already provides close, move and float controls and names each shell `<id>.dock`. Reuse these seams. |
| Host and commands | [`PanelHost`](../../src/patchtrace/gui/qt/host.py) creates shells before restoration and constructs controllers lazily, except eager declarations. [Commands](../../src/patchtrace/gui/qt/commands.py) expose show/hide, focus, float/dock and move, a palette, focus cycling and layout reset. |
| Layout state | [`gui/qt/layout.py`](../../src/patchtrace/gui/qt/layout.py) stores `layout/schema`, `layout/state` and `layout/state_sha256`; schema is 1 and the state cap is 64 KiB. Invalid stored state is cleared by the current restore path. Future-version preservation and generation recovery below are proposed changes. |
| Geometry and splitters | [`restore_preferences` and `closeEvent`](../../src/patchtrace/ui.py) read/write `desktop/geometry` and `desktop/workspace`, `desktop/vertical`, `desktop/code`. Geometry recovery clamps the main window. That code does not establish recovery of every floating dock after a monitor change. |

The older unbuilt-language in [SPEC-04](ui.md) and [SPEC-54](gui-framework.md) is not a current panel inventory. Their established separation of UI, services, evidence and task ownership remains applicable. Implementation must reconcile affected specification text alongside its code; this proposal does not change those contracts.

## 3. Proposed extraction

Keep one `QMainWindow`, the existing registry, native dock shells and one owning host. Replace the fixed core splitter with independent sections; a compact welcome/recovery surface may occupy the center. Demonstrate usable center sizing before extracting the full workspace. Transient setup, consent, creation and export workflows remain dialogs.

| Proposed IDs | Source surface and boundary |
|---|---|
| `matches`, `change_signals` | `_build_navigator`: preserve filters, selection, review and correction controls with their owning view; expose the selected relationship's signals separately. |
| `compare_controls`, `code_older`, `code_newer` | `_build_code`: keep representation/hunk controls coherent; each movable code side retains explicit Older/Newer, artifact and run identity. |
| `findings`, `finding_detail`, `finding_review`, `analyst_notes` | `_build_findings`: separate list, evidence, review and note surfaces while retaining the exact target of every edit. |
| `diagnostics` | `_build_workspace`: expose progress and the existing bounded log; global job status and Cancel remain reachable when the dock is hidden. |
| `engine_controls` | [`EvidencePanel`](../../src/patchtrace/ui_evidence.py): separate the Engines surface while sharing its existing controller with `evidence`. |
| `unified_detail`, `unified_code` | [`UnifiedPanel` and `UnifiedCodeView`](../../src/patchtrace/ui_unified.py): separate details and paired code while sharing their controller with `unified`. |

These 13 IDs are proposals, not manifest additions. Together with the current 14 reservations they would occupy 27 slots, within the existing cap. Retain all current panel IDs and shortcuts; new sections initially have no fixed shortcut. Guide remains unavailable and Related evidence is not activated by this work. Each shared controller must be constructed, notified and shut down once regardless of how many views are visible.

## 4. Proposed layouts and state ownership

The historical **Beginner** preset shows exactly `matches`, `compare_controls`, `code_older` and `code_newer`. Analysis, Compare engines, Reverse engineering and Findings review remain proposed alternate arrangements defined in the original source. Existing installations need an explicit migration that preserves their arrangement where possible. A preset must not start work, reset feature settings or make an unavailable panel appear implemented.

Preserve these requirements from the source proposal:

- Layout operations retain widgets, models, selected items, filters, code state and Series tabs. They neither run tools/providers nor write project data. Existing asynchronous view hydration may run when a view is revealed; layout handlers must not perform blocking reads.
- Hide/float/tab/reset never implicitly saves, discards or retargets an analyst draft. Keep drafts in memory under project and finding/match identity. Selection changes and exit need an explicit draft-resolution path. Draft text is excluded from layout persistence.
- Hiding an owning view does not cancel a job or drop its result. Existing cancellation and generation checks remain authoritative. Completion updates the correct model once without reopening hidden panels or stealing focus.
- Valid navigation reveals only its required destinations, including a hidden code side. Stale, missing, ambiguous or blocked links retain their existing outcome and do not choose a substitute target.
- Keyboard actions must cover show, focus, move, split, tab and float/dock. Focus cycling must not count the old fixed regions and their new docks twice. Theme, high contrast, accessible names and reduced-motion behavior remain part of parity.
- Save/restore named layouts, an undoable prior arrangement, reset, and a bring-floating-panels-on-screen command are proposed. Layout names and screen hints are presentation data; project paths, credentials, notes and results must not enter the layout envelope.

## 5. Proposed persistence and recovery

Evolve the existing settings behind a separate versioned `workspace_layout/` envelope. Keep Qt dock-state versioning separate from envelope versioning and preserve unchanged panel IDs. The original draft proposes a 64 KiB state cap, 128 KiB envelope cap, 20 named layouts, two autosave generations and one prior-layout snapshot. These are proposed bounds, not current settings or newly accepted contracts.

Publish a complete validated inactive generation before selecting it as active. Recovery must try valid generations and legacy inputs before defaults; interrupted writes and denied/full storage must leave the previous valid layout recoverable. Detect conflicts between instances. Unknown future envelope versions must remain intact while an in-memory fallback is used. A digest detects corruption; it is not authentication.

Migration must retain the original `layout/*` and `desktop/*` inputs, restore existing feature IDs, translate usable splitter proportions, and publish only after successful validation. Do not promise pixel-exact conversion. Font, sync, theme and feature settings survive; obsolete splitter keys must not override the new layout after migration. Reset affects layout state only.

Create cheap shells before restoration; validate types, bounds, versions, digests and IDs; restore geometry/state; reconcile logical visibility, focus and lifecycle once. Missing optional panels must not block opening. Recover floating title bars and controls onto available displays using logical coordinates, including negative origins and mixed DPI. A failed restore must leave one coherent usable arrangement, not a mixture of partially restored layouts.

## 6. Implementation order and acceptance still required

Use the historical order: confirm the contract and inventory; prove native shell sizing; extract core sections; separate shared-controller surfaces; implement durable layouts/migration; verify navigation, drafts and lifecycle; update help and record acceptance. Each slice should preserve the existing workflows and the Qt-free declaration boundary. No source modules, manifest entries or settings contracts are added by this documentation change.

| Historical gate | Required evidence before claiming the proposed workspace complete |
|---|---|
| DW-01, DW-02 | Exact Beginner open set; all proposed and existing IDs accounted for; Guide remains absent; no job starts. |
| DW-03, DW-04 | Every section moves independently; widget/controller identity and Older/Newer pairing survive split, tab, float, hide and sync navigation. |
| DW-05-DW-09 | Round-trip layouts; legacy, corrupt, partial, future and missing-panel fixtures; interrupted publication; denied writes and competing instances. |
| DW-10-DW-12 | Fake long jobs complete once under the right key; drafts keep their targets; hidden-target navigation preserves stale and ambiguous outcomes. |
| DW-13, DW-14 | Keyboard recovery from all-hidden layouts; usable small windows, mixed DPI and removed/negative-origin displays. |
| DW-15, DW-16 | Presets and undo are deterministic; repeated show/hide cycles do not duplicate controllers, widgets, subscriptions or tasks. |
| DW-17 | Record reference hardware and separate cold construction from layout timing; evaluate the original proposed responsiveness bounds without synchronous layout I/O. |
| DW-18 | Frozen Windows application, NVDA/Narrator, high contrast and reduced motion; record actual manual/native results separately. |

Existing seams include [layout tests](../../tests/test_gui_host_layout.py), [manifest tests](../../tests/test_gui_core_manifest.py), [host tests](../../tests/test_gui_host.py), [dock migration tests](../../tests/test_ui_m3_docks.py) and [dock stress tests](../../tests/stress/test_gui_stress_docks.py). They cover the present framework, not completion of these future gates. The repository suite, Ruff and Windows/manual acceptance still apply to any later implementation. Documentation checks alone cannot promote this proposal to approved, built or release-ready.
