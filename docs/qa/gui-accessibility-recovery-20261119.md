# Current-window accessibility recovery

Recovered the F-gui-1 contribution from
`6ad9ba7cbe9f86b2ddda58e1d59c583a21322fe8` on
`claude/autonomous-finish-20261104`, preserving the current panel implementations
and recovered Calls layout. The original tests reproduced five failures on the
current integration candidate: unnamed controls, duplicate accessible IDs,
sibling name collisions and unnamed combo child controls. Three controls passed.

The port restores the pure registered-name table, fills only empty control
names, preserves explicit names and dynamic status labels, and names combo
popups/editors and table headers. State-view bodies, notice strips, engine
checkboxes, graph minimap, chips, copy buttons and dock tabs receive distinct
accessible identifiers. No target analysis, network request or UI data changes.

The original port still found two gaps added after the source contribution:
the saved-search dialog reused `search.save` from the panel's Save query action,
and the signature-detail tree header had no name. The dialog now has scoped
Save/Cancel identifiers and the tree header is named. The whole-window controls
remain unchanged; no exemption was added to hide either failure.

Fresh combined verification on the final integrated implementation:

```bash
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q \
  tests/test_gui_a11y_window.py tests/test_gui_tips.py tests/test_gui_state_view.py \
  tests/test_ui_graph_layout.py tests/test_ui_search_saved.py tests/test_ui_inspection_signing.py
```

**145 passed in 62.37 seconds.** Normal full-source Ruff and diff whitespace
checks passed. This is actual offscreen Qt verification, not native Windows
screen-reader, AutomationId mapping, keyboard/DPI or complete-dialog acceptance.

An initial verification command named nonexistent `test_ui_state_view.py` and
collected no tests; the corrected selection uses `test_gui_state_view.py`.
Earlier overlapping results are not added to the final count. The source port
before the two integration fixes had 2 failures and 113 passing controls.
