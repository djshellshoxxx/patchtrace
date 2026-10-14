"""Qt-free core of the GUI framework (docs/specs/program-e/GUI-integration-plan.md, sections 7 and 8).

Nothing in this package imports Qt, `patchtrace.ui*` or any feature package; the Qt layer is the separate
`patchtrace.gui.qt` subpackage. Panels declare a pure `PanelSpec` here, so the manifest can be linted headless
(`patchtrace panels check`) and view-models can be tested without a display.
"""
