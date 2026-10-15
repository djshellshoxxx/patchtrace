"""SPEC-31 S4b: the Unified panel declaration is pure, agrees with its manifest slot and carries every tip the read
model names (07 s8)."""
from __future__ import annotations

import subprocess
import sys

from patchtrace.gui.registry import PanelSpec, lint, load_manifest
from patchtrace.panel_manifest import MANIFEST
from patchtrace.unified import read_model
from patchtrace.unified.panel import PANEL, TEMPLATES, TIPS


def test_panel_module_imports_no_qt():
    code = 'import sys, patchtrace.unified.panel; sys.exit(any(n.startswith("PySide6") for n in sys.modules))'
    assert subprocess.run([sys.executable, '-I', '-c', code], check=False).returncode == 0


def test_spec_equals_its_manifest_slot():
    slot = next(entry for entry in MANIFEST if entry.id == 'unified')
    assert isinstance(PANEL, PanelSpec)
    assert (PANEL.id, PANEL.area, PANEL.tabify_with, PANEL.shortcut) == (
        slot.id, slot.area, slot.tabify_with, slot.shortcut) == ('unified', 'right', 'evidence', 'Ctrl+Shift+U')


def test_every_tip_the_read_model_names_is_declared():
    wanted = set(read_model.TOOLTIP_IDS) | set(read_model.source_tooltip_ids())
    assert wanted <= set(TIPS)
    assert set(read_model.TOOLTIP_TEMPLATE_IDS) <= set(TEMPLATES)
    assert {'unified.dock', 'unified.action'} <= set(TIPS)


def test_manifest_lint_is_clean_with_the_panel_built():
    report = lint(MANIFEST, load_manifest(MANIFEST))
    assert [f for f in report.findings if f.panel == 'unified'] == []
