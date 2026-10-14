"""GUI core (slice F1): the explicit panel manifest with its 14 reserved slots (GUI-integration-plan 8.2).

The placement and the twelve shortcuts are the plan's. The module paths of the slots the plan does not name
(`capabilities`, `series`, `files`, `guide` and the like) are F1's choice; the integrator edits one line if a
feature builder puts its `panel.py` elsewhere.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from patchtrace import panel_manifest
from patchtrace.gui.registry import lint, lint_entries, load_manifest
from patchtrace.panel_manifest import MANIFEST

SOURCE = Path(panel_manifest.__file__)

# id: (module, area, tabify_with, shortcut), in the order of GUI-integration-plan 8.2.
EXPECTED = {
    'evidence': ('patchtrace.secondary.evidence_panel', 'right', None, 'Ctrl+Shift+E'),
    'unified': ('patchtrace.unified.panel', 'right', 'evidence', 'Ctrl+Shift+U'),
    'search': ('patchtrace.search.panel', 'bottom', None, 'Ctrl+Shift+F'),
    'graph': ('patchtrace.callgraph.panel', 'bottom', None, 'Ctrl+Shift+G'),
    'strings': ('patchtrace.strings.panel', 'bottom', 'graph', 'Ctrl+Shift+T'),
    'capabilities': ('patchtrace.intelligence.tools.capa_panel', 'bottom', 'graph', 'Ctrl+Shift+A'),
    'build_env': ('patchtrace.buildenv.panel', 'right', 'evidence', 'Ctrl+Shift+B'),
    'rules': ('patchtrace.rules.panel', 'right', None, 'Ctrl+Shift+R'),
    'kb': ('patchtrace.kbcorrelation.panel', 'right', None, 'Ctrl+Shift+K'),
    'kev': ('patchtrace.kev.panel', 'right', 'kb', 'Ctrl+Shift+X'),
    'leads': ('patchtrace.pilot.panel', 'left', None, 'Ctrl+Shift+L'),
    'guide': ('patchtrace.guide.panel', 'left', None, 'Ctrl+Shift+H'),
    'series': ('patchtrace.nway.panel', 'bottom', None, None),
    'files': ('patchtrace.pe_overview.panel', 'bottom', None, None),
}


def test_the_fourteen_planned_panels_are_reserved_in_the_plans_order():
    assert isinstance(MANIFEST, tuple)
    assert [entry.id for entry in MANIFEST] == list(EXPECTED)


@pytest.mark.parametrize('panel_id', list(EXPECTED))
def test_each_slot_has_the_planned_module_area_tab_group_and_shortcut(panel_id):
    entry = next(e for e in MANIFEST if e.id == panel_id)
    assert (entry.module, entry.area, entry.tabify_with, entry.shortcut) == EXPECTED[panel_id]


def test_default_placement_matches_the_plans_columns_and_tab_groups():
    def placed(area):
        return [e.id for e in MANIFEST if e.area == area and e.tabify_with is None]

    assert placed('right') == ['evidence', 'rules', 'kb']
    assert placed('bottom') == ['search', 'graph', 'series', 'files']
    assert placed('left') == ['leads', 'guide']
    tabbed = {e.id: e.tabify_with for e in MANIFEST if e.tabify_with}
    assert tabbed == {'unified': 'evidence', 'build_env': 'evidence', 'strings': 'graph', 'capabilities': 'graph',
                      'kev': 'kb'}


def test_the_three_planned_k_requests_are_settled_k_a_x():
    shortcuts = {e.id: e.shortcut for e in MANIFEST}
    assert (shortcuts['kb'], shortcuts['capabilities'], shortcuts['kev']) == (
        'Ctrl+Shift+K', 'Ctrl+Shift+A', 'Ctrl+Shift+X')
    assert shortcuts['evidence'] == 'Ctrl+Shift+E'  # the existing evidence dock toggle
    assert len({s for s in shortcuts.values() if s}) == 12  # P is the palette, so twelve letters are left to give


def test_the_shipped_manifest_passes_the_static_lint():
    assert lint_entries(MANIFEST) == []


def test_every_loader_imports_exactly_the_module_its_slot_declares():
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    loaders = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    for entry in MANIFEST:
        node = loaders[entry.load.__name__]
        body = [n for n in node.body if not isinstance(n, ast.Expr)]  # a docstring is allowed
        assert len(body) == 2 and isinstance(body[0], ast.ImportFrom) and isinstance(body[1], ast.Return), entry.id
        imported = body[0]
        assert imported.level == 1 and [a.name for a in imported.names] == ['PANEL'], entry.id
        assert 'patchtrace.' + imported.module == entry.module, entry.id
        assert isinstance(body[1].value, ast.Name) and body[1].value.id == 'PANEL', entry.id


def test_each_slot_has_its_own_loader_and_nothing_else_is_defined():
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    functions = [node.name for node in tree.body if isinstance(node, ast.FunctionDef)]
    assert sorted(functions) == sorted(entry.load.__name__ for entry in MANIFEST) and len(set(functions)) == 14


def test_the_manifest_never_discovers_modules_dynamically():
    text = SOURCE.read_text(encoding='utf-8')
    assert 'importlib' not in text and '__import__' not in text and 'import_module' not in text
    tree = ast.parse(text)
    toplevel = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert [(n.module, [a.name for a in n.names]) for n in toplevel if isinstance(n, ast.ImportFrom)] == [
        ('__future__', ['annotations']), ('gui.registry', ['ManifestEntry', 'PanelSpec'])]


def test_loading_the_real_manifest_raises_nothing_unexpected_and_every_built_panel_lints_clean():
    """Today every slot is absent. As features land this stays the gate: a module that raises on import, pulls in Qt
    or disagrees with its slot fails here (and in `patchtrace panels check`)."""
    loaded = load_manifest(MANIFEST)
    assert loaded.errors == {} and loaded.forbidden == {} and not loaded.cancelled
    assert set(loaded.specs) | set(loaded.not_built) == set(EXPECTED)
    assert not set(loaded.specs) & set(loaded.not_built)
    assert lint(MANIFEST, loaded).findings == ()
