"""GUI core (slice F1): PanelSpec, naming, limits and manifest loading (GUI-integration-plan 7 and 8.2). Pure."""
from __future__ import annotations

import dataclasses
import sys
import types
from types import SimpleNamespace

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.gui import registry
from patchtrace.gui.capabilities import Availability
from patchtrace.gui.registry import (
    CommandSpec,
    ManifestEntry,
    PanelContext,
    PanelSpec,
    TeachTopic,
    accessible_name,
    dock_name,
    forbidden_modules,
    is_panel_id,
    load_manifest,
    settings_prefix,
    tip_prefix,
    toggle_name,
)
from patchtrace.gui.text import CLAIMS_NEUTRAL

PROPS = settings(max_examples=300, deadline=None, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow])

# GUI-integration-plan section 7, "Limits (constants in gui/registry.py)".
PLAN_LIMITS = {
    'MAX_PANELS': 32, 'TITLE_LIMIT': 32, 'NAME_LIMIT': 80, 'DESCRIPTION_LIMIT': 160, 'LABEL_LIMIT': 200,
    'TABLE_ROWS': 100_000, 'CLIPBOARD_BYTES': 16 * 1024, 'GRAPH_NODES': 500, 'GRAPH_EDGES': 2_000,
    'GRAPH_NODES_MAX': 2_000, 'GRAPH_EDGES_MAX': 8_000, 'CODE_CHARS': 200_000, 'NOTICE_CHARS': 400,
    'PROGRESS_HZ': 10, 'ANNOUNCE_GAP_S': 1.5, 'SELECTION_DEBOUNCE_MS': 120, 'JOIN_TIMEOUT_S': 5, 'NAV_HISTORY': 50,
    'PALETTE_RESULTS': 50, 'FOCUS_ORDER_MIN': 100}


@pytest.mark.parametrize('name', list(PLAN_LIMITS))
def test_limits_are_the_plans_numbers(name):
    assert getattr(registry, name) == PLAN_LIMITS[name]


def test_areas_are_the_four_docks_and_none():
    assert registry.AREAS == ('left', 'right', 'top', 'bottom', 'none')


# ---- ids and names ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize('text', ['evidence', 'build_env', 'ab', 'a1', 'a' + 'b' * 23, 'k_v'],
                         ids=['plain', 'underscore', 'two', 'digit', 'longest', 'inner-underscore'])
def test_valid_panel_ids(text):
    assert is_panel_id(text)


@pytest.mark.parametrize('text', ['', 'a', 'A', 'Evidence', '1ab', '_ab', 'a-b', 'a.b', 'a b', 'a' + 'b' * 24,
                                  'abc\n', 'ab' + chr(0xe9), None, 7],
                         ids=['empty', 'one-char', 'upper-one', 'capital', 'digit-first', 'underscore-first', 'dash',
                              'dot', 'space', 'too-long', 'newline', 'accent', 'none', 'int'])
def test_invalid_panel_ids(text):
    assert not is_panel_id(text)


@PROPS
@given(st.from_regex(r'[a-z][a-z0-9_]{1,23}', fullmatch=True), st.text(max_size=30))
def test_ids_are_exactly_the_documented_grammar(valid, other):
    assert is_panel_id(valid)
    assert is_panel_id(other) == (
        2 <= len(other) <= 24 and other[0] in 'abcdefghijklmnopqrstuvwxyz'
        and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789_' for c in other))


@PROPS
@given(st.from_regex(r'[a-z][a-z0-9_]{1,23}', fullmatch=True), st.from_regex(r'[a-z][a-z0-9_]{1,23}', fullmatch=True),
       st.from_regex(r'[a-z0-9_.]{0,10}', fullmatch=True))
def test_tooltip_prefixes_of_distinct_ids_never_overlap(first, second, rest):
    """A dot cannot appear in an id, so '<id>.' prefixes are prefix-free: no tip can belong to two panels."""
    if first != second:
        assert not f'{second}.{rest}'.startswith(tip_prefix(first))


def test_naming_conventions():
    assert tip_prefix('search') == 'search.'
    assert dock_name('search') == 'search.dock'
    assert toggle_name('search') == 'search.action'
    assert settings_prefix('search') == 'search/'
    assert accessible_name('Search') == 'Search panel'


# ---- spec types -------------------------------------------------------------------------------------------------


def factory(ctx):
    raise AssertionError('not called here')


def test_panel_spec_defaults_follow_the_plan():
    spec = PanelSpec(id='search', title='Search', factory=factory)
    assert (spec.area, spec.tabify_with, spec.shortcut, spec.focus_order, spec.group) == (
        'right', None, None, 100, 'Panels')
    assert (spec.requires, spec.claims, dict(spec.tips), dict(spec.tip_templates)) == ((), CLAIMS_NEUTRAL, {}, {})
    assert (spec.extra_tip_prefixes, spec.commands, spec.teach) == ((), (), ())
    assert (spec.anchors_in, spec.anchors_out) == (frozenset(), frozenset())
    assert (spec.default_visible, spec.eager, spec.minimum_em, spec.contract) == (False, False, (40, 14), 1)


def test_panel_spec_is_frozen_slotted_and_compared_by_identity():
    spec = PanelSpec('search', 'Search', factory)
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.title = 'Other'
    assert not hasattr(spec, '__dict__')
    assert spec == spec and spec != PanelSpec('search', 'Search', factory)
    assert hash(spec) == hash(spec)  # tips are dicts: a field-based hash would raise
    assert PanelSpec('a1', 'A', factory).tips is not PanelSpec('a2', 'A', factory).tips


def test_command_spec_needs_a_run_and_is_available_by_default():
    ran = []
    command = CommandSpec(id='search.focus', title='Focus search', run=lambda: ran.append(1))
    assert command.enabled() == Availability(True)
    assert (command.tip_id, command.shortcut, command.group, command.keywords) == (None, None, 'Panels', ())
    command.run()
    assert ran == [1]
    with pytest.raises(TypeError):
        CommandSpec(id='x', title='x')
    with pytest.raises(TypeError):
        CommandSpec('x', 'x', lambda: None)  # keyword-only: the field list may grow


def test_teach_topic_is_plain_data():
    topic = TeachTopic('search.first', 'Meaning.', ('Step one.', 'Step two.'), ('search.focus',))
    assert (topic.id, topic.next, topic.commands) == ('search.first', ('Step one.', 'Step two.'), ('search.focus',))


class FakeShell:
    tasks, settings, theme = object(), object(), object()

    def announce(self, text, *, assertive=False):
        self.last = (text, assertive)


def test_context_exposes_the_shell_shortcuts_of_the_plan():
    shell = FakeShell()
    ctx = PanelContext(PanelSpec('search', 'Search', factory), SimpleNamespace(), SimpleNamespace(),
                       SimpleNamespace(), shell)
    assert ctx.tasks is shell.tasks and ctx.settings is shell.settings and ctx.theme is shell.theme
    ctx.announce('hello', assertive=True)
    assert shell.last == ('hello', True)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.shell = None


# ---- loading the manifest ---------------------------------------------------------------------------------------


def make_spec(panel_id, **kwargs):
    return PanelSpec(panel_id, panel_id.title(), factory, **kwargs)


def entry(panel_id, load, module=None, **kwargs):
    return ManifestEntry(panel_id, module or f'patchtrace.fixture_{panel_id}.panel', load, kwargs.pop('area', 'right'),
                         **kwargs)


def raiser(error):
    def load():
        raise error
    return load


def test_built_panels_are_collected_in_manifest_order():
    one, two = make_spec('one'), make_spec('two')
    loaded = load_manifest([entry('one', lambda: one), entry('two', lambda: two)])
    assert list(loaded.specs) == ['one', 'two'] and loaded.specs['one'] is one
    assert (loaded.not_built, loaded.errors, loaded.forbidden, loaded.cancelled) == ((), {}, {}, False)


@pytest.mark.parametrize('missing', [
    'patchtrace.fixture_gone.panel',   # the module itself
    'patchtrace.fixture_gone',         # its package: the usual case before a feature exists
], ids=['module', 'package'])
def test_a_missing_expected_module_means_not_built(missing):
    loaded = load_manifest([entry('gone', raiser(ModuleNotFoundError('x', name=missing)))])
    assert loaded.not_built == ('gone',) and loaded.errors == {} and loaded.specs == {}


@pytest.mark.parametrize('name', ['networkx', 'patchtrace', 'patchtrace.other', 'patchtrace.fixture_gone.panel.deeper',
                                  'patchtrace.fixture_gone_panel', '', None],
                         ids=['dependency', 'whole-app', 'sibling', 'submodule', 'lookalike', 'empty', 'unnamed'])
def test_any_other_missing_module_is_an_error_not_a_hidden_panel(name):
    loaded = load_manifest([entry('gone', raiser(ModuleNotFoundError('x', name=name)),
                                  module='patchtrace.fixture_gone.panel')])
    assert loaded.not_built == () and loaded.errors == {'gone': 'ModuleNotFoundError'}


def test_a_real_import_of_an_absent_package_and_module_is_not_built():
    def absent_package():
        from patchtrace.zz_absent_package.panel import PANEL
        return PANEL

    def absent_module():
        from patchtrace.gui.zz_absent_module import PANEL
        return PANEL

    loaded = load_manifest([
        entry('pkg', absent_package, module='patchtrace.zz_absent_package.panel'),
        entry('mod', absent_module, module='patchtrace.gui.zz_absent_module')])
    assert loaded.not_built == ('pkg', 'mod') and loaded.errors == {}


@pytest.mark.parametrize('error', [ImportError('x'), SyntaxError('x'), AttributeError('x'), RuntimeError('boom'),
                                   ValueError('x')], ids=lambda e: type(e).__name__)
def test_a_module_that_raises_is_an_error_with_its_class_name_only(error):
    spec = make_spec('good')
    loaded = load_manifest([entry('bad', raiser(error)), entry('good', lambda: spec)])
    assert loaded.errors == {'bad': type(error).__name__} and 'boom' not in repr(loaded)
    assert loaded.specs == {'good': spec}  # one broken module never hides the others


def test_something_that_is_not_a_panel_spec_is_an_error():
    loaded = load_manifest([entry('odd', lambda: object()), entry('none', lambda: None)])
    assert loaded.errors == {'odd': 'NotAPanelSpec', 'none': 'NotAPanelSpec'} and loaded.specs == {}


def test_cancelling_stops_before_the_next_panel():
    calls = []

    def load(name):
        def run():
            calls.append(name)
            return make_spec(name)
        return run

    remaining = iter([False, True])
    loaded = load_manifest([entry('one', load('one')), entry('two', load('two')), entry('three', load('three'))],
                           cancelled=lambda: next(remaining))
    assert calls == ['one'] and loaded.cancelled and list(loaded.specs) == ['one']


def test_forbidden_module_names_are_qt_heavy_libraries_and_the_ui_modules():
    names = ['os', 'json', 'patchtrace.gui.registry', 'patchtrace.gui', 'patchtrace.uix', 'patchtrace.gui.qtx',
             'pyside6', 'PySide6', 'PySide6.QtCore', 'shiboken6', 'PyQt5.QtGui', 'PyQt6', 'networkx.classes',
             'rapidfuzz', 'pygments.lexers', 'yara', 'yara_x', 'patchtrace.ui', 'patchtrace.ui_evidence',
             'patchtrace.gui.qt', 'patchtrace.gui.qt.host']
    assert forbidden_modules(names) == (
        'PyQt5', 'PyQt6', 'PySide6', 'networkx', 'patchtrace.gui.qt', 'patchtrace.gui.qt.host', 'patchtrace.ui',
        'patchtrace.ui_evidence', 'pygments', 'rapidfuzz', 'shiboken6', 'yara', 'yara_x')
    assert forbidden_modules([]) == ()


@pytest.fixture
def fake_heavy(monkeypatch):
    """A forbidden root that no earlier test can have imported, so attribution is exact."""
    monkeypatch.setattr(registry, 'FORBIDDEN_ROOTS', registry.FORBIDDEN_ROOTS | {'zz_heavy'})
    monkeypatch.delitem(sys.modules, 'zz_heavy', raising=False)
    return monkeypatch


def test_new_heavy_imports_are_attributed_to_the_panel_that_caused_them(fake_heavy):
    def sneaky():
        for name in ('zz_heavy', 'zz_heavy.sub', 'patchtrace.ui_zz_fixture'):
            fake_heavy.setitem(sys.modules, name, types.ModuleType(name))
        return make_spec('sneaky')

    loaded = load_manifest([entry('clean', lambda: make_spec('clean')), entry('sneaky', sneaky)])
    assert loaded.forbidden == {'sneaky': ('patchtrace.ui_zz_fixture', 'zz_heavy')}
    assert set(loaded.specs) == {'clean', 'sneaky'}


def test_a_blocked_import_is_not_a_loaded_one(fake_heavy):
    def load():
        fake_heavy.setitem(sys.modules, 'zz_heavy', None)  # how a test or hook blocks an import
        return make_spec('quiet')

    assert load_manifest([entry('quiet', load)]).forbidden == {}


def test_modules_already_loaded_before_the_panel_are_not_blamed_on_it(fake_heavy):
    fake_heavy.setitem(sys.modules, 'zz_heavy', types.ModuleType('zz_heavy'))
    assert load_manifest([entry('late', lambda: make_spec('late'))]).forbidden == {}
