"""gui/tips.py: idempotent tip registration, the framework tips and the accessible description (GUI plan 8.2, 8.7)."""
from __future__ import annotations

import pytest
from qt_support import join_gui_threads  # noqa: F401

from patchtrace import tooltips
from patchtrace.gui import tips
from patchtrace.gui.registry import DESCRIPTION_LIMIT, TIPS_CODE
from patchtrace.tooltips import TooltipEntry


@pytest.fixture(autouse=True)
def private_registry(monkeypatch):
    """Registrations must not leak into the tooltip tests that enumerate the registry."""
    # A MainWindow built earlier in the process has registered the framework tips; these tests start without them.
    monkeypatch.setattr(tooltips, 'REGISTRY', {k: v for k, v in tooltips.REGISTRY.items() if k not in tips.GUI_TIP_IDS})
    monkeypatch.setattr(tooltips, 'TEMPLATES', dict(tooltips.TEMPLATES))


def entry(what: str = 'Do the thing.') -> TooltipEntry:
    return TooltipEntry(what, 'Because.', 'Nothing changes.')


class Target:
    """Records the setters `apply_tooltip` and `apply_tip` call."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def __getattr__(self, name):
        if not name.startswith('set'):
            raise AttributeError(name)
        return lambda value: self.values.__setitem__(name, value)

    def objectName(self) -> str:
        return self.values.get('setObjectName', '')


def test_register_is_idempotent_and_reports_new_ids():
    assert tips.register_tips({'zz.one': entry()}) == ('zz.one',)
    assert tips.register_tips({'zz.one': entry()}) == ()
    assert tooltips.REGISTRY['zz.one'] == entry()


def test_register_templates_go_to_the_template_table():
    assert tips.register_tips({}, {'zz.row': entry('Row {who}.')}) == ('zz.row',)
    assert 'zz.row' in tooltips.TEMPLATES and 'zz.row' not in tooltips.REGISTRY


@pytest.mark.parametrize('first, second', [
    ({'zz.one': entry()}, {'zz.one': entry('Other text.')}),
    ({'zz.one': entry()}, {'zz.one': TooltipEntry('Do the thing.', 'Because.', 'Different effect.')}),
], ids=['what', 'effect'])
def test_conflicting_reregistration_is_refused_and_keeps_the_first(first, second):
    tips.register_tips(first)
    with pytest.raises(tips.TipError, match=TIPS_CODE):
        tips.register_tips(second)
    assert tooltips.REGISTRY['zz.one'] == entry()


def test_a_tip_cannot_also_be_a_template():
    with pytest.raises(tips.TipError):
        tips.register_tips({'zz.one': entry()}, {'zz.one': entry()})
    tips.register_tips({'zz.two': entry()})
    with pytest.raises(tips.TipError):
        tips.register_tips({}, {'zz.two': entry()})


def test_the_framework_tips_are_complete_plain_and_unique():
    found = tips.gui_tips()
    assert tuple(found) == tips.GUI_TIP_IDS
    whats = [item.what for item in found.values()]
    existing = {item.what for item in tooltips.REGISTRY.values()}
    assert len(set(whats)) == len(whats) and not set(whats) & existing
    for tip_id, item in found.items():
        assert tip_id.startswith(('gui.', 'panels.', 'menu.'))
        assert item.what and item.why and item.effect
        assert len(item.what) <= DESCRIPTION_LIMIT
        assert not any(char in text for text in (item.what, item.why, item.effect, item.source, item.availability)
                       for char in '<>')


def test_registering_the_framework_tips_twice_changes_nothing():
    assert tips.register_gui_tips() == tips.GUI_TIP_IDS
    assert tips.register_gui_tips() == ()


def test_apply_tip_sets_the_what_line_as_description_and_the_identifier():
    tips.register_tips({'zz.one': TooltipEntry('Do the thing.', 'Because.', 'Nothing changes.', 'src', 'avail')})
    target = Target()
    tips.apply_tip(target, 'zz.one')
    assert target.values['setAccessibleDescription'] == 'Do the thing.'
    assert target.values['setAccessibleIdentifier'] == 'zz.one'
    assert target.values['setWhatsThis'].startswith('What: Do the thing.\nWhy: Because.')
    assert 'Why' in target.values['setToolTip']


def test_apply_tip_full_keeps_the_whole_text_as_description():
    tips.register_tips({'zz.one': entry()})
    target = Target()
    tips.apply_tip(target, 'zz.one', accessible='full', name='panel.zz_one')
    assert target.values['setAccessibleDescription'].startswith('What: Do the thing. Why:')
    assert target.values['setAccessibleIdentifier'] == 'panel.zz_one'
    assert target.values['setObjectName'] == 'panel.zz_one'


def test_apply_tip_rejects_an_unknown_accessible_mode():
    tips.register_tips({'zz.one': entry()})
    with pytest.raises(ValueError):
        tips.apply_tip(Target(), 'zz.one', accessible='all')


def test_a_long_what_line_is_cut_for_the_description():
    tips.register_tips({'zz.long': entry('Word ' * 80)})
    description = tips.what_line('zz.long')
    assert len(description) == DESCRIPTION_LIMIT and description.endswith('...')


def test_a_template_what_line_is_filled_with_escaped_values():
    tips.register_tips({}, {'zz.row': entry('Row {who} here.')})
    target = Target()
    tips.apply_tip(target, 'zz.row', who='x\x00<b>')
    assert target.values['setAccessibleDescription'] == 'Row x<b> here.'
    assert '<b>' not in target.values['setToolTip'].replace('<br>', '')  # escaped in the rich text


def test_escaped_tip_neutralises_markup():
    text = tips.escaped_tip('<b>pwn</b>\nline')
    assert '<b>' not in text and '&lt;b&gt;' in text and '<br>' in text


def test_applied_to_a_real_widget(qtbot):
    from PySide6.QtWidgets import QPushButton
    tips.register_gui_tips()
    button = QPushButton('Retry')
    qtbot.addWidget(button)
    tips.apply_tip(button, 'gui.state_retry', name='search.state_retry')
    assert button.accessibleDescription() == 'Load this panel again.'
    assert button.accessibleIdentifier() == 'search.state_retry'
    assert button.objectName() == 'search.state_retry'
