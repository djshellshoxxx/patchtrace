"""GUI core (slice F1): key-sequence vocabulary and collision rules (GUI-integration-plan 8.3, section 6)."""
from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.gui.shortcuts import FRAMEWORK, RESERVED, ShortcutTable, normalize, panel_shortcut_error

PROPS = settings(max_examples=300, deadline=None, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow])
KEYS = ['e', 'E', 'p', '5', 'f6', 'F12', 'esc', 'Escape', 'left', 'PgUp', 'Del', 'space', 'Return']
MODIFIER_SPELLINGS = {'Ctrl': ['ctrl', 'Ctrl', 'CONTROL', 'Control'], 'Alt': ['alt', 'ALT', 'Alt'],
                      'Shift': ['shift', 'SHIFT', 'Shift'], 'Meta': ['meta', 'Meta']}


@st.composite
def chords(draw):
    names = draw(st.lists(st.sampled_from(sorted(MODIFIER_SPELLINGS)), unique=True, max_size=4))
    spelled = [draw(st.sampled_from(MODIFIER_SPELLINGS[name])) for name in names]
    return names, '+'.join([*spelled, draw(st.sampled_from(KEYS))])


@pytest.mark.parametrize('raw,expected', [
    ('ctrl+shift+e', 'Ctrl+Shift+E'),
    ('Shift+Ctrl+E', 'Ctrl+Shift+E'),
    ('CONTROL+SHIFT+e', 'Ctrl+Shift+E'),
    (' Ctrl + Shift + E ', 'Ctrl+Shift+E'),
    ('f6', 'F6'),
    ('shift+F6', 'Shift+F6'),
    ('Esc', 'Escape'),
    ('escape', 'Escape'),
    ('alt+left', 'Alt+Left'),
    ('Alt+Shift+Ctrl+Meta+1', 'Ctrl+Alt+Shift+Meta+1'),
    ('pgup', 'PageUp'),
], ids=['lower', 'order', 'alias', 'spaces', 'function', 'shifted-function', 'esc', 'escape-lower', 'arrow',
        'all-modifiers', 'page'])
def test_normalize_gives_one_canonical_spelling(raw, expected):
    assert normalize(raw) == expected


@pytest.mark.parametrize('bad', [
    '', '+', 'Ctrl', 'Ctrl+', '+E', 'Ctrl+Ctrl+E', 'Ctrl+Control+E', 'E+Ctrl', 'Ctrl+E+F', 'Ctrl+Foo', 'F25', 'F0',
    'Ctrl+K, Ctrl+C', 'Ctrl+?', 'Ctrl+ee', 'Ctrl+' + chr(0xe9), 'Ctrl+' + chr(0x663), None, 5,
], ids=['empty', 'plus', 'only-modifier', 'trailing-plus', 'leading-plus', 'repeat', 'alias-repeat', 'key-first',
        'two-keys', 'unknown-key', 'f25', 'f0', 'chord', 'punctuation', 'two-letters', 'accented', 'arabic-digit',
        'none', 'int'])
def test_normalize_rejects_what_is_not_one_key_sequence(bad):
    assert normalize(bad) is None


@PROPS
@given(chords())
def test_normalize_is_idempotent_and_ignores_case_and_modifier_order(chord):
    names, raw = chord
    once = normalize(raw)
    assert once is not None and normalize(once) == once
    shuffled = '+'.join([*reversed(raw.split('+')[:-1]), raw.split('+')[-1]])
    assert normalize(shuffled) == once
    assert normalize(raw.upper()) == once and normalize(raw.lower()) == once
    modifiers = once.split('+')[:-1]
    assert modifiers == [m for m in ('Ctrl', 'Alt', 'Shift', 'Meta') if m in names]


@pytest.mark.parametrize('sequence,ok', [
    ('Ctrl+Shift+E', True), ('ctrl+shift+k', True), ('shift+ctrl+Z', True),
    ('Ctrl+E', False), ('Ctrl+Alt+Shift+E', False), ('Ctrl+Shift+1', False), ('Ctrl+Shift+F6', False),
    ('Shift+E', False), ('F6', False), ('garbage', False),
], ids=['evidence', 'kb', 'order', 'one-modifier', 'extra-modifier', 'digit', 'function-key', 'shift-only',
        'bare', 'garbage'])
def test_panel_shortcuts_are_ctrl_shift_letter(sequence, ok):
    assert (panel_shortcut_error(sequence) is None) is ok


def test_reserved_set_is_the_plans_collision_input():
    assert set(RESERVED) == {'Ctrl+N', 'Ctrl+O', 'Ctrl+S', 'Ctrl+E', 'Ctrl+I', 'Ctrl+R', 'F1', 'F5', 'Escape',
                             'Alt+Up', 'Alt+Down'}
    assert 'Ctrl+Shift+E' not in RESERVED  # it stays the evidence dock toggle and is claimed by the evidence spec


def test_framework_keys_are_palette_panel_cycling_and_history():
    assert set(FRAMEWORK) == {'Ctrl+Shift+P', 'F6', 'Shift+F6', 'Alt+Left', 'Alt+Right'}
    assert not set(FRAMEWORK) & set(RESERVED)


@pytest.mark.parametrize('table', [RESERVED, FRAMEWORK], ids=['reserved', 'framework'])
def test_seed_tables_are_canonical_and_described(table):
    for sequence, owner in table.items():
        assert normalize(sequence) == sequence
        assert owner and owner.isprintable()


def test_claim_records_the_first_owner_and_reports_it_to_the_next():
    table = ShortcutTable()
    assert table.claim('search', 'ctrl+shift+f') is None
    assert table.claim('search', 'Ctrl+Shift+F') is None  # the owner may repeat itself
    assert table.claim('files', 'Shift+Ctrl+F') == 'search'
    assert table.owner('Ctrl+Shift+F') == 'search'
    assert table.owner('Ctrl+Shift+G') is None


def test_reserved_and_framework_keys_are_taken_from_the_start():
    table = ShortcutTable()
    assert table.claim('x', 'ctrl+s') == RESERVED['Ctrl+S']
    assert table.claim('x', 'Escape') == RESERVED['Escape']
    assert table.claim('x', 'ctrl+shift+p') == FRAMEWORK['Ctrl+Shift+P']
    assert table.claim('x', 'f6') == FRAMEWORK['F6']
    assert ShortcutTable({}).claim('x', 'Ctrl+S') is None


def test_claiming_something_that_is_not_a_key_sequence_is_a_programming_error():
    with pytest.raises(ValueError):
        ShortcutTable().claim('x', 'not a key')


@PROPS
@given(st.lists(chords(), min_size=1, max_size=12))
def test_a_table_never_gives_one_key_to_two_owners(drawn):
    table = ShortcutTable({})
    first_owner: dict[str, str] = {}
    for index, (_, raw) in enumerate(drawn):
        key = normalize(raw)
        taken_by = table.claim(f'owner{index}', raw)
        if key in first_owner:
            assert taken_by == first_owner[key]
        else:
            assert taken_by is None
            first_owner[key] = f'owner{index}'
    assert {key: table.owner(key) for key in first_owner} == first_owner
