"""PanelSettings: typed validated getters over QSettings (GUI plan section 7; slice F2). Offscreen, hermetic."""
from __future__ import annotations

import pytest
from qt_support import HOSTILE_PARAMS, join_gui_threads, settings  # noqa: F401

from patchtrace.gui.qt.settings import MAX_TEXT, PanelSettings


@pytest.fixture
def panel(settings):  # noqa: F811
    return PanelSettings(settings, 'search')


def test_values_round_trip_through_an_ini_file_under_the_panel_prefix(panel, settings):  # noqa: F811
    panel.set('page_size', 50)
    panel.set('wrap', True)
    panel.set('mode', 'exact')
    panel.set('recent', ['a', 'b'])
    settings.sync()
    fresh = PanelSettings(type(settings)(settings.fileName(), settings.format()), 'search')
    assert fresh.get_int('page_size', 10, 1, 100) == 50
    assert fresh.get_bool('wrap', False) is True
    assert fresh.get_enum('mode', 'fuzzy', {'exact', 'fuzzy'}) == 'exact'
    assert fresh.get_list('recent') == ('a', 'b')
    assert sorted(settings.allKeys()) == ['search/mode', 'search/page_size', 'search/recent', 'search/wrap']


def test_missing_values_give_the_default(panel):
    assert panel.get_int('n', 7, 0, 9) == 7
    assert panel.get_bool('b', True) is True
    assert panel.get_enum('e', 'x', {'x', 'y'}) == 'x'
    assert panel.get_text('t', 'dflt') == 'dflt'
    assert panel.get_list('l', ('z',)) == ('z',)


@pytest.mark.parametrize('stored, expected', [
    ('abc', 5), ('99', 5), ('-1', 5), ('3.5', 5), ('', 5), ('7', 7), (7, 7), (True, 5), ('0', 0),
], ids=['text', 'high', 'low', 'float', 'empty', 'str7', 'int7', 'bool', 'zero'])
def test_int_getter_checks_type_and_range(panel, settings, stored, expected):  # noqa: F811
    settings.setValue('search/n', stored)
    assert panel.get_int('n', 5, 0, 9) == expected


@pytest.mark.parametrize('stored, expected', [
    ('true', True), ('false', False), ('1', True), ('0', False), (True, True), ('yes', None), ('', None), (3, None),
], ids=['true', 'false', 'one', 'zero', 'bool', 'yes', 'empty', 'int'])
def test_bool_getter_accepts_only_unambiguous_values(panel, settings, stored, expected):  # noqa: F811
    settings.setValue('search/b', stored)
    assert panel.get_bool('b', None) is expected


def test_enum_getter_rejects_values_outside_the_set(panel, settings):  # noqa: F811
    settings.setValue('search/mode', 'bogus')
    assert panel.get_enum('mode', 'fuzzy', {'exact', 'fuzzy'}) == 'fuzzy'
    settings.setValue('search/mode', 5)
    assert panel.get_enum('mode', 'fuzzy', {'exact', 'fuzzy'}) == 'fuzzy'


def test_text_longer_than_256_characters_is_corrupt_even_with_a_larger_cap(panel, settings):  # noqa: F811
    settings.setValue('search/t', 'x' * (MAX_TEXT + 1))
    assert panel.get_text('t', 'dflt', max_length=10_000) == 'dflt'
    settings.setValue('search/t', 'x' * MAX_TEXT)
    assert panel.get_text('t', 'dflt') == 'x' * MAX_TEXT
    assert panel.get_text('t', 'dflt', max_length=10) == 'dflt'


def test_single_item_list_survives_the_ini_string_representation(panel, settings):  # noqa: F811
    panel.set('recent', ['only'])
    settings.sync()
    assert panel.get_list('recent') == ('only',)


def test_list_getter_rejects_too_many_or_non_text_items(panel, settings):  # noqa: F811
    settings.setValue('search/l', [str(i) for i in range(40)])
    assert panel.get_list('l', ('d',)) == ('d',)
    settings.setValue('search/l', ['ok', 3])
    assert panel.get_list('l', ('d',)) == ('d',)
    settings.setValue('search/l', ['a', 'b', 'c'])
    assert panel.get_list('l', ('d',), max_items=2) == ('d',)


@pytest.mark.parametrize('key', ['api_key', 'auth/token', 'Password', 'client_secret', 'credentials'],
                         ids=['apikey', 'authtoken', 'password', 'secret', 'cred'])
def test_credential_like_keys_are_refused_for_read_and_write(panel, key):
    with pytest.raises(ValueError, match='credential'):
        panel.set(key, 'x')
    with pytest.raises(ValueError, match='credential'):
        panel.get_text(key)


@pytest.mark.parametrize('key', ['', 'Upper', '../x', 'a b', '1x', 'a//b', '/a'],
                         ids=['empty', 'upper', 'dots', 'space', 'digit', 'double', 'slash'])
def test_malformed_keys_are_refused(panel, key):
    with pytest.raises(ValueError):
        panel.get_int(key, 0, 0, 1)


@pytest.mark.parametrize('panel_id', ['', 'Evidence', 'a/b', '1a', 'x' * 40], ids=['empty', 'upper', 'slash', 'digit', 'long'])
def test_malformed_panel_ids_are_refused(settings, panel_id):  # noqa: F811
    with pytest.raises(ValueError, match='panel id'):
        PanelSettings(settings, panel_id)


def test_oversized_writes_are_refused(panel, settings):  # noqa: F811
    with pytest.raises(ValueError, match='256'):
        panel.set('t', 'x' * 257)
    with pytest.raises(ValueError, match='list'):
        panel.set('l', ['x'] * 33)
    with pytest.raises(ValueError, match='list'):
        panel.set('l', ['x' * 257])
    assert settings.allKeys() == []


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_hostile_text_round_trips_as_inert_data(panel, settings, text):  # noqa: F811
    panel.set('t', text)
    settings.sync()
    assert panel.get_text('t', 'dflt') in (text, 'dflt')  # a NUL may not survive an INI file; never an error


def test_panels_do_not_see_each_others_keys_and_clear_is_scoped(settings):  # noqa: F811
    a, b = PanelSettings(settings, 'kb'), PanelSettings(settings, 'kev')
    a.set('n', 1)
    b.set('n', 2)
    a.clear()
    assert a.get_int('n', 0, 0, 9) == 0 and b.get_int('n', 0, 0, 9) == 2
    b.remove('n')
    assert settings.allKeys() == []


def test_existing_legacy_keys_are_left_alone(panel, settings):  # noqa: F811
    settings.setValue('evidence/geometry', b'\x01\x02')
    panel.set('n', 1)
    panel.clear()
    assert settings.contains('evidence/geometry')
