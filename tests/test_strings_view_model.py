"""WB3-S7a view-model: row precomputation, filters, ordering, sentences, states, escaped copy."""
from __future__ import annotations

import hashlib

import pytest

from patchtrace.strings import copy
from patchtrace.strings import view_model as vm
from patchtrace.strings.contracts import FunctionRef, SideObservation, StringChange, StringLink, StringsDelta
from patchtrace.strings.view_model import StringsFilter, apply_filter, build_rows

OLD = SideObservation(types=('static',), offsets=(0x600,), rvas=(0x2000,))
NEW = SideObservation(types=('static',), offsets=(0x640,), rvas=(0x2040,))


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def link(pair='modified', name='ParseHeader', rva=0x1000, match='m1'):
    return StringLink(tier='L1', join='exact', function=FunctionRef(side='newer', rva=rva, name=name, match_id=match),
                      pair_status=pair, lineage_group='ghidra:x', evidence_ref='rva:0x1')


def change(text, status='only-newer', tier=1, cues=(), links=(), reasons=(), length=None, types=('static',)):
    obs = {'only-newer': (None, NEW), 'only-older': (OLD, None), 'edited': (OLD, NEW), 'both': (OLD, NEW)}
    older, newer = obs[status]
    stamp = lambda o, t: o and o.model_copy(update={'types': t})  # noqa: E731
    return StringChange(id=sha('id' + text), value_sha256=sha(text), display=text, length=length or len(text),
                        status=status, older=stamp(older, types), newer=stamp(newer, types), links=tuple(links),
                        cues=tuple(cues), review_tier=tier, reasons=tuple(reasons))


def delta(*changes, comparable=True, notes=()):
    return StringsDelta(older_basis_digest='a' * 64, newer_basis_digest='b' * 64, comparable=comparable,
                        changes=() if not comparable else tuple(changes), basis_notes=tuple(notes))


SAMPLE = delta(
    change('zeta noise', tier=7, cues=['noise-like'], status='both'),
    change('Bad %s width', tier=1, cues=['message', 'format'], links=[link()], reasons=['pair-modified']),
    change('old path C:\\x', status='only-older', tier=4, cues=['path'], links=[link('removed', 'Gone', 0x900, 'm2')]),
    change('stack secret text', tier=5, types=('stack',), cues=['secret-like']),
    change('alpha text', tier=5),
)


def rows():
    return build_rows(SAMPLE)


def test_rows_are_in_review_order():
    assert [r.tier for r in rows()] == [1, 4, 5, 5, 7]
    assert [r.text for r in rows() if r.tier == 5] == ['alpha text', 'stack secret text']


def test_sentence_matches_the_card_shape():
    first = rows()[0]
    assert first.sentence == ('Only in newer. Static string, 12 characters. Function ParseHeader, modified. '
                              'Message with format specifier.')
    assert first.change == '+ Only in newer'
    assert 'Reasons: pair modified.' in first.description and 'Link tiers: L1.' in first.description


def test_row_places_and_function_ids():
    first, older_only = rows()[0], rows()[1]
    assert (first.older, first.newer) == ('-', '0x640') and older_only.older == '0x600'
    assert first.function_ids == ('m1',) and first.key == (sha('Bad %s width'), 'newer')


def test_hostile_text_is_escaped_in_every_field():
    hostile = 'a\x1b[31m\u202eb\x00\nc'
    row = build_rows(delta(change(hostile)))[0]
    for field in (row.text, row.sentence, row.tooltip, vm.copy_escaped([row])):
        assert not any(ord(ch) < 32 and ch not in '\t\n' for ch in field.replace(row.change, ''))
        assert '\u202e' not in field and '\x1b' not in field and '\x00' not in field
    assert '\\x1b' in row.text and '\\n' in row.text and len(row.tooltip) <= vm.TOOLTIP_CHARS


@pytest.mark.parametrize('flt, expected', [
    (StringsFilter(), ['Bad %s width', 'old path C:\\x', 'alpha text', 'stack secret text']),
    (StringsFilter(change='only-older'), ['old path C:\\x']),
    (StringsFilter(change='edited'), []),
    (StringsFilter(types=frozenset({'stack'})), ['stack secret text']),
    (StringsFilter(side='older'), ['old path C:\\x']),
    (StringsFilter(cues=frozenset({'path', 'format'})), ['Bad %s width', 'old path C:\\x']),
    (StringsFilter(min_length=13), ['old path C:\\x', 'stack secret text']),
    (StringsFilter(text='ALPHA'), ['alpha text']),
    (StringsFilter(function='m2'), ['old path C:\\x']),
    (StringsFilter(scope='all', change='all'),
     ['Bad %s width', 'old path C:\\x', 'alpha text', 'stack secret text', 'zeta noise']),
], ids=['default', 'older', 'edited-none', 'type', 'side', 'cues', 'minlen', 'text-casefold', 'function', 'inventory'])
def test_filters(flt, expected):
    assert [r.text for r in apply_filter(rows(), flt).rows] == expected


def test_noise_is_hidden_only_in_inventory_and_counted():
    inventory = StringsFilter(scope='all', change='all', hide_noise=True)
    result = apply_filter(rows(), inventory)
    assert result.hidden_noise == 1 and 'zeta noise' not in [r.text for r in result.rows]
    differences = apply_filter(rows(), StringsFilter(hide_noise=True))
    assert differences.hidden_noise == 0 and len(differences.rows) == 4


def test_filter_never_reorders():
    kept = apply_filter(rows(), StringsFilter(scope='all', change='all')).rows
    assert [r.id for r in kept] == [r.id for r in rows()]


@pytest.mark.parametrize('kwargs', [{'change': 'bogus'}, {'scope': 'bogus'}], ids=['change', 'scope'])
def test_bad_filter_is_rejected(kwargs):
    with pytest.raises(ValueError):
        StringsFilter(**kwargs)


def test_selection_survives_reload_by_value_and_side():
    key = rows()[2].key
    reloaded = tuple(reversed(rows()))
    assert reloaded[vm.reselect(reloaded, key)].key == key
    assert vm.reselect(reloaded, ('0' * 64, 'older')) is None and vm.reselect(reloaded, None) is None


def test_delta_states():
    assert vm.delta_state(SAMPLE) == ('ready', copy.STATES['ready'].format(n=4))
    assert vm.delta_state(delta())[0] == 'ready-none'
    state, text = vm.delta_state(delta(comparable=False, notes=['different rules\x1b']))
    assert state == 'blocked' and 'different rules\\x1b' in text and '\x1b' not in text


def test_state_text_escapes_values():
    text = vm.state_text('failed', code='PT-STR-SOURCE', message='bad\x00 output')
    assert text == 'String extraction stopped: PT-STR-SOURCE. bad\\x00 output Earlier results were not changed.'
    assert vm.state_text('running', side='older', n=1, elapsed='3 s').startswith('Reading strings from the older')


def test_copy_escaped_is_capped():
    many = tuple(build_rows(delta(*[change(f'string number {i:04d}') for i in range(300)])))
    assert len(vm.copy_escaped(many).splitlines()) == vm.CLIPBOARD_ROWS
    long = build_rows(delta(*[change('x' * 200 + str(i)) for i in range(120)]))
    assert len(vm.copy_escaped(long).encode()) <= vm.CLIPBOARD_BYTES


def test_visible_row_text_passes_the_banned_sweep():
    from test_strings_copy import assert_no_banned
    for row in rows():
        assert_no_banned(' '.join([row.change, row.sentence, row.description, row.cue_text]))


# ---- function pairing (unknown is shown as unknown; a function is never guessed) ----------------------------------------

def record_link(side, function_id, match, pair='modified', name='ParseHeader', ambiguous=False):
    ref = FunctionRef(side=side, rva=0x1000, project_function_id=function_id, match_id=match, name=name,
                      ambiguous=ambiguous)
    return StringLink(tier='L4', join='exact', function=ref, pair_status=pair, lineage_group='ghidra:x',
                      evidence_ref='f:line:1', line=1)


def test_function_cell_names_the_function_and_says_how_it_is_paired():
    (row,) = build_rows(delta(change('Bad %s width', links=[link('modified')])))
    assert row.function_cell == 'ParseHeader (modified)' and row.pair == 'modified'
    (unknown,) = build_rows(delta(change('Bad %s width', links=[link('unknown')])))
    assert unknown.function_cell == 'ParseHeader (pairing unknown)'


def test_function_cell_is_unknown_with_the_reason_when_no_pairing_exists():
    (row,) = build_rows(delta(change('alpha text')), unknown_reason='the project has no completed analysis')
    assert row.function_cell == 'Unknown: the project has no completed analysis' and row.function == ''
    (plain,) = build_rows(delta(change('alpha text')))
    assert plain.function_cell == 'No supported function link'


def test_a_linked_string_keeps_its_function_even_when_pairing_is_partly_unknown():
    (row,) = build_rows(delta(change('x text', links=[link()])), unknown_reason='whatever')
    assert row.function_cell == 'ParseHeader (modified)'


def test_ambiguous_names_are_not_guessed():
    (row,) = build_rows(delta(change('x text', links=[record_link('newer', None, None, 'unknown', ambiguous=True)])))
    assert row.function_cell == 'ParseHeader (ambiguous)' and row.open_target is None


def test_open_target_uses_the_function_record_of_a_unique_match():
    both = [record_link('older', 'fo', 'm9'), record_link('newer', 'fn', 'm9')]
    (row,) = build_rows(delta(change('x text', status='both', links=both)))
    assert row.function_ids == ('m9', 'fo', 'fn') and row.open_target == ('fo', 'older')
    (newer,) = build_rows(delta(change('y text', links=[record_link('newer', 'fn', 'm9')])))
    assert newer.open_target == ('fn', 'newer')


def test_open_target_is_none_when_links_disagree_or_have_no_id():
    split = [record_link('newer', 'f1', 'm1'), record_link('newer', 'f2', 'm2')]
    (row,) = build_rows(delta(change('z text', links=split)))
    assert row.open_target is None
    (bare,) = build_rows(delta(change('w text', links=[record_link('newer', None, None)])))
    assert bare.open_target is None


def test_linked_only_filter_keeps_rows_with_a_function():
    result = apply_filter(rows(), StringsFilter(linked_only=True))
    assert [r.text for r in result.rows] == ['Bad %s width', 'old path C:\\x']


def test_pairing_summary_counts_without_a_score():
    all_rows = rows()
    assert vm.pairing_summary(all_rows, None) == '2 of 5 strings have a function link.'
    assert vm.pairing_summary(all_rows, 'the project has no completed analysis') == \
        'Function pairing unknown: the project has no completed analysis.'
