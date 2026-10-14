"""GUI core (slice F1): state copy and precedence, notices, progress, task failures and chips (GUI plan 7, 8.4)."""
from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.gui.state import (
    ACTION_LABELS,
    CHIP_SHAPES,
    CHIP_TOKENS,
    PRECEDENCE,
    STATE_COPY,
    STATE_KINDS,
    ChipSpec,
    NoticeModel,
    Progress,
    StateModel,
    TaskFailure,
    action_name,
    chip_collisions,
    dominant,
    factory_failure,
    loading_kind,
    state_model,
    state_text,
)

PROPS = settings(max_examples=300, deadline=None, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow])

# The copy of GUI-integration-plan 8.4, filled for a panel titled "Search".
GOLDEN = {
    'no-project': ({}, 'Open a project to use Search.'),
    'idle': ({'hint': 'Type a query.'}, 'Search has no results yet. Type a query.'),
    'loading': ({'noun': 'results'}, 'Loading results...'),
    'refreshing': ({'noun': 'results'}, 'Refreshing results...'),
    'ready': ({}, ''),
    'partial': ({'reasons': 'capa did not run'},
                'Partial result: capa did not run. Missing evidence is unknown, not disagreement.'),
    'stale': ({'reason': 'the run changed'}, 'Search is stale: the run changed. It is shown for reference only.'),
    'blocked': ({'reason': 'capa was not found.', 'remedy': 'Open Setup.'},
                'Search is unavailable: capa was not found. Open Setup.'),
    'error': ({'code': 'PT-X-1', 'message': 'it broke'},
              'Search could not be loaded: PT-X-1: it broke. Earlier results are unchanged.'),
    'too-large': ({'n': 120000}, 'Too many rows to display (120000). Narrow the filter.'),
    'unsupported': ({'reason': 'Windows only.'}, 'Search is not supported here: Windows only.'),
    'cancelled': ({}, 'Cancelled. Earlier results are unchanged.'),
}


def test_the_twelve_state_kinds_each_have_copy_and_one_place_in_the_precedence():
    assert len(STATE_KINDS) == 12 and len(set(STATE_KINDS)) == 12
    assert set(STATE_KINDS) == set(STATE_COPY) == set(PRECEDENCE) == set(GOLDEN)
    assert len(PRECEDENCE) == len(set(PRECEDENCE))


@pytest.mark.parametrize('kind', STATE_KINDS)
def test_state_copy_matches_the_plan(kind):
    fields, expected = GOLDEN[kind]
    assert state_text(kind, 'Search', **fields) == expected
    assert state_model(kind, 'Search', **fields).text == expected


def test_copy_is_plain_ascii_templates():
    assert all(text.isascii() and text.isprintable() for text in STATE_COPY.values())


@pytest.mark.parametrize('kind', [k for k in STATE_KINDS if k != 'ready'])
def test_missing_fields_leave_no_braces_or_double_spaces(kind):
    text = state_text(kind, 'Search')
    assert '{' not in text and '  ' not in text and text == text.strip() and text


@pytest.mark.parametrize('field,value,expected', [
    ('message', 'it broke.', 'Search could not be loaded: PT-X-1: it broke. Earlier results are unchanged.'),
    ('message', 'it broke...', 'Search could not be loaded: PT-X-1: it broke. Earlier results are unchanged.'),
], ids=['one-period', 'ellipsis'])
def test_a_trailing_period_in_a_field_is_not_doubled(field, value, expected):
    assert state_text('error', 'Search', code='PT-X-1', **{field: value}) == expected


def test_fields_are_sanitized_and_cannot_forge_a_second_line():
    text = state_text('error', 'Se<b>arch' + chr(0x202e), code='PT-X',
                      message='boom\nVerdict: agree' + chr(0x202e) + '\x1b[31m')
    assert '\n' not in text and chr(0x202e) not in text and '\x1b' not in text
    assert 'Verdict: agree' in text and '<b>' in text  # literal, not interpreted: the sinks are plain text


def test_long_fields_are_bounded():
    assert len(state_text('error', 'Search', code='C', message='m' * 5000)) < 400


def test_unknown_kinds_are_a_programming_error():
    with pytest.raises(ValueError):
        state_text('weird', 'Search')
    with pytest.raises(ValueError):
        state_model('weird', 'Search')


def test_a_state_model_checks_its_kind():
    assert StateModel('ready', '').actions == ()
    with pytest.raises(ValueError):
        StateModel('weird', 'x')


def test_models_carry_detail_and_the_actions_of_their_kind():
    assert state_model('error', 'Search', code='C', message='m', detail='Traceback class only').detail == \
        'Traceback class only'
    assert {kind: state_model(kind, 'Search').actions for kind in STATE_KINDS} == {
        'stale': ('refresh',), 'blocked': ('setup',), 'error': ('retry', 'copy'),
        **{kind: () for kind in STATE_KINDS if kind not in ('stale', 'blocked', 'error')}}


def test_state_buttons_are_named_per_panel():
    assert action_name('retry', 'Search') == 'Retry loading Search'
    assert action_name('copy', 'Search') == 'Copy Search details'
    assert action_name('setup', 'Search') == 'Open setup for Search'
    assert action_name('refresh', 'Search') == 'Refresh Search'
    assert set(ACTION_LABELS) == {'retry', 'copy', 'setup', 'refresh'}
    assert action_name('retry', 'Files') != action_name('retry', 'Search')
    with pytest.raises(KeyError):
        action_name('explode', 'Search')


def test_factory_failure_names_only_the_exception_class():
    model = factory_failure('Search', 'KeyError')
    assert model.kind == 'error'
    assert model.text == ('Search could not be created: PT-GUI-FACTORY: KeyError. Other panels are unaffected.')
    assert factory_failure('Search', 'Bad\nClass').text.count('\n') == 0


# ---- precedence -----------------------------------------------------------------------------------------------


@pytest.mark.parametrize('kinds,expected', [
    ({'ready', 'stale'}, 'stale'),
    ({'ready', 'partial'}, 'partial'),
    ({'stale', 'partial'}, 'stale'),
    ({'error', 'stale', 'partial', 'ready'}, 'error'),
    ({'loading'}, 'loading'),
    ({'refreshing', 'ready'}, 'refreshing'),
    ({'ready', 'idle'}, 'ready'),
    ({'blocked', 'error'}, 'blocked'),
    ({'no-project', 'blocked'}, 'no-project'),
    ({'too-large', 'stale'}, 'too-large'),
    (set(), 'idle'),
], ids=['stale', 'partial', 'stale-over-partial', 'error-first', 'loading', 'refreshing', 'ready', 'blocked',
        'no-project', 'too-large', 'nothing'])
def test_dominant_state(kinds, expected):
    assert dominant(kinds) == expected


def test_error_beats_stale_beats_partial_beats_ready_as_specified():
    order = [k for k in PRECEDENCE if k in ('error', 'stale', 'partial', 'ready')]
    assert order == ['error', 'stale', 'partial', 'ready']


@PROPS
@given(st.sets(st.sampled_from(STATE_KINDS)))
def test_dominant_is_the_earliest_present_kind_whatever_the_order_given(kinds):
    expected = next((k for k in PRECEDENCE if k in kinds), 'idle')
    assert dominant(sorted(kinds)) == dominant(sorted(kinds, reverse=True)) == expected


def test_dominant_rejects_unknown_kinds():
    with pytest.raises(ValueError):
        dominant({'ready', 'sparkly'})


def test_loading_only_before_the_first_content():
    assert loading_kind(has_content=False) == 'loading'
    assert loading_kind(has_content=True) == 'refreshing'


# ---- notices, progress, failures ------------------------------------------------------------------------------


def test_notice_model_defaults_and_sanitizing():
    notice = NoticeModel('die.preflight', 'caution', 'Packed file.\nDetails below.' + 'x' * 600,
                         detail='line1\nline2' + chr(0x202e))
    assert (notice.dismissible, notice.scope) == (True, 'project')
    assert len(notice.text) == 400 and '\n' not in notice.text
    assert notice.detail == 'line1\nline2'


@pytest.mark.parametrize('kwargs', [
    {'key': '', 'level': 'notice', 'text': 't'},
    {'key': 'Bad Key', 'level': 'notice', 'text': 't'},
    {'key': 'k', 'level': 'info', 'text': 't'},
    {'key': 'k', 'level': 'notice', 'text': 't', 'scope': 'forever'},
    {'key': 'k' * 65, 'level': 'notice', 'text': 't'},
    {'key': 'k', 'level': 'notice', 'text': ''},
], ids=['empty-key', 'bad-key', 'bad-level', 'bad-scope', 'long-key', 'empty-text'])
def test_notice_model_rejects_invalid_values(kwargs):
    with pytest.raises(ValueError):
        NoticeModel(**kwargs)


def test_progress_is_bounded_and_may_be_indeterminate():
    progress = Progress('s' * 200, 3, None, 'm' * 500)
    assert len(progress.stage) == 80 and len(progress.message) == 200 and progress.total is None
    assert Progress('scan', 0, 10).total == 10
    for bad in (dict(stage='x', done=-1), dict(stage='x', done=0, total=-1)):
        with pytest.raises(ValueError):
            Progress(**bad)


def test_task_failure_carries_the_class_name_and_never_the_message():
    failure = TaskFailure.of(KeyError('secret path C:/Users/x'))
    assert (failure.exception_class, failure.code) == ('KeyError', 'PT-GUI-TASK')
    assert 'secret' not in repr(failure)
    assert TaskFailure('A\nB').exception_class == 'A B'


# ---- chips ----------------------------------------------------------------------------------------------------


def test_chip_vocabulary_is_the_plans():
    assert CHIP_SHAPES == ('round', 'square', 'diamond', 'dashed')
    assert CHIP_TOKENS == ('ok', 'change', 'caution', 'info', 'muted', 'alt', 'error', 'plain')


def test_chip_values_are_validated():
    assert ChipSpec('agree', '=', 'Agree', 'round', 'ok').glyph == '='
    for kwargs in (dict(glyph=''), dict(glyph='abc'), dict(glyph=' '), dict(glyph=chr(0xe9)), dict(shape='star'),
                   dict(token='red'), dict(text=''), dict(key=''), dict(key='k' * 65)):
        base = dict(key='k', glyph='=', text='Agree', shape='round', token='ok')
        with pytest.raises(ValueError):
            ChipSpec(**{**base, **kwargs})


def test_chip_text_is_sanitized():
    assert ChipSpec('k', '!', 'Cont\nested' + chr(0x202e), 'diamond', 'caution').text == 'Cont ested'


def test_chip_collisions_report_duplicate_glyph_and_shape_pairs():
    agree = ChipSpec('agree', '=', 'Agree', 'round', 'ok')
    contested = ChipSpec('contested', '!', 'Contested', 'diamond', 'caution')
    same_glyph_other_shape = ChipSpec('single', '=', 'Single engine', 'square', 'info')
    clash = ChipSpec('agree2', '=', 'Agree too', 'round', 'alt')
    assert chip_collisions([agree, contested, same_glyph_other_shape]) == ()
    assert chip_collisions([agree, contested, clash]) == (('agree', 'agree2'),)
    assert chip_collisions([agree, clash, ChipSpec('agree3', '=', 'Third', 'round', 'muted')]) == (
        ('agree', 'agree2'), ('agree', 'agree3'))
