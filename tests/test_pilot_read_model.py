"""PIL-C2 pure side: the Qt-free read model behind the Leads dock (states, rows, filters, banners, wording)."""
from __future__ import annotations

import sys
import threading
from datetime import UTC, datetime

import pytest
from pilot_synergy_support import arms, sources_for

from patchtrace.pilot import contracts as c
from patchtrace.pilot import keys, why
from patchtrace.pilot.read_model import (
    STATE_TEXT,
    LeadsInput,
    LeadsView,
    build_view,
    context_choices,
    filter_rows,
    resolve_state,
)
from patchtrace.pilot.service import localize
from patchtrace.pilot.store import Loaded

FIXED = datetime(2099, 1, 1, tzinfo=UTC)
BANNED = ('probab', 'likelihood', 'confiden', 'percent', 'vulnerab', 'exploit', 'proven', 'certain', 'verified', 'safe',
          'secure')
SANCTIONED = (why.FOOTER, 'absence says nothing about exploitation', 'CISA KEV', 'Analyst statement')


def assessment_of(arm: str) -> c.PilotAssessment:
    return localize(sources_for(arms()[arm]), keys.default_config(), threading.Event(), clock=lambda: FIXED)


@pytest.fixture(scope='module')
def full() -> c.PilotAssessment:
    return assessment_of('full')


def loaded(assessment, state='current', changed=()) -> Loaded:
    return Loaded(state=state, assessment=assessment, changed=changed)


@pytest.mark.parametrize(('given', 'expected'),
                         [(LeadsInput(project_open=False), 'L0'),
                          (LeadsInput(loaded=Loaded(state='none')), 'L1'),
                          (LeadsInput(preparing=('compare', 1, 3)), 'L2'),
                          (LeadsInput(error=('PT-PILOT-X', 'broke'), loaded=Loaded(state='none')), 'L5'),
                          (LeadsInput(preparing=('compare', 1, 3), error=('PT-PILOT-X', 'broke')), 'L5')],
                         ids=['no-project', 'no-result', 'preparing', 'error-over-none', 'error-over-preparing'])
def test_state_resolution_before_a_table(given, expected):
    assert resolve_state(given) == expected


def test_stale_beats_missing_evidence_beats_table(full):
    assert resolve_state(LeadsInput(loaded=loaded(full, 'stale', ('newer build',)))) == 'L6'
    partial = full.model_copy(update={'channels': tuple(
        s.model_copy(update={'state': 'not-run'}) if s.channel == 'capa' else s for s in full.channels)})
    assert resolve_state(LeadsInput(loaded=loaded(partial))) == 'L4'
    assert resolve_state(LeadsInput(loaded=loaded(full), error=('E', 'm'))) == 'L5'


def test_every_state_text_is_exact_and_banned_free():
    assert STATE_TEXT['L0'] == 'Open a project to see leads.'
    assert STATE_TEXT['L1'].startswith('No comparison result yet.')
    for text in STATE_TEXT.values():
        for phrase in SANCTIONED:
            text = text.replace(phrase, '')
        assert not any(word in text.lower() for word in BANNED), text


def test_view_rows_are_precomputed_plain_strings(full):
    view = build_view(LeadsInput(loaded=loaded(full)))
    assert isinstance(view, LeadsView) and view.state in {'L3', 'L4'} and view.rows
    row = view.rows[0]
    assert row.badge in {'FITS ADVISORY', 'NEEDS REVIEW', 'PARTIAL FIT', 'CODE CHANGE', 'CHANGED, NO FIT'} or row.badge
    assert all(isinstance(v, str) for v in (row.rank, row.title, row.badge, row.expected, row.pairing, row.flags))
    assert view.footer == why.FOOTER


def test_context_choices_put_code_only_first_then_kev_listed(full):
    choices = context_choices(full)
    assert choices[0].cve is None and choices[0].label == 'No advisory (code evidence only)'
    assert all(ch.label.startswith('CVE-') for ch in choices[1:])
    assert any(ch.kev_listed for ch in choices[1:])
    assert list(choices[1:]) == sorted(choices[1:], key=lambda ch: (not ch.kev_listed, ch.cve))


def test_filter_by_class_and_search_and_dismissed(full):
    rows = build_view(LeadsInput(loaded=loaded(full))).rows
    assert filter_rows(rows, lead_class=None, search='', show_dismissed=True) == rows
    one = rows[0]
    got = filter_rows(rows, lead_class=one.lead_class, search='', show_dismissed=True)
    assert got and all(r.lead_class == one.lead_class for r in got)
    assert one in filter_rows(rows, lead_class=None, search=one.title[:3].upper(), show_dismissed=True)
    assert filter_rows(rows, lead_class=None, search='zz-no-such-function-zz', show_dismissed=True) == ()


def test_too_many_rows_is_l8_with_the_count(full):
    view = build_view(LeadsInput(loaded=loaded(full)), row_limit=0)
    assert view.state == 'L8' and '(' in view.message


def test_hostile_function_names_are_neutralised(full):
    lead = full.leads[0]
    ref = lead.newer[0].model_copy(update={'name': 'evil‮\x1b[31m<b>x</b>'}) if lead.newer else None
    if ref is None:
        pytest.skip('lead without a newer side')
    hostile = full.model_copy(update={'leads': (lead.model_copy(update={'newer': (ref,)}), *full.leads[1:])})
    title = build_view(LeadsInput(loaded=loaded(hostile))).rows[0].title
    assert '‮' not in title and '\x1b' not in title and '\n' not in title


def test_read_model_imports_no_qt():
    assert not [m for m in sys.modules if m.startswith('PySide6') and 'read_model' in m]
    import patchtrace.pilot.read_model as module
    assert 'PySide6' not in open(module.__file__, encoding='utf-8').read()
