"""PIL-C2 read model: what the Leads dock says, as plain data (docs/specs/program-e/PIL-integration-plan.md s8).

Pure: no Qt. The sweeps cover every string the model can produce, because the dock may not claim a likelihood, show an
uncalibrated number or let an enum slug reach a person."""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest
from leads_support import HOSTILE, KEV, lead_of, loaded_of, sample_assessment
from pilot_localize_support import CVE_A, CVE_B, sha

from patchtrace.gui.state import chip_collisions
from patchtrace.pilot import contracts as c
from patchtrace.pilot import read_model as rm
from patchtrace.pilot.review import LeadReview


@pytest.fixture(scope='module')
def assessment():
    return sample_assessment()


@pytest.fixture(scope='module')
def model(assessment):
    return rm.LeadsModel(assessment)


def event(candidate_key: str, action: str, text: str = '', cve: str | None = CVE_A, second: int = 0) -> c.ReviewEvent:
    when = (datetime(2099, 1, 2, tzinfo=UTC) + timedelta(seconds=second)).strftime('%Y-%m-%dT%H:%M:%SZ')
    return c.ReviewEvent(candidate_key=candidate_key, cve=cve, action=action, text=text, created_utc=when)


def every_string(model: rm.LeadsModel) -> list[str]:
    """Every string the model produces for the sample result, in every context."""
    found = [rm.L0, rm.L1, rm.L1B, rm.L4, rm.L5, rm.L6, rm.L7, rm.L8, rm.L2, rm.L2_NO_COUNTS, rm.WINDOW, rm.ORIENTATION,
             rm.NO_ADVISORY, *rm.GATE_TEXT.values(), *rm.CLASS_BADGE.values(), *rm.KEV_TEXT.values(),
             *rm.ROLE_WORDS.values(), *rm.STATE_WORDS.values(), *rm.PAIRING_WORDS.values(), *rm.CLASS_NAME.values(),
             *(text for _value, text in rm.CLASS_FILTER), *rm._INPUT_WORDS.values()]
    for chip in rm.channel_chips(model.assessment):
        found.append(chip.text)
    for context in model.contexts:
        found += [context.label, context.counts_line, *context.banners, context.kev_line or '']
        for row in model.rows(context.cve):
            found += [row.rank, row.name, row.badge, row.expected, row.channels, row.pairing, row.flags, row.accessible,
                      model.detail(row)]
            for obs in model.observations(row):
                found += [obs.standing, obs.kind, obs.channel, obs.role, obs.verification, obs.origin, obs.detail]
    return found


# ---- contexts and rows -------------------------------------------------------------------------------------------

def test_contexts_list_kev_cves_first_then_the_code_only_list(model):
    assert [c.cve for c in model.contexts] == [CVE_A, CVE_B, None]
    assert model.contexts[0].label.startswith(f'{CVE_A}  KEV, 3 fit, 1 review')
    assert model.contexts[-1].label == rm.NO_ADVISORY


def test_a_result_without_advisories_has_only_the_code_only_list_and_says_so():
    plain = sample_assessment().model_copy(update={'cves': ()})
    contexts = rm.contexts_of(plain)
    assert [c.cve for c in contexts] == [None] and contexts[0].banners == (rm.L7,)


@pytest.mark.parametrize('state, text', [
    ('listed', 'CISA KEV: listed (added 2099-01-02)'),
    ('unknown', 'CISA KEV: unknown'),
], ids=['listed', 'unknown'])
def test_the_kev_line_is_the_sanctioned_wording(state, text):
    kev = KEV if state == 'listed' else c.Kev(state='unknown')
    context = rm.contexts_of(sample_assessment(kev=kev))[0]
    assert context.kev_line == text


def test_kev_absence_says_nothing_about_exploitation():
    kev = c.Kev(state='not-in-snapshot', snapshot_id=sha('kev'))
    context = rm.contexts_of(sample_assessment(kev=kev))[0]
    assert context.kev_line == 'CISA KEV: not in the loaded snapshot; absence says nothing about exploitation'


def test_rows_carry_class_badges_in_words_and_a_shape(model):
    rows = {r.lead.newer[0].name: r for r in model.rows(CVE_A)}
    assert rows['read_item'].badge == '(+) FITS ADVISORY'
    assert rows[HOSTILE].badge == '(?) NEEDS REVIEW'
    assert all(any(ch.isalpha() for ch in r.badge) and not r.badge[0].isalpha() for r in rows.values())


def test_a_tie_shows_its_rank_range(model):
    ties = [r for r in model.rows(None) if r.lead.tie.size > 1]
    assert ties and all(re.fullmatch(r'\d+-\d+ \(tie\)', r.rank) for r in ties)
    assert [r.rank for r in model.rows(CVE_A)][:2] == ['1', '2']


def test_expected_changes_are_a_count_never_a_score(model):
    row = next(r for r in model.rows(CVE_A) if r.lead.newer[0].name == 'read_item')
    assert re.fullmatch(r'\d+ of \d+', row.expected)
    assert next(r for r in model.rows(None)).expected == rm.NO_FITS


def test_channels_name_what_supports_a_lead_and_what_is_unknown(model):
    row = next(r for r in model.rows(CVE_A) if r.lead.newer[0].name == 'read_item')
    assert row.channels.startswith('Advisory + Code') or row.channels.startswith('Code')
    assert 'unknown:' in row.channels and 'Capa' in row.channels.split('unknown:')[1]


def test_flags_say_text_evidence_only_and_contested(model):
    row = next(r for r in model.rows(CVE_A) if r.lead.lead_class == 'fit')
    assert 'text evidence only' in row.flags
    assert 'contested' in next(r for r in model.rows(CVE_A) if r.lead.lead_class == 'review').flags


def test_a_context_the_gate_refuses_has_no_rows():
    refused = sample_assessment(gate_b='not-applicable')
    assert rm.LeadsModel(refused).rows(CVE_B) == ()
    assert 'No leads are produced for it' in rm.LeadsModel(refused).context(CVE_B).banners[0]


def test_review_events_pin_dismiss_and_annotate_without_changing_the_class(assessment):
    fit = lead_of(assessment, 'copy_block', CVE_A)
    reviews = {(fit.candidate_key, CVE_A): LeadReview(pinned=True, statements=(event(fit.candidate_key, 'note', 'my own words'),))}
    rows = rm.LeadsModel(assessment, reviews).rows(CVE_A)
    assert rows[0].lead.candidate_key == fit.candidate_key and rows[0].pinned
    assert rows[0].lead.lead_class == fit.lead_class
    assert 'pinned' in rows[0].flags and 'analyst note' in rows[0].flags
    detail = rm.LeadsModel(assessment, reviews).detail(rows[0])
    assert 'Analyst statement' in detail and 'my own words' in detail


def test_the_detail_has_the_fixed_headers_and_ends_with_the_footer(model):
    detail = model.detail(model.rows(CVE_A)[0])
    for header in ('Summary', 'Expected changes', 'Independent evidence', 'Against', 'Unknown', 'Alternatives',
                   'Pairing', 'Provenance', 'Limitations'):
        assert header in detail
    assert detail.endswith(rm.FOOTER)


def test_observations_are_flat_bounded_and_have_no_invented_location(model):
    row = model.rows(CVE_A)[0]
    observations = model.observations(row)
    assert 0 < len(observations) <= rm.OBS_LIMIT
    assert {o.standing for o in observations} <= {'for', 'against', 'unknown', 'alternative'}
    assert all(o.nav is None or o.nav.rva >= 0 for o in observations)


# ---- states ------------------------------------------------------------------------------------------------------

def ok_model(**kw):
    return rm.LeadsModel(sample_assessment(**kw))


@pytest.mark.parametrize('kwargs, state, text', [
    (dict(project=False, has_run=False, model=None), 'L0', rm.L0),
    (dict(project=True, has_run=False, model=None), 'L1', rm.L1),
    (dict(project=True, has_run=True, model=None), 'L1b', rm.L1B),
    (dict(project=True, has_run=True, model=None, progress=('collecting', 1, 3)), 'L2',
     'Preparing leads: collecting 1/3'),
    (dict(project=True, has_run=True, model=None, progress=('collecting', 0, None)), 'L2',
     'Preparing leads: collecting (no counts available)'),
    (dict(project=True, has_run=True, model=None, error=('PT-PILOT-STORAGE', 'It failed')), 'L5',
     'Leads could not be prepared: PT-PILOT-STORAGE: It failed. The stored comparison and earlier leads are unchanged.'),
], ids=['L0', 'L1', 'L1b', 'L2', 'L2-no-counts', 'L5-empty'])
def test_states_without_a_table_use_the_exact_text(kwargs, state, text):
    view = rm.present(**kwargs)
    assert (view.state, view.headline, view.content) == (state, text, False)


def test_l2_shows_cancel_and_l5_shows_retry_and_copy():
    assert rm.present(project=True, has_run=True, model=None, progress=('x', 0, 1)).actions == ('cancel',)
    assert rm.present(project=True, has_run=True, model=None, error=('A', 'b')).actions == ('retry', 'copy_details')


def test_l3_shows_the_table_with_no_banner_when_every_channel_ran():
    every = rm.LeadsModel(sample_assessment().model_copy(update={'channels': tuple(
        c.ChannelStatus(channel=ch, state='available') for ch in c.CHANNELS)}))
    view = rm.present(project=True, has_run=True, model=every, context=every.contexts[1])
    assert (view.state, view.content) == ('L3', True)
    assert view.banners == every.contexts[1].banners


def test_l4_names_the_channels_that_were_not_available(model):
    view = rm.present(project=True, has_run=True, model=model)
    assert view.state == 'L4'
    assert 'Some evidence was not available: ' in view.banners[0]
    assert 'Capa (not run)' in view.banners[0] and view.banners[0].endswith('is unknown, not a negative result.')


def test_l6_names_the_changed_input_and_offers_refresh(model):
    view = rm.present(project=True, has_run=True, model=model, stale_changed=('newer_sha256', 'raw_sha256'))
    assert view.state == 'L6'
    assert view.banners[0] == ('These leads are out of date: the newer file, the Ghidriff output. They are shown for '
                               'reference only.')
    assert 'refresh' in view.actions


def test_precedence_is_l5_then_l6_then_l4(model):
    view = rm.present(project=True, has_run=True, model=model, stale_changed=('config_digest',), error=('E', 'm'))
    assert view.state == 'L5' and view.banners[0].startswith('Leads could not be prepared')
    assert view.banners[1].startswith('These leads are out of date')
    assert view.banners[2].startswith('Some evidence was not available')


def test_l8_replaces_the_rows_with_a_narrowing_hint(model):
    assert rm.present(project=True, has_run=True, model=model, too_many=123_456).banners[-1] == (
        'Too many rows to display (123456). Narrow the filter.')


def test_gate_and_window_texts_come_from_the_context(model):
    unverified = model.context(CVE_B)
    assert unverified.banners[0].startswith('This advisory could not be tied to these builds')
    window = c.Confounding(state='yes', cves=(CVE_A, CVE_B))
    both = rm.LeadsModel(sample_assessment().model_copy(update={'cves': tuple(
        x.model_copy(update={'confounding': window}) for x in sample_assessment().cves)}))
    assert both.context(CVE_A).banners[-1].startswith('The advisory lists 2 CVEs fixed in this build.')


def test_chips_are_unique_by_glyph_and_shape_and_say_the_state_in_words(assessment):
    chips = rm.channel_chips(assessment)
    assert [chip.key for chip in chips] == list(c.CHANNELS)
    assert {chip.text for chip in chips} >= {'Capa: not run', 'Code: available', 'Calls: partial'}
    states = {(g, s) for g, s, _t in rm._CHANNEL_CHIP.values()}
    assert len(states) == len(rm._CHANNEL_CHIP) and not chip_collisions(
        [rm.ChipSpec(k, g, k, s, t) for k, (g, s, t) in rm._CHANNEL_CHIP.items()])


# ---- sweeps ------------------------------------------------------------------------------------------------------

def test_no_producible_string_claims_a_likelihood_or_vulnerability(model):
    strings = every_string(model)
    assert len(strings) > 100
    assert [(s, rm.CLAIMS.violations(s)) for s in strings if rm.CLAIMS.violations(s)] == []


def test_the_sweep_catches_a_banned_word():
    assert rm.CLAIMS.violations('a probable exploit with 90 percent confidence') != ()


def test_no_enum_slug_reaches_a_person(model):
    slugs = ['verified-bytes', 'tool-reported', 'label-only', 'advisory-claim', 'rule-hypothesis', 'analyst-assertion',
             'not-run', 'D_ghidra', 'D_vendor_text', 'rule_id', 'not-assessed', 'unassessed']
    text = '\n'.join(every_string(model))
    assert [slug for slug in slugs if slug in text] == []


def test_no_uncalibrated_number_is_shown_as_a_measure_of_belief(model):
    rows = [r for ctx in model.contexts for r in model.rows(ctx.cve)]
    for row in rows:
        cells = ' '.join((row.rank, row.expected, row.badge, row.flags, row.channels))
        assert '%' not in cells and '.' not in re.sub(r'\.\.\.', '', cells.replace('(tie)', ''))
    assert all(isinstance(x, (int, str)) for r in rows for x in (r.lead.rank, r.lead.tie.size))


def test_hostile_function_text_is_cut_to_plain_one_line_text(assessment):
    lead = lead_of(assessment, HOSTILE, CVE_A)
    nasty = 'evil\x00\x1b[31m‮⁦name\nsecond line\t' + 'x' * 400
    hostile = lead.model_copy(update={'newer': (lead.newer[0].model_construct(rva=0x80, name=nasty),)})
    row = rm.make_row(hostile, LeadReview(), {}, {})
    assert '\n' not in row.name and '\x00' not in row.name and '‮' not in row.name and '\x1b' not in row.name
    assert len(row.name) <= 400
    note = event(lead.candidate_key, 'note', 'plain').model_construct(
        candidate_key=lead.candidate_key, cve=CVE_A, action='note', text='a\x00b\u202ec\nd', created_utc='2099-01-02T00:00:00Z')
    shown = rm.LeadsModel(assessment, {(lead.candidate_key, CVE_A): LeadReview(statements=(note,))})
    detail = shown.detail(next(r for r in shown.rows(CVE_A) if r.lead.candidate_key == lead.candidate_key))
    assert 'Analyst statement' in detail and '\x00' not in detail and '\u202e' not in detail


def test_the_hostile_name_stays_text_in_every_cell(model):
    row = next(r for r in model.rows(CVE_A) if r.lead.lead_class == 'review')
    assert HOSTILE.split()[0] in row.name and '{0}' in row.name
    assert '<b>x</b>' in row.accessible  # carried as text, never as markup (Qt labels are PlainText)


def test_loaded_helper_marks_a_result_stale(assessment):
    assert loaded_of(assessment, 'stale', ('raw_sha256',)).changed == ('raw_sha256',)
