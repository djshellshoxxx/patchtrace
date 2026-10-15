"""PIL-C1 report: canonical JSON and escaped Markdown of a stored assessment (PIL-integration-plan.md s6, s8, s9 PIL-C1).

The assessment is the record; the report restates it without adding a claim. Advisory and function-name text is
untrusted: nothing is rendered as markup, every enum slug is mapped to words, no sentence claims a probability, a
likelihood or that a function contains or fixes a CVE. Goldens live in `tests/fixtures/pilot/report/` (LF only);
regenerate after a deliberate change with `PATCHTRACE_UPDATE_GOLDENS=1 python -m pytest tests/test_pilot_report.py`
and review the diff. Synthetic data only.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import threading
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import get_args

import pytest
from pilot_synergy_support import arms, load_ledger, sources_for

from patchtrace.pilot import contracts as c
from patchtrace.pilot import keys, limits, report, review, why
from patchtrace.pilot.service import localize

FIXTURES = Path(__file__).parent / 'fixtures' / 'pilot' / 'report'
UPDATE = os.environ.get('PATCHTRACE_UPDATE_GOLDENS') == '1'
FIXED = datetime(2099, 1, 1, tzinfo=UTC)
UNSAFE = frozenset({'Cc', 'Cf', 'Cs', 'Co', 'Cn'})
# stems match as prefixes, the rest as whole words ('provenance' is fine), as the repo's other sweeps do
BANNED = re.compile(r'\b(?:probab|likelihood|confiden|percent|vulnerab|exploit|(?:proven|certain|verified|safe|secure)\b)',
                    re.I)
SANCTIONED = (why.FOOTER, 'absence says nothing about exploitation', 'CISA KEV', 'Analyst statement')


def assessment_of(arm: str) -> c.PilotAssessment:
    """The synergy ledger through an arm, with the clock fixed so the bytes are reproducible."""
    sources = sources_for(arms()[arm])
    return localize(sources, keys.default_config(), threading.Event(), clock=lambda: FIXED)


def swept(text: str) -> None:
    for phrase in SANCTIONED:
        text = text.replace(phrase, '')
    hit = BANNED.search(text)
    assert hit is None, (hit.group(0), text[max(0, hit.start() - 60):hit.end() + 60])


def check_golden(name: str, data: bytes) -> None:
    path = FIXTURES / name
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    expected = path.read_bytes()
    if expected != data:
        at = next((i for i, (a, b) in enumerate(zip(expected, data, strict=False)) if a != b),
                  min(len(expected), len(data)))
        raise AssertionError(f'{name} differs at byte {at} (golden {len(expected)} B, produced {len(data)} B): '
                             f'{expected[max(0, at - 60):at + 60]!r} != {data[max(0, at - 60):at + 60]!r}; '
                             'rerun with PATCHTRACE_UPDATE_GOLDENS=1 and review the diff if this is deliberate')


def reviewed(assessment: c.PilotAssessment) -> dict:
    """An analyst pinned the top lead of CVE-2099-20001, dismissed another and left two statements."""
    top = next(x for x in assessment.leads if x.cve == 'CVE-2099-20001' and x.rank == 1)
    low = next(x for x in assessment.leads if x.cve == 'CVE-2099-20001' and x.rank == 6)
    stamp = iter(f'2099-02-0{i}T10:00:00.000000+00:00' for i in range(1, 9))
    events = [c.ReviewEvent(candidate_key=top.candidate_key, cve=top.cve, action='pin', created_utc=next(stamp)),
              c.ReviewEvent(candidate_key=top.candidate_key, cve=top.cve, action='note',
                            text='Checked the copy by hand.\nThe new compare runs first.', created_utc=next(stamp)),
              c.ReviewEvent(candidate_key=low.candidate_key, cve=low.cve, action='dismiss', text='compiler churn',
                            created_utc=next(stamp))]
    return review.fold(events)


# --- goldens: the report is reproducible byte for byte ------------------------------------------------------------------

GOLDENS = {'full': 'synergy-full', 'b1': 'synergy-code-only', 'window-unknown': 'synergy-window-unknown'}


@pytest.mark.parametrize('arm', GOLDENS, ids=list(GOLDENS))
def test_markdown_matches_the_golden_byte_for_byte(arm):
    check_golden(f'{GOLDENS[arm]}.report.md', report.render(assessment_of(arm), 'md'))


def test_markdown_with_analyst_statements_matches_its_golden():
    assessment = assessment_of('full')
    check_golden('synergy-full-reviewed.report.md', report.render(assessment, 'md', reviewed(assessment)))


def test_the_json_export_is_the_canonical_assessment_and_reads_back():
    assessment = assessment_of('full')
    data = report.render(assessment, 'json')
    text = data.decode('utf-8')
    assert data.isascii() and text.endswith('\n') and '\r' not in text and text.startswith('{\n  "')
    back = c.PilotAssessment.model_validate_json(data)
    assert back == assessment and keys.canonical_bytes(back) == keys.canonical_bytes(assessment)
    assert list(json.loads(text)) == sorted(json.loads(text))  # sorted keys
    keys.verify_assessment(back)
    assert report.render(assessment, 'json') == data  # deterministic


# --- the words: nothing the report says is a slug, a probability or a claim about the code ---------------------------------

@pytest.mark.parametrize('arm', list(arms()), ids=list(arms()))
def test_report_banned_strings(arm):
    assessment = assessment_of(arm)
    text = report.render(assessment, 'md', reviewed(assessment) if arm == 'full' else None).decode('utf-8')
    swept(text)
    assert '%' not in text
    assert why.FOOTER in text  # the standing caption is on every report


def test_the_word_tables_cover_every_value_and_say_nothing_banned():
    for table, vocabulary in ((report.CLASS_BADGES, c.LeadClass), (report.PAIRING_WORDS, c.Identity),
                              (report.DEPTH_WORDS, c.Depth), (report.CAP_FLAGS, c.Cap),
                              (report.STATE_WORDS, c.ChannelState), (report.STATUS_WORDS, c.RunStatus),
                              (report.CWE_WORDS, c.CweStatus)):
        assert set(table) == set(get_args(vocabulary)), vocabulary
    assert set(report.GATE_BANNERS) == set(get_args(c.ContextGate)) - {'applies'}
    for table in (report.CLASS_BADGES, report.PAIRING_WORDS, report.DEPTH_WORDS, report.CAP_FLAGS, report.STATE_WORDS,
                  report.STATUS_WORDS, report.GATE_BANNERS, report.CWE_WORDS):
        for word in table.values():
            swept(word)
    for sentence in (report.INTRO, report.NO_ADVISORY, report.MISSING_EVIDENCE, report.WINDOW_UNKNOWN):
        swept(sentence)
    swept(report.window_text(3))
    assert {badge.split()[0].rstrip(',') for badge in report.CLASS_BADGES.values()} == {'FITS', 'NEEDS', 'PARTIAL', 'CODE', 'CHANGED'}


def test_no_enum_slug_reaches_the_report():
    slugs = set()
    for vocabulary in (c.Verification, c.Mechanism, c.Cap, c.ChannelState, c.Basis, c.KevState):
        slugs |= {value for value in get_args(vocabulary) if '-' in value or '_' in value}
    slugs |= {'rule-hypothesis', 'not-assessed', 'label-only', 'advisory-claim', 'tool-reported', 'verified-bytes'}
    for arm in ('full', 'b1', 'adv'):
        text = report.render(assessment_of(arm), 'md').decode('utf-8').replace('\\', '')
        found = sorted(slug for slug in slugs if slug in text)
        assert not found, (arm, found)


# --- what the report says -------------------------------------------------------------------------------------------------

def sections(text: str) -> dict[str, str]:
    parts = re.split(r'^## ', text, flags=re.M)
    return {part.split('\n', 1)[0]: part for part in parts[1:]}


def rows_of(section: str) -> list[list[str]]:
    """The body rows of the first table of a section, as cells."""
    table = [line for line in section.split('\n### ')[0].splitlines() if line.startswith('| ')]
    return [[cell.strip() for cell in line.strip('|').split(' | ')] for line in table[2:]]


def test_the_report_names_its_result_builds_orientation_and_channels():
    assessment = assessment_of('full')
    text = report.render(assessment, 'md').decode('utf-8')
    assert text.startswith('# Patch-intent leads\n')
    for needle in (assessment.result_id, assessment.older_sha256, assessment.newer_sha256, 'older to newer'):
        assert needle in text
    channels = sections(text)['Evidence channels']
    assert '| Calls | partial |' in channels and '| Capa | available |' in channels
    assert report.MISSING_EVIDENCE in text  # the calls channel is partial: missing evidence is unknown


def test_each_context_gets_its_gate_kev_window_counts_and_leads():
    assessment = assessment_of('full')
    body = sections(report.render(assessment, 'md').decode('utf-8'))
    first, second = body['`CVE-2099-20001`'], body['`CVE-2099-20002`']
    assert 'CISA KEV: listed (added 2099-02-10)' in first
    assert 'CISA KEV: not in the snapshot' in second and 'absence says nothing about exploitation' in second
    assert report.window_text(2) in first and report.window_text(2) in second
    assert '- Weakness class: stated by the advisory (CWE-122, CWE-787)' in first
    assert '- Leads: fits advisory 1; needs review 2; partial fit 3; code change 0; changed, no fit 3' in first
    rows = rows_of(first)
    assert [row[3] for row in rows[:3]] == ['FITS ADVISORY', 'NEEDS REVIEW', 'NEEDS REVIEW']
    function = next(f for f in load_ledger().functions if f.id == 'F1')
    assert rows[0][:3] == ['1', function.newer.name, f'older 0x{function.older.rva:x}, newer 0x{function.newer.rva:x}']
    assert rows[0][4:] == ['2 of 3', '2', 'corroborated', '-']
    assert 'CHANGED, NO FIT' in {row[3] for row in rows} and 'NOT ASSESSED' in {row[3] for row in rows}
    assert '### Why: ' in first and 'Seen: guard added' in first.replace('\\', '')
    assert why.FOOTER not in first.split('\n### ', 1)[1]  # the caption is on top, not under every lead
    assert not any(line == '**Limitations**' for line in first.splitlines())


def test_tied_leads_show_their_whole_range_not_a_false_precision():
    assessment = assessment_of('full')
    rows = rows_of(sections(report.render(assessment, 'md').decode('utf-8'))['`CVE-2099-20002`'])
    tied = [row for row in rows if row[0].endswith('(tie)')]
    assert {row[0] for row in tied} == {'3-4 (tie)', '6-7 (tie)'} and [row[0] for row in rows if '(tie)' not in row[0]]
    for tie in {row[0] for row in tied}:
        assert sum(row[0] == tie for row in tied) == 2  # every member of the group says the same range


def test_the_code_only_context_is_listed_last_and_without_a_cve():
    both = sections(report.render(assessment_of('full'), 'md').decode('utf-8'))
    assert list(both)[-1] == 'Code evidence only' and report.NO_ADVISORY not in both['Code evidence only']
    only = sections(report.render(assessment_of('b1'), 'md').decode('utf-8'))
    assert list(only) == ['Evidence channels', 'Code evidence only'] and report.NO_ADVISORY in only['Code evidence only']
    assert 'CISA KEV' not in only['Code evidence only'] and len(rows_of(only['Code evidence only'])) == 9


@pytest.mark.parametrize('gate', ['unverified', 'conflict', 'asserted', 'not-applicable'])
def test_a_gate_other_than_applies_has_its_banner(gate):
    assessment = assessment_of('full')
    context = assessment.cves[0]
    leads = tuple(x for x in assessment.leads if x.cve != context.cve)
    if gate != 'not-applicable':
        leads += tuple(x.model_copy(update={'gate': gate}) for x in assessment.leads if x.cve == context.cve)
    counts = c.LeadCounts(fit=0, review=0, partial=0, code=0, queue=0) if gate == 'not-applicable' else context.counts
    patched = assessment.model_copy(update={
        'cves': (context.model_copy(update={'gate': gate, 'counts': counts}), *assessment.cves[1:]), 'leads': leads})
    text = report.render(patched, 'md').decode('utf-8')
    section = sections(text)['`CVE-2099-20001`']
    assert f'> {report.GATE_BANNERS[gate]}' in section
    swept(text.replace('\\', ''))
    assert (rows_of(section) == []) == (gate == 'not-applicable')


def test_analyst_statements_are_attributed_and_never_change_a_class():
    assessment = assessment_of('full')
    plain = report.render(assessment, 'md').decode('utf-8')
    marked = report.render(assessment, 'md', reviewed(assessment)).decode('utf-8')
    assert 'Analyst statement' in marked and 'Analyst statement' not in plain
    assert '- 2099-02-02: Checked the copy by hand\\. The new compare runs first\\.' in marked  # one line
    first = sections(marked)['`CVE-2099-20001`']
    before = rows_of(sections(plain)['`CVE-2099-20001`'])
    after = rows_of(first)
    assert len(after) == len(before) and {tuple(r[:5]) for r in after} == {tuple(r[:5]) for r in before}
    assert after[0][7] == 'pinned' and after[0][3] == 'FITS ADVISORY'  # the Pinned band, class unchanged
    assert next(row for row in after if row[0] == '6')[7].endswith('dismissed') or any(
        row[7].endswith('dismissed') for row in after)
    swept(marked.replace('\\', ''))


def test_leads_are_cut_at_the_per_context_limit_with_a_pointer_to_the_json_export():
    small = dataclasses.replace(limits.DEFAULT_LIMITS, p10_markdown_leads_per_cve=2)
    first = sections(report.to_markdown(assessment_of('full'), limits=small))['`CVE-2099-20001`']
    assert len(rows_of(first)) == 2 and '7 further leads are not listed here; the JSON export has them all.' in first


def test_explanations_are_written_for_the_first_leads_only_and_say_so(monkeypatch):
    monkeypatch.setattr(report, 'EXPLAINED_PER_CONTEXT', 2)
    first = sections(report.to_markdown(assessment_of('full')))['`CVE-2099-20001`']
    assert first.count('### Why: ') == 2 and 'Explanations are written for the first 2 leads' in first


def test_the_markdown_stops_at_its_size_limit_and_says_so():
    assessment = assessment_of('full')
    small = dataclasses.replace(limits.DEFAULT_LIMITS, p10_markdown_bytes=6000)
    text = report.to_markdown(assessment, limits=small)
    assert len(text.encode('utf-8')) <= 6000 and 'size limit' in text.splitlines()[-1]
    assert report.to_markdown(assessment) != text
    assert text.count('\n## ') >= 1  # whole blocks only: the table of a context is never cut in the middle
    for section in sections(text).values():
        if '| --- |' in section:
            width = section.count('| --- ')
            assert all(line.count(' | ') + 1 == width for line in section.splitlines() if line.startswith('| '))


def test_the_json_export_over_its_limit_is_refused_not_cut():
    small = dataclasses.replace(limits.DEFAULT_LIMITS, p10_json_bytes=1000)
    with pytest.raises(limits.PilotError) as raised:
        report.render(assessment_of('full'), 'json', limits=small)
    assert raised.value.code == 'PT-PILOT-LIMIT'



# --- untrusted text -------------------------------------------------------------------------------------------------------

HOSTILE = ['<script>alert(1)</script>', '[click](javascript:alert(1))', '![p](https://evil.example/p.png)', 'a | b | c',
           '`code` **bold** _under_ ~~strike~~', '# heading', '> quote', 'https://evil.example/autolink', '&amp; &#x27;',
           '<img src=x onerror=alert(1)>', 'x' * 256]


def hostile_assessment(name: str) -> c.PilotAssessment:
    base = assessment_of('full')
    ref = c.FunctionRef(rva=0x1000, name=name)
    return base.model_copy(update={
        'leads': tuple(x.model_copy(update={'older': (ref,), 'newer': (ref,)}) if x.rank <= 3 else x
                       for x in base.leads),
        'limitations': (name[:300],), 'status': 'partial'})


def inert(text: str) -> None:
    assert not [ch for ch in text if ch != '\n' and unicodedata.category(ch) in UNSAFE]
    prose = '\n'.join(line.removeprefix('> ') for line in text.splitlines())  # a leading '> ' is the template's quote
    assert '<' not in prose and '>' not in prose
    assert not re.search(r'&(?!(?:amp|lt|gt|quot|#x27);)', text)
    assert not re.search(r'\]\(', text) and not re.search(r'(?<!\\)[\[\]]', text.replace('\\[', '').replace('\\]', ''))
    assert not re.search(r'https?://|javascript:', text)  # a URL is text: its colon is escaped


@pytest.mark.parametrize('name', HOSTILE, ids=[f'h{i}' for i in range(len(HOSTILE))])
def test_hostile_function_names_and_notes_never_become_markup(name):
    assessment = hostile_assessment(name)
    state = {(x.candidate_key, x.cve): review.LeadReview(pinned=True, statements=(
        c.ReviewEvent(candidate_key=x.candidate_key, cve=x.cve, action='note', text=name + '\nsecond line',
                      created_utc='2099-02-01T10:00:00.000000+00:00'),)) for x in assessment.leads if x.rank <= 3}
    text = report.render(assessment, 'md', state).decode('utf-8')
    inert(text)
    width = None
    for line in text.splitlines():  # a pipe in a name cannot add a cell: every row of a table is as wide as its header
        if not line.startswith('|'):
            width = None
        elif width is None:
            width = line.count(' | ')
        else:
            assert line.count(' | ') == width and line.endswith(' |'), line


BIDI, LSEP = chr(0x202e), chr(0x2028)


def test_control_and_bidi_characters_in_a_stored_record_are_shown_as_markers():
    base = assessment_of('b1')
    name = f'a\x07b{BIDI}c\x1b[31md\x00e{LSEP}f'
    ref = c.FunctionRef.model_construct(rva=0x10, name=name)  # the contract would refuse this name: a stored record may lie
    forged = base.model_copy(update={'leads': tuple(
        x.model_copy(update={'older': (ref,), 'newer': ()}) if x.rank == 1 else x for x in base.leads)})
    text = report.to_markdown(forged)
    assert not [ch for ch in text if ch != '\n' and unicodedata.category(ch) in UNSAFE]
    assert '\\u0007' in text and '\\u202e' in text and '\\u001b' in text and '\\u0000' in text
    assert 'e f' in text  # a layout break is flattened to a space, never kept


def test_the_terminal_label_of_a_function_is_one_clean_line():
    lead = next(x for x in assessment_of('b1').leads if x.rank == 1)
    ref = c.FunctionRef.model_construct(rva=0x10, name=f'a\x07b\nc{BIDI}d')
    label = report.plain_label(lead.model_copy(update={'older': (ref,), 'newer': ()}))
    assert '\n' not in label and '\x07' not in label and BIDI not in label and '\\u0007' in label and '\\u202e' in label


# --- files ------------------------------------------------------------------------------------------------------------------

def test_the_suffix_chooses_the_format_and_anything_else_is_refused():
    assert report.format_for(Path('x/report.json')) == 'json' and report.format_for(Path('R.MD')) == 'md'
    for name in ('report', 'report.txt', 'report.html', 'report.markdown'):
        with pytest.raises(limits.PilotError) as raised:
            report.format_for(Path(name))
        assert raised.value.code == 'PT-PILOT-INPUT'
    with pytest.raises(limits.PilotError) as raised:
        report.render(assessment_of('b1'), 'html')
    assert raised.value.code == 'PT-PILOT-INPUT'


def test_an_export_is_written_atomically_as_utf8_with_lf_only(tmp_path):
    target = tmp_path / 'leads.md'
    target.write_bytes(b'earlier report')
    data = report.render(assessment_of('b1'), 'md')
    report.write_export(target, data)
    assert target.read_bytes() == data and b'\r' not in data
    assert sorted(p.name for p in tmp_path.iterdir()) == ['leads.md']  # no partial file is left behind
    with pytest.raises(limits.PilotError) as raised:
        report.write_export(tmp_path / 'absent' / 'leads.md', data)
    assert raised.value.code == 'PT-PILOT-STORAGE' and target.read_bytes() == data


# --- shared row words (the CLI and the dock say the same thing) ---------------------------------------------------------------

def test_badge_expected_changes_and_flags_follow_the_stored_lead():
    assessment = assessment_of('full')
    leads = {x.candidate_key: x for x in assessment.leads if x.cve == 'CVE-2099-20001'}
    top = min(leads.values(), key=lambda x: x.rank)
    assert report.badge(top) == 'FITS ADVISORY' and report.expected_seen(top) == '2 of 3'
    queue = next(x for x in leads.values() if x.lead_class == 'queue')
    assert report.badge(queue) == 'CHANGED, NO FIT' and report.expected_seen(queue) in ('-', '0 of 3', '0 of 2', '0 of 1')
    assert report.rank_text(top) == '1' and report.rank_text(max(leads.values(), key=lambda x: x.tie.size)).endswith(
        '(tie)') == any(x.tie.size > 1 for x in leads.values())
    flagged = [x for x in leads.values() if 'text evidence only' in report.flags(x)]
    assert all(x.depth == 'lexical' for x in flagged)
    contested = next(x for x in leads.values() if x.identity == 'contested')
    assert 'pairing contested' in report.flags(contested)
    pinned = review.LeadReview(pinned=True, dismissed=True)
    assert report.flags(top, pinned)[-2:] == ('pinned', 'dismissed')
