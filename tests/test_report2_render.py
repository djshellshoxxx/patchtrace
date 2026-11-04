"""SPEC-50 RPT2-3: JSON, Markdown and HTML renderers, content digest, goldens."""
from __future__ import annotations

import base64
import hashlib
import html.parser
import json
import re

import pytest
from test_report2_support import FIXED_TIME, HOSTILE_NAME, check_or_update, hostile_project, synergy_sections

from patchtrace.report2 import contracts, text
from patchtrace.report2.assemble import build_report
from patchtrace.report2.calibration_block import build_calibration_block
from patchtrace.report2.inputs import RedactionProfile, SectionInputs
from patchtrace.report2.render_html import render_html
from patchtrace.report2.render_json import content_digest, finalize, render_json
from patchtrace.report2.render_md import render_md
from patchtrace.reports import _snapshot

BIDI_RE = re.compile('[\u200e\u200f\u202a-\u202e\u2066-\u2069\u061c]')


@pytest.fixture
def no_artifact(tmp_path, monkeypatch):
    monkeypatch.setattr('patchtrace.calibration.artifact.BUNDLED_DIR', tmp_path)


@pytest.fixture
def built(no_artifact):
    project, a, b = hostile_project()
    snapshot = _snapshot(project, False, True, None)
    report = build_report(snapshot, include_code=False, include_notes=True, sections=synergy_sections(a, b),
                          generated_at=FIXED_TIME, calibration=build_calibration_block())
    data = finalize(report)
    return data, a, b


def test_json_envelope_keeps_v1_keys_and_adds_v2_keys(built):
    data, _, _ = built
    v1 = {'schema_version', 'project_id', 'name', 'revision', 'created', 'sample', 'limitations', 'selection',
          'artifacts', 'analysis_runs', 'matches', 'interpretations', 'change_ranking', 'annotations'}
    v2 = {'report_version', 'content_digest', 'generated_at', 'sections_present', 'stale_sections', 'tool',
          'orientation', 'calibration', 'redaction', 'provenance', 'unknowns', 'normalization'}
    assert v1 | v2 <= set(data) and data['report_version'] == 2 and data['schema_version'] == 1


def test_calibration_is_ordinal_and_no_probability_field_exists(built):
    data, _, _ = built
    assert data['calibration'] == {'display_level': 'ordinal', 'profile': None, 'model_id': None,
                                   'artifact_digest': None, 'gates': None, 'note': contracts.CALIBRATION_NOTE}
    blob = render_json(data)
    assert 'shown_p' not in blob and 'probability"' not in blob


def test_no_aggregate_key_under_engine_evidence(built):
    data, _, _ = built
    banned = {'mean', 'average', 'combined_score', 'confidence'}

    def keys(value):
        if isinstance(value, dict):
            yield from value
            for v in value.values():
                yield from keys(v)
        elif isinstance(value, list):
            for v in value:
                yield from keys(v)
    assert not banned & set(keys(data['engine_evidence']))


def test_sections_present_lists_exactly_the_sections_with_data(built):
    data, _, _ = built
    assert data['sections_present'] == ['advisories', 'build_facts', 'engine_evidence', 'leads', 'symbols']
    assert not {'series', 'unified_result'} & set(data)
    assert any('Series context not included' in u for u in data['unknowns'])


def test_verdicts_missing_engines_and_ordinal_index_option(built):
    data, a, b = built
    rows = {r['match_id']: r for r in data['engine_evidence']['rows']}
    assert rows[a]['verdict'] == 'corroborated' and rows[a]['missing_engines'] == ['rz-diff']
    assert rows[b]['verdict'] == 'contested' and rows[b]['contradicting_engines'] == ['bindiff']
    assert all(r['ordinal_index'] is None for r in rows.values())  # off by default


def test_ordinal_index_only_with_option(no_artifact):
    project, a, b = hostile_project()
    report = build_report(_snapshot(project, False, True, None), include_code=False, include_notes=True,
                          sections=synergy_sections(a, b), profile=RedactionProfile(include_ordinal_index=True),
                          generated_at=FIXED_TIME)
    rows = {r['match_id']: r for r in finalize(report)['engine_evidence']['rows']}
    assert rows[a]['ordinal_index'] == 75


def test_hostile_name_is_neutralized_in_json_and_the_report_says_so(built):
    data, _, _ = built
    blob = render_json(data)
    assert '<U+202E>gnidnuf<script>alert(1)</script>?# Injected' in blob and not BIDI_RE.search(blob)
    assert data['normalization'] == 'report/2 text normalization applied'
    text.encode_report(blob)


def test_ranking_key_stays_with_ordinal_label(no_artifact):
    project, a, b = hostile_project()
    snapshot = _snapshot(project, False, True, None)
    snapshot['change_ranking'] = {'formula': 'attention/1', 'config_digest': 'c', 'input_digest': 'i',
                                  'status': 'complete', 'stale': True, 'profile': None, 'note': 'note',
                                  'entries': [{'rank': 1, 'score': 70, 'raw': 3, 'evidence': 'strong',
                                               'match_id': a, 'functions': ['f']}]}
    data = finalize(build_report(snapshot, include_code=False, include_notes=True, generated_at=FIXED_TIME))
    ranking = data['change_ranking']
    assert ranking['display_label'] == 'attention index (ordinal)'
    assert ranking['entries'][0]['attention_index'] == 70 and 'score' not in ranking['entries'][0]
    assert data['stale_sections'] == ['change_ranking'] and 'change_ranking' in data['sections_present']
    assert 'Change ranking (attention index (ordinal), STALE)' in render_md(data)


def test_content_digest_ignores_time_and_is_stable(built, no_artifact):
    data, a, b = built
    project, _, _ = hostile_project()
    again = finalize(build_report(_snapshot(project, False, True, None), include_code=False, include_notes=True,
                                  sections=synergy_sections(a, b), generated_at='2030-01-01T00:00:00+00:00'))
    assert again['content_digest'] == data['content_digest']
    assert again['generated_at'] != data['generated_at']
    changed = dict(data, name='other')
    assert content_digest(changed) != data['content_digest']
    assert content_digest(dict(data, created='x', generated_at='y', content_digest='z')) == data['content_digest']


def test_share_profile_defangs_urls_and_removed_hides_them(no_artifact):
    project, a, b = hostile_project()
    for profile, expected in ((RedactionProfile.share(), 'hxxps://evil[.]example/adv[.]html'),
                              (RedactionProfile(urls='removed'), '[URL REMOVED]'),
                              (RedactionProfile(), 'https://evil.example/adv.html')):
        report = build_report(_snapshot(project, False, True, None), include_code=False, include_notes=True,
                              sections=synergy_sections(a, b), profile=profile, generated_at=FIXED_TIME)
        data = finalize(report)
        assert data['advisories'][0]['url_text'] == expected
        assert data['redaction']['urls'] == profile.urls


# --- HTML -------------------------------------------------------------------------------------------------------

class _Doc(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.attrs, self.style = [], [], ''
        self._in_style = False

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs += [(tag, k, v) for k, v in attrs]
        self._in_style = tag == 'style'

    def handle_endtag(self, tag):
        self._in_style = False

    def handle_data(self, data):
        if self._in_style:
            self.style += data


def test_html_has_no_script_links_or_data_attributes(built):
    data, _, _ = built
    page = render_html(data)
    assert '<script' not in page and '<a ' not in page and '<img' not in page
    doc = _Doc()
    doc.feed(page)
    assert not {k for _, k, _ in doc.attrs} & {'href', 'src', 'srcset', 'style', 'onerror', 'onload', 'onclick'}
    assert 'script' not in doc.tags and 'a' not in doc.tags and 'img' not in doc.tags
    assert doc.tags.count('style') == 1
    fixed = {('html', 'lang', 'en'), ('meta', 'charset', 'utf-8'), ('meta', 'name', 'viewport'),
             ('meta', 'content', 'width=device-width, initial-scale=1'), ('meta', 'name', 'referrer'),
             ('meta', 'content', 'no-referrer'), ('meta', 'http-equiv', 'Content-Security-Policy')}
    csp = [v for t, k, v in doc.attrs if k == 'content' and 'default-src' in (v or '')]
    assert len(csp) == 1
    assert set(doc.attrs) - fixed == {('meta', 'content', csp[0])}


def test_html_csp_is_a_hash_of_the_one_style_block(built):
    data, _, _ = built
    page = render_html(data)
    doc = _Doc()
    doc.feed(page)
    digest = base64.b64encode(hashlib.sha256(doc.style.encode('utf-8')).digest()).decode('ascii')
    csp = next(v for _, k, v in doc.attrs if k == 'content' and 'default-src' in v)
    assert f"style-src 'sha256-{digest}'" in csp and 'unsafe-inline' not in csp and "default-src 'none'" in csp
    assert '<meta name="referrer" content="no-referrer">' in page


def test_html_hostile_text_is_inert(built):
    data, _, _ = built
    page = render_html(data)
    assert 'alert(1)</script>' not in page and not BIDI_RE.search(page)
    assert '&lt;U+202E&gt;gnidnuf&lt;script&gt;' in page
    assert '&lt;b&gt;Corp&lt;/b&gt;' in page


# --- Markdown ---------------------------------------------------------------------------------------------------

def _outside_fences(md: str) -> list[str]:
    lines, kept, fence = md.split('\n'), [], None
    for line in lines:
        if fence is None:
            m = re.fullmatch(r'(`{3,})', line)
            if m:
                fence = m.group(1)
            else:
                kept.append(line)
        elif line == fence:
            fence = None
    assert fence is None, 'unterminated fence'
    return kept


def test_report2_markdown_has_no_live_links(built):
    data, _, _ = built
    md = render_md(data)
    outside = '\n'.join(_outside_fences(md))
    assert '](' not in outside and '<' not in outside and not BIDI_RE.search(md)
    assert not re.search(r'(?i)(https?|ftp):|www\.|\w@\w', outside)  # the colon is escaped: nothing autolinks
    assert not re.search(r'(?m)^# Injected', outside) and not re.search(r'(?m)^<', outside)


def test_markdown_headings_are_single_lines_and_the_hostile_one_is_escaped(built):
    data, _, _ = built
    headings = [line for line in _outside_fences(render_md(data)) if line.startswith('#')]
    hostile = [h for h in headings if 'gnidnuf' in h]
    assert len(hostile) == 1 and hostile[0].startswith('### ') and 'Injected' in hostile[0]
    assert all(re.match(r'#{1,3} \S', h) for h in headings)
    assert [h for h in headings if h.startswith('# ')] == ['# PatchTrace report']


def test_markdown_table_rows_keep_their_cell_count(built):
    data, _, _ = built
    tables, current = [], []
    for line in _outside_fences(render_md(data)):
        if line.startswith('|'):
            current.append(line)
        elif current:
            tables.append(current)
            current = []
    assert tables
    for rows in tables:
        counts = {len(re.findall(r'(?<!\\)\|', row)) for row in rows}
        assert len(counts) == 1, rows


def test_markdown_advisory_fence_outgrows_content_backticks(built):
    data, _, _ = built
    md = render_md(data)
    fences = re.findall(r'(?m)^(`{3,})$', md)
    assert fences and max(len(f) for f in fences) >= 6  # advisory text holds a five-backtick run
    assert md.count('\n``````\n') >= 2 or '``````' in md


# --- goldens ----------------------------------------------------------------------------------------------------

def test_goldens_for_the_synergy_fixture(built):
    data, _, _ = built
    check_or_update('synergy_v2.json', render_json(data))
    check_or_update('synergy_v2.md', render_md(data))
    check_or_update('synergy_v2.html.golden', render_html(data))   # data suffix: not analysed as HTML


def test_render_json_round_trips_and_digest_matches(built):
    data, _, _ = built
    parsed = json.loads(render_json(data))
    assert parsed == data and parsed['content_digest'] == content_digest(parsed)


def test_empty_sections_render_without_errors(no_artifact):
    project, _, _ = hostile_project()
    data = finalize(build_report(_snapshot(project, True, True, None), include_code=True, include_notes=True,
                                 sections=SectionInputs(), generated_at=FIXED_TIME))
    assert data['sections_present'] == [] and len(data['unknowns']) >= 7
    md, page = render_md(data), render_html(data)
    assert 'Engine evidence' not in md and 'Engine evidence' not in page
    assert '<U+202E>gnidnuf' in md and 'read_item' in md
    assert HOSTILE_NAME not in render_json(data)
