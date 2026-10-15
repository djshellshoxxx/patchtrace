"""KEV K5 report block: escaped Markdown for exports with provenance, a table, the timeline and any drift.

The block is built from a recorded ``KevContext`` and, while the catalog file is still stored, its ``KevCatalogMeta``.
Text from the catalog, from a file name or from the caller is untrusted: it is escaped and never rendered as markup.
"""
from __future__ import annotations

import re

import pytest
from kev_helpers import (
    NOW,
    SYNTHETIC,
    at,
    document,
    entry,
    fixture_bytes,
    fixture_document,
    mutated,
    parse_document,
    parse_fixture,
    socket_guard,
)

from patchtrace.kev.contracts import ConsentRecord, plan_for
from patchtrace.kev.kb_adapter import TIMELINE_UNKNOWN, TIMELINE_UNVERIFIED
from patchtrace.kev.parse import parse_catalog
from patchtrace.kev.project_context import build_context
from patchtrace.kev.report import CLOSING, HEADING, MAX_PROSE, escape_md, report_block
from patchtrace.kev.view_model import NOT_RECOGNIZED, RANSOMWARE_UNKNOWN, KevColumnProvider

no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)
STAMP, KB = '2099-03-02T08:00:00Z', 'KB5000001'
KNOWN, NOT_LISTED, UNKNOWN, PADDED = 'CVE-2099-10001', 'CVE-2099-10002', 'CVE-2099-10004', 'CVE-2099-10010'
CVES = (KNOWN, NOT_LISTED, UNKNOWN, PADDED)
BANNED = re.compile(r'\b(exploitable|vulnerable function|confirmed vulnerab\w*|weaponi[sz]ed|proves?|is safe|fixes this'
                    r'|risk|probab\w*|likelihood)\b|%', re.IGNORECASE)
SANCTIONED = ('does not mean not exploited', 'has not been shown to be unexploited')
HOSTILE_NAME = 'x|y`z<script>alert(1)<b>[a](javascript:alert(1)) ![i](u) www.evil.test &amp; # *b* _i_ ~s~.json'
HOSTILE_VERSION = 'v|<b>*x*_[l](u)`'
HOSTILE_TEXT = ['x\n# injected heading\n| a | b |', '<script>alert(1)</script>', '[x](http://evil.test) ![i](u)',
                'www.evil.test', '`tick` &amp; *b* _i_', 'ends with a backslash \\']


@pytest.fixture(scope='module')
def catalog():
    return parse_fixture(SYNTHETIC)


def context(catalog, cves=CVES, now=NOW, **overrides):
    fields = {'created_at': STAMP, 'kb': KB, 'release_date': '2099-02-11', 'orientation_verified': True} | overrides
    return build_context(KevColumnProvider(catalog, now), cves, **fields)


def block_lines(text: str) -> list[str]:
    assert text.endswith('\n') and not text.endswith('\n\n') and '\r' not in text
    return text[:-1].split('\n')


def table_rows(text: str) -> list[str]:
    return [line for line in text.split('\n') if line.startswith('|')]


# --- the block ------------------------------------------------------------------------------------------------------

def test_the_block_for_the_synthetic_scenario(catalog):
    meta = catalog.meta
    assert report_block(context(catalog), meta) == '\n'.join([
        '### Exploitation context (CISA KEV)',
        '',
        f'Catalog `2099.03.01`, released 2099-03-01 18:00:00 UTC, 4 entries; retrieved 2099-03-02 from a local file '
        f'(`kev-synthetic-2099.json`); SHA-256 `{meta.raw_sha256}`; snapshot `{meta.snapshot_id}`; recorded '
        '2099-03-02. Data: CISA Known Exploited Vulnerabilities catalog, CC0 1.0; not endorsed by CISA or DHS.',
        '',
        '| CVE | KEV | Added to KEV | CISA due date | Known ransomware campaign use | Forensic triage required by '
        'CISA |',
        '| --- | --- | --- | --- | --- | --- |',
        '| `CVE-2099-10001` | Listed | `2099-02-10` | `2099-02-13` | Known | Yes |',
        '| `CVE-2099-10002` | Not listed | - | - | - | - |',
        '| `CVE-2099-10004` | Listed | `2099-02-20` | `2099-03-13` | Unknown | No |',
        '| `CVE-2099-10010` | Listed | `2099-02-27` | `2099-03-13` | - | - |',
        '',
        f'In the ransomware column, Unknown means: {RANSOMWARE_UNKNOWN}',
        '',
        '- `CVE-2099-10001`: Added to KEV 1 day before the update was released (KB5000001, 2099-02-11).',
        '- `CVE-2099-10004`: Added to KEV 9 days after the update was released (KB5000001, 2099-02-11).',
        '- `CVE-2099-10010`: Added to KEV 16 days after the update was released (KB5000001, 2099-02-11).',
        '',
        CLOSING,
        ''])
    assert CLOSING == ('KEV lists a CVE as a known exploited vulnerability. It does not identify builds, KBs, files or '
                       'functions. Not listed does not mean not exploited.')
    assert HEADING == '### Exploitation context (CISA KEV)'


def test_empty_cells_are_dashes_and_unknown_is_never_written_as_no(catalog):
    rows = {line.split('|')[1].strip(' `'): [cell.strip() for cell in line.split('|')[2:-1]]
            for line in table_rows(report_block(context(catalog), catalog.meta))[2:]}
    assert rows[PADDED] == ['Listed', '`2099-02-27`', '`2099-03-13`', '-', '-']        # the optional fields are absent
    assert rows[UNKNOWN][3] == 'Unknown' and rows[UNKNOWN][4] == 'No'                     # No is the triage answer only
    assert rows[NOT_LISTED] == ['Not listed', '-', '-', '-', '-']


def test_the_unknown_legend_appears_only_when_a_row_says_unknown(catalog):
    assert 'Unknown means' in report_block(context(catalog, (UNKNOWN,)), catalog.meta)
    assert 'Unknown means' not in report_block(context(catalog, (KNOWN, NOT_LISTED, PADDED)), catalog.meta)


def test_an_unrecognized_value_is_said_so(catalog):
    odd = parse_document(mutated(fixture_document(SYNTHETIC), ('vulnerabilities', 3, 'forensicTriage'), 'Maybe'))
    text = report_block(context(odd, (KNOWN,), now=NOW), odd.meta)
    assert f'| Known | {NOT_RECOGNIZED} |' in text


def test_a_fetched_catalog_names_its_host_not_a_file():
    plan = plan_for('cisa-github')
    consent = ConsentRecord(operation='fetch-kev-catalog', source='cisa-github', url=plan.url, plan_sha=plan.plan_sha,
                            granted_at='2099-03-02T07:59:00Z', surface='cli')
    fetched = parse_catalog(fixture_bytes(SYNTHETIC), source='cisa-github', retrieved_at='2099-03-02T08:00:00Z',
                            source_url=plan.url, final_url=plan.url, consent=consent)
    line = block_lines(report_block(context(fetched), fetched.meta))[2]
    assert 'retrieved 2099-03-02 from `raw.githubusercontent.com`; SHA-256 ' in line and 'local file' not in line
    without_file = block_lines(report_block(context(fetched)))[2]
    assert '; source `raw.githubusercontent.com`; snapshot ' in without_file and 'local file' not in without_file


def test_without_the_stored_catalog_the_row_speaks_for_itself(catalog):
    recorded = context(catalog)
    line = block_lines(report_block(recorded))[2]
    assert line == (f'Catalog `2099.03.01`, released 2099-03-01 18:00:00 UTC; source a local file; snapshot '
                    f'`{recorded.snapshot_id}`; content `{recorded.content_digest}`; recorded 2099-03-02. The catalog '
                    'file is no longer stored on this computer, so its SHA-256 and retrieval details are not shown. '
                    'Data: CISA Known Exploited Vulnerabilities catalog, CC0 1.0; not endorsed by CISA or DHS.')
    assert table_rows(report_block(recorded)) == table_rows(report_block(recorded, catalog.meta))


def test_a_catalog_of_one_entry_says_entry_not_entries():
    one = parse_document(document([entry(1)], catalogVersion='2099.03.01', dateReleased='2099-03-01T18:00:00.0000Z'))
    recorded = build_context(KevColumnProvider(one, NOW), ['CVE-2098-00001'], created_at=STAMP)
    assert ', 1 entry; retrieved ' in report_block(recorded, one.meta)


def test_a_local_file_without_a_name_is_just_a_local_file():
    nameless = parse_catalog(fixture_bytes(SYNTHETIC), source='local-import', retrieved_at='2099-03-02T08:00:00Z')
    line = block_lines(report_block(context(nameless), nameless.meta))[2]
    assert 'from a local file; SHA-256 ' in line and '(' not in line


def test_the_meta_of_another_catalog_is_refused(catalog):
    other = parse_document(document([entry(1)]))
    with pytest.raises(ValueError, match='snapshot'):
        report_block(context(catalog), other.meta)


# --- the timeline ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(('overrides', 'sentence'), [
    ({'orientation_verified': False}, TIMELINE_UNVERIFIED), ({'release_date': None}, TIMELINE_UNKNOWN)],
    ids=['orientation-not-verified', 'release-date-unknown'])
def test_a_fixed_timeline_sentence_is_said_once_not_per_cve(catalog, overrides, sentence):
    text = report_block(context(catalog, **overrides), catalog.meta)
    assert text.count(sentence) == 1 and not re.search(r'before the update|after the update', text)
    assert not [line for line in text.split('\n') if line.startswith('- ')]


def test_no_kb_means_no_timeline(catalog):
    text = report_block(context(catalog, kb=None, release_date=None, orientation_verified=False), catalog.meta)
    assert 'update was released' not in text and TIMELINE_UNVERIFIED not in text and TIMELINE_UNKNOWN not in text


def test_no_timeline_when_no_cve_is_listed(catalog):
    text = report_block(context(catalog, (NOT_LISTED,), orientation_verified=False), catalog.meta)
    assert 'update was released' not in text and TIMELINE_UNVERIFIED not in text and TIMELINE_UNKNOWN not in text


def test_the_timeline_covers_the_listed_cves_only(catalog):
    bullets = [line for line in report_block(context(catalog), catalog.meta).split('\n') if line.startswith('- ')]
    assert [line.split('`')[1] for line in bullets] == [KNOWN, UNKNOWN, PADDED]


# --- drift ----------------------------------------------------------------------------------------------------------

def test_drift_lines_are_listed_escaped_after_the_timeline(catalog):
    drift = ['KEV data changed since recorded: CVE-2099-10002 was not listed on 2099-03-01 and is listed now (added '
             '2099-03-05).']
    lines = block_lines(report_block(context(catalog), catalog.meta, drift=drift))
    bullet = '- ' + escape_md(drift[0])
    assert bullet in lines and '\\:' in bullet                   # a URL-like text can never become a link
    assert lines.index(bullet) > max(i for i, line in enumerate(lines) if line.startswith('- `')) and lines[-2] == ''
    assert lines[-1] == CLOSING


def test_long_drift_sentences_are_kept_to_a_thousand_characters(catalog):
    kept = 'KEV data changed since recorded: ' + 'x' * 600
    lines = block_lines(report_block(context(catalog), catalog.meta, drift=[kept, 'y' * 2000]))
    assert '- ' + escape_md(kept, MAX_PROSE) in lines and 'x' * 600 in '\n'.join(lines)
    assert '- ' + 'y' * 997 + '\\.\\.\\.' in lines


# --- hostile text ---------------------------------------------------------------------------------------------------

def hostile_catalog():
    return parse_document(document([entry(1)], catalogVersion=HOSTILE_VERSION), name=HOSTILE_NAME)


def test_report_block_escapes_hostile_text():
    hostile = hostile_catalog()
    recorded = build_context(KevColumnProvider(hostile, at(2098, 2, 2)), ['CVE-2098-00001'], created_at=STAMP, kb=KB,
                             release_date='2098-02-01', orientation_verified=True)
    assert hostile.meta.file_name == HOSTILE_NAME and recorded.catalog_version == HOSTILE_VERSION
    text = report_block(recorded, hostile.meta, drift=HOSTILE_TEXT)
    lines = block_lines(text)
    assert '<' not in text and '>' not in text                                        # no HTML, only entities
    assert [line for line in lines if line.startswith('#')] == [HEADING]               # no injected heading
    assert all(len(re.findall(r'(?<!\\)\|', line)) == 7 for line in table_rows(text))  # six cells, whatever the text
    assert len(re.findall(r'(?<!\\)`', text)) % 2 == 0                                 # every code span is closed
    assert '](' not in text and 'www.evil.test' not in text and 'javascript:' not in text
    assert escape_md(HOSTILE_NAME) in text and escape_md(HOSTILE_VERSION) in text
    assert HOSTILE_NAME not in text and HOSTILE_VERSION not in text
    for item in HOSTILE_TEXT:
        assert '- ' + escape_md(item) in lines and '\n' not in escape_md(item)
    assert '&amp;amp;' in text                                                      # an entity in the text stays text


@pytest.mark.parametrize(('value', 'expected'), [
    ('plain words', 'plain words'), ('a|b', 'a\\|b'), ('`x`', '\\`x\\`'), ('<b>&"\'', '&lt;b&gt;&amp;&quot;&#x27;'),
    ('1. [x](y)', '1\\. \\[x\\]\\(y\\)'), ('line\nbreak\ttab', 'line break tab'), ('esc\x1b[2J', 'esc\\[2J'),
    ('bidi‮flip', 'bidiflip'), ('', ''), (None, ''), ('x' * 400, 'x' * 297 + '\\.\\.\\.')],
    ids=['plain', 'pipe', 'backtick', 'html', 'link', 'whitespace', 'escape', 'bidi', 'empty', 'none', 'long'])
def test_escape_md(value, expected):
    assert escape_md(value) == expected


MARKDOWN_SPECIALS = '\\`*_{}[]()#+-.!|~=^$@:'


@pytest.mark.parametrize('char', MARKDOWN_SPECIALS, ids=[f'u{ord(char):04x}' for char in MARKDOWN_SPECIALS])
def test_every_markdown_special_is_backslash_escaped(char):
    assert escape_md(f'a{char}b') == f'a\\{char}b'


@pytest.mark.parametrize('name', ['my catalog.json', 'a|b.json', 'a`b.json', 'café.json'],
                         ids=['space', 'pipe', 'backtick', 'non-ascii'])
def test_a_file_name_is_a_code_span_only_when_it_is_inert(name):
    named = parse_document(document([entry(1)]), name=name)
    recorded = build_context(KevColumnProvider(named, at(2098, 2, 2)), ['CVE-2098-00001'], created_at=STAMP)
    line = block_lines(report_block(recorded, named.meta))[2]
    assert f'a local file ({escape_md(name)})' in line and f'`{name}`' not in line


# --- copy -----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('now', [at(2099, 3, 2), at(2099, 3, 20), at(2099, 2, 27)], ids=['fresh', 'stale', 'future'])
def test_the_block_makes_no_banned_claim_and_stays_plain(catalog, now):
    text = report_block(context(catalog, now=now), catalog.meta, drift=['KEV data changed since recorded: x'])
    cleaned = text
    for phrase in SANCTIONED:
        cleaned = cleaned.replace(phrase, '')
    assert not BANNED.search(cleaned) and text.isascii()
    assert block_lines(text)[0] == HEADING and block_lines(text)[-1] == CLOSING
    assert 'BOD' not in text and 'federal' not in text.lower()


def test_the_block_is_deterministic(catalog):
    first, second = context(catalog), context(catalog)
    assert report_block(first, catalog.meta) == report_block(second, catalog.meta)
