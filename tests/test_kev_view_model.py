"""kev/1 view models: cell texts, detail wording, banners, filter and order, copy sweep, tooltip rules."""
from __future__ import annotations

import datetime
import json
import re
import time
from pathlib import Path

import pytest

from patchtrace.kev import teach, tooltip_entries, view_model
from patchtrace.kev.join import diff, lookup
from patchtrace.kev.parse import parse_catalog
from patchtrace.kev.ports import KevLookupPort
from patchtrace.kev.view_model import (
    KevColumnProvider,
    banner,
    delta_lines,
    detail_text,
    filter_indices,
    order_indices,
    status_line,
)
from patchtrace.tooltips import TooltipEntry, template

FIXTURES = Path(__file__).parent / 'fixtures' / 'kev'
UTC = datetime.UTC
RELEASE = datetime.datetime(2099, 3, 1, 12, 0, tzinfo=UTC)


def catalog(mutate=None, source='cisa-github'):
    data = json.loads((FIXTURES / 'kev-synthetic-2099.json').read_text(encoding='utf-8'))
    if mutate:
        mutate(data)
        data['count'] = len(data['vulnerabilities'])
    return parse_catalog(json.dumps(data).encode('utf-8'), source=source, retrieved_at='2099-03-01T13:00:00Z',
                         source_url='https://raw.githubusercontent.com/cisagov/kev-data/main/x.json',
                         final_url='https://raw.githubusercontent.com/cisagov/kev-data/main/x.json')


def at(**delta):
    return RELEASE + datetime.timedelta(**delta)


@pytest.mark.parametrize(('cve', 'state', 'text'), [
    ('CVE-2099-10001', 'listed-ransomware', 'Listed - ransomware known'),
    ('CVE-2099-10002', 'listed', 'Listed'),
    ('CVE-2099-99999', 'not-listed', 'Not listed'),
    ('not an id', 'invalid', 'Invalid CVE ID'),
], ids=['ransomware', 'listed', 'not-listed', 'invalid'])
@pytest.mark.parametrize(('delta', 'italic'), [({}, False), ({'days': 5}, False), ({'days': 40}, True),
                                               ({'days': -3}, True)], ids=['fresh', 'aging', 'stale', 'future'])
def test_cell_texts_by_state_and_freshness(cve, state, text, delta, italic):
    cell = KevColumnProvider(catalog(), at(**delta)).cell(cve)
    assert (cell.state, cell.text) == (state, text)
    assert cell.italic == (italic and state != 'invalid')
    assert cell.order_key == (0 if state.startswith('listed') else 1)
    assert cell.ransomware_known == (state == 'listed-ransomware')


def test_no_catalog_cell_and_never_a_green_check_or_percentage():
    provider = KevColumnProvider(None, at())
    assert provider.cell('CVE-2099-10001').text == 'No catalog'
    texts = [KevColumnProvider(catalog(), at()).cell(c).text for c in ('CVE-2099-99999', 'CVE-2099-10002')]
    assert not any(ch in ''.join(texts) + teach.CELL_NOT_LISTED for ch in '\u2713\u2714%')


def test_accessible_sentences():
    provider = KevColumnProvider(catalog(), at(days=1))
    assert provider.cell('CVE-2099-10001').accessible == (
        'CVE-2099-10001: listed in CISA KEV, added 2099-02-10, ransomware campaign use known to CISA. '
        'Catalog 2099.03.01.')
    assert provider.cell('CVE-2099-99999').accessible == (
        'CVE-2099-99999: not listed in CISA KEV catalog 2099.03.01, 1 day old. Not listed does not mean not exploited.')
    assert 'out of date' in KevColumnProvider(catalog(), at(days=30)).cell('CVE-2099-10002').accessible


def test_provider_implements_the_port():
    assert isinstance(KevColumnProvider(None, at()), KevLookupPort)


def test_filter_and_order_are_stable_and_complete():
    provider = KevColumnProvider(catalog(), at())
    ids = ['CVE-2099-99999', 'CVE-2099-10002', 'bogus', 'CVE-2099-10001', 'CVE-2099-88888', 'CVE-2099-10004']
    cells = [provider.cell(c) for c in ids]
    assert filter_indices(cells, 'all') == list(range(6))
    assert filter_indices(cells, 'listed') == [1, 3, 5]
    assert filter_indices(cells, 'listed-ransomware') == [3]
    assert filter_indices(cells, 'not-listed') == [0, 4]
    assert filter_indices(cells, 'no-catalog-or-invalid') == [2]
    everything = filter_indices(cells, 'all')
    assert order_indices(cells, everything, 'input') == everything
    assert order_indices(cells, everything, 'kev-first') == [1, 3, 5, 0, 2, 4]
    assert order_indices(cells, [4, 3, 0], 'kev-first') == [3, 0, 4]


def test_provider_scales_to_a_hundred_thousand_rows():
    provider = KevColumnProvider(catalog(), at())
    ids = [f'CVE-2099-{n:05}' for n in range(100_000)]
    start = time.perf_counter()
    cells = [provider.cell(c) for c in ids]
    order_indices(cells, filter_indices(cells, 'all'), 'kev-first')
    assert time.perf_counter() - start <= 6.0  # generous CI ceiling; the plan's target is far lower


def test_status_line_and_banners():
    cat = catalog()
    assert status_line(cat, at()) == ('KEV catalog 2099.03.01 - released 2099-03-01 12:00 UTC - 4 entries - '
                                      'retrieved 2099-03-01 from the CISA GitHub mirror - today')
    assert status_line(cat, at(days=1)).endswith('1 day old') and status_line(cat, at(days=9)).endswith('9 days old')
    assert banner(cat, at(days=2)) == ''
    assert banner(cat, at(days=4)) == 'This catalog is 4 days old. CVEs CISA added since then are not shown as listed.'
    assert banner(cat, at(days=15)).startswith('This catalog is 15 days old. A CVE shown as Not listed may have')
    assert banner(cat, at(days=-1)) == teach.K6_FUTURE
    assert banner(None, at()) == ''


def detail(cve, cat=None, **delta):
    cat = cat or catalog()
    [result] = lookup(cat, [cve], at(**delta))
    return detail_text(result, cat, at(**delta))


def test_detail_text_for_a_listed_cve_is_exact():
    expected = '\n'.join([
        'KEV: listed',
        "CVE-2099-10001 is in CISA's Known Exploited Vulnerabilities catalog (catalog 2099.03.01, released 2099-03-01).",
        'Added to KEV: 2099-02-10', 'CISA due date: 2099-03-03', 'Known ransomware campaign use: Known',
        '  Known: CISA reports this vulnerability has been leveraged as part of a ransomware campaign.',
        'Forensic triage required by CISA: No',
        'CISA lists this as: Example Corp Example Windows Component - Example Windows Component Elevation of '
        'Privilege Vulnerability',
        'CISA weakness list (CWE): CWE-416 (listed by CISA; not used by PatchTrace for ranking)',
        'CISA required action: Synthetic required action. Apply updates per vendor instructions.',
        'CISA notes: https://example.invalid/advisory/10001',
        '  https://example.invalid/nvd/CVE-2099-10001',
        'What this means: ' + teach.WHAT_THIS_MEANS_LISTED,
        'Source: CISA KEV catalog (CC0 1.0), retrieved 2099-03-01 from raw.githubusercontent.com, SHA-256 '
        + catalog().meta.raw_sha256 + ', parser kev-parse/1.'])
    assert detail('CVE-2099-10001') == expected


def test_detail_unknown_ransomware_never_reads_as_no():
    text = detail('CVE-2099-10002')
    assert 'Known ransomware campaign use: Unknown' in text
    assert 'This is not a statement that it has not been.' in text
    assert 'Forensic triage required by CISA: Yes' in text
    assert 'CISA weakness list (CWE): none listed' in text
    assert 'CISA notes: -' in text
    assert 'ransomware campaign use: No' not in text


def test_detail_variants():
    cat = catalog()
    not_listed = detail('CVE-2099-99999', cat, days=2)
    assert not_listed.splitlines()[0] == 'KEV: not listed'
    assert ("CVE-2099-99999 is not in CISA's Known Exploited Vulnerabilities catalog 2099.03.01 "
            '(released 2099-03-01, 2 days old).') in not_listed
    assert 'That is not evidence that the CVE is unexploited' in not_listed
    assert detail_text(lookup(None, ['CVE-2099-1000'], at())[0], None, at()) == (
        'KEV: no catalog loaded\n' + teach.NO_CATALOG_DETAIL)
    invalid = detail('\uff23\uff36\uff25')
    assert invalid == 'Invalid CVE ID\nExpected CVE-YYYY-NNNN with ASCII digits (for example CVE-2024-38063).'


def test_detail_for_a_local_import_names_no_host():
    cat = parse_catalog((FIXTURES / 'kev-synthetic-2099.json').read_bytes(), source='local-import',
                        retrieved_at='2099-03-01T13:00:00Z')
    assert 'retrieved 2099-03-01 from a local file, SHA-256' in detail('CVE-2099-10001', cat)


HOSTILE = ('<script>', '\u202e', '\x1b[31m', '\x00')


def test_hostile_strings_are_escaped_in_every_text_output():
    cat = catalog()
    text = detail('CVE-2099-10003', cat)
    assert '\u202e' not in text and '\x1b' not in text
    assert '\\u202eevil\\u202c \\x1b[31mred' in text  # shown as visible escapes, not interpreted
    assert '<script>alert(1)</script>' in text  # plain text only: nothing renders markup
    lines = text.splitlines()
    first = next(i for i, line in enumerate(lines) if line.startswith('CISA notes:'))
    assert lines[first].startswith('CISA notes: file:///C:/Windows') and lines[first + 1] == '  not a url'
    cell = KevColumnProvider(cat, at()).cell('\u202e<b>CVE')
    assert '\u202e' not in cell.cve_id + cell.accessible


def test_delta_lines():
    old = catalog()

    def change(data):
        data['vulnerabilities'].pop(3)
        data['vulnerabilities'][0]['knownRansomwareCampaignUse'] = 'Unknown'
        data['vulnerabilities'].append({**data['vulnerabilities'][1], 'cveID': 'CVE-2099-20001'})
    new = catalog(change)
    assert delta_lines(diff(old, new), new) == [
        '1 new, 1 changed, 1 removed since catalog 2099.03.01.',
        'CVE-2099-20001 added 2099-02-20 (Example Corp Example Gateway)',
        'CVE-2099-10001 changed: Known ransomware campaign use was Known, now Unknown',
        'CVE-2099-10004 removed']


def test_delta_lines_are_capped_at_two_hundred():
    old = catalog()

    def many(data):
        template_entry = data['vulnerabilities'][0]
        data['vulnerabilities'] += [{**template_entry, 'cveID': f'CVE-2098-{n:05}'} for n in range(1, 401)]
    new = catalog(many)
    lines = delta_lines(diff(old, new), new)
    assert len(lines) == 200 and lines[-1] == '202 more lines are not shown.'
    assert lines[0].startswith('400 new,')


# -- copy sweep ------------------------------------------------------------------------------------------------

BANNED = re.compile(r'\b(exploitable|vulnerable function|confirmed vulnerab\w*|weaponized|proves|is safe|fixes this)\b',
                    re.IGNORECASE)


def all_copy() -> list[str]:
    cat = catalog()
    texts = [value for name, value in vars(teach).items() if name.isupper() and isinstance(value, str)]
    texts += [text for name in ('K7_REASONS', 'ACCESSIBLE_NAMES', 'SOURCE_LABELS') for text in getattr(teach, name).values()]
    texts += [label for _, label in teach.FILTERS + teach.SORTS]
    for entry in (*tooltip_entries.KEV_TOOLTIPS.values(), *tooltip_entries.KEV_TEMPLATES.values()):
        texts += [entry.what, entry.why, entry.effect, entry.source, entry.availability]
    texts += list(tooltip_entries.COLUMN_MEANINGS.values())
    provider = KevColumnProvider(cat, at(days=20))
    for cve in ('CVE-2099-10001', 'CVE-2099-10002', 'CVE-2099-99999', 'bogus'):
        cell = provider.cell(cve)
        texts += [cell.text, cell.accessible]
        texts.append(detail(cve, cat, days=20))
    texts += [banner(cat, at(days=d)) for d in (5, 20, -1)] + [status_line(cat, at())]
    return texts


def test_copy_has_no_banned_claims():
    sanctioned = re.compile('|'.join(re.escape(s) for s in teach.SANCTIONED_NEGATIONS))
    texts = all_copy()
    assert len(texts) > 100
    for text in texts:
        assert not BANNED.search(sanctioned.sub('', text)), text
    joined = ' '.join(texts)
    for phrase in ('does not mean not exploited', 'not endorsed by CISA or DHS', 'It does not locate the fix in code'):
        assert phrase in joined


def test_copy_has_no_score_words_or_percentages():
    for text in all_copy():
        assert not re.search(r'\bscore\b', text.replace('not a score', '').replace('(reading order, not a score)', '')), text
        assert '%' not in text and '\u2713' not in text, text


# -- tooltips --------------------------------------------------------------------------------------------------

def test_tooltip_entries_follow_registry_rules():
    registry = tooltip_entries.KEV_TOOLTIPS
    assert len(registry) == 18
    rendered, whats = {}, set()
    for key, entry in registry.items():
        assert isinstance(entry, TooltipEntry) and key.startswith('kev.')
        text = entry.render()
        assert entry.what and entry.why and entry.effect, key
        assert text.startswith('What: ') and '<' not in text and '>' not in text, key
        assert text not in rendered and entry.what not in whats, key
        rendered[text] = key
        whats.add(entry.what)
    for key in ('kev.update', 'kev.changes', 'kev.lookup_box', 'kev.lookup_button', 'kev.goto'):
        assert registry[key].availability, key
    for key in ('kev.dock', 'kev.table', 'kev.detail', 'kev.copy', 'kev.changes'):
        assert registry[key].source == tooltip_entries.SOURCE == 'CISA KEV catalog, CC0 1.0'


def test_tooltip_ids_do_not_collide_with_the_main_registry():
    from patchtrace import tooltips
    assert not set(tooltip_entries.KEV_TOOLTIPS) & set(tooltips.REGISTRY)
    assert not set(tooltip_entries.KEV_TEMPLATES) & set(tooltips.TEMPLATES)
    assert set(tooltip_entries.KEV_TEMPLATES) == {'kev.cell', 'kev.badge', 'kev.column', 'kev.row_header'}


def test_kev_templates_fill_and_escape_untrusted_values(monkeypatch):
    from patchtrace import tooltips
    monkeypatch.setitem(tooltips.TEMPLATES, 'kev.cell', tooltip_entries.KEV_TEMPLATES['kev.cell'])
    cell = KevColumnProvider(catalog(), at()).cell('CVE-2099-10001')
    html = template('kev.cell', **cell.tooltip_values())
    assert 'CVE-2099-10001' in html and 'Listed - ransomware known' in html and '2099.03.01' in html
    hostile = template('kev.cell', cve='<img src=x onerror=1>', state='x', version='v', meaning='m')
    assert '<img' not in hostile and '&lt;img' in hostile


def test_every_column_meaning_is_neutral_about_dates():
    assert set(tooltip_entries.COLUMN_MEANINGS) == {'KEV', 'Added to KEV', 'CISA due date',
                                                    'Known ransomware campaign use'}
    assert 'not the date exploitation began' in tooltip_entries.COLUMN_MEANINGS['Added to KEV']
    assert 'not a severity rating' in tooltip_entries.COLUMN_MEANINGS['CISA due date']
    assert view_model.age_phrase(None) == 'age unknown'
