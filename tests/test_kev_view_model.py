"""kev/1 view model: cell texts, filters and reading order, detail text, state copy, teach hooks, tooltip entries.

The reading order is a stable partition and never a score; every string that reaches a person is swept for claims the
data cannot support (plan section 6).
"""
from __future__ import annotations

import re
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
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

from patchtrace import tooltips
from patchtrace.kev import limits, teach, tooltip_entries, view_model
from patchtrace.kev.contracts import ConsentRecord, KevLookup, plan_for
from patchtrace.kev.join import diff, lookup
from patchtrace.kev.parse import parse_catalog
from patchtrace.kev.view_model import (
    FILTER_ITEMS,
    SORT_ITEMS,
    KevCell,
    KevColumnProvider,
    changes_lines,
    detail_text,
    filter_indices,
    order_indices,
)

FAST = settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)
LISTED_KNOWN, NOT_LISTED, LISTED_UNKNOWN, DECOY, PADDED = ('CVE-2099-10001', 'CVE-2099-10002', 'CVE-2099-10004',
                                                           'CVE-2099-10009', 'CVE-2099-10010')
CATALOG = '2099.03.01'


@pytest.fixture(scope='module')
def catalog():
    return parse_fixture(SYNTHETIC)


def provider(catalog, now=NOW):
    return KevColumnProvider(catalog, now)


# --- cells: text by state, sentence by freshness ------------------------------------------------------------

def test_cell_texts_by_state_and_freshness(catalog):
    by_age = {'fresh': at(2099, 3, 2), 'aging': at(2099, 3, 10), 'stale': at(2099, 3, 20), 'future': at(2099, 2, 27)}
    clause = {'fresh': '', 'aging': ' The catalog is 9 days old.',
              'stale': ' The catalog is 19 days old and may lack newer entries.',
              'future': " The catalog's release time is in the future; treat as unverified."}
    for freshness, now in by_age.items():
        cells = provider(catalog, now)
        known, plain, absent = cells.cell(LISTED_KNOWN), cells.cell(LISTED_UNKNOWN), cells.cell(NOT_LISTED)
        assert (known.text, plain.text, absent.text) == ('Listed - ransomware known', 'Listed', 'Not listed')
        assert known.accessible == (f'CVE-2099-10001: listed in CISA KEV, added 2099-02-10, ransomware campaign use '
                                    f'known to CISA. Catalog {CATALOG}.{clause[freshness]}')
        assert plain.accessible == (f'CVE-2099-10004: listed in CISA KEV, added 2099-02-20. Catalog {CATALOG}.'
                                    f'{clause[freshness]}')
        assert absent.accessible == (f'CVE-2099-10002: not listed in CISA KEV catalog {CATALOG}. Not listed does not '
                                     f'mean not exploited.{clause[freshness]}')
        assert all(cell.italic == (freshness in ('stale', 'future')) for cell in (known, plain, absent)), freshness
        assert (known.order_key, plain.order_key, absent.order_key) == (0, 0, 1)
        assert (known.ransomware_known, plain.ransomware_known, absent.ransomware_known) == (True, False, False)


def test_cells_without_a_catalog_or_with_a_bad_id(catalog):
    nothing = KevColumnProvider(None, NOW)
    cell = nothing.cell(LISTED_KNOWN)
    assert (cell.state, cell.text, cell.order_key, cell.italic) == ('no-catalog', 'No catalog', 1, False)
    assert cell.accessible == 'CVE-2099-10001: no KEV catalog is loaded.'
    bad = provider(catalog).cell('CVE-２０９９-10001')
    assert (bad.state, bad.text, bad.order_key) == ('invalid-id', 'Invalid CVE ID', 1)
    assert bad.accessible == 'Invalid CVE ID CVE-２０９９-10001. Expected CVE-YYYY-NNNN with ASCII digits.'
    assert nothing.cell('nonsense').state == 'invalid-id'                     # an ID problem outranks "no catalog"


def test_no_cell_ever_says_no_for_a_ransomware_unknown(catalog):
    texts = {provider(catalog).cell(cve).text for cve in (LISTED_KNOWN, LISTED_UNKNOWN, NOT_LISTED, DECOY, PADDED)}
    assert texts == {'Listed - ransomware known', 'Listed', 'Not listed'}
    assert 'No' not in {text.split()[-1] for text in texts}


def test_cell_echo_of_a_hostile_id_is_clean():
    cell = provider(parse_fixture(SYNTHETIC)).cell('x\x1b[31m‮evil\n' + 'y' * 200)
    assert cell.state == 'invalid-id' and '\x1b' not in cell.accessible and '‮' not in cell.accessible
    assert '\n' not in cell.accessible and len(cell.accessible) < 160


def test_cell_tooltip_values_are_plain_strings(catalog):
    cell = provider(catalog).cell(LISTED_KNOWN)
    assert cell.tooltip_values() == {'cve': LISTED_KNOWN, 'state': 'Listed - ransomware known', 'version': CATALOG,
                                     'meaning': 'CISA lists this CVE as a known exploited vulnerability.'}
    assert KevColumnProvider(None, NOW).cell(LISTED_KNOWN).tooltip_values()['version'] == 'none'


def test_provider_memoizes_cells_and_agrees_with_the_join(catalog):
    cells = provider(catalog)
    assert cells.cell(LISTED_KNOWN) is cells.cell(LISTED_KNOWN)
    for cve in (LISTED_KNOWN, NOT_LISTED, 'bad'):
        assert cells.lookup(cve) == lookup(catalog, [cve], NOW)[0]
    assert cells.meta is catalog.meta and (cells.freshness, cells.age_days) == ('fresh', 1)
    assert KevColumnProvider(None, NOW).meta is None and KevColumnProvider(None, NOW).freshness == 'unknown'


def test_a_hundred_thousand_provider_calls_stay_within_the_budget(catalog):
    cells = provider(catalog)
    ids = [f'CVE-2099-{n % 3000:05d}' for n in range(100_000)]
    started = time.perf_counter()
    rows = [cells.cell(cve) for cve in ids]
    elapsed = time.perf_counter() - started
    assert len(rows) == 100_000 and elapsed < 1.5, f'{elapsed:.3f}s'


# --- filter and reading order: a stable partition, never a score --------------------------------------------

def sample_cells(catalog):
    cells = provider(catalog)
    return [cells.cell(cve) for cve in (LISTED_KNOWN, NOT_LISTED, LISTED_UNKNOWN, 'bad', DECOY)]


def test_kev_first_puts_listed_cves_first_and_keeps_the_input_order_in_each_group(catalog):
    cells = sample_cells(catalog)
    assert order_indices(cells, 'input') == [0, 1, 2, 3, 4]
    assert order_indices(cells, 'kev-first') == [0, 2, 4, 1, 3]
    assert [cells[i].cve for i in order_indices(cells, 'kev-first')][:2] == [LISTED_KNOWN, LISTED_UNKNOWN]
    assert order_indices(cells, 'kev-first', [3, 1, 4, 0]) == [4, 0, 3, 1]       # an index subset keeps its own order


def test_the_synergy_worklist_order_of_the_plan(catalog):
    cells = provider(catalog)
    section = [cells.cell(cve) for cve in (LISTED_KNOWN, NOT_LISTED, LISTED_UNKNOWN)]
    assert [section[i].cve for i in order_indices(section, 'input')] == [LISTED_KNOWN, NOT_LISTED, LISTED_UNKNOWN]
    assert [section[i].cve for i in order_indices(section, 'kev-first')] == [LISTED_KNOWN, LISTED_UNKNOWN, NOT_LISTED]


@pytest.mark.parametrize(('mode', 'expected'), [
    ('all', [0, 1, 2, 3, 4]), ('listed', [0, 2, 4]), ('listed-ransomware', [0]), ('not-listed', [1]),
    ('no-catalog-or-invalid', [3])], ids=['all', 'listed', 'listed-ransomware', 'not-listed', 'unknown-status'])
def test_filter_indices(catalog, mode, expected):
    assert filter_indices(sample_cells(catalog), mode) == expected


def test_filter_and_order_reject_unknown_modes_and_expose_their_labels(catalog):
    with pytest.raises(ValueError, match='filter'):
        filter_indices(sample_cells(catalog), 'risky')
    with pytest.raises(ValueError, match='order'):
        order_indices(sample_cells(catalog), 'by-score')
    assert [label for _, label in FILTER_ITEMS] == ['All CVEs', 'Listed in KEV', 'Listed, ransomware use known',
                                                    'Not listed', 'No catalog or invalid ID']
    assert [label for _, label in SORT_ITEMS] == ['Input order', 'KEV-listed first (reading order, not a score)']
    assert [mode for mode, _ in SORT_ITEMS] == ['input', 'kev-first']


@given(st.lists(st.sampled_from([LISTED_KNOWN, NOT_LISTED, LISTED_UNKNOWN, 'bad', DECOY, PADDED]), max_size=40))
@FAST
def test_kev_first_is_a_stable_partition_property(cves):
    cells = [provider(parse_fixture(SYNTHETIC)).cell(cve) for cve in cves]
    order = order_indices(cells, 'kev-first')
    assert sorted(order) == list(range(len(cells)))                              # a permutation, nothing lost
    listed = [i for i in order if cells[i].order_key == 0]
    other = [i for i in order if cells[i].order_key == 1]
    assert order == listed + other and listed == sorted(listed) and other == sorted(other)


# --- detail text --------------------------------------------------------------------------------------------

def test_detail_of_a_listed_cve_in_cisas_own_words(catalog):
    row = lookup(catalog, [LISTED_KNOWN], NOW)[0]
    meta = catalog.meta
    assert detail_text(row, meta) == '\n'.join([
        'KEV: listed',
        f"{LISTED_KNOWN} is in CISA's Known Exploited Vulnerabilities catalog (catalog {CATALOG}, "
        'released 2099-03-01).',
        'Added to KEV: 2099-02-10',
        'CISA due date: 2099-02-13',
        'Known ransomware campaign use: Known',
        '  Known: CISA reports this vulnerability has been leveraged as part of a ransomware campaign.',
        'Forensic triage required by CISA: Yes',
        'CISA lists this as: Microsoft Windows - Microsoft Windows Synthetic Heap Buffer Overflow Vulnerability',
        'CISA weakness list (CWE): CWE-787 (listed by CISA; not used by PatchTrace for ranking)',
        'CISA required action: SYNTHETIC: no action, this entry is test data.',
        'CISA notes:',
        '  https://example.invalid/advisory/CVE-2099-10001',
        '  https://example.invalid/vendor/microsoft',
        'What this means: CISA lists this CVE as a known exploited vulnerability. It does not say which builds, KBs, '
        'files or functions were involved, and it does not show that any function changed in your comparison relates '
        'to this CVE.',
        f'Source: CISA KEV catalog (CC0 1.0), retrieved 2099-03-02 from a local file ({SYNTHETIC}), '
        f'SHA-256 {meta.raw_sha256}, parser kev-parse/1.'])


def test_detail_explains_unknown_ransomware_use_without_calling_it_no(catalog):
    text = detail_text(lookup(catalog, [LISTED_UNKNOWN], NOW)[0], catalog.meta)
    assert ('Known ransomware campaign use: Unknown\n  Unknown: CISA lacks confirmation that this vulnerability has '
            'been utilized for ransomware. This is not a statement that it has not been.\n') in text
    assert 'Known ransomware campaign use: No' not in text and 'Forensic triage required by CISA: No\n' in text


def test_detail_marks_absent_optional_fields_as_not_provided(catalog):
    text = detail_text(lookup(catalog, [PADDED], NOW)[0], catalog.meta)
    assert 'Known ransomware campaign use: not provided in this catalog\n' in text
    assert 'Forensic triage required by CISA: not provided in this catalog\n' in text
    assert 'CISA weakness list (CWE): none listed\n' in text and 'CISA notes' not in text
    assert 'CISA lists this as: Example Networks Router - Example Networks Router Synthetic' in text


def test_detail_marks_unrecognized_values(catalog):
    changed = parse_document(mutated(fixture_document(SYNTHETIC), ('vulnerabilities', 3, 'forensicTriage'), 'Maybe'))
    text = detail_text(lookup(changed, [LISTED_KNOWN], NOW)[0], changed.meta)
    assert 'Forensic triage required by CISA: value not recognized by PatchTrace\n' in text


def test_detail_of_a_cve_that_is_not_listed(catalog):
    text = detail_text(lookup(catalog, [NOT_LISTED], at(2099, 3, 4))[0], catalog.meta)
    assert text.splitlines()[:3] == [
        'KEV: not listed',
        f"{NOT_LISTED} is not in CISA's Known Exploited Vulnerabilities catalog {CATALOG} (released 2099-03-01, "
        f'3 days old).',
        'What this means: this snapshot does not list the CVE. That is not evidence that the CVE is unexploited: CISA '
        'lists only entries that meet its own requirements, and the catalog may have changed since this snapshot.']
    assert text.splitlines()[3].startswith('Source: CISA KEV catalog (CC0 1.0), retrieved 2099-03-02')
    assert 'Added to KEV' not in text and len(text.splitlines()) == 4


def test_detail_without_a_catalog_and_with_a_bad_id(catalog):
    nothing = detail_text(lookup(None, [LISTED_KNOWN], NOW)[0], None)
    assert nothing == ('KEV: no catalog loaded\nNothing can be said about this CVE until a catalog is loaded. Use '
                       'Update from CISA... or Import file...')
    bad = detail_text(lookup(catalog, ['CVE-２０９９-10001'], NOW)[0], catalog.meta)
    assert bad == ('Invalid CVE ID\nExpected CVE-YYYY-NNNN with ASCII digits (for example CVE-2024-38063).')


def test_detail_of_a_future_catalog_asks_for_a_clock_check(catalog):
    text = detail_text(lookup(catalog, [LISTED_KNOWN], at(2099, 2, 27))[0], catalog.meta)
    assert "The catalog's release time is in the future. Check this computer's clock and treat results as " \
           'unverified.' in text.splitlines()


def test_detail_of_a_fetched_catalog_names_the_host_not_a_file(catalog):
    plan = plan_for('cisa-github')
    consent = ConsentRecord(operation='fetch-kev-catalog', source='cisa-github', url=plan.url, plan_sha=plan.plan_sha,
                            granted_at='2099-03-02T07:59:00Z', surface='cli')
    fetched = parse_catalog(fixture_bytes(SYNTHETIC), source='cisa-github', retrieved_at='2099-03-02T08:00:00Z',
                            source_url=plan.url, final_url=plan.url, consent=consent)
    text = detail_text(lookup(fetched, [LISTED_KNOWN], NOW)[0], fetched.meta)
    assert 'retrieved 2099-03-02 from raw.githubusercontent.com, SHA-256 ' in text.splitlines()[-1]


def test_detail_of_a_slim_entry_leaves_out_the_long_texts(catalog):
    full = lookup(catalog, [LISTED_KNOWN], NOW)[0]
    slim = KevLookup(**{**full.model_dump(exclude={'contract'}), 'entry': full.entry.slim()})
    text = detail_text(slim, catalog.meta)
    assert 'CISA required action' not in text and 'CISA notes' not in text and 'Added to KEV: 2099-02-10' in text


def test_notes_are_one_segment_per_line_capped_and_never_markup():
    segments = ';'.join(f'<b>segment {n}</b>' for n in range(30))
    catalog = parse_document(document([entry(1, notes=segments + ' ; ' + 'z' * 10)]))
    row = lookup(catalog, ['CVE-2098-00001'], at(2098, 2, 2))[0]
    lines = detail_text(row, catalog.meta).splitlines()
    start = lines.index('CISA notes:')
    shown = [line for line in lines[start + 1:] if line.startswith('  ')]
    assert len(shown) == limits.MAX_NOTE_LINES + 1 and shown[-1] == '  ... and 11 more segments not shown.'
    assert shown[0] == '  <b>segment 0</b>'                                  # plain text: shown verbatim, never parsed


def test_hostile_text_cannot_forge_a_line_or_an_escape(catalog):
    hostile = entry(1, vulnerabilityName='Name\nSource: forged', shortDescription='x', requiredAction='Do this\r\n'
                    'What this means: it is safe\x1b[2J', notes='a KEV: not listed', product='P‮P')
    changed = parse_document(document([hostile]))
    text = detail_text(lookup(changed, ['CVE-2098-00001'], at(2098, 2, 2))[0], changed.meta)
    lines = text.splitlines()
    assert sum(line.startswith('Source:') for line in lines) == 1
    assert sum(line.startswith('KEV:') for line in lines) == 1
    assert sum(line.startswith('What this means:') for line in lines) == 1
    assert '\x1b' not in text and '‮' not in text and ' ' not in text and '\r' not in text


# --- summary, status, banners, changes ----------------------------------------------------------------------

def test_summary_line_counts_listed_cves_without_a_percentage(catalog):
    cells = provider(catalog)
    assert cells.summary_line([LISTED_KNOWN, NOT_LISTED, LISTED_UNKNOWN]) == (
        f'2 of 3 CVEs in this KB are listed in CISA KEV (catalog {CATALOG}, 1 day old). Not listed does not mean not '
        f'exploited.')
    assert cells.summary_line([NOT_LISTED, NOT_LISTED, 'bad']) == (
        f'0 of 1 CVEs in this KB are listed in CISA KEV (catalog {CATALOG}, 1 day old). Not listed does not mean not '
        f'exploited.')
    assert provider(catalog, at(2099, 3, 1, 20)).summary_line([DECOY]).endswith(
        f'(catalog {CATALOG}, today). Not listed does not mean not exploited.')
    assert cells.summary_line([]) is None and cells.summary_line(['bad']) is None
    assert KevColumnProvider(None, NOW).summary_line([LISTED_KNOWN]) is None


def test_status_line_and_banners(catalog):
    provider_ = provider(catalog)
    assert view_model.status_line(catalog.meta, 'fresh', 1) == (
        f'KEV catalog {CATALOG} - released 2099-03-01 18:00:00 UTC - 4 entries - retrieved 2099-03-02 from a local '
        f'file - 1 day old')
    assert view_model.status_line(catalog.meta, 'fresh', 0).endswith('- today')
    assert view_model.status_line(catalog.meta, 'stale', 40).endswith('- 40 days old')
    assert view_model.status_line(catalog.meta, 'future', -2).endswith('- release time in the future')
    assert view_model.banner_text('fresh', 2) is None and view_model.banner_text('unknown', 0) is None
    assert view_model.banner_text('aging', 9) == (
        'This catalog is 9 days old. CVEs CISA added since then are not shown as listed.')
    assert view_model.banner_text('stale', 19) == (
        'This catalog is 19 days old. A CVE shown as Not listed may have been added since. Update from CISA... or '
        'import a newer file.')
    assert view_model.banner_text('future', -2) == (
        "The catalog's release time is in the future. Check this computer's clock and treat results as unverified.")
    assert provider_.meta is catalog.meta


def test_changes_lines_report_added_changed_and_removed(catalog):
    base = fixture_document(SYNTHETIC)
    new = mutated(base, ('vulnerabilities', 1, 'knownRansomwareCampaignUse'), 'Known')
    new = mutated(new, ('vulnerabilities', 0, 'forensicTriage'), 'Yes')
    del new['vulnerabilities'][2]
    new['vulnerabilities'].insert(0, entry(11, cveID='CVE-2099-10011', dateAdded='2099-02-28', dueDate='2099-03-14',
                                           vendorProject='Example Vendor', product='Example Product'))
    new['count'] = len(new['vulnerabilities'])
    newer = parse_document(new)
    lines = changes_lines(diff(catalog, newer), newer, CATALOG)
    assert lines == (
        f'1 new, 2 changed, 1 removed since catalog {CATALOG}.',
        'CVE-2099-10011 added 2099-02-28 (Example Vendor Example Product)',
        'CVE-2099-10004 changed: Known ransomware campaign use was Unknown, now Known',
        'CVE-2099-10010 changed: Forensic triage required by CISA was not provided in this catalog, now Yes',
        'CVE-2099-10009 is no longer listed')


def test_changes_lines_are_capped_with_an_honest_remainder(catalog):
    grown = fixture_document(SYNTHETIC)
    grown['vulnerabilities'] += [entry(n, cveID=f'CVE-2099-{30000 + n}', dateAdded='2099-02-20', dueDate='2099-03-30')
                                 for n in range(1, 301)]
    grown['count'] = len(grown['vulnerabilities'])
    newer = parse_document(grown)
    lines = changes_lines(diff(catalog, newer), newer, CATALOG)
    assert len(lines) == limits.MAX_CHANGE_LINES and lines[0].startswith('300 new, 0 changed, 0 removed since')
    assert lines[-1] == '... and 102 more not shown.'


def test_changes_lines_when_nothing_changed(catalog):
    assert changes_lines(diff(catalog, catalog), catalog, CATALOG) == (
        f'0 new, 0 changed, 0 removed since catalog {CATALOG}.',)


# --- GUI state copy -----------------------------------------------------------------------------------------

def test_state_copy_matches_the_plan():
    text = view_model.STATE_TEXT
    assert text['no-catalog'] == (
        'No KEV catalog is loaded. PatchTrace works without it. Update from CISA... downloads about 1.8 MB after you '
        'confirm the exact request. Import file... reads a KEV JSON file you saved yourself '
        '(known_exploited_vulnerabilities.json).')
    assert text['blocked'] == 'Network updates are switched off here. Import file... still works.'
    assert text['loading'] == 'Loading the KEV catalog from this computer...'
    assert text['checking'] == 'Checking the downloaded file...'
    assert text['empty-list'] == 'Type or paste CVE IDs above, or open a KB or CVE view that passes its CVEs here.'
    assert view_model.FOOTER == ('KEV is context about a CVE. It does not locate the fix in code. Data: CISA Known '
                                 'Exploited Vulnerabilities catalog (CC0 1.0); not endorsed by CISA or DHS.')


def test_consent_copy_shows_the_exact_request_and_what_leaves_the_computer():
    plan = plan_for('cisa-github')
    lines = view_model.consent_lines(plan)
    assert lines[0] == 'Download the KEV catalog from CISA?'
    assert lines[1] == f'Request: GET {plan.url}'
    assert lines[2] == ('Sent: only this address and the headers Accept: application/json and User-Agent: PatchTrace. '
                        'No project data and no CVE IDs. Environment proxies are ignored.')
    assert lines[3] == ('Received: one JSON file, about 1.8 MB (limit 16 MiB). It is saved on this computer and '
                        'checked before it replaces the catalog in use.')
    assert view_model.SOURCE_CHOICES == {
        'cisa-site': 'CISA website (www.cisa.gov)',
        'cisa-github': "CISA GitHub mirror (raw.githubusercontent.com): CISA's own copy, synchronized within minutes."}


def test_progress_and_error_copy():
    assert view_model.downloading_text('www.cisa.gov', 0.4, 1.8) == (
        'Downloading from www.cisa.gov... 0.4 of about 1.8 MB')
    assert view_model.mirror_older_text('2026.10.06', '2026.10.13') == (
        'The downloaded catalog (2026.10.06) is older than the one in use (2026.10.13); the newer one was kept.')
    kept = view_model.kept_text('2026.10.13', '2026-10-14')
    assert kept == 'The catalog 2026.10.13 from 2026-10-14 is still in use.'
    assert view_model.kept_text(None, None) == 'No catalog is loaded.'
    assert view_model.error_text('network', kept) == (
        'Could not update the KEV catalog: the connection failed or timed out. The catalog 2026.10.13 from 2026-10-14 '
        'is still in use.')
    assert view_model.error_text('http', 'No catalog is loaded.', status=503) == (
        'Could not update the KEV catalog: the server answered HTTP 503. No catalog is loaded.')
    assert view_model.error_text('shrink', kept, n=300).startswith(
        'Could not update the KEV catalog: the new catalog has 300 fewer entries than the one in use.')
    assert 'the file failed checks (dueDate)' in view_model.error_text('checks', kept, check='dueDate')
    with pytest.raises(KeyError):
        view_model.error_text('weather', kept)


# --- the claims sweep: everything a person can read ---------------------------------------------------------

BANNED = re.compile(r'\b(exploitable|vulnerable function|confirmed vulnerab\w*|weaponi[sz]ed|proves?|is safe|fixes this'
                    r'|risk|probab\w*|likelihood)\b|%', re.IGNORECASE)
SANCTIONED = ('does not mean not exploited', 'has not been shown to be unexploited')


def all_copy(catalog) -> list[str]:
    texts = list(view_model.STATE_TEXT.values()) + [view_model.FOOTER, *view_model.STATE_MEANING.values()]
    texts += list(view_model.COLUMN_MEANING.values()) + [label for _, label in FILTER_ITEMS + SORT_ITEMS]
    texts += [*view_model.consent_lines(plan_for('cisa-site')), *view_model.SOURCE_CHOICES.values()]
    for now in (at(2099, 3, 1, 20), at(2099, 3, 2), at(2099, 3, 10), at(2099, 3, 20), at(2099, 2, 27)):
        provider_ = provider(catalog, now)
        for cve in (LISTED_KNOWN, LISTED_UNKNOWN, NOT_LISTED, PADDED, 'bad'):
            cell = provider_.cell(cve)
            texts += [cell.text, cell.accessible, cell.meaning, detail_text(provider_.lookup(cve), catalog.meta)]
        texts += [provider_.summary_line([LISTED_KNOWN, NOT_LISTED]) or '',
                  view_model.banner_text(provider_.freshness, provider_.age_days) or '',
                  view_model.status_line(catalog.meta, provider_.freshness, provider_.age_days)]
    nothing = KevColumnProvider(None, NOW)
    texts += [nothing.cell(LISTED_KNOWN).accessible, detail_text(nothing.lookup(LISTED_KNOWN), None)]
    texts += [view_model.error_text(reason, 'No catalog is loaded.', status=500, n=3, check='count')
              for reason in view_model.ERROR_REASONS]
    texts += [view_model.downloading_text('www.cisa.gov', 1.0, 1.8), view_model.mirror_older_text('a', 'b')]
    for hook in teach.TEACH_HOOKS:
        texts += [hook.meaning, hook.next_step]
    for entry_ in (*tooltip_entries.KEV_TOOLTIPS.values(), *tooltip_entries.KEV_TEMPLATES.values()):
        texts += entry_.lines()
    return texts


def test_copy_has_no_banned_claims(catalog):
    texts = all_copy(catalog)
    assert len(texts) > 150
    for text in texts:
        cleaned = text
        for phrase in SANCTIONED:
            cleaned = cleaned.replace(phrase, '')
        assert not BANNED.search(cleaned), text


def test_the_sweep_would_catch_a_claim():
    assert BANNED.search('this function is exploitable') and BANNED.search('Confirmed vulnerable function')
    assert BANNED.search('proves the fix') and BANNED.search('about 40%') and BANNED.search('high risk')
    assert not BANNED.search('Not listed does not mean not exploited.'.replace(SANCTIONED[0], ''))


def test_no_kev_copy_names_a_directive(catalog):
    joined = '\n'.join(all_copy(catalog))
    assert 'BOD' not in joined and 'federal' not in joined.lower() and 'DHS' in view_model.FOOTER


# --- teach hooks (data only) --------------------------------------------------------------------------------

def test_teach_hooks_carry_the_plan_wording_and_point_at_real_tooltips():
    hooks = {hook.id: hook for hook in teach.TEACH_HOOKS}
    assert set(hooks) == {'kev.listed', 'kev.not-listed', 'kev.no-catalog', 'kev.stale', 'kev.no-detector'}
    assert hooks['kev.listed'].meaning == 'CISA lists this CVE as a known exploited vulnerability.'
    assert hooks['kev.listed'].next_step == (
        'Open its expected patch changes and candidate functions; KEV does not say where the fix is.')
    assert hooks['kev.not-listed'].meaning == 'Not in this catalog snapshot; that is not evidence of safety.'
    assert hooks['kev.no-catalog'].next_step == 'Update from CISA or import a file if you want exploitation context.'
    assert hooks['kev.stale'].next_step == 'Refresh before relying on Not listed.'
    assert hooks['kev.no-detector'].next_step == ('An empty candidate list is unknown; read the changed functions '
                                                  'yourself.')
    known = set(tooltip_entries.KEV_TOOLTIPS) | set(tooltip_entries.KEV_TEMPLATES)
    assert all(hook.tooltip_id in known for hook in hooks.values())
    assert all(len(hook.meaning) <= 300 and len(hook.next_step) <= 200 for hook in hooks.values())


# --- tooltip entries: the registry rules --------------------------------------------------------------------

STATIC_IDS = {'kev.action', 'kev.dock', 'kev.update', 'kev.import', 'kev.consent_download', 'kev.consent_cancel',
              'kev.source_cisa', 'kev.source_mirror', 'kev.changes', 'kev.copy', 'kev.copy_url', 'kev.lookup_box',
              'kev.lookup_button', 'kev.filter', 'kev.sort', 'kev.table', 'kev.detail', 'kev.goto'}
TEMPLATE_IDS = {'kev.cell', 'kev.badge', 'kev.column', 'kev.row_header'}
DATA_BEARING = {'kev.dock', 'kev.changes', 'kev.copy', 'kev.table', 'kev.detail', 'kev.cell', 'kev.badge',
                'kev.column', 'kev.row_header'}
CONDITIONAL = {'kev.update', 'kev.changes', 'kev.lookup_box', 'kev.lookup_button', 'kev.goto'}
SOURCE = 'CISA KEV catalog, CC0 1.0'


def test_tooltip_entries_follow_registry_rules():
    own, templates = tooltip_entries.KEV_TOOLTIPS, tooltip_entries.KEV_TEMPLATES
    assert set(own) == STATIC_IDS and set(templates) == TEMPLATE_IDS
    # the KEV panel registers these same entries globally once any test builds it, so compare against everything else
    mine = {**own, **templates}
    others = {key: entry_ for key, entry_ in {**tooltips.REGISTRY, **tooltips.TEMPLATES}.items()
              if mine.get(key) != entry_}
    assert not set(mine) & set(others)
    rendered, whats = {}, {entry_.what for key, entry_ in tooltips.REGISTRY.items() if key not in mine}
    existing = {entry_.render() for key, entry_ in tooltips.REGISTRY.items() if key not in mine}
    for key, entry_ in (*own.items(), *templates.items()):
        assert isinstance(entry_, tooltips.TooltipEntry), key
        assert entry_.what and entry_.why and entry_.effect, key
        text = entry_.render()
        assert text.startswith('What: ') and '<' not in text and '>' not in text, key
        assert text not in existing and text not in rendered, f'{key} duplicates {rendered.get(text)}'
        assert entry_.what not in whats, f'{key} repeats a What'
        rendered[text], whats = key, whats | {entry_.what}
        assert entry_.why.endswith('.') and '. ' not in entry_.why, f'{key}: Why is one sentence'
        assert len(text) >= 25, key
        if key in own:
            assert '{' not in text and '}' not in text, key
    for key in DATA_BEARING:
        assert (own.get(key) or templates[key]).source.endswith(SOURCE), key
    for key in CONDITIONAL:
        assert own[key].availability, key
    assert all(not own[key].availability for key in set(own) - CONDITIONAL)


def test_tooltip_templates_fill_from_escaped_values(monkeypatch):
    monkeypatch.setattr(tooltips, 'REGISTRY', {**tooltips.REGISTRY, **tooltip_entries.KEV_TOOLTIPS})
    monkeypatch.setattr(tooltips, 'TEMPLATES', {**tooltips.TEMPLATES, **tooltip_entries.KEV_TEMPLATES})
    values = {'cve': 'CVE-2099-10001', 'state': 'Listed', 'version': '2099.03.01', 'meaning': 'It means <b>x</b>.'}
    for key in TEMPLATE_IDS:
        plain = tooltips.template_description(key, **values)
        assert '{' not in plain and plain.startswith('What: '), key
        rich = tooltips.template(key, **values)
        assert '<b>' not in rich.replace('<p style="white-space:pre-wrap">', '')
        if key in ('kev.badge', 'kev.column'):                     # the templates that show the meaning text
            assert '&lt;b&gt;' in rich, key
    assert tooltips.tooltip('kev.dock').startswith('<p style="white-space:pre-wrap">What: Context from CISA')
    assert 'Ctrl+Shift+X' in tooltips.plain_description('kev.action')


def test_kev_cell_is_a_small_immutable_value(catalog):
    cell = provider(catalog).cell(LISTED_KNOWN)
    assert isinstance(cell, KevCell) and not hasattr(cell, '__dict__')
    with pytest.raises(AttributeError):
        cell.text = 'changed'
