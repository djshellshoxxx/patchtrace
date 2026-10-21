"""QA-S2 KEV catalogue: a 20k-entry synthetic catalogue (scale knob PATCHTRACE_STRESS_SCALE caps it at the 20,000
entry limit), the 50k refusal, duplicate and malformed rows, and 5,000-ID lookups over hostile text. Synthetic only.
"""
from __future__ import annotations

import json
import os
import random
import sys
import time
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kev_helpers import NOW, document, entry, mutated, parse_bytes, render  # noqa: E402

from patchtrace.kev import limits  # noqa: E402
from patchtrace.kev.contracts import KevError  # noqa: E402
from patchtrace.kev.join import diff, lookup, split_cve_ids  # noqa: E402
from patchtrace.kev.parse import parse_catalog  # noqa: E402

SCALE = int(os.environ.get('PATCHTRACE_STRESS_SCALE', '1'))
SIZE = min(limits.MAX_ENTRIES, 20_000 * SCALE)
SETTINGS = settings(max_examples=60, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow])


@pytest.fixture(scope='module')
def big_catalog():
    rows = [entry(number) for number in range(1, SIZE + 1)]
    return parse_bytes(render(document(rows)))


def test_large_catalogue_parses_within_budget_and_indexes_every_entry():
    rows = [entry(number) for number in range(1, SIZE + 1)]
    raw = render(document(rows))
    started = time.monotonic()
    catalog = parse_bytes(raw)
    elapsed = time.monotonic() - started
    assert catalog.meta.entry_count == len(catalog.entries) == len(catalog.by_cve) == SIZE
    assert [item.cve_id for item in catalog.entries] == sorted(item.cve_id for item in catalog.entries)
    assert elapsed < 20


def test_catalogue_over_the_raw_size_cap_is_refused_before_parsing():
    rows = [entry(number, notes='x' * 200) for number in range(1, 50_001)]
    with pytest.raises(KevError) as info:
        parse_bytes(render(document(rows)))
    assert info.value.code == 'PT-KEV-LIMIT'


def test_entry_count_above_the_limit_is_refused():
    rows = [entry(number) for number in range(1, limits.MAX_ENTRIES + 2)]
    with pytest.raises(KevError) as info:
        parse_bytes(render(document(rows)))
    assert info.value.code in {'PT-KEV-LIMIT', 'PT-KEV-VALIDATE'}


def test_duplicate_identifier_in_a_large_catalogue_is_refused():
    rows = [entry(number) for number in range(1, 5_001)] + [entry(4_999)]
    with pytest.raises(KevError) as info:
        parse_bytes(render(document(rows)))
    assert info.value.code == 'PT-KEV-VALIDATE' and 'CVE-2098-04999' in str(info.value)


@pytest.mark.parametrize('bad_row', [None, 5, 'CVE-2098-00001', ['x'], {'cveID': 'NOPE'}],
                         ids=['null', 'number', 'string', 'list', 'partial-object'])
def test_malformed_row_in_a_large_catalogue_is_a_typed_refusal(bad_row):
    rows = [entry(number) for number in range(1, 2_001)]
    rows[1_000] = bad_row
    with pytest.raises(KevError) as info:
        parse_bytes(render(document(rows)))
    assert info.value.code.startswith('PT-KEV-')


_JSON = st.recursive(st.none() | st.booleans() | st.integers(-5, 10**20) | st.floats(allow_nan=False)
                     | st.text(max_size=30),
                     lambda kids: st.lists(kids, max_size=3) | st.dictionaries(st.text(max_size=8), kids, max_size=3),
                     max_leaves=12)
_FIELDS = st.sampled_from(['cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded',
                           'shortDescription', 'requiredAction', 'dueDate', 'knownRansomwareCampaignUse',
                           'forensicTriage', 'notes', 'cwes', 'unexpectedField'])


@SETTINGS
@given(_FIELDS, _JSON)
def test_arbitrary_field_values_only_ever_raise_kev_error(field, value):
    base = document([entry(1), entry(2)])
    candidate = mutated(base, ('vulnerabilities', 0, field), value)
    try:
        parse_bytes(json.dumps(candidate).encode('utf-8'))
    except KevError as error:
        assert error.code.startswith('PT-KEV-')


@SETTINGS
@given(st.binary(max_size=400))
def test_arbitrary_bytes_only_ever_raise_kev_error(raw):
    try:
        parse_catalog(raw, source='local-import', retrieved_at='2099-03-02T08:00:00Z')
    except KevError:
        pass


def test_lookup_of_five_thousand_hostile_ids_is_total_and_bounded(big_catalog):
    rng = random.Random(5)
    ids = [f'CVE-2098-{rng.randint(1, SIZE * 2):05d}' for _ in range(5_000)]
    ids += ['cve-2098-00001\x1b[31m', 'CVE-2098-' + '9' * 500, '‮CVE-2098-00001', 'CVE-２０９８-00001']
    rows = lookup(big_catalog, ids, NOW)
    assert len(rows) == len(dict.fromkeys(ids))
    assert all(row.status in {'listed', 'not-listed', 'invalid-id'} for row in rows)
    for row in rows:
        if row.status == 'invalid-id':
            assert all(ord(char) >= 32 for char in row.cve_id)


def test_lookup_refuses_more_than_the_distinct_id_cap():
    ids = [f'CVE-2098-{number:05d}' for number in range(limits.MAX_LOOKUP_CVES + 1)]
    with pytest.raises(KevError):
        lookup(None, ids, NOW)


def test_split_cve_ids_refuses_pasted_text_over_the_cap():
    text = ' '.join(f'CVE-2098-{number:05d}' for number in range(limits.MAX_LOOKUP_CVES + 1))
    with pytest.raises(KevError):
        split_cve_ids(text)


def test_split_cve_ids_keeps_first_seen_order_over_large_paste():
    text = ',;\n'.join(f'cve-2098-{number % 3000:05d}' for number in range(20_000))
    tokens = split_cve_ids(text)
    assert len(tokens) == 3000 and tokens[0] == 'CVE-2098-00000'
    assert len(set(tokens)) == len(tokens)


def test_diff_of_two_large_catalogues_accounts_for_every_change(big_catalog):
    rows = [entry(number) for number in range(1, SIZE - 99)] + [entry(SIZE + number) for number in range(1, 101)]
    newer = parse_bytes(render(document(rows)))
    delta = diff(big_catalog, newer)
    assert len(delta.added) == 100 and len(delta.removed) == 100
