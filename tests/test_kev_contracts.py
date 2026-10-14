"""kev/1 records: strictness, invariants, error codes and fixed plans."""
from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from patchtrace.kev import limits
from patchtrace.kev.contracts import (
    ERROR_CODES,
    EXIT_CODES,
    KevCatalog,
    KevCatalogMeta,
    KevContext,
    KevEntry,
    KevError,
    KevLookup,
    KevPlan,
)
from patchtrace.kev.join import lookup, make_context
from patchtrace.kev.parse import parse_catalog

FIXTURES = Path(__file__).parent / 'fixtures' / 'kev'
NOW = datetime.datetime(2099, 3, 2, tzinfo=datetime.UTC)


def catalog() -> KevCatalog:
    return parse_catalog((FIXTURES / 'kev-synthetic-2099.json').read_bytes(), source='local-import',
                         retrieved_at='2099-03-01T13:00:00Z')


def test_every_error_code_has_an_exit_code_in_the_envelope_range():
    assert set(ERROR_CODES) == set(EXIT_CODES)
    assert set(EXIT_CODES.values()) == {2, 3, 4, 5}
    assert KevError('PT-KEV-NOTFOUND', 'no catalog').exit_code == 4
    assert KevError('PT-KEV-CONSENT', 'x').exit_code == 2 and KevError('PT-KEV-SHRINK', 'x').exit_code == 3
    with pytest.raises(ValueError):
        KevError('PT-KEV-BOGUS', 'x')


def test_records_are_frozen_strict_and_forbid_extras():
    entry = catalog().entries[0]
    with pytest.raises(ValidationError):
        entry.cve_id = 'CVE-2099-1'
    data = json.loads(entry.model_dump_json())
    with pytest.raises(ValidationError):
        KevEntry.model_validate_json(json.dumps({**data, 'surprise': 1}))
    with pytest.raises(ValidationError):
        KevEntry.model_validate({**data, 'cwes': ['CWE-1']})  # strict: a list is not a tuple outside JSON
    assert KevEntry.model_validate_json(json.dumps(data)) == entry


def test_json_round_trip_of_the_whole_catalog():
    cat = catalog()
    assert KevCatalog.model_validate_json(cat.model_dump_json()) == cat


def test_pattern_does_not_accept_trailing_newline_or_non_ascii_digits():
    data = json.loads(catalog().entries[0].model_dump_json())
    for bad in ('CVE-2099-10001\n', 'CVE-٢099-10001', 'CVE-2099-10001 '):
        with pytest.raises(ValidationError):
            KevEntry.model_validate_json(json.dumps({**data, 'cve_id': bad}))


def test_catalog_invariants():
    cat = catalog()
    with pytest.raises(ValidationError):
        KevCatalog(meta=cat.meta, entries=tuple(reversed(cat.entries)))
    with pytest.raises(ValidationError):
        KevCatalog(meta=cat.meta, entries=cat.entries[:2])
    with pytest.raises(ValidationError):
        KevCatalogMeta.model_validate_json(
            cat.meta.model_dump_json().replace('"skipped_entries":0', '"skipped_entries":1'))


def test_lookup_requires_an_entry_exactly_when_listed():
    listed = lookup(catalog(), ['CVE-2099-10001'], NOW)[0]
    with pytest.raises(ValidationError):
        KevLookup(cve_id=listed.cve_id, status='not-listed', entry=listed.entry, freshness='fresh')


def test_context_identity_is_verified_on_load():
    row = make_context(catalog(), ['CVE-2099-10001'], NOW)
    forged = row.model_dump_json().replace(row.context_id, 'e' * 64)
    with pytest.raises(ValidationError):
        KevContext.model_validate_json(forged)


def test_slim_entry_drops_only_the_long_texts():
    entry = catalog().entries[0]
    slim = entry.slim()
    assert set(entry.model_dump()) - set(slim.model_dump()) == {'short_description', 'required_action', 'notes'}
    assert slim.entry_digest == entry.entry_digest


@pytest.mark.parametrize('source', ['cisa-site', 'cisa-github'])
def test_plan_is_the_fixed_request_for_its_source(source):
    plan = KevPlan.for_source(source)
    assert plan.url == limits.SOURCE_URLS[source] and plan.method == 'GET' and plan.max_bytes == 16 * 1024 * 1024
    assert plan.host == {'cisa-site': 'www.cisa.gov', 'cisa-github': 'raw.githubusercontent.com'}[source]
    assert (plan.headers.accept, plan.headers.user_agent) == ('application/json', 'PatchTrace')
    assert KevPlan.model_validate_json(plan.model_dump_json()) == plan
    with pytest.raises(ValidationError):
        KevPlan.model_validate_json(plan.model_dump_json().replace(plan.host, 'example.invalid'))


def test_plan_rejects_an_unknown_source():
    with pytest.raises(KevError) as err:
        KevPlan.for_source('local-import')
    assert err.value.code == 'PT-KEV-INPUT'
    assert KevPlan.for_source('cisa-site').plan_sha != KevPlan.for_source('cisa-github').plan_sha


def test_source_urls_are_https_without_userinfo_or_query():
    for url in limits.SOURCE_URLS.values():
        assert url.startswith('https://') and '@' not in url and '?' not in url
