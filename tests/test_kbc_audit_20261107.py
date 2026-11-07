"""Regression tests for the 2026-11-07 KB/CVE correlation audit (docs/qa/audit-kb-correlation-20261107.md).

Offline; synthetic documents only. Findings that are reported but not fixed are strict xfail so the suite stays green
and the defect stays executable: fixing one turns its xfail into an XPASS failure that asks for the marker's removal.
"""
from __future__ import annotations

import copy
import json

import pytest
from kbc_k1_support import IntelligenceAdvisoryPort, valid_csaf
from kbc_k5_support import record, rows_of

from patchtrace.kbcorrelation import resolver as rs
from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.products import scope_for
from patchtrace.kbcorrelation.sources.importer import import_bytes

NOW = '2099-03-01T00:00:00Z'
PRODUCT = 'Windows 11 Version 24H2 for x64-based Systems'


def cvrf(date: str, kb: str) -> bytes:
    document = {'release_id': '2099-Feb', 'current_release_date': date}
    return json.dumps({'dialect': 'cvrf-json/0', 'document': document,
                       'product_tree': [{'product_id': 'P1', 'name': PRODUCT}],
                       'vulnerabilities': [{'cve': 'CVE-2099-0001', 'remediations': [
                           {'type': 2, 'description': kb, 'product_ids': ['P1']}]}]}).encode()


def csaf(*, revision: str, namespace: str | None = None, released: str = '2099-02-13T00:00:00Z'):
    doc = valid_csaf()
    tracking = doc['document']['tracking']
    tracking.update(version=revision, current_release_date=released, initial_release_date='2099-02-01T00:00:00Z',
                    revision_history=[{'date': '2099-02-01T00:00:00Z', 'number': str(n), 'summary': 'r'}
                                      for n in range(1, int(revision) + 1)])
    if namespace is not None:
        doc['document']['publisher']['namespace'] = namespace
    return import_bytes(json.dumps(doc).encode(), now=NOW, advisory=IntelligenceAdvisoryPort())


# --- KBA-01: Windows 10 scopes never match real Winbindex version keys -----------------------------------------

def test_kba01_windows_10_product_resolves_against_real_winbindex_version_keys():
    """Real Winbindex keys Windows 10 as ``22H2`` and Windows 11 as ``11-22H2`` (docs/research/kbcve/
    winbindex-servicing-catalog.md, live). The product scope key ``10-22H2`` matched no real row, so every Windows 10
    product answered "Not in the file index"."""
    doc = record()
    only = {sha: entry for sha, entry in doc.items() if '10-22H2' in entry.get('windowsVersions', {})}
    assert only, 'fixture lost its Windows 10 22H2 entry'
    real = copy.deepcopy(only)
    for entry in real.values():
        entry['windowsVersions'] = {'22H2': entry['windowsVersions']['10-22H2']}
        entry['windowsVersions']['22H2']['BASE'] = {'windowsVersionInfo': {'releaseDate': '2099-01-01'}}
    rows, _ = rows_of(real)
    scope = scope_for('d' * 64, 'P1', 'Windows 10 Version 22H2 for x64-based Systems')
    assert scope.winbindex_key == '10-22H2'
    res = rs.resolve(rows, kb='KB5099002', scope=scope, file_name='exampledrv.sys')
    assert res.note != 'Not in the file index (Windows 10/11 client x64 only).'
    assert res.blockers != ('NO_NEWER',)


# --- KBA-02: timestamps ordered as text ------------------------------------------------------------------------

def test_kba02_timeline_is_oldest_first_by_instant():
    index = ReverseIndex()
    older = import_bytes(cvrf('2099-02-13T10:00:00+05:00', 'KB1111'), now=NOW)     # 05:00Z
    newer = import_bytes(cvrf('2099-02-13T08:00:00Z', 'KB2222'), now=NOW)          # 08:00Z
    index.add(older)
    index.add(newer)
    scope_id = index.scopes()[0].scope_id
    kbs = [entry.kbs for entry in index.timeline('CVE-2099-0001', scope_id)]
    assert kbs == [('KB1111',), ('KB2222',)]


def test_kba02_coverage_watermark_is_the_newest_instant():
    index = ReverseIndex()
    index.add(import_bytes(cvrf('2099-02-13T10:00:00+05:00', 'KB1111'), now=NOW))
    index.add(import_bytes(cvrf('2099-02-13T08:00:00Z', 'KB2222'), now=NOW))
    assert index.coverage(now=NOW).watermark_current_release_date == '2099-02-13T08:00:00Z'


# --- KBA-03/04: CSAF revision selection ------------------------------------------------------------------------

@pytest.mark.parametrize('order', [('1', '2'), ('2', '1')])
def test_kba03_higher_csaf_revision_is_active_when_release_dates_tie(order):
    index, docs = ReverseIndex(), {}
    for revision in order:
        docs[revision] = csaf(revision=revision)
        index.add(docs[revision])
    assert docs['1'].tracking_id == docs['2'].tracking_id
    assert index.active_ids() == frozenset({docs['2'].doc_id})


def test_kba04_same_tracking_id_from_two_publishers_are_not_revisions_of_each_other():
    index = ReverseIndex()
    first = csaf(revision='1', namespace='https://vendor-a.example', released='2099-02-10T00:00:00Z')
    second = csaf(revision='1', namespace='https://vendor-b.example', released='2099-02-13T00:00:00Z')
    index.add(first)
    index.add(second)
    assert index.active_ids() == frozenset({first.doc_id, second.doc_id})


# --- KBA-05: an impossible release date in stored advisory facts crashed supersession --------------------------

def test_kba05_supersession_survives_a_facts_date_that_is_only_shaped_like_a_timestamp():
    """``Timestamp`` is a pattern, so '2099-13-45T00:00:00Z' is a valid ``AdvisoryFacts`` field; ``parse_date_time``
    returns None for it and ``max()`` then compared a datetime with None (TypeError out of ``advisories()``)."""
    import hashlib
    from pathlib import Path

    from patchtrace.intelligence.contracts import AdvisoryFacts
    from patchtrace.intelligence.csaf import applicability as ap
    from patchtrace.intelligence.csaf import normalize, validate

    def facts(name):
        raw = (Path(__file__).parent / 'fixtures' / 'csaf' / name).read_bytes()
        parsed, report = validate.load_document(raw)
        return normalize.normalize(parsed, report, hashlib.sha256(raw).hexdigest())

    first, second = facts('synthetic-advisory-rev1.json'), facts('synthetic-advisory-rev2.json')
    broken = AdvisoryFacts.model_validate_json(json.dumps(
        {**first.model_dump(mode='json'), 'current_release_date': '2099-13-45T00:00:00Z'}))
    state = ap.supersession([broken, second])
    assert state == {broken.facts_id: True, second.facts_id: False}   # an unreadable date is the oldest
