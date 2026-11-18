"""Source-lineage guard (vendor-feeds-and-source-matrix-spec.md s5 rule 1, s9): one advisory statement that arrives
through three Microsoft source forms (CVRF month, CSAF 2.0, SUG per-CVE) is ONE `msrc` lineage and ONE independent
origin, never three corroborating sources.

Level: source/provider lineage. Not the leads-group channel set (`test_kbf04_kb_lineage`) and not anchor phrase dedup
(`test_kbf04_false_positive_control`). Synthetic fixtures only; the SUG body is the trimmed provider fixture edited
in code to state the same CVE and CWE as the CVRF and CSAF fixtures. Offline.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from kbc_k1_support import import_fixture, no_sockets  # noqa: F401

from patchtrace.enrichment import cve as enrichment_cve
from patchtrace.fabric import origins
from patchtrace.pilot.sources import advisory, snapshot

pytestmark = pytest.mark.usefixtures('no_sockets')

CVE, CWE, TITLE = 'CVE-2099-20001', 'CWE-125', 'Out-of-bounds read in the item reader'
SUG_FIXTURE = Path(__file__).parent / 'fixtures' / 'cve' / 'msrc_CVE-2024-38063.json'


def _sug_snapshot():
    doc = json.loads(SUG_FIXTURE.read_text(encoding='utf-8'))
    doc.update(cveNumber=CVE, cveTitle=TITLE, cweList=[f'{CWE}: Out-of-bounds Read'])
    return enrichment_cve.normalize(CVE, {'msrc': json.dumps(doc).encode()}, '2099-02-13T00:00:00Z')


def _card(doc):
    (card,) = [c for c in doc.cards if c.cve == CVE]
    return card


def _observations(fact):
    return advisory.context_from_fact(fact).observations


@pytest.fixture(scope='module')
def forms():
    cvrf, csaf, sug = import_fixture('cvrf-2099-Feb.json'), import_fixture('csaf-kb-valid.json'), _sug_snapshot()
    return cvrf, csaf, sug


def test_the_three_forms_state_the_same_fact_through_distinct_documents(forms):
    cvrf, csaf, sug = forms
    assert (cvrf.source.kind, csaf.source.kind) == ('cvrf-month', 'csaf')
    assert cvrf.source.doc_id != csaf.source.doc_id  # three documents, so a document count would say 3
    assert (_card(cvrf).source_kind, _card(csaf).source_kind) == ('cvrf', 'csaf')
    assert {_card(cvrf).stated_cwe, _card(csaf).stated_cwe} == {CWE}
    assert [(c.source, c.value) for c in sug.cwes] == [('msrc', CWE)]


def test_cvrf_sug_and_csaf_are_one_msrc_source_family(forms):
    cvrf, csaf, sug = forms
    families = {cvrf.source.lineage, csaf.source.lineage, *(c.source for c in sug.cwes), *sug.response_digests}
    assert families == {'msrc'}
    assert len(families) == 1  # 1 source family, however many documents carry the statement


def test_the_same_statement_from_three_forms_is_one_independent_origin(forms):
    cvrf, csaf, sug = forms
    facts = [snapshot.fact_from_excerpt({'cve': CVE, 'cwe': _card(doc).stated_cwe, 'description': _card(doc).title})
             for doc in (cvrf, csaf)]
    facts.append(snapshot.fact_from_snapshot(sug))
    per_form = [_observations(fact) for fact in facts]
    assert all(per_form)  # every form yields its own advisory observation of the CWE
    assert all('cwe:' + CWE in o.anchor_ids for obs in per_form for o in obs)
    sets = [o.origins for obs in per_form for o in obs]
    assert len(sets) >= 3
    assert origins.independent_count(sets) == 1
    assert origins.components(sets) == (('D_vendor_text',),)


def test_a_genuinely_different_origin_still_counts_separately(forms):
    """Control: the count is not hard-wired to 1; KEV's catalog listing is a second, independent origin."""
    cvrf, csaf, sug = forms
    sets = [o.origins for o in _observations(snapshot.fact_from_snapshot(sug))]
    sets += [o.origins for o in _observations(snapshot.fact_from_excerpt(
        {'cve': CVE, 'cwe': CWE, 'description': _card(cvrf).title}))]
    assert origins.independent_count(sets) == 1
    sets.append(origins.DefaultOriginRegistry().tags_for('kev-catalog'))
    assert origins.independent_count(sets) == 2
