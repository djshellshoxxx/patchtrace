"""Circularity guard over a real ``SearchService`` (search-anchors-bridge-spec section 5.1, test named in section 11).

An anchor is derived from advisory TEXT. Once the advisory groups are indexed (section 7), a ``module``, ``feature``,
``component`` or ``api`` anchor whose value is named in the advisory would — with no kind filter — match the advisory
document it came from in the ``indexed`` scope and report ``indexed-only``, a false positive that says nothing about the
binary. The section 5.1 fix restricts every anchor (except the ``string``/``pdb`` overrides) to a closed allow-list of
binary-evidence kinds, so a hint can only ever match binary evidence, never the vendor's own words.

The project is the synthetic ``make_service`` build (function ``CheckLength`` added, ``MainLoop`` unchanged); the
advisory names ``clfs.sys``, which no function, string or import contains. Every group — the advisory included — is
indexed first, so the premise of the circularity actually holds. Synthetic data only; offline.
"""
from __future__ import annotations

import pytest
from search_builders import make_service

from patchtrace.enrichment.identity import domain_id
from patchtrace.intelligence.contracts import Anchor
from patchtrace.search.anchors import coverage_for, plans_for
from patchtrace.search.contracts import SearchRequest
from patchtrace.search.query import parse_query
from patchtrace.search.segment import SegmentDoc
from patchtrace.search.service import SearchService
from patchtrace.search.sources.base import SourceSpec

MODULE = 'clfs.sys'  # named only in the advisory, absent from the synthetic binary
CVE = 'CVE-2099-55555'


def _advisory_specs(_request):
    """Index one advisory document whose title and body name the module, as section 7 would."""
    advisory = SegmentDoc('advisory', None, CVE, CVE, 0, text_title=f'{MODULE} Elevation of Privilege Vulnerability',
                          text_body=f'{MODULE} mishandles a container size')
    meta = {'docs': [(advisory.kind, advisory.subject, advisory.display)]}
    return (SourceSpec('adv', ('advisory',), ('text',), None, meta, lambda: (advisory,)),)


def _anchor(kind: str, value: str) -> Anchor:
    return Anchor(anchor_id=domain_id('anchor', 1, {'kind': kind, 'value': value, 'source': 'csaf-title',
                                                    'pointer': '/vulnerabilities/0/title'}),
                  kind=kind, value=value, source='csaf-title', pointer='/vulnerabilities/0/title', quality='derived',
                  label=f'{kind} {value}')


@pytest.fixture(scope='module')
def service(tmp_path_factory):
    svc = SearchService(make_service(tmp_path_factory.mktemp('circ') / 'project'),
                        tmp_path_factory.mktemp('circ-cache'), extra_specs=_advisory_specs)
    svc.build()  # index every group, the advisory included, so the circularity premise actually holds
    return svc


def _coverage(service, anchor: Anchor):
    (coverage,) = coverage_for(plans_for([anchor]), lambda request: service.search(request, build=False))
    return coverage


def test_the_advisory_is_indexed_and_names_the_module(service):
    """Premise: the advisory is indexed and the module name is genuinely findable in the advisory group — so the
    absence of a module-anchor hit below is the guard working, not an unindexed advisory."""
    result = service.search(SearchRequest(plan=parse_query(f'kind:advisory "{MODULE}"', mode='words'), limit=1,
                                          expand=False), build=False)
    assert (result.total or len(result.hits)) >= 1


def test_a_module_anchor_named_only_in_the_advisory_is_not_a_located_match(service):
    """The circularity guard: clfs.sys occurs only in the advisory it was derived from, so the binary-evidence kind
    filter (section 5.1) means the anchor can never match that advisory document. It is not a located binary match —
    no hit, never ``changed`` or ``indexed-only``. (With an IR group available the status is exactly ``none``; this
    synthetic project has no IR, so the honest status is ``unknown`` — absence unproven — never a false hit.)"""
    coverage = _coverage(service, _anchor('module', MODULE))
    assert coverage.hits == 0
    assert coverage.status not in ('changed', 'indexed-only')
    assert coverage.status in ('none', 'unknown')


def test_a_changed_function_name_anchor_is_changed(service):
    """Control: a real binary token that changed is still found in the changed scope (the guard did not blind search)."""
    assert _coverage(service, _anchor('api', 'CheckLength')).status == 'changed'


def test_an_unchanged_function_name_anchor_is_indexed_only(service):
    """Control: a real binary token present but unchanged is ``indexed-only`` — the discriminating other value of the
    status the module anchor must NOT get."""
    assert _coverage(service, _anchor('api', 'MainLoop')).status == 'indexed-only'
