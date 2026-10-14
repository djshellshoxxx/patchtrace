"""K1: CVRF month documents -> KB/CVE/product edges (KB-integration-plan 6, 7.2, 10.2; SPEC-37 32A s6 S01-S11, S19).

SYNTHETIC and mocked: the dialects ``cvrf-json/0`` and ``cvrf-xml/0`` are project placeholders (README of the fixture
directory); nothing here is live evidence about MSRC. Each docstring names the source scenario id it covers.
"""
from __future__ import annotations

import copy
import gzip
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import kbc_helpers as h
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from kbc_k1_support import NOW, import_doc, import_fixture, json_bytes, no_sockets, projection  # noqa: F401

from patchtrace.kbcorrelation.limits import KbcLimits
from patchtrace.kbcorrelation.sources import cvrf
from patchtrace.kbcorrelation.sources.cvrf import SourceError, build_edges, parse_cvrf
from patchtrace.kbcorrelation.sources.importer import gunzip_bounded, import_bytes

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.usefixtures('no_sockets')

DOC_ID = 'a' * 64


def edges_of(name: str):
    return import_fixture(name)


def by_cve(doc, cve: str):
    return [e for e in doc.edges if e.cve == cve]


def kinds(doc, cve: str):
    return sorted((e.kb, e.relation) for e in by_cve(doc, cve))


def scope_name(doc, edge) -> str:
    return next(s.display_name for s in doc.scopes if s.scope_id == edge.scope_id)


# --------------------------------------------------------------------------------------------- baseline month

def test_baseline_counts_are_four_edges_and_one_mention_only():
    """Plan 10.1 step 1 reconciliation: 4 vendor-remediation edges + 1 mention-only = 5 rows (README of the fixtures)."""
    doc = edges_of('cvrf-2099-Feb.json')
    assert doc.counts() == {'vulnerabilities': 3, 'edges': 4, 'mention_only': 1, 'disputed': 0, 'edge_rows': 5,
                            'scopes': 4, 'problems': 0}
    assert {e.relation for e in doc.edges} == {'vendor-remediation', 'mention-only'}
    assert doc.source.kind == 'cvrf-month' and doc.source.release_id == '2099-Feb'
    assert doc.source.dialect == 'cvrf-json/0' and doc.source.current_release_date == '2099-02-13T00:00:00Z'


def test_s01_kb_in_a_product_scoped_row():
    """S01 (KBC/KPS): KB5099001 belongs to CVE-2099-20001 for the client and ARM64 products only, never the server."""
    doc = edges_of('cvrf-2099-Feb.json')
    rows = [e for e in doc.edges if e.kb == h.KB_CLIENT and e.relation == 'vendor-remediation']
    assert {(e.cve, scope_name(doc, e)) for e in rows} == {
        (h.CVE_A, 'Example OS 24H2 x64'), (h.CVE_A, 'Example OS 24H2 ARM64')}
    assert {e.fixed_build for e in rows} == {'26100.9001'}
    assert all(e.ref.assertion == 'advisory_fact' and e.release_id == '2099-Feb' for e in rows)
    assert all(e.ref.pointer == '/vulnerabilities/0/remediations/0' for e in rows)


def test_s02_different_kbs_per_product_are_not_cross_joined():
    """S02 (KPS): CVE A maps to KB5099001 for client scopes and KB5099002 for the server scope, never the cross."""
    doc = edges_of('cvrf-2099-Feb.json')
    pairs = {(scope_name(doc, e), e.kb) for e in by_cve(doc, h.CVE_A) if e.relation == 'vendor-remediation'}
    assert pairs == {('Example OS 24H2 x64', 'KB5099001'), ('Example OS 24H2 ARM64', 'KB5099001'),
                     ('Example Server 2099 x64', 'KB5099002')}


def test_cvrf_type5_mention_never_edge():
    """S07 and NEG-06 (plan 6): a Type 5 known-issue text that names a KB is mention-only, never a remediation."""
    base = edges_of('cvrf-2099-Feb.json')
    assert kinds(base, h.CVE_MENTION) == [(h.KB_CLIENT, 'mention-only')]
    neg = edges_of('cvrf-2099-Feb-neg.json')
    assert kinds(neg, 'CVE-2099-20007') == [('KB5099006', 'mention-only')]
    assert not [e for e in neg.edges if e.kb == 'KB5099006' and e.relation != 'mention-only']


def test_s03_one_kb_three_cves_two_products():
    """S03 (README): KB5099007 repairs CVE-2099-20012..20014 for both client architectures: 6 separate edges."""
    doc = edges_of('cvrf-2099-Feb-neg.json')
    rows = [e for e in doc.edges if e.kb == h.KB_SHARED]
    assert sorted({e.cve for e in rows}) == ['CVE-2099-20012', 'CVE-2099-20013', 'CVE-2099-20014']
    assert len(rows) == 6 and len({e.scope_id for e in rows}) == 2
    assert len({e.edge_id for e in rows}) == 6


def test_s04_several_product_ids_one_source_row_make_several_edges():
    """S04: one Type 2 row naming two products gives two edges with the same pointer and different scopes."""
    doc = edges_of('cvrf-2099-Feb-neg.json')
    rows = by_cve(doc, 'CVE-2099-20005')
    assert len(rows) == 2 and len({e.ref.pointer for e in rows}) == 1 and len({e.scope_id for e in rows}) == 2
    assert {scope_name(doc, e) for e in rows} == {'Example Server 2099 x64', 'Example Server 2099 Core x64'}


def test_s05_duplicate_rows_keep_separate_pointers():
    """S05: two identical remediation rows are two edges at two pointers (display deduplication is the index's job)."""
    doc = edges_of('cvrf-2099-Feb-neg.json')
    rows = by_cve(doc, 'CVE-2099-20004')
    assert [e.ref.pointer for e in rows] == ['/vulnerabilities/0/remediations/0', '/vulnerabilities/0/remediations/1']
    assert len({(e.kb, e.cve, e.scope_id, e.relation) for e in rows}) == 1


def test_s06_undefined_product_id_makes_no_edge_and_is_reported():
    """S06: a ProductID that is not in the product tree is not a wildcard: no edge, a problem with the pointer."""
    doc = edges_of('cvrf-2099-Feb-neg.json')
    assert by_cve(doc, 'CVE-2099-20006') == []
    problem = next(p for p in doc.problems if p.code == 'UNKNOWN_PRODUCT_ID')
    assert problem.pointer == '/vulnerabilities/2/remediations/0/product_ids/0'


def test_product_status_disputes_edge():
    """S08 (plan 6): a Fixed remediation for a product the same CVE lists as 'Not affected' becomes a disputed edge
    that cites the status pointer; it is not a vendor-remediation edge."""
    doc = edges_of('cvrf-2099-Feb-neg.json')
    (edge,) = by_cve(doc, 'CVE-2099-20008')
    assert edge.relation == 'disputed' and edge.kb == 'KB5099008'
    assert edge.product_status.value == 'Not affected'
    assert edge.product_status.pointer == '/vulnerabilities/4/product_statuses/Not affected/0'
    assert edge.ref.pointer == '/vulnerabilities/4/remediations/0'


def test_unknown_status_names_never_dispute_or_assert():
    """Plan 6: an unfamiliar status name is recorded raw, classed 'unknown', and never disputes a fix."""
    row = h.vulnerability('CVE-2099-30001', 'x', remediations=[h.remediation(2, '5099300', [h.PRODUCT_CLIENT])],
                          product_statuses={'Totally New Status': [h.PRODUCT_CLIENT]})
    doc = import_doc(h.cvrf_document([row]))
    (edge,) = doc.edges
    assert edge.relation == 'vendor-remediation' and edge.product_status.value == 'Totally New Status'
    assert doc.statuses[0].klass == 'unknown'


@pytest.mark.parametrize('value,klass', [('Not affected', 'not_affected'), ('known_not_affected', 'not_affected'),
                                         ('Fixed', 'fixed'), ('first_fixed', 'fixed'),
                                         ('Known Affected', 'affected'), ('under_investigation', 'investigating'),
                                         ('weird', 'unknown'), ('', 'unknown')])
def test_status_classes(value, klass):
    assert cvrf.status_class(value) == klass


def test_s09_unrelated_number_in_a_type2_row_is_rejected():
    """S09: a Type 2 description that is prose with a build number is not a KB: no edge, KB_UNPARSED."""
    doc = edges_of('cvrf-2099-Feb-neg.json')
    assert by_cve(doc, 'CVE-2099-20009') == []
    assert any(p.code == 'KB_UNPARSED' and '/vulnerabilities/5/' in p.pointer for p in doc.problems)


def test_neg01_slash_and_control_characters_are_not_a_kb():
    """NEG-01: '5099010/../x<BEL>' yields no edge and no token."""
    doc = edges_of('cvrf-2099-Feb-neg.json')
    assert by_cve(doc, 'CVE-2099-20010') == []
    assert any(p.code == 'KB_UNPARSED' and '/vulnerabilities/6/' in p.pointer for p in doc.problems)


def test_s19_neg24_neg25_hostile_text_stays_plain_text_and_is_never_fetched():
    """S19, NEG-24, NEG-25: HTML, a bidi mark and an external URL in advisory text become plain text on the card; the
    URL is not stored anywhere an edge, a scope or a problem could use it."""
    doc = edges_of('cvrf-2099-Feb-neg.json')
    card = next(c for c in doc.cards if c.cve == 'CVE-2099-20011')
    assert card.title.startswith('Spoofing in the preview pane <img src=x onerror=alert(1)>')
    assert '‮' not in card.title
    dump = json.dumps([e.model_dump(mode='json') for e in doc.edges] + [s.model_dump(mode='json') for s in doc.scopes]
                      + [p.as_dict() for p in doc.problems])
    assert 'evil.example.invalid' not in dump and '<script' not in dump
    (edge,) = by_cve(doc, 'CVE-2099-20011')
    assert edge.kb == 'KB5099011'


def test_clean_text_removes_controls_and_bidi_and_bounds_length():
    from patchtrace.kbcorrelation.products import clean_text
    assert clean_text('a\x00b\x07c\nd\te‮f⁦g\x85h') == 'abc d efgh'
    assert clean_text('x' * 5000) == 'x' * 1000
    assert clean_text(None) == '' and clean_text(5) == ''
    assert clean_text('\ud800') == '�'


def test_errors_never_echo_document_text():
    """Plan 6 (hostile text): error messages are fixed templates, never the document's own words."""
    secret = 'SECRET-<script>-‮'
    bad = [json_bytes({'dialect': secret}), json_bytes([secret]), f'{{"a": "{secret}", "a": 1}}'.encode(),
           json_bytes({'dialect': 'cvrf-json/0', 'document': {'release_id': secret}, 'product_tree': [],
                       'vulnerabilities': []})]
    for raw in bad:
        with pytest.raises(SourceError) as info:
            parse_cvrf(raw)
        assert 'SECRET' not in info.value.message and '<script>' not in info.value.message


# --------------------------------------------------------------------------------------------- dialects and safety

def test_s11_unknown_dialect_is_an_error_not_an_empty_month():
    """S11: the renamed-root XML is refused with 'dialect unknown' (PT-KBC-SOURCE), not read as zero CVEs."""
    with pytest.raises(SourceError) as info:
        parse_cvrf(h.read_fixture_bytes('cvrf-2099-Feb-dialect-unknown.xml'))
    assert info.value.code == 'PT-KBC-SOURCE' and 'dialect unknown' in info.value.message


def test_cvrf_unknown_dialect_is_error_for_json_shapes():
    """S11: JSON without the pinned dialect (including something shaped like a real MSRC document) is refused."""
    real_like = {'DocumentTitle': {'Value': 'x'}, 'ProductTree': {}, 'Vulnerability': []}
    for value in (real_like, {'dialect': 'cvrf-json/9'}, {}, []):
        with pytest.raises(SourceError, match='dialect unknown'):
            parse_cvrf(json_bytes(value))
    with pytest.raises(SourceError, match='looks like an MSRC'):
        parse_cvrf(json_bytes(real_like))
    with pytest.raises(SourceError, match='dialect unknown'):
        parse_cvrf(b'plain text')


@pytest.mark.parametrize('mutate,pointer', [
    (lambda d: d.pop('document'), '/document'),
    (lambda d: d['document'].update(release_id='2099-Xyz'), 'release_id'),
    (lambda d: d.update(product_tree={}), '/product_tree'),
    (lambda d: d.update(vulnerabilities='no'), '/vulnerabilities'),
])
def test_structural_damage_is_a_source_error(mutate, pointer):
    doc = copy.deepcopy(h.baseline_cvrf())
    mutate(doc)
    with pytest.raises(SourceError) as info:
        parse_cvrf(json_bytes(doc))
    assert info.value.code == 'PT-KBC-SOURCE' and pointer in info.value.message


def test_empty_xml_month_parses_with_no_rows():
    """S07 (README): the valid empty month is read, not refused; it has zero vulnerabilities and one product."""
    doc = edges_of('cvrf-2099-Feb-empty.xml')
    assert doc.vulnerabilities == 0 and doc.edges == () and doc.cards == ()
    assert doc.source.dialect == 'cvrf-xml/0' and doc.source.release_id == '2099-Feb'
    assert len(doc.scopes) == 1


def test_neg07_duplicate_keys_refuse_the_whole_source():
    """NEG-07: duplicate JSON keys make the source ambiguous; nothing is returned."""
    with pytest.raises(SourceError, match='duplicate key') as info:
        parse_cvrf(h.read_fixture_bytes('cvrf-2099-Feb-duplicate-key.json'))
    assert info.value.code == 'PT-KBC-SOURCE'


@pytest.mark.parametrize('raw,needle', [
    (b'\xef\xbb\xbf{}', 'byte order mark'),
    (b'{"dialect": "\xff"}', 'UTF-8'),
    (b'{"dialect": NaN}', 'invalid number'),
    (b'{"dialect": 1e999}', 'invalid number'),
    (b'{"a": 1', 'not valid JSON'),
    (b'{"a": ' + b'9' * 5000 + b'}', 'invalid number'),
])
def test_strict_json_refuses(raw, needle):
    with pytest.raises(SourceError, match=needle) as info:
        parse_cvrf(raw)
    assert info.value.code == 'PT-KBC-SOURCE'


# --------------------------------------------------------------------------------------------- XML safety

XMLNS = cvrf.XML_NS


def xml_doc(vulnerabilities: str = '', *, extra: str = '', head: str = '', tree: str | None = None) -> bytes:
    tree = tree if tree is not None else (
        '<cvrf:ProductTree><cvrf:Branch Type="Product Family" Name="x">'
        '<cvrf:FullProductName ProductID="PT-CLIENT" Family="windows-client" Architecture="amd64">'
        'Example OS 24H2 x64</cvrf:FullProductName></cvrf:Branch></cvrf:ProductTree>')
    return (f'<?xml version="1.0" encoding="utf-8"?>\n{head}<cvrf:CvrfDoc xmlns:cvrf="{XMLNS}" ReleaseId="2099-Feb" '
            f'CurrentReleaseDate="2099-02-13"{extra}><cvrf:DocumentTracking Identification="X" Version="1"/>{tree}'
            f'<cvrf:Vulnerabilities>{vulnerabilities}</cvrf:Vulnerabilities></cvrf:CvrfDoc>').encode()


XML_VULN = ('<cvrf:Vulnerability CVE="CVE-2099-30002" Title="t &amp; &lt;b&gt;"><cvrf:CWE ID="CWE-125"/>'
            '<cvrf:Remediations><cvrf:Remediation Type="2" FixedBuild="10.0.26100.9001"><cvrf:Description>5099001'
            '</cvrf:Description><cvrf:ProductID>PT-CLIENT</cvrf:ProductID></cvrf:Remediation></cvrf:Remediations>'
            '</cvrf:Vulnerability>')


def test_xml_vulnerabilities_parse_to_the_same_edges_as_json():
    """The synthetic XML dialect maps to the same intermediate model as the JSON one."""
    doc = import_bytes(xml_doc(XML_VULN), now=NOW)
    (edge,) = doc.edges
    assert (edge.kb, edge.cve, edge.relation, edge.fixed_build) == ('KB5099001', 'CVE-2099-30002',
                                                                     'vendor-remediation', '26100.9001')
    assert doc.cards[0].title == 't & <b>' and doc.cards[0].stated_cwe == 'CWE-125'
    twin = import_doc(h.cvrf_document([h.vulnerability(
        'CVE-2099-30002', 't & <b>', cwe=('CWE-125', 'x'),
        remediations=[h.remediation(2, '5099001', ['PT-CLIENT'], '10.0.26100.9001')])],
        products=({'product_id': 'PT-CLIENT', 'name': 'Example OS 24H2 x64', 'family': 'windows-client',
                   'architecture': 'amd64'},)))
    assert projection(doc.edges) == projection(twin.edges)


BOMB = ('<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>\n')
XXE = '<!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]>\n'


@pytest.mark.parametrize('head', [BOMB, XXE, '<!DOCTYPE d>\n', '<!ENTITY e "x">\n', '<!ELEMENT a ANY>\n'])
def test_xml_markup_declarations_are_refused_before_parsing(head):
    """Safe XML: any DOCTYPE/ENTITY/ELEMENT declaration is refused, so no entity is expanded and nothing external is
    read; the message does not echo the payload."""
    with pytest.raises(SourceError) as info:
        parse_cvrf(xml_doc(head=head))
    assert info.value.code == 'PT-KBC-SOURCE' and 'markup declaration' in info.value.message
    assert 'passwd' not in info.value.message and 'lol' not in info.value.message


def test_xml_comments_and_cdata_are_allowed_but_never_interpreted():
    doc = import_bytes(xml_doc('<!-- a plain comment --><cvrf:Vulnerability CVE="CVE-2099-30003">'
                               '<cvrf:Remediations><cvrf:Remediation Type="5"><cvrf:Description><![CDATA[Known issue '
                               'KB5099300 <b>x</b>]]></cvrf:Description><cvrf:ProductID>PT-CLIENT</cvrf:ProductID>'
                               '</cvrf:Remediation></cvrf:Remediations></cvrf:Vulnerability>'), now=NOW)
    assert [(e.kb, e.relation) for e in doc.edges] == [('KB5099300', 'mention-only')]


def test_xml_declaration_text_inside_a_comment_is_refused_conservatively():
    with pytest.raises(SourceError, match='markup declaration'):
        parse_cvrf(xml_doc('<!-- <!DOCTYPE x> -->'))


def test_xml_encoding_and_wellformedness_guards():
    cases = {
        'utf-16 bom': (b'\xff\xfe<\x00c\x00/\x00>\x00', 'not UTF-8'),
        'latin-1 declaration': (b'<?xml version="1.0" encoding="iso-8859-1"?><a/>', 'other than UTF-8'),
        'broken': (b'<a><b></a>', 'not well-formed'),
        'unclosed': (b'<a>', 'not well-formed'),
        'invalid utf-8': (b'<a>\xff</a>', 'UTF-8'),
    }
    for name, (raw, needle) in cases.items():
        with pytest.raises(SourceError, match=needle):
            parse_cvrf(raw)
        assert name


def test_xml_root_without_vulnerabilities_container_is_not_an_empty_month():
    raw = (f'<?xml version="1.0"?><cvrf:CvrfDoc xmlns:cvrf="{XMLNS}" ReleaseId="2099-Feb"/>').encode()
    with pytest.raises(SourceError, match='Vulnerabilities container is missing'):
        parse_cvrf(raw)


def test_xml_node_and_depth_limits():
    deep = ('<a>' * 80 + '</a>' * 80).encode()
    with pytest.raises(SourceError) as info:
        parse_cvrf(deep)
    assert info.value.code == 'PT-KBC-LIMIT'
    small = KbcLimits(cvrf_json_nodes=20)
    with pytest.raises(SourceError) as info:
        parse_cvrf(xml_doc(XML_VULN * 5), small)
    assert info.value.code == 'PT-KBC-LIMIT'


# --------------------------------------------------------------------------------------------- XML containers, types

def xml_statuses(*kinds: str) -> str:
    """One ProductStatuses container with a Status per kind, each naming PT-CLIENT."""
    inner = ''.join(f'<cvrf:Status Type="{kind}"><cvrf:ProductID>PT-CLIENT</cvrf:ProductID></cvrf:Status>'
                    for kind in kinds)
    return f'<cvrf:ProductStatuses>{inner}</cvrf:ProductStatuses>'


def vuln_with(*extra: str) -> bytes:
    """The XML month with ``extra`` appended inside its one Vulnerability."""
    return xml_doc(XML_VULN.replace('</cvrf:Vulnerability>', ''.join(extra) + '</cvrf:Vulnerability>'))


def month_with(extra: str) -> bytes:
    """The XML month with ``extra`` appended as a further child of the root."""
    return xml_doc(XML_VULN).replace(b'</cvrf:CvrfDoc>', extra.encode() + b'</cvrf:CvrfDoc>')


@pytest.mark.parametrize('raw', [
    month_with('<cvrf:Vulnerabilities>' + XML_VULN.replace('30002', '30003') + '</cvrf:Vulnerabilities>'),
    month_with('<cvrf:ProductTree/>'),
    month_with('<cvrf:DocumentTracking Identification="Y" Version="2"/>'),
    vuln_with(xml_statuses('Fixed'), xml_statuses('Not affected')),
    vuln_with(xml_statuses('Not affected'), xml_statuses('Fixed')),
    vuln_with('<cvrf:Remediations/>'),
    vuln_with('<cvrf:CWE ID="CWE-79"/>'),
], ids=['vulnerabilities', 'product-tree', 'tracking', 'statuses-fixed-first', 'statuses-negative-first',
        'remediations', 'cwe'])
def test_ra2_a_repeated_xml_container_is_ambiguous_and_refuses_the_source(raw):
    """RA-2, the XML twin of NEG-07: a container occurring twice under one parent was last-wins, so the order of two
    ProductStatuses flipped disputed and vendor-remediation and a second Vulnerabilities replaced the first."""
    with pytest.raises(SourceError, match='ambiguous duplicate element') as info:
        import_bytes(raw, now=NOW)
    assert info.value.code == 'PT-KBC-SOURCE'


def test_ra2_many_entries_in_one_container_are_not_duplicates():
    """The rule is about a container repeated under one parent, not the entries inside one: a single
    ProductStatuses holding Fixed and Not affected still disputes the fix."""
    (edge,) = import_bytes(vuln_with(xml_statuses('Fixed', 'Not affected')), now=NOW).edges
    assert edge.relation == 'disputed' and edge.product_status.value == 'Not affected'


@pytest.mark.parametrize('kind', ['\N{ARABIC-INDIC DIGIT TWO}', '\N{FULLWIDTH DIGIT TWO}', ' 2 ', '+2', '0_2', '-2',
                                  '1000', '2.0', ''],
                         ids=['arabic-indic', 'full-width', 'padded', 'plus', 'underscore', 'minus', 'four-digits',
                              'decimal', 'empty'])
def test_ra5_xml_remediation_type_is_one_to_three_ascii_digits(kind):
    """RA-5: int() alone read U+0662, U+FF12, ' 2 ', '+2' and '0_2' as the vendor-fix type 2; the JSON dialect needs
    a real integer, so the XML twin accepts nothing but [0-9]{1,3}."""
    doc = import_bytes(xml_doc(XML_VULN.replace('Type="2"', f'Type="{kind}"')), now=NOW)
    assert doc.edges == () and [p.code for p in doc.problems] == ['TYPE_INVALID']


# --------------------------------------------------------------------------------------------- size limits

def test_cap_32_mib_boundary_and_gzip_bomb():
    """Plan 7.4 / NEG-26: 32 MiB raw cap; a gzip bomb is stopped while inflating, before it fills memory."""
    cap = KbcLimits().cvrf_doc_bytes
    assert cap == 32 * 1024 * 1024
    with pytest.raises(SourceError) as info:
        import_bytes(b'{' + b' ' * cap, now=NOW)
    assert info.value.code == 'PT-KBC-LIMIT' and str(cap) in info.value.message
    bomb = gzip.compress(b'{' + b' ' * (cap + 10), compresslevel=9)
    assert len(bomb) < 100_000
    with pytest.raises(SourceError) as info:
        import_bytes(bomb, now=NOW)
    assert info.value.code == 'PT-KBC-LIMIT'


def test_cap_boundary_with_a_small_limit_is_exact():
    raw = h.render_json(h.baseline_cvrf())
    exact = KbcLimits(cvrf_doc_bytes=len(raw))
    assert import_bytes(raw, now=NOW, limits=exact).counts()['edges'] == 4
    with pytest.raises(SourceError) as info:
        import_bytes(raw, now=NOW, limits=KbcLimits(cvrf_doc_bytes=len(raw) - 1))
    assert info.value.code == 'PT-KBC-LIMIT'


def test_gunzip_rejects_damage():
    good = gzip.compress(b'abc')
    assert gunzip_bounded(good, 10) == b'abc'
    for bad, needle in ((good[:-6], 'truncated'), (good + b'junk', 'trailing'), (b'\x1f\x8bxx', 'not valid gzip')):
        with pytest.raises(SourceError, match=needle):
            gunzip_bounded(bad, 10)


def test_nesting_node_string_and_edge_limits():
    with pytest.raises(SourceError) as info:
        parse_cvrf(b'{"a":' + b'[' * 200_000 + b']' * 200_000 + b'}')
    assert info.value.code == 'PT-KBC-LIMIT'
    nested = {'dialect': 'cvrf-json/0', 'x': 1}
    cursor = nested
    for _ in range(70):
        cursor['n'] = {}
        cursor = cursor['n']
    with pytest.raises(SourceError, match='deeper than 64') as info:
        parse_cvrf(json_bytes(nested))
    assert info.value.code == 'PT-KBC-LIMIT'
    with pytest.raises(SourceError, match='JSON values'):
        parse_cvrf(h.render_json(h.baseline_cvrf()), KbcLimits(cvrf_json_nodes=30))
    with pytest.raises(SourceError, match='over-long string'):
        parse_cvrf(json_bytes({'dialect': 'cvrf-json/0', 's': 'x' * (cvrf.MAX_STRING + 1)}))
    parsed = parse_cvrf(h.render_json(h.baseline_cvrf()))
    with pytest.raises(SourceError, match='more than 2 edges') as info:
        build_edges(parsed, DOC_ID, KbcLimits(cvrf_edges_per_doc=2))
    assert info.value.code == 'PT-KBC-LIMIT'


def test_oversized_field_values_become_problems_not_crashes():
    row = h.vulnerability('CVE-2099-30004', 'x', remediations=[h.remediation(2, '5099400', [h.PRODUCT_CLIENT])],
                          product_statuses={'S' * 5000: [h.PRODUCT_CLIENT]})
    doc = import_doc(h.cvrf_document([row]))
    assert any(p.code == 'STATUS_SHAPE' for p in doc.problems) and len(doc.edges) == 1
    long_sub = h.vulnerability('CVE-2099-30005', 'x', remediations=[
        {**h.remediation(2, '5099401', [h.PRODUCT_CLIENT]), 'sub_type': 'T' * 5000}])
    doc = import_doc(h.cvrf_document([long_sub]))
    assert doc.edges[0].sub_type == 'T' * 1000


@pytest.mark.parametrize('length,kept', [(200, True), (201, False), (5000, False)],
                         ids=['200-kept', '201-dropped', '5000-dropped'])
def test_ra6_xml_status_type_guard_is_the_json_guard(length, kept):
    """RA-6: a status Type over 200 characters (the JSON guard) is one STATUS_SHAPE problem. It used to overflow the
    pointer bound of ProductStatus and refuse the whole month; the remediation edge and the next row survive."""
    first = XML_VULN.replace('</cvrf:Vulnerability>', xml_statuses('S' * length) + '</cvrf:Vulnerability>')
    second = XML_VULN.replace('30002', '30003').replace('5099001', '5099002')
    doc = import_bytes(xml_doc(first + second), now=NOW)
    assert sorted((e.cve, e.kb, e.relation) for e in doc.edges) == [
        ('CVE-2099-30002', 'KB5099001', 'vendor-remediation'), ('CVE-2099-30003', 'KB5099002', 'vendor-remediation')]
    assert [p.code for p in doc.problems] == ([] if kept else ['STATUS_SHAPE'])
    assert len(doc.statuses) == (1 if kept else 0)


def test_ra6_a_status_that_breaks_its_contract_costs_only_its_row(monkeypatch):
    """RA-6: ProductStatus is built inside the row-level try, so whatever its contract refuses is one ROW_SHAPE problem
    and no edge for that remediation, never a refused month."""
    real = cvrf.ProductStatus
    monkeypatch.setattr(cvrf, 'ProductStatus', lambda **kwargs: real(value='', pointer=kwargs['pointer']))
    rows = [h.vulnerability('CVE-2099-30030', 'with a status', product_statuses={'Fixed': [h.PRODUCT_CLIENT]},
                            remediations=[h.remediation(2, '5099030', [h.PRODUCT_CLIENT])]),
            h.vulnerability('CVE-2099-30031', 'without', remediations=[h.remediation(2, '5099031', [h.PRODUCT_CLIENT])])]
    doc = import_doc(h.cvrf_document(rows))
    assert [(e.cve, e.kb) for e in doc.edges] == [('CVE-2099-30031', 'KB5099031')]
    assert [(p.code, p.pointer) for p in doc.problems] == [('ROW_SHAPE', '/vulnerabilities/0/remediations/0')]


# --------------------------------------------------------------------------------------------- row rules

def one_row(remediations, **kw):
    return import_doc(h.cvrf_document([h.vulnerability('CVE-2099-30010', 'row', remediations=remediations, **kw)]))


def test_each_line_of_a_type2_description_is_its_own_kb():
    doc = one_row([h.remediation(2, '5099001\r\n\r\n kb5099002 \nKB 5099003\n5099004', [h.PRODUCT_CLIENT])])
    assert sorted(e.kb for e in doc.edges) == ['KB5099001', 'KB5099002', 'KB5099003', 'KB5099004']
    assert all(e.relation == 'vendor-remediation' for e in doc.edges)


def test_a_type2_line_of_prose_with_an_exact_token_is_mention_only_and_reported():
    doc = one_row([h.remediation(2, 'See KB5099005 for details', [h.PRODUCT_CLIENT])])
    assert [(e.kb, e.relation) for e in doc.edges] == [('KB5099005', 'mention-only')]
    assert any(p.code == 'KB_UNPARSED' for p in doc.problems)


@pytest.mark.parametrize('description', ['', '   ', 'KB123', 'KB12345678901', 'build 19045', 'KB٥٠٩٩',
                                         'KB5099001x', '5099001 5099002', '../5099001'])
def test_non_kb_type2_descriptions_make_no_remediation_edge(description):
    doc = one_row([h.remediation(2, description, [h.PRODUCT_CLIENT])])
    assert not [e for e in doc.edges if e.relation == 'vendor-remediation']


@pytest.mark.parametrize('kind', ['2', 2.0, True, None, [2]])
def test_remediation_type_must_be_an_integer(kind):
    row = h.vulnerability('CVE-2099-30011', 'row', remediations=[h.remediation(2, '5099001', [h.PRODUCT_CLIENT])])
    row['remediations'][0]['type'] = kind
    doc = import_doc(h.cvrf_document([row]))
    assert doc.edges == () and any(p.code == 'TYPE_INVALID' for p in doc.problems)


def test_other_remediation_types_only_ever_mention():
    for kind in (0, 1, 5, 9):
        doc = one_row([h.remediation(kind, 'Workaround for KB5099006', [h.PRODUCT_CLIENT])])
        assert [e.relation for e in doc.edges] == ['mention-only']


def test_cve_must_be_canonical_and_unique():
    rows = [h.vulnerability('cve-2099-30012', 'lower', remediations=[h.remediation(2, '5099001', [h.PRODUCT_CLIENT])]),
            h.vulnerability('CVE-2099-30013', 'a', remediations=[h.remediation(2, '5099002', [h.PRODUCT_CLIENT])]),
            h.vulnerability('CVE-2099-30013', 'b', remediations=[h.remediation(2, '5099003', [h.PRODUCT_CLIENT])]),
            h.vulnerability('CVE-2099-30014', 'ok', remediations=[h.remediation(2, '5099004', [h.PRODUCT_CLIENT])])]
    doc = import_doc(h.cvrf_document(rows))
    assert [e.cve for e in doc.edges] == ['CVE-2099-30014']
    assert {p.code for p in doc.problems} == {'CVE_INVALID', 'CVE_DUPLICATE'}
    assert [c.cve for c in doc.cards] == ['CVE-2099-30014']


def test_row_shapes_that_do_not_fit_are_reported_not_skipped_silently():
    doc_json = h.baseline_cvrf()
    doc_json['vulnerabilities'] += ['not an object', {'cve': 5}]
    doc_json['vulnerabilities'][0]['remediations'] += [7, {'type': 2, 'description': ['x'], 'product_ids': 'no'}]
    doc_json['product_tree'] += [{'product_id': '', 'name': 'x'}, 'x']
    doc = import_doc(doc_json)
    codes = Counter(p.code for p in doc.problems)
    assert codes['ROW_SHAPE'] >= 3 and codes['CVE_INVALID'] == 1 and codes['PRODUCT_ID_INVALID'] == 2
    assert doc.counts()['edges'] == 4  # the good rows are untouched


def test_duplicate_product_ids_are_ambiguous_and_dropped():
    doc_json = h.baseline_cvrf()
    doc_json['product_tree'].append(dict(doc_json['product_tree'][0], name='Other name'))
    doc = import_doc(doc_json)
    assert sum(1 for p in doc.problems if p.code == 'PRODUCT_DUPLICATE') == 2
    assert not [e for e in doc.edges if e.cve == h.CVE_A and e.kb == h.KB_CLIENT and e.scope_id in
                {s.scope_id for s in doc.scopes if s.display_name == 'Other name'}]


@pytest.mark.parametrize('value,expect', [('10.0.26100.9001', '26100.9001'), ('26100.9001', '26100.9001'),
                                          ('10.0.26100', None), ('x.y', None), ('1.2.3.4.5', None), (None, None),
                                          (' 26100.1 ', '26100.1'), ('10.0.1234567.1', None)])
def test_fixed_build_forms(value, expect):
    assert cvrf.parse_fixed_build(value) == expect


def test_fixed_build_supersedes_and_sub_type_are_carried():
    rem = h.remediation(2, '5099010', [h.PRODUCT_CLIENT], '10.0.26100.9010')
    rem.update(supersedes=['KB5099009', 'kb5099008', 'KB5099010', 'nonsense'], sub_type='Security Update')
    doc = one_row([rem])
    (edge,) = doc.edges
    assert edge.fixed_build == '26100.9010' and edge.sub_type == 'Security Update'
    assert edge.supersedes == ('KB5099008', 'KB5099009')  # sorted, self removed, junk dropped
    assert any(p.code == 'SUPERSEDES_UNPARSED' for p in doc.problems)
    bad = h.remediation(2, '5099011', [h.PRODUCT_CLIENT], 'not a build')
    assert one_row([bad]).edges[0].fixed_build is None
    assert any(p.code == 'FIXED_BUILD_UNPARSED' for p in one_row([bad]).problems)


def test_status_missing_for_a_remediated_product_is_flagged_for_review():
    doc = one_row([h.remediation(2, '5099012', [h.PRODUCT_CLIENT, h.PRODUCT_SERVER])],
                  product_statuses={'Fixed': [h.PRODUCT_CLIENT]})
    flagged = [p for p in doc.problems if p.code == 'PRODUCT_STATUS_MISSING']
    assert len(flagged) == 1 and flagged[0].level == 'info' and flagged[0].pointer.endswith('/product_ids/1')
    assert doc.counts()['problems'] == 0 and len(doc.edges) == 2


def test_hint_that_contradicts_the_name_marks_the_scope_conflicted():
    products = ({'product_id': 'PT-X', 'name': 'Windows Server 2022 for x64-based Systems', 'family': 'windows-client',
                 'architecture': 'arm64'},)
    doc = import_doc(h.cvrf_document([h.vulnerability(
        'CVE-2099-30020', 'x', remediations=[h.remediation(2, '5099020', ['PT-X'])])], products=products))
    (scope,) = doc.scopes
    assert scope.mapping == 'conflicted' and scope.family == 'unknown' and scope.architecture == 'unknown'
    assert any(p.code == 'PRODUCT_HINT_CONFLICT' for p in doc.problems)


# --------------------------------------------------------------------------------------------- order and identity

def test_reordered_fixture_has_the_same_content_with_different_positions():
    base = edges_of('cvrf-2099-Feb.json')
    rev = edges_of('cvrf-2099-Feb-reordered.json')
    assert projection(base.edges) == projection(rev.edges)
    assert {s.scope_id for s in base.scopes} == {s.scope_id for s in rev.scopes}
    assert {e.edge_id for e in base.edges} != {e.edge_id for e in rev.edges}  # positions differ, so ids differ
    assert base.doc_id != rev.doc_id


def test_parse_is_deterministic():
    one, two = edges_of('cvrf-2099-Feb-neg.json'), edges_of('cvrf-2099-Feb-neg.json')
    assert one == two


def test_edge_ids_are_stable_across_hash_seed_and_locale():
    """Plan 10.2: edge ids do not depend on PYTHONHASHSEED or the locale (subprocess with different settings)."""
    code = ("import sys; sys.path[:0]=['src','tests']; import kbc_helpers as h; "
            "from patchtrace.kbcorrelation.sources.importer import import_bytes; "
            "d=import_bytes(h.read_fixture_bytes('cvrf-2099-Feb-neg.json'), now='2099-02-15T00:00:00Z'); "
            "print(d.doc_id); print(','.join(e.edge_id for e in d.edges))")
    outputs = set()
    for seed, lang in (('0', 'C'), ('12345', 'tr_TR.UTF-8'), ('random', 'de_DE.UTF-8')):
        env = {**os.environ, 'PYTHONHASHSEED': seed, 'LC_ALL': lang, 'LANG': lang}
        done = subprocess.run([sys.executable, '-I', '-c', code], cwd=ROOT, env=env, capture_output=True, text=True,
                              check=True)
        outputs.add(done.stdout)
    assert len(outputs) == 1


def test_unrelated_cve_changes_nothing_for_other_rows():
    base = h.baseline_cvrf()
    more = copy.deepcopy(base)
    more['vulnerabilities'].append(h.vulnerability('CVE-2099-39999', 'unrelated', remediations=[
        h.remediation(2, '5099999', [h.PRODUCT_SERVER], '10.0.26100.9999')]))
    one, two = import_doc(base), import_doc(more)
    assert projection(one.edges) == projection([e for e in two.edges if e.cve != 'CVE-2099-39999'])
    assert [e for e in two.edges if e.cve == 'CVE-2099-39999'][0].kb == 'KB5099999'


# --------------------------------------------------------------------------------------------- property tests

CVES = [f'CVE-2099-4{n:04d}' for n in range(8)]
DESCRIPTIONS = ['5099101', 'KB5099102', 'kb5099103', '5099104\n5099105', 'build 12345 junk', '', 'KB5099106 mention',
                '5099107/../x', 'KB 5099108']
PIDS = [h.PRODUCT_CLIENT, h.PRODUCT_ARM, h.PRODUCT_SERVER, h.PRODUCT_SERVER_CORE, h.PRODUCT_UNKNOWN]


@st.composite
def cvrf_documents(draw):
    cves = draw(st.lists(st.sampled_from(CVES), unique=True, max_size=6))
    rows = []
    for cve in cves:
        rems = [h.remediation(draw(st.sampled_from([2, 2, 5, 0])), draw(st.sampled_from(DESCRIPTIONS)),
                              draw(st.lists(st.sampled_from(PIDS), unique=True, max_size=3)),
                              draw(st.sampled_from([None, '10.0.26100.9001', '26100.9002', 'junk'])))
                for _ in range(draw(st.integers(0, 3)))]
        statuses = {name: draw(st.lists(st.sampled_from(PIDS[:4]), unique=True, max_size=3))
                    for name in draw(st.lists(st.sampled_from(['Fixed', 'Not affected', 'Known affected']),
                                              unique=True, max_size=2))}
        rows.append(h.vulnerability(cve, f'title {cve}', cwe=draw(st.sampled_from([None, ('CWE-125', 'x')])),
                                    remediations=rems, product_statuses=statuses))
    return h.cvrf_document(rows)


def shuffle_everything(doc, rnd):
    out = copy.deepcopy(doc)
    rnd.shuffle(out['product_tree'])
    rnd.shuffle(out['vulnerabilities'])
    for row in out['vulnerabilities']:
        rnd.shuffle(row['remediations'])
        for item in row['remediations']:
            rnd.shuffle(item['product_ids'])
        for members in row['product_statuses'].values():
            rnd.shuffle(members)
    return out


def view(doc):
    return (projection(doc.edges), sorted(s.scope_id for s in doc.scopes),
            sorted((c.cve, c.title, c.stated_cwe) for c in doc.cards),
            sorted(Counter(p.code for p in doc.problems).items()), doc.counts())


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(cvrf_documents(), st.randoms(use_true_random=False))
def test_property_array_reorder_invariance(doc, rnd):
    """Plan 10.2: parsing does not depend on the order of any array (edges, scopes, cards, problems by code)."""
    assert view(import_doc(doc)) == view(import_doc(shuffle_everything(doc, rnd)))


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(cvrf_documents())
def test_property_unrelated_cve_changes_nothing(doc):
    extra = copy.deepcopy(doc)
    extra['vulnerabilities'].append(h.vulnerability('CVE-2099-49999', 'unrelated', remediations=[
        h.remediation(2, '5099998', [h.PRODUCT_CLIENT], '10.0.26100.9998')]))
    before, after = import_doc(doc), import_doc(extra)
    assert projection(before.edges) == projection([e for e in after.edges if e.cve != 'CVE-2099-49999'])


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(cvrf_documents())
def test_property_every_edge_is_justified_by_its_pointer(doc):
    """Every remediation edge points at a Type 2 row whose line is a KB; every mention-only edge at a non-fix text."""
    parsed = import_doc(doc)
    for edge in parsed.edges:
        vi, ri = (int(x) for x in edge.ref.pointer.split('/')[2:5:2])
        rem = doc['vulnerabilities'][vi]['remediations'][ri]
        assert doc['vulnerabilities'][vi]['cve'] == edge.cve
        if edge.relation in ('vendor-remediation', 'disputed'):
            assert rem['type'] == 2 and edge.kb[2:] in rem['description'].replace(' ', '').upper().replace('KB', '')
        else:
            assert edge.kb in rem['description'] or edge.kb in rem['description'].replace('kb', 'KB')
