"""Audit D-02: ``text_field_bytes`` is a byte limit; a remediation description is clipped by UTF-8 bytes, on a
character boundary, in both the JSON and the XML CVRF readers."""
from __future__ import annotations

import json

import pytest

from patchtrace.kbcorrelation.limits import KbcLimits
from patchtrace.kbcorrelation.sources import cvrf

LIMIT = 10
TEXT = 'é' * 8  # 2 bytes each: 16 bytes, 8 characters


def json_raw() -> bytes:
    return json.dumps({
        'dialect': 'cvrf-json/0', 'document': {'release_id': '2099-Feb'},
        'product_tree': [{'product_id': 'P1', 'name': 'Windows 11'}],
        'vulnerabilities': [{'cve': 'CVE-2099-0001', 'remediations': [
            {'type': 2, 'description': TEXT, 'product_ids': ['P1']}]}]}, ensure_ascii=False).encode('utf-8')


def xml_raw() -> bytes:
    return (f'<CvrfDoc xmlns="{cvrf.XML_NS}" ReleaseId="2099-Feb"><Vulnerabilities>'
            '<Vulnerability CVE="CVE-2099-0001"><Remediations><Remediation Type="2">'
            f'<Description>{TEXT}</Description><ProductID>P1</ProductID>'
            '</Remediation></Remediations></Vulnerability></Vulnerabilities></CvrfDoc>').encode()


def descriptions(raw: bytes) -> list[str]:
    doc = cvrf.parse_cvrf(raw, KbcLimits(text_field_bytes=LIMIT))
    return [r.description for v in doc.vulnerabilities for r in v.remediations]


@pytest.mark.parametrize('raw', [json_raw, xml_raw], ids=['json', 'xml'])
def test_description_is_clipped_by_bytes_on_a_character_boundary(raw):
    (text,) = descriptions(raw())
    assert 0 < len(text.encode('utf-8')) <= LIMIT and text == TEXT[:len(text)]
