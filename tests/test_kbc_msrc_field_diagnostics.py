"""Precise diagnostic fields over mutated offline MSRC factual projection; no acceptance expansion."""
from __future__ import annotations

import hashlib

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from test_kbc_msrc_provenance import NOW, _assert_all_imported_pointers_resolve, _data, _raw

from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore

AT = '/Vulnerability/0/Remediations/0'
pytestmark = pytest.mark.usefixtures('no_sockets')


@pytest.mark.parametrize('invalid', [None, {}, False, 'product', ['']])
def test_invalid_product_membership_identifies_only_product_field(invalid):
    value = _data()
    value['Vulnerability'][0]['Remediations'][0]['ProductID'] = invalid
    doc = import_bytes(_raw(value), now=NOW)
    problem, = (p for p in doc.problems if p.code == 'ROW_SHAPE')
    assert problem.pointer == AT + '/ProductID'
    assert problem.detail == 'ProductID has the wrong type'
    assert not [e for e in doc.edges if e.kb == 'KB5041571']
    assert doc.edges
    _assert_all_imported_pointers_resolve(value, doc)


@pytest.mark.parametrize(('description', 'suffix', 'detail'), [
    (None, '/Description', 'Description.Value has the wrong type'),
    ('text', '/Description', 'Description.Value has the wrong type'),
    ({'Value': None}, '/Description/Value', 'Description.Value has the wrong type'),
    ({'Value': 42}, '/Description/Value', 'Description.Value has the wrong type'),
    ({}, '/Description', 'missing Description.Value')])
def test_invalid_description_points_to_existing_value_or_nearest_parent(description, suffix, detail):
    value = _data()
    value['Vulnerability'][0]['Remediations'][0]['Description'] = description
    doc = import_bytes(_raw(value), now=NOW)
    problem, = (p for p in doc.problems if p.code == 'ROW_SHAPE')
    assert problem.pointer == AT + suffix and problem.detail == detail
    assert not [e for e in doc.edges if e.kb == 'KB5041571']
    _assert_all_imported_pointers_resolve(value, doc)


def test_both_invalid_fields_keep_both_resolvable_diagnostics_and_exact_stored_bytes(tmp_path):
    value = _data()
    value['Vulnerability'][0]['Remediations'][0].update(Description={}, ProductID={})
    raw = _raw(value)
    doc = import_bytes(raw, now=NOW)
    assert {(p.pointer, p.detail) for p in doc.problems if p.code == 'ROW_SHAPE'} == {
        (AT + '/Description', 'missing Description.Value'),
        (AT + '/ProductID', 'ProductID has the wrong type')}
    _assert_all_imported_pointers_resolve(value, doc)
    with WorkspaceStore(tmp_path / 'ws') as ws:
        assert ws.add_document(doc, raw)
        restored, = ws.load_index().documents
        assert restored == doc and ws.read_object(doc.source.sha256) == raw
        assert doc.source.sha256 == hashlib.sha256(raw).hexdigest()
    assert doc.source.authenticity == 'unverified-local-file'


def test_nonfix_missing_description_still_only_diagnoses_invalid_present_product_field():
    value = _data()
    value['Vulnerability'][0]['Remediations'][0]['Type'] = 3
    del value['Vulnerability'][0]['Remediations'][0]['Description']
    value['Vulnerability'][0]['Remediations'][0]['ProductID'] = None
    doc = import_bytes(_raw(value), now=NOW)
    problem, = (p for p in doc.problems if p.code == 'ROW_SHAPE')
    assert problem.pointer == AT + '/ProductID'
    assert problem.detail == 'ProductID has the wrong type'
    _assert_all_imported_pointers_resolve(value, doc)
