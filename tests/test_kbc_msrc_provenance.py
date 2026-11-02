"""Offline provenance regressions over the existing native MSRC factual projection.

Mutations are negative controls, not vendor statements or additional live acceptance evidence.
"""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest
from kbc_k1_support import no_sockets  # noqa: F401

from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore

FIXTURE = Path(__file__).parent / 'fixtures/kbcve/msrc/2024-Aug-CVE-2024-38193.facts.json'
NOW = '2026-11-02T00:00:00Z'
CASES = [
    ('/DocumentTracking', 'CurrentReleaseDate', 'DATE_INVALID'),
    ('/Vulnerability/0', 'CVE', 'CVE_INVALID'),
    ('/Vulnerability/0/Remediations/0', 'Type', 'TYPE_INVALID'),
]
pytestmark = pytest.mark.usefixtures('no_sockets')


def _data():
    return json.loads(FIXTURE.read_bytes())


def _raw(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode('utf-8')


def _resolve(value, pointer):
    assert pointer.startswith('/')
    for token in pointer.split('/')[1:]:
        token = token.replace('~1', '/').replace('~0', '~')
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


def _assert_all_imported_pointers_resolve(value, doc):
    pointers = [p.pointer for p in doc.problems]
    pointers.extend(s.pointer for s in doc.statuses)
    for edge in doc.edges:
        assert edge.ref.doc_id == doc.doc_id
        pointers.append(edge.ref.pointer)
        if edge.product_status is not None:
            pointers.append(edge.product_status.pointer)
    assert pointers
    for pointer in pointers:
        _resolve(value, pointer)


def _assert_row_behavior(doc, field):
    assert doc.source.dialect == 'msrc-cvrf-json/1'
    assert doc.source.authenticity == 'unverified-local-file'
    assert doc.source.current_release_date is None
    if field == 'CVE':
        assert doc.vulnerabilities == 0
        assert not doc.edges and not doc.cards and not doc.statuses
    else:
        assert doc.vulnerabilities == 1
        assert doc.edges and doc.cards and doc.statuses
        if field == 'Type':
            assert all(e.kb != 'KB5041571' for e in doc.edges)
        else:
            assert len([e for e in doc.edges if e.kb == 'KB5041571']) == 2


@pytest.mark.parametrize(('parent', 'field', 'code'), CASES)
def test_missing_field_diagnostic_names_field_and_points_to_existing_parent(parent, field, code):
    value = _data()
    container = _resolve(value, parent)
    del container[field]
    doc = import_bytes(_raw(value), now=NOW)
    problem, = (p for p in doc.problems if p.code == code)
    assert problem.pointer == parent
    assert field in problem.detail
    assert _resolve(value, problem.pointer) is container
    assert field not in container
    _assert_all_imported_pointers_resolve(value, doc)
    _assert_row_behavior(doc, field)


@pytest.mark.parametrize(('parent', 'field', 'code'), CASES)
@pytest.mark.parametrize('invalid', [None, False, 0.5, '', 'invalid', [], {}])
def test_present_invalid_field_retains_exact_diagnostic_pointer(parent, field, code, invalid):
    value = _data()
    _resolve(value, parent)[field] = invalid
    doc = import_bytes(_raw(value), now=NOW)
    problem, = (p for p in doc.problems if p.code == code)
    assert problem.pointer == parent + '/' + field
    assert _resolve(value, problem.pointer) == invalid
    _assert_all_imported_pointers_resolve(value, doc)
    _assert_row_behavior(doc, field)


@pytest.mark.parametrize(('parent', 'field', 'code'), CASES)
def test_missing_field_provenance_and_exact_raw_sha_survive_workspace_reload(tmp_path, parent, field, code):
    value = _data()
    del _resolve(value, parent)[field]
    raw = _raw(value)
    sha = hashlib.sha256(raw).hexdigest()
    doc = import_bytes(raw, now=NOW)
    root = tmp_path / 'kb'
    with WorkspaceStore(root) as store:
        assert store.add_document(doc, raw)
    with WorkspaceStore(root, create=False) as store:
        source, = store.sources()
        assert source.sha256 == sha == doc.source.sha256
        assert source.size == len(raw)
        assert store.read_object(sha) == raw
        stored = gzip.decompress((root / source.object_path).read_bytes())
        assert stored == raw and hashlib.sha256(stored).hexdigest() == sha
        restored, = store.load_index().documents
    assert restored == doc
    problem, = (p for p in restored.problems if p.code == code)
    assert problem.pointer == parent and field in problem.detail
    persisted_value = json.loads(stored)
    assert field not in _resolve(persisted_value, parent)
    _assert_all_imported_pointers_resolve(persisted_value, restored)
    _assert_row_behavior(restored, field)


def test_unmodified_factual_projection_resolves_every_imported_pointer():
    raw = FIXTURE.read_bytes()
    doc = import_bytes(raw, now=NOW)
    assert doc.source.sha256 == hashlib.sha256(raw).hexdigest()
    assert doc.edges and doc.statuses and doc.problems
    _assert_all_imported_pointers_resolve(json.loads(raw), doc)
