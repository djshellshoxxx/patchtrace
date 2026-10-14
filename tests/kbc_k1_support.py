"""Shared helpers of the K1 tests (KB-CVE correlator slice K1). SYNTHETIC data only; every test using these is a
mocked/synthetic test and is never live evidence (MSRC, CSAF and Winbindex shapes stay unverified until probes L1-L4).

* ``no_sockets``: autouse-able fixture that refuses every socket operation (plan 10.2, hermetic network).
* ``NOW`` and ``import_fixture``: import a committed fixture with a fixed clock.
* ``IntelligenceAdvisoryPort``: a test-side binding of ``AdvisoryPort`` to the real ``intelligence`` CSAF validator and
  normaliser (the production binding is slice K3's ``wiring.py``).
* ``valid_csaf``: the CSAF fixture ``csaf-kb-valid.json`` (K0f's ``csaf-kb.json`` fails CSAF test 6.1.6, see README).
"""
from __future__ import annotations

import copy
import json
import socket
from typing import Any

import kbc_helpers as h
import pytest

from patchtrace.kbcorrelation.sources.importer import ImportedDocument, import_bytes

NOW = '2099-02-15T00:00:00Z'
CSAF_VALID = 'csaf-kb-valid.json'


@pytest.fixture
def no_sockets(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError('KB tests must not open sockets')

    monkeypatch.setattr(socket, 'socket', refuse)
    monkeypatch.setattr(socket, 'create_connection', refuse)
    monkeypatch.setattr(socket, 'getaddrinfo', refuse)


class IntelligenceAdvisoryPort:
    """AdvisoryPort over the real, offline CSAF validator and normaliser."""

    def parse_csaf(self, raw: bytes, *, source_sha256: str) -> dict[str, Any]:
        from patchtrace.intelligence.csaf.normalize import normalize
        from patchtrace.intelligence.csaf.validate import load_document
        document, report = load_document(raw)
        return normalize(document, report, source_sha256).model_dump(mode='json')

    def report_for(self, cve, facts, older_sha256, newer_sha256):  # pragma: no cover - not used by K1
        raise NotImplementedError


def valid_csaf() -> dict[str, Any]:
    """``baseline_csaf()`` with the contradiction fixed: CVE-2099-20001 lists PT-SERVER as known_affected and the two
    client products as fixed (the baseline lists the client products as both, which CSAF test 6.1.6 forbids)."""
    doc = copy.deepcopy(h.baseline_csaf())
    doc['vulnerabilities'][0]['product_status'] = {'known_affected': [h.PRODUCT_SERVER],
                                                   'fixed': [h.PRODUCT_CLIENT, h.PRODUCT_ARM]}
    doc['document']['title'] = 'Synthetic KB fixture advisory, valid variant (not Microsoft)'
    doc['document']['tracking']['id'] = 'PT-SYNTH-KB-2099-02-VALID'
    return doc


def csaf_valid_bytes() -> bytes:
    return h.render_json(valid_csaf())


def json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True).encode('utf-8')


def import_fixture(name: str, *, now: str = NOW) -> ImportedDocument:
    advisory = IntelligenceAdvisoryPort() if name.startswith('csaf') else None
    return import_bytes(h.read_fixture_bytes(name), now=now, advisory=advisory)


def import_doc(doc: dict[str, Any], *, now: str = NOW) -> ImportedDocument:
    return import_bytes(json_bytes(doc), now=now)


def projection(edges) -> list[tuple]:
    """Order- and position-independent view of edges: what a document says, not where it says it."""
    return sorted((e.kb, e.cve, e.scope_id, e.relation, e.fixed_build or '',
                   e.product_status.value if e.product_status else '', e.supersedes) for e in edges)
