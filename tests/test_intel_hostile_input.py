"""Hostile-input sweep over the CSAF chain (audit C-01, C-02, C-06 and the crash classes found beside them).

Property: whatever a document contains, ``load_document`` and everything downstream of an accepted document
(normalize, classify, hypotheses, anchors, applicability) either succeeds or raises ``IntelError``; a raw
``TypeError``, ``ValueError`` or pydantic ``ValidationError`` is a bug. The mutations are structure aware (they
replace, delete, duplicate and extend real fixture values with awkward ones) and use a fixed seed, so the sweep is
deterministic. Inputs are mutations of the SYNTHETIC fixtures; nothing here is live evidence.
"""
from __future__ import annotations

import copy
import hashlib
import json
import random
from pathlib import Path

import pytest

from patchtrace.intelligence import anchors, hypotheses, lexicon
from patchtrace.intelligence.contracts import ArtifactIdentity, IntelError
from patchtrace.intelligence.csaf import applicability, normalize, validate

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'
NAMES = ('synthetic-advisory-rev1.json', 'synthetic-advisory-rev2.json', 'synthetic-vex.json')
DOCS = [json.loads((FIXTURES / name).read_text(encoding='utf-8')) for name in NAMES]
ODD = (None, True, False, 0, -1, 5, 2 ** 70, 1.5, '', ' ', 'x', 'x' * 5000, '\ud800', '‮', [], {}, [None],
       [[]], ['a'], [['a']], {'a': 1}, {'a': []}, '<i></i> Remote Code Execution Vulnerability', 'CVE-2099-10001',
       '1' + '0' * 5000, '0.0.0', '1.0.0-' + '9' * 5000, 'PT-100-1', ['PT-100-1', 'PT-100-1'])
SWEEP = 500


def pointers(node, prefix=()):
    yield prefix
    if isinstance(node, dict):
        for key, value in node.items():
            yield from pointers(value, prefix + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from pointers(value, prefix + (index,))


def at(node, path):
    for step in path:
        node = node[step]
    return node


def mutate(doc: dict, rng: random.Random) -> dict:
    doc = copy.deepcopy(doc)
    for _ in range(rng.choice((1, 1, 1, 2, 3))):
        path = rng.choice([p for p in pointers(doc) if p])
        parent, key = at(doc, path[:-1]), path[-1]
        operation = rng.choice(('replace', 'replace', 'replace', 'delete', 'duplicate', 'extend', 'long-key'))
        if operation == 'replace':
            parent[key] = copy.deepcopy(rng.choice(ODD))
        elif operation == 'delete':
            del parent[key]
        elif operation == 'duplicate' and isinstance(parent, list):
            parent.insert(key, copy.deepcopy(parent[key]))
        elif operation == 'extend' and isinstance(at(doc, path), dict):
            at(doc, path)['x_ext'] = copy.deepcopy(rng.choice(ODD))
        elif operation == 'long-key' and isinstance(at(doc, path), dict):
            at(doc, path)[rng.choice(('k' * 4200, '\ud800', 'a/b~c'))] = 1
    return doc


def identity(side: str, product_ids=()) -> ArtifactIdentity:
    return ArtifactIdentity(side=side, sha256=('e' if side == 'older' else 'f') * 64, facts_state='verified-bytes',
                            asserted_product_ids=tuple(sorted(set(product_ids))))


def run_chain(raw: bytes) -> bool:
    """The whole chain for one document; returns whether the validator accepted it."""
    try:
        doc, report = validate.load_document(raw)
    except IntelError:
        return False
    try:
        facts = normalize.normalize(doc, report, hashlib.sha256(raw).hexdigest())
    except IntelError:
        return True  # a value beyond the normalized contract bounds is a typed rejection
    for item in facts.vulnerabilities:
        if item.cve is None:
            continue
        profile = lexicon.classify(item)
        hints = hypotheses.hypotheses_for(profile)
        anchors.anchors_for(item.cve, [facts], (), hints)
        asserted = [claim.product_id for claim in item.product_status[:1]]
        applicability.resolve(item.cve, [facts], identity('older', asserted), identity('newer'))
    return True


def test_mutated_documents_end_in_success_or_a_typed_error():
    rng = random.Random(20261014)
    accepted = 0
    for _ in range(SWEEP):
        raw = json.dumps(mutate(rng.choice(DOCS), rng)).encode('utf-8')
        accepted += run_chain(raw)
    assert accepted > SWEEP // 10  # the sweep must keep reaching the stages behind the validator


@pytest.mark.parametrize('name', NAMES)
def test_unmutated_fixtures_run_the_whole_chain(name):
    assert run_chain((FIXTURES / name).read_bytes())
