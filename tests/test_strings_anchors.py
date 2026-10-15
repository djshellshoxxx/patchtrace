"""WB3-S6 anchors: advisory hints join strings as `anchor`-strength hits that never move the review tier."""
from __future__ import annotations

import hashlib

import pytest
from test_strings_delta import PAIRING, table

from patchtrace.intelligence.contracts import Anchor, AnchorSet
from patchtrace.strings import anchors as anchors_module
from patchtrace.strings.anchors import attach_anchors, join_anchors, terms
from patchtrace.strings.contracts import StringsDelta
from patchtrace.strings.cues import CueContext
from patchtrace.strings.delta import compute_delta

CVE = 'CVE-2026-0001'


def anchor(kind: str, value: str) -> Anchor:
    return Anchor(anchor_id=hashlib.sha256(f'{kind}:{value}'.encode()).hexdigest(), kind=kind, value=value,
                  source='csaf-title', quality='explicit', label=f'{kind} hint')


def anchor_set(*items: Anchor) -> AnchorSet:
    return AnchorSet(cve=CVE, anchors=items)


@pytest.fixture(scope='module')
def delta():
    older = table('older', ['kept string one', 'Old message here'])
    newer = table('newer', ['kept string one', 'index %u exceeds length %u', 'RtlULongAdd', 'exampledrv.sys',
                            'C:\\build\\exampledrv.pdb', 'AKIAIOSFODNN7EXAMPLE'])
    return compute_delta(older, newer, pairing=PAIRING, contexts={'newer': CueContext(imports=['RtlULongAdd'])})


def hits(delta, *items):
    shown = {c.value_sha256: c.display for c in delta.changes}
    return {(h.kind, h.match, shown[h.string_id]) for h in join_anchors(delta, anchor_set(*items)).hits}


@pytest.mark.parametrize('item, expected', [
    (anchor('string', 'exceeds length'), ('string', 'substring', 'index %u exceeds length %u')),
    (anchor('string', 'INDEX %U EXCEEDS LENGTH %U'), ('string', 'casefold', 'index %u exceeds length %u')),
    (anchor('string', 'index %u exceeds length %u'), ('string', 'exact', 'index %u exceeds length %u')),
    (anchor('api', 'RtlULongAdd'), ('api', 'import-equal', 'RtlULongAdd')),
    (anchor('module', 'ExampleDrv.SYS'), ('module', 'casefold', 'exampledrv.sys')),
    (anchor('pdb', 'exampledrv.pdb'), ('pdb', 'substring', 'C:\\build\\exampledrv.pdb')),
], ids=['substring', 'casefold', 'exact', 'import-equal', 'module', 'pdb'])
def test_match_kinds(delta, item, expected):
    assert hits(delta, item) == {expected}


def test_short_hint_never_matches_by_substring(delta):
    assert hits(delta, anchor('string', 'length')) == set()


def test_hit_is_anchor_strength_with_presence_and_lineage(delta):
    (hit,) = join_anchors(delta, anchor_set(anchor('api', 'RtlULongAdd'))).hits
    assert hit.strength == 'anchor' and (hit.presence_older, hit.presence_newer) == (False, True)
    assert hit.lineage_group == f'bytes:{hit.string_id}'


def test_a_secret_is_never_matched(delta):
    assert join_anchors(delta, anchor_set(anchor('string', 'AKIAIOSFODNN7EXAMPLE'))).hits == ()


def test_join_does_not_change_tiers_or_order(delta):
    after = attach_anchors(delta, anchor_set(anchor('api', 'RtlULongAdd'), anchor('string', 'exceeds length')))
    assert [(c.id, c.review_tier) for c in after.changes] == [(c.id, c.review_tier) for c in delta.changes]
    assert after.anchors.digest and len(after.anchors.hits) == 2


def test_join_is_independent_of_anchor_order(delta):
    items = [anchor('api', 'RtlULongAdd'), anchor('string', 'exceeds length'), anchor('module', 'exampledrv.sys')]
    assert join_anchors(delta, anchor_set(*items)) == join_anchors(delta, anchor_set(*reversed(items)))


def test_no_anchors_leaves_the_delta_untouched(delta):
    assert attach_anchors(delta, None) is delta
    assert join_anchors(delta, anchor_set()).hits == ()


def test_unusable_kinds_and_the_cap():
    many = [anchor('string', f'unmatched phrase {i:04d}') for i in range(anchors_module.MAX_ANCHORS + 20)]
    assert len(anchors_module.usable(anchor_set(*many, anchor('component', 'x')))) == anchors_module.MAX_ANCHORS


def test_terms_feed_the_cue_layer():
    found = terms(anchor_set(anchor('api', 'RtlULongAdd'), anchor('string', 'Exceeds Length'), anchor('pdb', 'a.pdb')))
    assert found.api_hints == {'RtlULongAdd'} and found.advisory_phrases == ('exceeds length',)
    assert terms(None).api_hints == frozenset()


def test_not_comparable_delta_gets_no_join():
    refused = StringsDelta(older_basis_digest='a' * 64, newer_basis_digest='b' * 64, comparable=False)
    assert attach_anchors(refused, anchor_set(anchor('api', 'x'))) is refused
