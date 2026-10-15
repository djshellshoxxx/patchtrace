"""WB3-S5 review tiers: ordinal reading order, never a score."""
from __future__ import annotations

import pytest

from patchtrace.strings.contracts import FunctionRef, StringLink
from patchtrace.strings.rank import REASONS, review_tier


def link(status, rva=None):
    return StringLink(tier='L1', join='exact', function=FunctionRef(side='newer', rva=rva), pair_status=status,
                      lineage_group='ghidra:x', evidence_ref='rva:0x1')


MODIFIED, ADDED, REMOVED, UNKNOWN = ([link(s)] for s in ('modified', 'added', 'removed', 'unknown'))


@pytest.mark.parametrize('status, cues, links, kwargs, tier', [
    ('only-newer', ['message', 'format'], MODIFIED, {}, 1),
    ('edited', ['message'], MODIFIED, {}, 1),
    ('only-newer', ['advisory-text'], MODIFIED, {}, 1),
    ('only-newer', ['identifier'], ADDED, {}, 2),
    ('only-newer', ['message'], ADDED, {}, 2),
    ('only-newer', ['registry'], UNKNOWN, {}, 3),
    ('only-newer', ['dynamic-api', 'advisory-api'], [], {}, 3),
    ('only-older', ['message'], MODIFIED, {}, 4),
    ('only-older', ['path'], REMOVED, {}, 4),
    ('only-older', ['message'], UNKNOWN, {}, 5),
    ('only-newer', ['message'], UNKNOWN, {}, 5),
    ('indeterminate', ['message'], MODIFIED, {}, 5),
    ('only-newer', ['message'], MODIFIED, {'emulation': True}, 5),
    ('representation-changed', ['message'], MODIFIED, {}, 6),
    ('edited', ['lookalike'], MODIFIED, {'lookalike': True}, 6),
    ('only-newer', ['noise-like'], MODIFIED, {}, 7),
    ('only-newer', ['resource'], MODIFIED, {}, 7),
    ('both', ['message'], MODIFIED, {}, 7),
], ids=['r1-message', 'r1-edited', 'r1-advisory', 'r2-ident', 'r2-message-added', 'r3-registry', 'r3-api',
        'r4-message', 'r4-path', 'r5-older-unknown', 'r5-newer-unknown', 'r5-indeterminate', 'r5-emulation',
        'r6-representation', 'r6-lookalike', 'r7-noise', 'r7-resource', 'r7-relocated'])
def test_tier_rules(status, cues, links, kwargs, tier):
    assert review_tier(status, cues, links, **kwargs)[0] == tier


def test_reasons_use_the_fixed_vocabulary():
    _, reasons = review_tier('edited', ['message', 'format'], [link('modified')], format_spec=True)
    assert reasons == ('pair-modified', 'format-spec') and set(reasons) <= set(REASONS)
