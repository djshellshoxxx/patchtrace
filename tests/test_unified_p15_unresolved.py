"""Regression for SPEC-31 P15: unknown callees never establish exact call identity.

Synthetic state only. These tests do not establish live Ghidra matching accuracy.
"""
from __future__ import annotations

from types import SimpleNamespace

from patchtrace.unified.ladder.passes import _rehash_keys, rehash_exact


def _state(older_sites, newer_sites):
    """Minimal ladder state with unmatched callers and a recording accept seam."""
    def side(sites):
        return SimpleNamespace(
            n=1, content_ok=[True], hub=[False], h1=['same-masked-body'], sites=[sites]
        )

    st = SimpleNamespace(
        a=side(older_sites), b=side(newer_sites),
        mate_a=[-1], mate_b=[-1], pair_a=[-1], pair_b=[-1],
        icf_a=[False], icf_b=[False], pairs=[],
        budget=SimpleNamespace(tick=lambda: None),
        bump=lambda _: None,
        limit_hit=lambda _: (_ for _ in ()).throw(AssertionError('rehash repeated without progress')),
    )
    accepted = []

    def accept(a, b, **kw):
        accepted.append((a, b, kw))
        st.mate_a[a], st.mate_b[b] = b, a

    st.accept = accept
    return st, accepted


def test_unresolved_direct_callee_cannot_create_p15_exact_match():
    # Old and new targets may differ even though the body mask and jump kind coincide.
    st, accepted = _state([(-1, '', False)], [(-1, '', False)])
    assert _rehash_keys(st, 'a')[0] == {}
    assert _rehash_keys(st, 'b')[0] == {}
    rehash_exact(st, 4)
    assert accepted == []


def test_any_unknown_call_blocks_entire_p15_rehash_not_just_that_token():
    # A known import call cannot 'launder' a second unknown call into exact evidence.
    sites = [(-1, 'kernel32!CreateFileW', False), (-1, '', True)]
    st, accepted = _state(sites, sites)
    rehash_exact(st, 4)
    assert accepted == []


def test_identified_import_call_still_supports_p15_matching():
    sites = [(-1, 'kernel32!CreateFileW', False)]
    st, accepted = _state(sites, sites)
    rehash_exact(st, 4)
    assert len(accepted) == 1
    assert accepted[0][:2] == (0, 0)
    assert accepted[0][2]['pass_id'] == 'P15'
    assert accepted[0][2]['tier'] == 'A'


def test_missing_call_key_is_not_equivalent_to_known_import_key():
    older = [(-1, '', False)]
    newer = [(-1, 'kernel32!CreateFileW', False)]
    st, accepted = _state(older, newer)
    rehash_exact(st, 4)
    assert accepted == []
