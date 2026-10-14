"""Persisted identities must not move when canonical JSON gets faster: the optimized `_normalize`
is checked byte for byte (and error for error) against the original implementation kept here."""
from __future__ import annotations

import json
import unicodedata
from collections import OrderedDict
from collections.abc import Mapping
from types import MappingProxyType

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.enrichment import identity


def _reference_normalize(value):  # verbatim copy of the pre-Phase-D implementation
    if isinstance(value, str):
        return unicodedata.normalize('NFC', value)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise TypeError('floats are not permitted in identity payloads')
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError('identity payload keys must be strings')
            normalized = unicodedata.normalize('NFC', key)
            if normalized in out:
                raise ValueError('keys collide after NFC normalization')
            out[normalized] = _reference_normalize(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_reference_normalize(item) for item in value]
    raise TypeError(f'unsupported identity payload type {type(value).__name__}')


def _reference(value) -> bytes:
    return json.dumps(_reference_normalize(value), sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _outcome(fn, value):
    try:
        return ('ok', fn(value))
    except (TypeError, ValueError) as exc:
        return (type(exc).__name__, str(exc))


TEXT = st.text(alphabet=st.sampled_from(['a', 'Z', '_', '1', 'e', '́', 'é', 'Å', 'A', '̊',
                                         '\U0001f600', '"', '\\', '\n', ' ']), max_size=6)
SCALARS = st.one_of(st.none(), st.booleans(), st.integers(min_value=-2**70, max_value=2**70), TEXT,
                    st.floats(allow_nan=False, allow_infinity=False), st.just(1.0))
VALUES = st.recursive(SCALARS, lambda inner: st.one_of(
    st.lists(inner, max_size=4), st.lists(inner, max_size=4).map(tuple),
    st.dictionaries(TEXT, inner, max_size=4),
    st.dictionaries(st.one_of(TEXT, st.integers(0, 3)), inner, max_size=3),
    st.dictionaries(TEXT, inner, max_size=3).map(OrderedDict),
    st.dictionaries(TEXT, inner, max_size=3).map(MappingProxyType)), max_leaves=12)


@settings(max_examples=400, deadline=None)
@given(VALUES)
def test_canonical_json_matches_reference(value):
    assert _outcome(identity.canonical_json, value) == _outcome(_reference, value)


@pytest.mark.parametrize('value', [
    {'é': 1, 'é': 2},  # NFC key collision
    {'k': {1, 2}}, {'k': b'x'}, {'k': object()}, [1.5], {'a': [{'b': float('nan')}]},
    True, 0, -1, 2**80, 'plain', '', {'': None}, [[], {}, ()],
])
def test_canonical_json_edge_cases_match_reference(value):
    assert _outcome(identity.canonical_json, value) == _outcome(_reference, value)


def _reference_domain_id(domain, version, payload) -> str:
    import hashlib
    data = b'patchtrace\x00' + domain.encode('ascii') + b'\x00' + str(version).encode('ascii') + b'\x00'
    return hashlib.sha256(data + _reference(payload)).hexdigest()


def _reference_sorted_unique(items):
    seen = {_reference(item): item for item in items}
    return [seen[key] for key in sorted(seen)]


OCCURRENCES = st.lists(st.fixed_dictionaries({
    'diff_id': st.just('d' * 64), 'side': st.sampled_from(['older', 'newer']),
    'address': st.one_of(st.none(), st.integers(0, 2**64 - 1)), 'name': TEXT, 'ordinal': st.integers(0, 3)}),
    max_size=4)


@settings(max_examples=300, deadline=None)
@given(OCCURRENCES, OCCURRENCES, st.booleans())
def test_pairing_and_signal_ids_match_reference(older, newer, manual):
    expected = _reference_domain_id('pairing', 1, {
        'diff_id': 'd' * 64, 'category': 'modified', 'manual': manual,
        'older': _reference_sorted_unique(older), 'newer': _reference_sorted_unique(newer)})
    assert identity.pairing_id('d' * 64, 'modified', manual, older, newer) == expected
    expected = _reference_domain_id('signal', 1, {'pairing_id': 'p', 'detector': 'BND', 'detector_version': 2,
                                                  'group_key': 'g', 'locations': _reference_sorted_unique(older)})
    assert identity.signal_id('p', 'BND', 2, 'g', older) == expected


def test_known_identities_are_pinned():
    """Values computed with the original implementation (2026-10-14) before the fast path landed."""
    assert identity.domain_id('t', 1, {'b': [1, 'x'], 'a': 'é'}) == \
        '96d7f1b050d2722dbbeb14125b1089a5b9a0729ea844ec242ff1842a170afb32'
    diff = 'a' * 64
    assert identity.pairing_id(diff, 'modified', False, [identity.occurrence(diff, 'older', 0x140001000, 'FUN_1', 0)],
                               [identity.occurrence(diff, 'newer', None, 'fé', 0)]) == \
        '901af2aa8f69f05e43cc08c7d2392ebdeb3bb14e219528bbeb52593e52581f77'


# --- signals._clean fast path: identical output to the original char loop ------------------------

def _reference_clean(lines):  # verbatim copy of the pre-Phase-D implementation
    out, in_block = [], False
    for line in lines:
        buf, i, n = [], 0, len(line)
        while i < n:
            c = line[i]
            if in_block:
                if line.startswith('*/', i):
                    in_block, i = False, i + 2
                else:
                    i += 1
                continue
            if line.startswith('/*', i):
                in_block, i = True, i + 2
                buf.append(' ')
            elif line.startswith('//', i):
                break
            elif c in '"\'':
                j = i + 1
                while j < n and line[j] != c:
                    j += 2 if line[j] == '\\' else 1
                buf.append(c + c)
                i = j + 1
            else:
                buf.append(c)
                i += 1
        out.append(''.join(buf))
    return out


LINES = st.lists(st.text(alphabet=st.sampled_from(['a', ' ', '/', '*', '"', "'", '\\', 'x', '(', ';']), max_size=12),
                 max_size=6).map(tuple)


@settings(max_examples=500, deadline=None)
@given(LINES)
def test_clean_matches_reference(lines):
    from patchtrace.enrichment import signals
    assert signals._clean(lines) == _reference_clean(lines)
