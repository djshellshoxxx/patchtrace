"""WB3-S5 delta: value-hash identity, basis-gated claims, and the algebraic properties of the comparison."""
from __future__ import annotations

import hashlib
import random

import pytest
from test_strings_basis import basis, floss_parts

from patchtrace.intelligence.tools.normalize import FunctionPairing
from patchtrace.strings import contracts as c
from patchtrace.strings import delta as delta_module
from patchtrace.strings.delta import compute_delta
from patchtrace.strings.table import ENCODINGS, FLAG_SECRET, TYPES, StringRow, StringTable

PAIRING = FunctionPairing.empty()


def sha(text: str) -> bytes:
    return hashlib.sha256(text.encode()).digest()


def table(side, texts, *, kind='static', enc='ASCII', start=0x2000, step=0x20, base=None, flags=0):
    """Rows for `texts` at consecutive RVAs; `base` is the basis (default: built-in scan, static complete)."""
    rows = [StringRow(sha(t), TYPES.index(kind), ENCODINGS.index(enc), len(t), offset=start + i * step - 0x1400,
                      rva=start + i * step, display=t, flags=flags) for i, t in enumerate(texts)]
    return with_basis(rows, base or basis(side))


def with_basis(rows, base):
    base = base.model_copy(update={'rows_seen': len(rows), 'rows_kept': len(rows)})
    return StringTable.from_rows(base, rows)


def by_status(result):
    out = {}
    for change in result.changes:
        out.setdefault(change.status, []).append(change.display)
    return out


def test_relocated_string_is_in_both():
    older = table('older', ['alpha message', 'moved message here'])
    newer = table('newer', ['inserted text value', 'alpha message', 'moved message here'])
    result = compute_delta(older, newer, pairing=PAIRING)
    assert by_status(result) == {'only-newer': ['inserted text value']}
    assert result.counts['both'] == 2 and result.counts['relocated'] == 2


def test_only_older_and_only_newer():
    result = compute_delta(table('older', ['keep this one', 'drop this one']),
                           table('newer', ['keep this one', 'brand new text']), pairing=PAIRING)
    assert by_status(result) == {'only-older': ['drop this one'], 'only-newer': ['brand new text']}
    assert result.comparable and result.value_gate == 'unvalidated'


def test_encoding_only_change_is_representation_changed():
    result = compute_delta(table('older', ['plain text'], enc='ASCII'), table('newer', ['plain text'], enc='UTF-16LE'),
                           pairing=PAIRING)
    (change,) = result.changes
    assert change.status == 'representation-changed' and change.review_tier == 6
    assert change.older.encodings == ('ASCII',) and change.newer.encodings == ('UTF-16LE',)


def test_truncated_side_is_indeterminate():
    truncated = basis('newer', stages={'static': c.StageState(state='truncated')})
    result = compute_delta(table('older', ['gone away text']), table('newer', ['arrived text'], base=truncated),
                           pairing=PAIRING)
    assert sorted(by_status(result)) == ['indeterminate'] and len(result.changes) == 2
    assert {ch.review_tier for ch in result.changes} == {5} and result.basis_notes


def test_shorter_strings_are_dropped_from_both_sides_not_reported_removed():
    older = table('older', ['abcd', 'long enough text'], base=basis('older', min_length=4))
    newer = table('newer', ['long enough text'], base=basis('newer', min_length=6))
    result = compute_delta(older, newer, pairing=PAIRING)
    assert result.changes == () and result.harmonized.min_length == 6


def test_emulation_types_never_say_removed():
    def floss(side, texts):
        return table(side, texts, kind='decoded', base=basis(side, parts=floss_parts(('static', 'decoded'))))
    result = compute_delta(floss('older', ['build one value']), floss('newer', ['build two value']), pairing=PAIRING)
    assert {ch.status for ch in result.changes} == {'only-older', 'only-newer'}
    for change in result.changes:
        assert change.review_tier == 5 and any('absence is not evidence' in n for n in change.notes)
        assert not any('removed' in text.lower() or 'added' in text.lower() for text in (*change.notes, *change.reasons))


def test_emulation_on_one_side_is_not_compared():
    older = table('older', ['static text here'], base=basis('older', parts=floss_parts(('static',))))
    newer_rows = [StringRow(sha('decoded only text'), TYPES.index('decoded'), 0, 17, display='decoded only text'),
                  StringRow(sha('static text here'), 0, 0, 16, display='static text here', rva=0x2000, offset=0x600)]
    newer = with_basis(newer_rows, basis('newer', parts=floss_parts(('static', 'decoded'))))
    result = compute_delta(older, newer, pairing=PAIRING)
    assert result.changes == () and result.counts['not-compared-rows'] == 1


def test_non_comparable_delta_has_no_changes():
    other = basis('newer', parts=(c.BasisPart(source='builtin-scan', semantics_id='other/v2', types=('static',),
                                              config_digest='c' * 64),))
    result = compute_delta(table('older', ['some text']), table('newer', ['other text'], base=other),
                           pairing=PAIRING)
    assert not result.comparable and result.changes == () and result.basis_notes


def test_secret_is_redacted_in_the_change():
    result = compute_delta(table('older', []), table('newer', ['AKIAIOSFODNN7EXAMPLE']), pairing=PAIRING)
    (change,) = result.changes
    assert 'AKIA' not in change.display and change.display.startswith('[redacted') and 'secret-like' in change.cues


def test_flagged_secret_is_redacted_even_when_the_pattern_is_unknown():
    result = compute_delta(table('older', []), table('newer', ['hunter2 passphrase'], flags=FLAG_SECRET),
                           pairing=PAIRING)
    assert result.changes[0].display.startswith('[redacted')


def test_wrong_orientation_is_stale():
    with pytest.raises(c.StringsError) as raised:
        compute_delta(table('newer', ['x text']), table('older', ['y text']), pairing=PAIRING)
    assert raised.value.code == 'PT-STR-STALE'


def test_changes_are_capped_with_a_flag(monkeypatch):
    monkeypatch.setattr(delta_module, 'MAX_DELTA_ROWS', 3)
    result = compute_delta(table('older', []), table('newer', [f'new string number {i}' for i in range(5)]),
                           pairing=PAIRING)
    assert len(result.changes) == 3 and result.truncated and result.counts['only-newer'] == 5


# ---- properties ------------------------------------------------------------------------------------------------

POOL = [f'string value number {i}' for i in range(12)]
MIRROR = {'only-older': 'only-newer', 'only-newer': 'only-older', 'both': 'both',
          'representation-changed': 'representation-changed', 'edited': 'edited', 'indeterminate': 'indeterminate'}


def random_pair(seed):
    rng = random.Random(seed)
    return rng.sample(POOL, 7), rng.sample(POOL, 7)


def signature(result, side_swap=False):
    status = {c_.value_sha256: (MIRROR[c_.status] if side_swap else c_.status) for c_ in result.changes}
    return status, {c_.value_sha256: c_.id for c_ in result.changes}


@pytest.mark.parametrize('seed', range(6), ids=lambda s: f's{s}')
def test_swap_symmetry(seed):
    a, b = random_pair(seed)
    forward = compute_delta(table('older', a), table('newer', b), pairing=PAIRING)
    # The same two row sets, with the roles of the builds exchanged.
    backward = compute_delta(table('older', b), table('newer', a), pairing=PAIRING)
    assert signature(forward, side_swap=True)[0] == signature(backward)[0]
    assert forward.counts['only-older'] == backward.counts.get('only-newer', 0)


@pytest.mark.parametrize('shift', [0x40, 0x1000, 0x12340], ids=['0x40', '0x1000', '0x12340'])
def test_offset_shift_invariance(shift):
    a, b = random_pair(3)
    plain = compute_delta(table('older', a), table('newer', b), pairing=PAIRING)
    moved = compute_delta(table('older', a), table('newer', b, start=0x2000 + shift), pairing=PAIRING)
    keep = lambda r: [(ch.id, ch.status, ch.review_tier) for ch in r.changes if ch.status != 'both']  # noqa: E731
    assert keep(plain) == keep(moved)


@pytest.mark.parametrize('seed', range(5), ids=lambda s: f's{s}')
def test_row_order_does_not_matter(seed):
    a, b = random_pair(seed)
    shuffled_a, shuffled_b = a[:], b[:]
    random.Random(seed + 100).shuffle(shuffled_a)
    random.Random(seed + 200).shuffle(shuffled_b)
    first = compute_delta(table('older', a), table('newer', b), pairing=PAIRING)
    second = compute_delta(table('older', shuffled_a), table('newer', shuffled_b), pairing=PAIRING)
    assert signature(first) == signature(second)


def test_identical_tables_have_no_changes():
    assert compute_delta(table('older', POOL), table('newer', POOL), pairing=PAIRING).changes == ()

