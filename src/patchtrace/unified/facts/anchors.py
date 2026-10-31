"""MAT-ANCHOR for the IR deltas (SPEC-31 05 s2.5, review R-08, S3). Pure.

A semantic delta seen by the first channel (C2, the bytes group) is promoted to `material` only when a second channel
of ANOTHER data group observes the SAME change; any other difference does not count:

| delta                          | anchored by                                                                           |
|--------------------------------|---------------------------------------------------------------------------------------|
| callee, call-added/removed     | C4 differs by exactly that callee pair; else C6 shows the call; else BinDiff flag C     |
| constant, struct-offset        | C6 shows the old -> new literal pair (a constant-only edit stays `review` without C6) |
| comparison, condition          | C6 shows a changed relational or logical operator                                      |
| data-ref                       | C6 shows the datum label change between two MAPPED data tokens                         |
| string                         | C6 shows the changed string literal (C5 is in the bytes group and never anchors)       |
| block-added/removed with a     | C3 block or edge counts differ; else BinDiff flag G                                    |
| store or call                  |                                                                                        |

`register-only`, `address-only`, `frame`, `eh`, `cfg` and `unknown` are never anchored: they stay `review`.
"""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from ..contracts import BLOCK_CLASSES, Delta
from . import CALL_CLASSES
from .irchannels import IrPair
from .operands import CallTarget, DeltaInfo
from .pseudo import Canon

_FIELD_OFFSET = re.compile(r'(?:^|_)0x([0-9a-fA-F]+)$')
MASKS = (0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)


@dataclass(frozen=True)
class AnchorInputs:
    states: Mapping[str, str]
    pair: IrPair
    canon_old: Canon | None
    canon_new: Canon | None
    bindiff_flags: tuple[str, ...] | None
    identity: Callable[[str, CallTarget | None], str | None]    # a callee as the canonical text names it
    data_token: Callable[[str, int], str | None]


def _removed_added(old: tuple, new: tuple) -> tuple[Counter, Counter]:
    return Counter(old) - Counter(new), Counter(new) - Counter(old)


def _literal_forms(value: int) -> set[str]:
    """How the decompiler may spell a machine constant: as is, negated (it prints `x - 7` for `add x, -7`) and as
    the unsigned view of every operand width."""
    forms = {value, -value, *(value & mask for mask in MASKS)}
    return {f'#{v}' for v in forms}


def _offsets(counter: Counter) -> set[int]:
    found = set()
    for token in counter:
        match = _FIELD_OFFSET.search(token)
        if match is not None:
            found.add(int(match.group(1), 16))
    return found


def _shows(counter: Counter, value: int | None, *, offsets: bool = False) -> bool:
    if value is None:
        return True
    # Type hints remain in C5/C6 equality; a machine-value anchor compares the numeric part only.
    values = {token.partition(':')[0] for token in counter if token.startswith('#')}
    return bool(_literal_forms(value) & values) or (offsets and value in _offsets(counter))


def _call_anchor(delta: Delta, info: DeltaInfo, inp: AnchorInputs) -> str | None:
    old_target, new_target = info.tokens
    pair, states = inp.pair, inp.states
    if delta.channel != 'C4' and states.get('C4') == 'differs' and (old_target or new_target) \
            and (old_target is None or old_target in pair.leftovers[0]) \
            and (new_target is None or new_target in pair.leftovers[1]):
        return 'C4'
    if states.get('C6') == 'differs' and inp.canon_old is not None and inp.canon_new is not None:
        removed, added = _removed_added(inp.canon_old.calls, inp.canon_new.calls)
        ids = (inp.identity('older', old_target), inp.identity('newer', new_target))
        if (ids[0] is not None and ids[0] in removed) or (ids[1] is not None and ids[1] in added):
            return 'C6'
    if states.get('C8') == 'differs' and inp.bindiff_flags is not None and 'C' in inp.bindiff_flags:
        return 'C8'
    return None


def _c6_texts(inp: AnchorInputs) -> tuple[Canon, Canon] | None:
    if inp.states.get('C6') == 'differs' and inp.canon_old is not None and inp.canon_new is not None:
        return inp.canon_old, inp.canon_new
    return None


def anchor_for(delta: Delta, info: DeltaInfo, inp: AnchorInputs) -> str | None:
    """The second channel (another data group, in state `differs`) that shows the same change, or None."""
    cls = delta.cls
    if cls in CALL_CLASSES:
        return _call_anchor(delta, info, inp)
    if cls in BLOCK_CLASSES:
        if not info.effect:
            return None
        if inp.pair.counts_differ and inp.states.get('C3') == 'differs':
            return 'C3'
        return 'C8' if inp.states.get('C8') == 'differs' and inp.bindiff_flags and 'G' in inp.bindiff_flags else None
    canon = _c6_texts(inp)
    if canon is None:
        return None
    old, new = canon
    if cls in ('constant', 'struct-offset'):
        if info.values == (None, None):
            return None
        removed, added = _removed_added(old.numbers, new.numbers)
        removed_tokens, added_tokens = _removed_added(old.tokens, new.tokens)
        offsets = cls == 'struct-offset'
        return 'C6' if (_shows(removed, info.values[0]) or (offsets and _shows(removed_tokens, info.values[0], offsets=True))) \
            and (_shows(added, info.values[1]) or (offsets and _shows(added_tokens, info.values[1], offsets=True))) \
            else None
    if cls in ('comparison', 'condition'):
        return 'C6' if (Counter(old.relational) != Counter(new.relational)
                        or Counter(old.logical) != Counter(new.logical)) else None
    if cls == 'data-ref':
        token_old = inp.data_token('older', info.data[0]) if info.data[0] is not None else None
        token_new = inp.data_token('newer', info.data[1]) if info.data[1] is not None else None
        if token_old is None or token_new is None:
            return None
        removed, added = _removed_added(old.tokens, new.tokens)
        return 'C6' if token_old in removed and token_new in added else None
    if cls == 'string':
        removed, added = _removed_added(old.strings, new.strings)
        return 'C6' if _string_shown(removed, info.strings[0]) and _string_shown(added, info.strings[1]) else None
    return None


def _string_shown(literals: Counter, prefix: str | None) -> bool:
    if prefix is None:
        return True
    if not prefix:
        return False
    for literal in literals:
        text = literal[1:-1].replace('\\"', '"') if len(literal) >= 2 else literal
        if text.startswith(prefix) or prefix.startswith(text) and text:
            return True
    return False
