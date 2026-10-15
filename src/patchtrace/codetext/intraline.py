"""Token marks for one displayed row pair (WBQ S8, `codetext/1`): which tokens differ, and how much to believe it. Pure.

The panes pair rows by position inside a replace hunk, so a pair is two lines that may or may not be the same
statement. `diff_row(old, new, language)` compares them as token sequences (whitespace ignored) after masking the two
kinds of name that move without the code changing: Ghidra address-derived names and numbers with positive address
evidence (`address`), and decompiler temporaries (`temp`). Everything else is compared by spelling, so a named callee,
a constant, a register or an operator that differs is a `changed` mark, never masked.

* `changed`: the spellings differ (a lexical hint, not a behavioural claim: `ecx` to `edx` is a different register,
  nothing more). A target oracle can turn an address pair into a `changed` callee when the run pairs one of the two
  functions with something else; a rename oracle can do the same for a temporary pair that contradicts a
  function-wide renaming.
* `address-only`: only an address-derived name differs. Drawn, muted, never "cosmetic": the target is not verified
  unless the oracle says the run pairs them.
* `rename-maybe`: only a temporary's name differs. It may be the decompiler renumbering or a real change of variable;
  it is counted apart and never silenced.

Alignment. Among the alignments with the fewest inserted and removed tokens, the one with the fewest renames with a
different spelling, then the fewest address pairs with a different spelling, then the fewest runs of change is taken
(dynamic programming over what remains after the shared head and tail). The four counts belong to the pair and not to
the argument order, so swapping the two lines swaps the sides and keeps the changed tokens, the renames, the address
pairs, the number of changes and the gate; only how equally good alignments group the changed tokens into marks may
differ.

Gate. A row is skipped, with the status copy "paired by position only", when fewer than 80 % of the tokens (both
sides together, masked) are shared, unless the difference is a single token replaced, inserted or removed
(`SMALL_EDIT`): a short line such as `return 0;` shares too little to pass any ratio yet is plainly one edit. The
shared count is measured first, bit-parallel and without a table, so a mispaired row costs a few big-integer steps.

Bounds. A line is skipped above `MAX_LINE_CHARS` characters or `MAX_PAIR_TOKENS` tokens. A row that passes the gate
gets a table only as wide as its exact distance needs (a path with D inserted or removed tokens stays within
(D + |n - m|) / 2 diagonals of the main one, so the band is exact, not a heuristic); it evaluates at most
`MAX_DP_CELLS` cells, and a pair that needs more is skipped, never approximated.
"""
from __future__ import annotations

import re
from typing import NamedTuple

from .marks import Mark, RowMarks
from .names import AUTO_NAME, parse_auto_name
from .operands import CONDITIONAL_JUMPS, Operand, OperandSource, TextOperandSource, asm_mnemonic
from .oracle import NullOracle, NullRenameOracle, RenameOracle, Target, TargetOracle
from .tokens import MAX_LINE_CHARS, Language, Token, tokenize_line

SIMILARITY_GATE = 0.8
SMALL_EDIT = 2  # inserted plus removed tokens that are always marked, whatever the similarity
MAX_PAIR_TOKENS = 256
MAX_DP_CELLS = 8_192
NO_DIFFERENCE = 'No token-level differences on this line.'
_SNIPPET_CHARS = 40
_LISTED = 3
# Each field of the alignment cost has to stay below the next one's weight: runs <= 512, address pairs and rename
# pairs <= 256 each, so the sum of the lower fields is below 2**30 and the distance is `cost >> 30`.
_INF = 1 << 62
_W_RUN, _W_ADDRESS, _W_TEMP, _W_GAP = 1, 1 << 10, 1 << 20, 1 << 30
_RELATIONAL = frozenset({'<', '<=', '>', '>=', '==', '!='})
_LOGICAL = frozenset({'&&', '||', '!'})
# Characters that could reorder, hide or break a line of the summary: C0 and C1 controls, no-break and other
# spaces, bidirectional controls, zero-width and default-ignorable characters, line and paragraph separators, the
# BOM, variation selectors, tags and lone surrogates. Spelled with \U escapes so that this file holds none of them.
_UNSAFE = re.compile(
    r'[\x00-\x1f\x7f-\xa0\xad\U0000034f\U0000061c\U0000115f\U00001160\U00001680\U000017b4\U000017b5'
    r'\U0000180b-\U0000180f\U00002000-\U0000200f\U00002028-\U0000202f\U0000205f-\U0000206f\U00002800'
    r'\U00003000\U00003164\U0000d800-\U0000dfff\U0000fe00-\U0000fe0f\U0000feff\U0000ffa0\U0000fff0-\U0000fffb'
    r'\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff]')
_CALL_OPERANDS = frozenset({'symbol', 'auto_name', 'number'})
_TEXT_SOURCE = TextOperandSource()
_NULL_TARGETS = NullOracle()
_NULL_RENAMES = NullRenameOracle()
_new = tuple.__new__  # builds a _Tok without NamedTuple's Python-level __new__: a pane pair is hundreds of tokens


class _Tok(NamedTuple):
    kind: str
    start: int
    end: int
    text: str
    key: str  # equal keys may be paired; a masked token's key drops its address digits or its number
    weight: int  # cost of pairing the token with a different spelling; 0 when its key is its spelling
    operand: Operand | None
    target: Target | None
    call: bool  # a callee: a name followed by `(` in C, an operand of `call` in assembly


class _Measure(NamedTuple):
    head: int  # leading tokens spelled alike on both lines
    tail: int  # trailing ones
    shared: int  # tokens a best alignment pairs
    distance: int  # tokens it inserts plus removes


class _Alignment(NamedTuple):
    pairs: list[tuple[int, int]] | None  # (older index, newer index) of every paired token; None: does not fit
    distance: int
    cells: int  # dynamic-programming cells evaluated


class _Event(NamedTuple):
    state: str
    label: str
    old: tuple[int, int] | None  # code point range on the older line
    new: tuple[int, int] | None
    note: str = ''  # why an oracle made it a change
    detail: str = ''  # address-only: the target state; rename-maybe: the rename state


def _key(kind: str, text: str, operand: Operand | None) -> tuple[str, int]:
    """The comparison key of a token and the cost of pairing it with a different spelling (0: it is never masked)."""
    if kind == 'temp':
        return '~', _W_TEMP
    if kind == 'auto_name':
        match = AUTO_NAME.fullmatch(text)
        if match:
            return '@' + text[:match.start('address')], _W_ADDRESS
    elif operand is not None and operand.cls == 'address':
        return '#', _W_ADDRESS
    return kind + ':' + text, 0


def _is_call(kind: str, language: Language, mnemonic: str, line: str, following: Token | None) -> bool:
    """A callee: a name followed by `(` in C, an operand of `call` in assembly."""
    if language == 'asm':
        return mnemonic == 'call' and kind in _CALL_OPERANDS
    if kind == 'symbol':
        return True
    return kind == 'auto_name' and following is not None and line[following.start:following.end] == '('


def _prepare(line: str, language: Language, in_comment: bool, source: OperandSource) -> list[_Tok] | None:
    """The non-blank tokens of a line with their masked keys, or None when there are more than MAX_PAIR_TOKENS."""
    found = tokenize_line(line, language, in_comment).tokens
    kept = [index for index, token in enumerate(found) if token.kind != 'ws']
    if len(kept) > MAX_PAIR_TOKENS:
        return None
    operands = source.operands(line, found, language)
    mnemonic = asm_mnemonic(line, found)[1] if language == 'asm' else ''
    out = []
    for position, index in enumerate(kept):
        token = found[index]
        kind, text = token.kind, line[token.start:token.end]
        operand = operands.get(index)
        key, weight = _key(kind, text, operand)
        target = operand.target if operand else None
        if target is None and kind == 'auto_name':
            parsed = parse_auto_name(text)
            target = Target(parsed.kind, parsed.address) if parsed else None
        following = found[kept[position + 1]] if position + 1 < len(kept) else None
        call = _is_call(kind, language, mnemonic, line, following)
        out.append(_new(_Tok, (kind, token.start, token.end, text, key, weight, operand, target, call)))
    return out


def _same(a: _Tok, b: _Tok) -> bool:
    return a.key == b.key and a.text == b.text


def _lcs_length(a: list[_Tok], b: list[_Tok]) -> int:
    """Length of a longest common subsequence of the keys of two token lists. Bit-parallel (Hyyro, 2004): one step of
    big-integer arithmetic per token of `a`, about len(a) * len(b) / 64 word operations in all."""
    where: dict[str, int] = {}
    for index, token in enumerate(b):
        where[token.key] = where.get(token.key, 0) | (1 << index)
    ones = vector = (1 << len(b)) - 1
    for token in a:
        hits = vector & where.get(token.key, 0)
        vector = ((vector + hits) | (vector - hits)) & ones
    return len(b) - vector.bit_count()


def _measure(old: list[_Tok], new: list[_Tok]) -> _Measure:
    """How many tokens a best alignment pairs: the shared head and tail first (exact spelling, always part of a best
    alignment), then the common subsequence of what is left."""
    n, m = len(old), len(new)
    head = 0
    while head < min(n, m) and _same(old[head], new[head]):
        head += 1
    tail = 0
    while tail < min(n, m) - head and _same(old[n - 1 - tail], new[m - 1 - tail]):
        tail += 1
    shared = head + tail + _lcs_length(old[head:n - tail], new[head:m - tail])
    return _Measure(head, tail, shared, n + m - 2 * shared)


def _cells(n: int, m: int, band: int) -> int:
    """Cells of an (n + 1) x (m + 1) table within `band` diagonals of the main one."""
    return sum(min(m, i + band) - max(0, i - band) + 1 for i in range(n + 1))


def _table(a: list[_Tok], b: list[_Tok], band: int) -> tuple[list[list[int]], list[list[int]], int]:
    """Cost of the best alignment of a[:i] with b[:j] ending in a pairing (f0) or in an insertion or removal (f1),
    for every cell within `band` diagonals of the main one. Column index is j - i + band + 1, so one padding column
    on each side stays infinite and a neighbour outside the band reads as unreachable."""
    n, m = len(a), len(b)
    width = 2 * band + 3
    f0 = [[_INF] * width for _ in range(n + 1)]
    f1 = [[_INF] * width for _ in range(n + 1)]
    f0[0][band + 1] = 0
    cells = 0
    run_gap = _W_GAP + _W_RUN
    for i in range(n + 1):
        row0, row1 = f0[i], f1[i]
        up0, up1, left = (f0[i - 1], f1[i - 1], a[i - 1]) if i else (row0, row1, None)
        for j in range(max(0, i - band), min(m, i + band) + 1):
            cells += 1
            x = j - i + band + 1
            if left is not None and j and left.key == b[j - 1].key:
                best = up0[x] if up0[x] < up1[x] else up1[x]
                if best < _INF:
                    row0[x] = best + (0 if left.text == b[j - 1].text else left.weight)
            gap = _INF
            if i:  # removing a[i - 1], from the cell above
                gap = up0[x + 1] + run_gap
                if up1[x + 1] + _W_GAP < gap:
                    gap = up1[x + 1] + _W_GAP
            if j:  # inserting b[j - 1], from the cell to the left
                if row0[x - 1] + run_gap < gap:
                    gap = row0[x - 1] + run_gap
                if row1[x - 1] + _W_GAP < gap:
                    gap = row1[x - 1] + _W_GAP
            if gap < _INF:
                row1[x] = gap
    return f0, f1, cells


def _trace(a: list[_Tok], b: list[_Tok], f0: list[list[int]], f1: list[list[int]],
           band: int) -> list[tuple[int, int]]:
    """The paired tokens of the best alignment, walking the table back from its far corner. Ties are broken in a
    fixed order, so the alignment is deterministic."""
    i, j = len(a), len(b)
    state = 0 if f0[i][j - i + band + 1] <= f1[i][j - i + band + 1] else 1
    pairs = []
    run_gap = _W_GAP + _W_RUN
    while i or j:
        x = j - i + band + 1
        if state == 0:  # reached by pairing a[i - 1] with b[j - 1]
            left = a[i - 1]
            before = f0[i][x] - (0 if left.text == b[j - 1].text else left.weight)
            pairs.append((i - 1, j - 1))
            i, j = i - 1, j - 1
            state = 0 if f0[i][x] == before else 1
            continue
        here = f1[i][x]  # reached by removing a[i - 1] or inserting b[j - 1], from a state that was or was not a run
        if i and f0[i - 1][x + 1] + run_gap == here:
            i, state = i - 1, 0
        elif i and f1[i - 1][x + 1] + _W_GAP == here:
            i, state = i - 1, 1
        elif j and f0[i][x - 1] + run_gap == here:
            j, state = j - 1, 0
        else:
            j, state = j - 1, 1
    pairs.reverse()
    return pairs


def _pair_tokens(old: list[_Tok], new: list[_Tok], measure: _Measure) -> _Alignment:
    """The best alignment of two token lists whose `measure` is known; `pairs` is None when the table it needs would
    exceed `MAX_DP_CELLS`."""
    n, m = len(old), len(new)
    a, b = old[measure.head:n - measure.tail], new[measure.head:m - measure.tail]
    pairs = [(k, k) for k in range(measure.head)]
    cells = 0
    if a and b:
        band = (measure.distance + abs(len(a) - len(b))) // 2
        if _cells(len(a), len(b), band) > MAX_DP_CELLS:
            return _Alignment(None, measure.distance, 0)
        f0, f1, cells = _table(a, b, band)
        pairs += [(measure.head + i, measure.head + j) for i, j in _trace(a, b, f0, f1, band)]
    pairs += [(n - measure.tail + k, m - measure.tail + k) for k in range(measure.tail)]
    return _Alignment(pairs, measure.distance, cells)


def _align(old: list[_Tok], new: list[_Tok]) -> _Alignment:
    return _pair_tokens(old, new, _measure(old, new))


def _is_target(token: _Tok) -> bool:
    return token.kind in ('symbol', 'auto_name') or (token.operand is not None and token.operand.cls == 'address')


def _target_label(old: _Tok, new: _Tok) -> str:
    kinds = {token.target.kind for token in (old, new) if token.target}
    if old.call or new.call or 'function' in kinds:
        return 'callee'
    return 'cfg' if kinds == {'label'} else 'data-ref'


def _pair_label(old: _Tok, new: _Tok) -> str:
    """The `ChangeClass` of one token replaced by one other, or `token` when no class describes it."""
    if _is_target(old) and _is_target(new):
        return _target_label(old, new)
    if old.kind != new.kind:
        return 'token'
    kind = old.kind
    if kind == 'register':
        return 'register-only'
    if kind == 'number':
        classes = {token.operand.cls for token in (old, new) if token.operand}
        return 'frame' if classes == {'stack'} else 'struct-offset' if classes == {'memory'} else 'constant'
    if kind == 'char':
        return 'constant'
    if kind == 'string':
        return 'string'
    if kind == 'op':
        if old.text in _RELATIONAL and new.text in _RELATIONAL:
            return 'comparison'
        if old.text in _LOGICAL and new.text in _LOGICAL:
            return 'condition'
    if kind == 'mnemonic' and old.text.lower() in CONDITIONAL_JUMPS and new.text.lower() in CONDITIONAL_JUMPS:
        return 'condition'
    return 'token'


def _run_label(removed: list[_Tok], added: list[_Tok]) -> str:
    if removed and added:
        return _pair_label(removed[0], added[0]) if len(removed) == len(added) == 1 else 'token'
    run = removed or added
    if any(token.call for token in run):
        return 'call-removed' if removed else 'call-added'
    return 'token'


def _span(tokens: list[_Tok]) -> tuple[int, int] | None:
    return (tokens[0].start, tokens[-1].end) if tokens else None


def _masked_event(old: _Tok, new: _Tok, targets: TargetOracle, renames: RenameOracle) -> _Event:
    """The event for two masked tokens whose spelling differs: a rename, or an address pair."""
    where = ((old.start, old.end), (new.start, new.end))
    if old.kind == 'temp':
        verdict = renames.rename_state(old.text, new.text)
        if verdict == 'conflict':
            return _Event('changed', 'token', *where, note='inconsistent rename')
        return _Event('rename-maybe', 'name-only', *where, detail='consistent' if verdict == 'consistent' else 'unknown')
    verdict = targets.target_state(old.target, new.target) if old.target and new.target else 'unmapped'
    if verdict == 'conflict':
        return _Event('changed', _target_label(old, new), *where, note='not a matched pair')
    return _Event('address-only', 'address-only', *where, detail='mapped' if verdict == 'mapped' else 'unmapped')


def _events(old: list[_Tok], new: list[_Tok], pairs: list[tuple[int, int]], targets: TargetOracle,
            renames: RenameOracle) -> list[_Event]:
    events = []
    before_old = before_new = -1
    for i, j in (*pairs, (len(old), len(new))):
        removed, added = old[before_old + 1:i], new[before_new + 1:j]
        if removed or added:
            events.append(_Event('changed', _run_label(removed, added), _span(removed), _span(added)))
        if i < len(old) and old[i].text != new[j].text:
            events.append(_masked_event(old[i], new[j], targets, renames))
        before_old, before_new = i, j
    return events


def _snippet(text: str) -> str:
    """A printable rendering of untrusted code text for a one-line status sentence, cut at `_SNIPPET_CHARS` characters
    as they are shown: a control or invisible character is written as `<U+202E>`, so it can neither hide nor reorder
    the sentence."""
    shown, size = [], 0
    for char in text:
        piece = f'<U+{ord(char):04X}>' if _UNSAFE.match(char) else char
        if size + len(piece) > _SNIPPET_CHARS:
            return ''.join(shown) + '...'
        shown.append(piece)
        size += len(piece)
    return ''.join(shown)


def _plural(count: int, word: str) -> str:
    return word if count == 1 else word + 's'


def _listed(items: list[str]) -> str:
    shown = ', '.join(items[:_LISTED])
    return shown if len(items) <= _LISTED else f'{shown} and {len(items) - _LISTED} more'


def _arrow(event: _Event, old_line: str, new_line: str) -> str:
    old = _snippet(old_line[slice(*event.old)]) if event.old else '(none)'
    new = _snippet(new_line[slice(*event.new)]) if event.new else '(none)'
    return f'{old} -> {new}'


def _target_phrase(events: list[_Event]) -> str:
    mapped = sum(1 for event in events if event.detail == 'mapped')
    count = len(events)
    if mapped == 0:
        return f'{_plural(count, "target")} not verified'
    if mapped == count:
        return f'{_plural(count, "target")} paired by this run'
    return f'{mapped} of {count} targets paired by this run, the rest not verified'


def _summary(events: list[_Event], old_line: str, new_line: str, row: int, rows: int) -> str:
    if not events:
        return NO_DIFFERENCE
    changed = [e for e in events if e.state == 'changed']
    renamed = [e for e in events if e.state == 'rename-maybe']
    moved = [e for e in events if e.state == 'address-only']
    parts = []
    if changed:
        items = [f'{e.label} {_arrow(e, old_line, new_line)}' + (f' ({e.note})' if e.note else '') for e in changed]
        parts.append(f'{len(changed)} {_plural(len(changed), "change")}: {_listed(items)}')
    if renamed:
        sure = 'consistent' if all(e.detail == 'consistent' for e in renamed) else 'possible'
        items = [_arrow(e, old_line, new_line) for e in renamed]
        parts.append(f'{len(renamed)} {sure} {_plural(len(renamed), "rename")} ({_listed(items)})')
    if moved:
        items = [_arrow(e, old_line, new_line) for e in moved]
        lead = 'address-only difference' if len(moved) == 1 else f'{len(moved)} address-only differences'
        parts += [f'{lead} ({_listed(items)})', _target_phrase(moved)]
    return f'Line {row + 1} of {rows}: ' + '; '.join(parts) + '.'


def long_line_sentence(row: int) -> str:
    return f'Line {row + 1} is longer than {MAX_LINE_CHARS:,} characters; shown without colours or token marks.'


def _skipped(row: int, similarity: float | None, reason: str, summary: str, work: int = 0) -> RowMarks:
    return RowMarks(row, (), (), similarity, True, summary, reason, work)


def diff_row(old: str, new: str, language: Language, *, row: int = 0, rows: int = 1, old_in_comment: bool = False,
             new_in_comment: bool = False, source: OperandSource = _TEXT_SOURCE,
             targets: TargetOracle = _NULL_TARGETS, renames: RenameOracle = _NULL_RENAMES) -> RowMarks:
    """Token marks for the older line `old` and the newer line `new`, which the panes show on the same row.

    `row` and `rows` (0-based row, row count) only word the sentence ("Line 8 of 15"). `*_in_comment` is whether a
    `/* */` comment is open at the start of the line (`tokens.open_comment_lines`). The marks are lexical hints:
    nothing here says a difference matters, or that a masked one does not."""
    if old == new:
        return RowMarks(row, (), (), 1.0, False, NO_DIFFERENCE)
    if len(old) > MAX_LINE_CHARS or len(new) > MAX_LINE_CHARS:
        return _skipped(row, None, 'long-line', long_line_sentence(row))
    first = _prepare(old, language, old_in_comment, source)
    second = _prepare(new, language, new_in_comment, source)
    if first is None or second is None:
        return _skipped(row, None, 'tokens', f'Line {row + 1} has more than {MAX_PAIR_TOKENS} tokens; '
                                              'token marks skipped.')
    measure = _measure(first, second)
    total = len(first) + len(second)
    similarity = 2 * measure.shared / total if total else 1.0
    # A ratio of integers below 513 is either exactly 0.8 or at least 1e-6 away from it: the comparison is exact.
    if similarity < SIMILARITY_GATE and measure.distance > SMALL_EDIT:
        percent = 200 * measure.shared // total  # rounded down, so a gated row never prints the gate itself
        return _skipped(row, similarity, 'similarity', 'Lines are paired by position only '
                                                       f'(similarity {percent / 100:.2f}); token marks skipped.')
    alignment = _pair_tokens(first, second, measure)
    if alignment.pairs is None:
        return _skipped(row, None, 'size', f'Line {row + 1} differs in too many places to compare within the work '
                                           'limit; token marks skipped.')
    events = _events(first, second, alignment.pairs, targets, renames)
    return RowMarks(
        row,
        tuple(Mark('older', e.old[0], e.old[1], e.state, e.label) for e in events if e.old),
        tuple(Mark('newer', e.new[0], e.new[1], e.state, e.label) for e in events if e.new),
        similarity, False, _summary(events, old, new, row, rows), '', alignment.cells)
