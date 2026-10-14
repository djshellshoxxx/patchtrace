"""S0 channels (05 s2.1, s6): C4n, C5t, C6 and C8 for the chosen pair of a decided row. Pure.

Everything comes from stored data: Ghidriff's decompiled text and callee names (by RVA, from the records of ANY
match, so a pair another source made out of an `added` and a `deleted` function still has code) and the stored
BinDiff flags of the exact pair. The IR channels C0-C3 and C7 are `unavailable` in S0. Deltas are located at
function entry RVAs (no instruction addresses without IR).
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence

from .. import keys
from ..addressing import AddressMap, parse_va_text
from ..contracts import Delta
from ..fusion.arbiter import Decided
from ..limits import DEFAULT_LIMITS, UnifiedLimits
from ..sources import SnapshotFunction, SnapshotMatch
from . import CALL_CLASSES, Evidence, severity
from .pseudo import FUNC_LABEL, Canon, canonicalize

S0_CHANNELS = ('C4', 'C5', 'C6', 'C8')
CHANGING_FLAGS = frozenset('GIELC')  # J alone is branch inversion (a hint); O is never set by BinDiff (R02 s7)
TEXT_LIMIT = 120


class PairMap:
    """Function RVAs mapped through `matched` rows with a tier A or M support (05 s2.7): the only targets that may
    count as mapped. Both sides of one row share one token, so equal code on both sides canonicalises equally."""

    def __init__(self, older: Mapping[int, str], newer: Mapping[int, str]):
        self._tokens = {'older': dict(older), 'newer': dict(newer)}

    @classmethod
    def from_pairs(cls, older_sha256: str, newer_sha256: str, pairs: Iterable[tuple[int, int]]) -> PairMap:
        older, newer = {}, {}
        for o, n in pairs:
            token = '@F:' + keys.row_id(older_sha256, newer_sha256, [o], [n])[:12]
            older[o], newer[n] = token, token
        return cls(older, newer)

    @classmethod
    def from_rows(cls, older_sha256: str, newer_sha256: str, rows: Iterable[Decided]) -> PairMap:
        return cls.from_pairs(older_sha256, newer_sha256, (r.pair for r in rows if r.mapped and r.pair))

    def token(self, side: str, rva: int) -> str | None:
        return self._tokens[side].get(rva)


def _show_number(token: str) -> str:
    if token.startswith('#'):
        value = int(token[1:])
        return str(value) if -9 <= value <= 9 else (f'0x{value:x}' if value >= 0 else f'-0x{-value:x}')
    return token[2:] if token[:2] in ('f:', 'c:', 'n:') else token


def _number_key(token: str) -> tuple:
    return (0, int(token[1:]), '') if token.startswith('#') else (1, 0, token)


def _short(text: object) -> str:
    from ...secondary.evidence_view import sanitize_text
    return sanitize_text(text, TEXT_LIMIT)


class FactsContext:
    """Per-run indexes over the snapshot, built once; `collect` is then O(code of the pair)."""

    def __init__(self, older_sha256: str, newer_sha256: str, addr: AddressMap, basis: str, pair_map: PairMap,
                 functions: Mapping[str, Mapping[int, SnapshotFunction]], names: Mapping[str, Mapping[str, int]],
                 modified: frozenset[tuple[int, int]], bindiff_flags: Mapping[tuple[int, int], tuple[str, ...]],
                 limits: UnifiedLimits):
        self.addr, self.basis, self.pair_map, self.limits = addr, basis, pair_map, limits
        self.functions, self.names = functions, names
        self.modified, self.bindiff_flags = modified, bindiff_flags
        self.older_sha256, self.newer_sha256 = older_sha256, newer_sha256

    @classmethod
    def build(cls, *, older_sha256: str, newer_sha256: str, addr: AddressMap, matches: Sequence[SnapshotMatch],
              rows: Sequence[Decided], bindiff_flags: Mapping[tuple[int, int], tuple[str, ...]],
              limits: UnifiedLimits = DEFAULT_LIMITS) -> FactsContext:
        ordered = sorted(matches, key=lambda m: m.id)
        older_values = [v for m in ordered for f in m.older if (v := parse_va_text(f.address)) is not None]
        newer_values = [v for m in ordered for f in m.newer if (v := parse_va_text(f.address)) is not None]
        basis = addr.set_basis(older_values, newer_values)
        functions: dict[str, dict[int, SnapshotFunction]] = {'older': {}, 'newer': {}}
        names: dict[str, dict[str, set[int]]] = {'older': {}, 'newer': {}}
        modified: set[tuple[int, int]] = set()
        if basis != 'not-comparable':
            def rva_of(side: str, function: SnapshotFunction) -> int | None:
                value = parse_va_text(function.address)
                return None if value is None else addr.to_rva(side, value, basis)
            for match in ordered:
                rvas: dict[str, list[int | None]] = {}
                for side, items in (('older', match.older), ('newer', match.newer)):
                    rvas[side] = [rva_of(side, f) for f in items]
                    for rva, function in zip(rvas[side], items, strict=True):
                        if rva is not None:
                            functions[side].setdefault(rva, function)
                            names[side].setdefault(function.name, set()).add(rva)
                if (match.category == 'modified' and len(match.older) == 1 and len(match.newer) == 1
                        and rvas['older'][0] is not None and rvas['newer'][0] is not None):
                    modified.add((rvas['older'][0], rvas['newer'][0]))
        unique = {side: {name: next(iter(found)) for name, found in table.items() if len(found) == 1}
                  for side, table in names.items()}
        return cls(older_sha256, newer_sha256, addr, 'va' if basis == 'not-comparable' else basis,
                   PairMap.from_rows(older_sha256, newer_sha256, rows), functions, unique, frozenset(modified),
                   dict(bindiff_flags), limits)

    # -- helpers -----------------------------------------------------------------------------------------------------

    def _over_cap(self, code: str | None) -> bool:
        return code is not None and (len(code) > self.limits.l29_pseudo_chars
                                     or code.count('\n') + 1 > self.limits.l29_pseudo_lines)

    def _identity(self, side: str, name: str) -> str:
        """Row token when the callee resolves to a mapped function, the name for a real name, a side-specific
        unmapped identity for a default `FUN_` label (F6: an unmatched callee is a semantic delta)."""
        found = FUNC_LABEL.match(name)
        if found is not None:
            rva = self.addr.to_rva(side, int(found.group(1), 16), self.basis)
        else:
            rva = self.names[side].get(name)
        token = self.pair_map.token(side, rva) if rva is not None else None
        if token is not None:
            return token
        if found is None:
            return name
        return f'@{"o" if side == "older" else "n"}:{rva:x}' if rva is not None else name

    # -- the pair ----------------------------------------------------------------------------------------------------

    def collect(self, row: Decided) -> Evidence:
        o, n = row.pair
        old, new = self.functions['older'].get(o), self.functions['newer'].get(n)
        states = dict.fromkeys(S0_CHANNELS, 'unavailable')
        limits_hit: list[str] = []
        found: list[tuple[Delta, frozenset[str]]] = []   # delta + the callee identities it is about
        canon_old: Canon | None = None
        canon_new: Canon | None = None
        if old is not None and new is not None:
            if old.code_omitted or new.code_omitted or self._over_cap(old.code) or self._over_cap(new.code):
                limits_hit.append('pseudo-cap')
            elif old.code is not None and new.code is not None:
                canon_old = canonicalize(old.code, 'older', self.pair_map, self.addr, self.basis, self.limits)
                canon_new = canonicalize(new.code, 'newer', self.pair_map, self.addr, self.basis, self.limits)

        def delta(cls: str, channel: str, before: str | None, after: str | None, tokens=()) -> None:
            found.append((Delta(cls=cls, channel=channel, older_rva=o, newer_rva=n,
                                old=None if before is None else _short(before),
                                new=None if after is None else _short(after)), frozenset(tokens)))

        c4_tokens: set[str] = set()
        c6_call_tokens: set[str] = set()
        conflicts = 0
        if old is not None and new is not None:
            names: dict[str, str] = {}
            old_ids = Counter(self._ident_named('older', c, names) for c in old.callees)
            new_ids = Counter(self._ident_named('newer', c, names) for c in new.callees)
            states['C4'] = 'equal' if old_ids == new_ids else 'differs'
            removed, added = sorted((old_ids - new_ids).elements()), sorted((new_ids - old_ids).elements())
            c4_tokens = set(removed) | set(added)
            if states['C4'] == 'differs':
                conflicts += self._calls(delta, 'C4', removed, added, lambda i: names.get(i, i))
        if canon_old is not None and canon_new is not None:
            states['C6'] = 'equal' if canon_old.tokens == canon_new.tokens else 'differs'
            literals_old = (Counter(canon_old.numbers), Counter(canon_old.strings))
            literals_new = (Counter(canon_new.numbers), Counter(canon_new.strings))
            states['C5'] = 'equal' if literals_old == literals_new else 'differs'
            call_removed = sorted((Counter(canon_old.calls) - Counter(canon_new.calls)).elements())
            call_added = sorted((Counter(canon_new.calls) - Counter(canon_old.calls)).elements())
            c6_call_tokens = set(call_removed) | set(call_added)
            if states['C4'] != 'differs' and states['C6'] == 'differs':  # callee lists do not show it: the text does
                conflicts += self._calls(delta, 'C6', call_removed, call_added, lambda i: i.lstrip('@'))
            self._pairs(delta, 'constant', 'C5', literals_old[0] - literals_new[0], literals_new[0] - literals_old[0],
                        _number_key, _show_number)
            self._pairs(delta, 'string', 'C5', literals_old[1] - literals_new[1], literals_new[1] - literals_old[1],
                        lambda t: (0, 0, t), lambda t: t)
            self._pairs(delta, 'comparison', 'C6', Counter(canon_old.relational) - Counter(canon_new.relational),
                        Counter(canon_new.relational) - Counter(canon_old.relational), lambda t: (0, 0, t),
                        lambda t: t)
            self._pairs(delta, 'condition', 'C6', Counter(canon_old.logical) - Counter(canon_new.logical),
                        Counter(canon_new.logical) - Counter(canon_old.logical), lambda t: (0, 0, t), lambda t: t)
            if states['C6'] == 'differs' and not found:
                delta('unknown', 'C6', None, None)
        flags = self.bindiff_flags.get((o, n))
        if flags is not None:
            states['C8'] = 'differs' if CHANGING_FLAGS & set(flags) else 'equal'
        found.sort(key=lambda item: severity(item[0]))
        anchors = tuple(self._anchor(d, tokens, states, c4_tokens, c6_call_tokens, flags) for d, tokens in found)
        targets = (len(canon_old.mapped) if canon_old else 0,
                   canon_old.unmapped + canon_new.unmapped if canon_old and canon_new else 0, conflicts)
        diff_types = tuple(sorted({*(old.diff_types if old else ()), *(new.diff_types if new else ())}))
        return Evidence(states=states, deltas=tuple(d for d, _ in found), anchors=anchors, targets=targets,
                        eh='unavailable', change_signal=(o, n) in self.modified, diff_types=diff_types,
                        limits_hit=tuple(limits_hit))

    # -- delta builders ----------------------------------------------------------------------------------------------

    def _ident_named(self, side: str, name: str, names: dict[str, str]) -> str:
        identity = self._identity(side, name)
        names.setdefault(identity, name)
        return identity

    @staticmethod
    def _calls(delta, channel: str, removed: list[str], added: list[str], show) -> int:
        """Replaced callees pair up in sorted order; the surplus is a call removed or added. Returns the number of
        replacements between two mapped rows (a conflict in the sense of 05 s2.7)."""
        conflicts = 0
        for before, after in zip(removed, added, strict=False):
            delta('callee', channel, show(before), show(after), (before, after))
            conflicts += before.startswith('@F:') and after.startswith('@F:')
        for before in removed[len(added):]:
            delta('call-removed', channel, show(before), None, (before,))
        for after in added[len(removed):]:
            delta('call-added', channel, None, show(after), (after,))
        return conflicts

    @staticmethod
    def _pairs(delta, cls: str, channel: str, removed: Counter, added: Counter, order, show) -> None:
        before, after = sorted(removed.elements(), key=order), sorted(added.elements(), key=order)
        for b, a in zip(before, after, strict=False):
            delta(cls, channel, show(b), show(a))
        for b in before[len(after):]:
            delta(cls, channel, show(b), None)
        for a in after[len(before):]:
            delta(cls, channel, None, show(a))

    @staticmethod
    def _anchor(d: Delta, tokens: frozenset[str], states: Mapping[str, str], c4_tokens: set[str],
                c6_call_tokens: set[str], flags: tuple[str, ...] | None) -> str | None:
        """05 s2.5 MAT-ANCHOR for S0: a callee-class delta needs ANOTHER data group (calls C4, decompiler C6,
        BinDiff C8) to show the same change; constants, strings, comparisons and conditions have no anchor here
        because C5 and C6 share the decompiler group."""
        if d.cls not in CALL_CLASSES:
            return None
        if d.channel != 'C4' and states['C4'] == 'differs' and tokens & c4_tokens:
            return 'C4'
        if d.channel != 'C6' and states['C6'] == 'differs' and tokens & c6_call_tokens:
            return 'C6'
        if states['C8'] == 'differs' and flags is not None and 'C' in flags:
            return 'C8'
        return None
