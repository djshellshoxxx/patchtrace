"""The residual passes P16-P19 of the L1 ladder (SPEC-31 04 s6.2-s6.4), stages T4 and T5.

They run only on functions still unmatched after P01-P15 and propagation, through the `PassSpec.run` hook that
`ladder/passspec.py` provides for them; no file of the S2 ladder changes. A residual table is built per pair of IR sides
(`residual_passes(older, newer)`: the two optional `MnemonicSource`s are the sides' mnemonic streams for MinHash), and
the B-07 fallback "skip residual" is the pass table without them (`pass_table(residual=False)` is exactly `PASSES`).

* P16 reference vectors (clean-room from the Ghidra Version Tracking help text, 09 s2): features are matched
  callee / caller pair ids, called import keys and rare strings with weight `w = sqrt(-ln p)`; the dot product and the
  squared norms therefore sum `w^2 = -ln p`, which is what this module stores. Similarity is the cosine, confidence
  the dot product x 10; a pair is accepted as the mutual best of its blocked candidates with a margin. Tier B when the
  shared features span two types, else C.
* P17 block votes (DarunGrim / binkit: idea only) and P18 layout gaps (BinDiff address sequence: idea only): tier C.
* P19 assignment with rejection (QBinDiff / BinSlayer: idea only; the solver is `assign.py`): tier C.

Tier-C results are SOFT candidates (see `state.py`): they only become pairs after the last pass, and two candidates that
share an endpoint cancel each other. Every pass computes first and commits last (no budget check in between), so a
budget stop leaves nothing of an interrupted pass. All decisions are integer arithmetic (nano-nats from the correctly
rounded `decimal` logarithm, integer square roots for the cosine): the same result on every platform and hash seed.
"""
from __future__ import annotations

import dataclasses
import decimal
import math
from collections import Counter
from collections.abc import Sequence
from typing import NamedTuple

from ...enrichment.identity import domain_id
from ..limits import UnifiedLimits
from .assign import assign_with_rejection
from .blocking import (
    Blocked,
    MinHasher,
    MnemonicSource,
    Signatures,
    block,
    eligible,
    import_refs,
    import_sets,
    rare_strings,
    references,
    side_of,
    string_refs,
)
from .passes import FAMILY_STRUCT, PASSES, pass_table_digest, ratio_ok
from .passspec import PassSpec
from .side import K_EXTERNAL, K_NORMAL
from .state import SoftCand, State

RESIDUAL_VERSION = 'residual/1'      # bump on any change of a residual rule that the pass rows do not show
STAGE_REFERENCES = 5                 # T4: P16, P17, P18
STAGE_ASSIGNMENT = 6                 # T5: P19
NANO = 10 ** 9
MICRO = 10 ** 6
MILLI = 1000
AMBIGUOUS = 'residual-ambiguous'
MAX_ANCHORS = 4
_FEATURE_TYPE = {'c': 'pair', 'r': 'pair', 'i': 'import', 's': 'string'}
_DECIMAL = decimal.Context(prec=40, rounding=decimal.ROUND_HALF_EVEN)

# One row per pass (04 s4); the `run` hook is attached per pair of IR sides in `residual_passes`.
P16 = PassSpec('P16', 'ref-vector', STAGE_REFERENCES, 'B', FAMILY_STRUCT, 'E-RESID')
P17 = PassSpec('P17', 'bb-vote', STAGE_REFERENCES, 'C', FAMILY_STRUCT, 'E-RESID')
P18 = PassSpec('P18', 'layout-gap', STAGE_REFERENCES, 'C', FAMILY_STRUCT, 'E-LAYOUT')
P19 = PassSpec('P19', 'assignment', STAGE_ASSIGNMENT, 'C', FAMILY_STRUCT, 'E-RESID')
RESIDUAL_IDS = (P16.id, P17.id, P18.id, P19.id)


# ---- exact arithmetic --------------------------------------------------------------------------------------------------------

def nats_nano(count: int, total: int) -> int:
    """`round(-ln(count / total) * 10**9)` as an integer. The decimal logarithm is correctly rounded, so the value does
    not depend on the platform's libm (a float `log` may differ in the last bit between Linux and Windows)."""
    if count >= total:
        return 0
    ln_ratio = _DECIMAL.subtract(_DECIMAL.ln(decimal.Decimal(total)), _DECIMAL.ln(decimal.Decimal(max(count, 1))))
    return int(_DECIMAL.to_integral_value(_DECIMAL.scaleb(ln_ratio, 9)))


def cosine_micro(dot: int, norm_a: int, norm_b: int) -> int:
    """`floor(10**6 * dot / sqrt(norm_a * norm_b))` by an exact integer square root; 0 for an empty vector."""
    if dot <= 0 or norm_a <= 0 or norm_b <= 0:
        return 0
    return math.isqrt(dot * dot * MICRO * MICRO // (norm_a * norm_b))


def confident(dot: int, limits: UnifiedLimits) -> bool:
    """Confidence = dot product (nats) x 10 must reach L-20 (10.0): `dot_nano / 10**9 * 10 >= minimum_milli / 1000`."""
    return dot * 10 * MILLI >= limits.l20_confidence_min_milli * NANO


def _bump(st: State, name: str, count: int) -> None:
    """A counter only exists once something was counted (a zero would be noise in `Correspondence.stats`)."""
    if count:
        st.bump(name, count)


# ---- P16 feature weights and vectors -----------------------------------------------------------------------------------------

def incidences(st: State, letter: str) -> int:
    """F of one side: the number of feature references of all its functions, as `references(hubs=True)` lists them.
    Closed form over degrees: a matched non-external function is a matched callee of each of its callers and a matched
    caller of each of its callees."""
    side, mate, _icf = side_of(st, letter)
    total = sum(map(len, import_sets(side))) + sum(map(len, rare_strings(side, st.limits)))
    for fid in range(side.n):
        if mate[fid] >= 0:
            if side.kind[fid] != K_EXTERNAL:
                total += len(side.callers[fid])
            total += len(side.callees[fid])
    return total


class _Weights:
    """`-ln p_f` of every feature in nano-nats, `p_f = (refs_A + refs_B) / (F_A + F_B)` (04 s6.2). A function that
    refers to an unmatched function adds a feature with p = 0.5 that nothing can share (`unmatched`)."""

    def __init__(self, st: State):
        self._st = st
        self._total = incidences(st, 'a') + incidences(st, 'b')
        self._by_count: dict[int, int] = {}
        self.unmatched = nats_nano(1, 2)
        self._imports = (import_refs(st.a), import_refs(st.b))
        self._strings = (string_refs(st.a, st.limits), string_refs(st.b, st.limits))

    def _count(self, token: tuple) -> int:
        st, (kind, value) = self._st, token
        if kind == 'c':
            return len(st.a.callers[value]) + len(st.b.callers[st.mate_a[value]])
        if kind == 'r':
            return len(st.a.callees[value]) + len(st.b.callees[st.mate_a[value]])
        table = self._imports if kind == 'i' else self._strings
        return table[0][value] + table[1][value]

    def of(self, token: tuple) -> int:
        count = self._count(token)
        weight = self._by_count.get(count)
        if weight is None:
            weight = self._by_count[count] = nats_nano(count, self._total)
        return weight


class _Vectors:
    """Memoised `(feature -> weight, squared norm)` of the functions of both sides."""

    def __init__(self, st: State):
        self._st = st
        self._weights = _Weights(st)
        self._cache: dict[tuple[str, int], tuple[dict[tuple, int], int]] = {}

    def __call__(self, letter: str, fid: int) -> tuple[dict[tuple, int], int]:
        got = self._cache.get((letter, fid))
        if got is None:
            self._st.budget.tick()
            refs = references(self._st, letter, fid, hubs=True)
            features = {token: self._weights.of(token) for token in (
                *refs.pairs, *(('i', key) for key in refs.imports), *(('s', h) for h in refs.strings))}
            got = self._cache[(letter, fid)] = (
                features, sum(features.values()) + refs.unmatched * self._weights.unmatched)
        return got


Decision = tuple[int, int, str, tuple[tuple[int, int], ...]]        # older fid, newer fid, tier, anchor pairs


def _score_pairs(st: State, blocked: Blocked, vectors: _Vectors) -> tuple[dict[tuple[int, int], tuple[int, int]], int]:
    """(older, newer) -> (cosine in micro units, dot in nano-nats) for every blocked pair that shares a feature, and
    the number of pairs evaluated."""
    scores: dict[tuple[int, int], tuple[int, int]] = {}
    evaluated = 0
    for x, ys in blocked.older.items():
        features_x, norm_x = vectors('a', x)
        for y in ys:
            st.budget.tick()
            features_y, norm_y = vectors('b', y)
            evaluated += 1
            small, large = (features_x, features_y) if len(features_x) <= len(features_y) else (features_y, features_x)
            dot = sum(weight for token, weight in small.items() if token in large)
            if dot:
                scores[(x, y)] = (cosine_micro(dot, norm_x, norm_y), dot)
    return scores, evaluated


def _ranked(scores: dict[tuple[int, int], tuple[int, int]], index: int) -> dict[int, list[tuple[int, int]]]:
    """Per function the two best `(-cosine, other)` entries, best first, ties to the lower fid."""
    by_fid: dict[int, list[tuple[int, int]]] = {}
    for key, (cosine, _dot) in scores.items():
        by_fid.setdefault(key[index], []).append((-cosine, key[1 - index]))
    return {fid: sorted(entries)[:2] for fid, entries in by_fid.items()}


def _runner_up(entries: list[tuple[int, int]]) -> int:
    return -entries[1][0] if len(entries) > 1 else 0


def _evidence(st: State, vectors: _Vectors, x: int, y: int) -> tuple[str, tuple[tuple[int, int], ...]]:
    """Tier (B when the shared features span two types) and the shared matched pairs (<= 4, sorted) of an accepted pair."""
    features_y = vectors('b', y)[0]
    shared = [token for token in vectors('a', x)[0] if token in features_y]
    tier = 'B' if len({_FEATURE_TYPE[token[0]] for token in shared}) >= 2 else 'C'
    return tier, tuple(sorted((pid, st.mate_a[pid]) for kind, pid in shared if kind in 'cr'))[:MAX_ANCHORS]


def _decide(st: State, scores: dict[tuple[int, int], tuple[int, int]], vectors: _Vectors,
            ) -> tuple[list[Decision], list[tuple[int, int]]]:
    """Mutual best with a margin in both directions (L-20); `ambiguous` are the plausible pairs that failed on it."""
    limits = st.limits
    by_a, by_b = _ranked(scores, 0), _ranked(scores, 1)
    cosine_min, margin = limits.l20_cosine_min_milli * MILLI, limits.l20_margin_milli * MILLI
    decisions: list[Decision] = []
    ambiguous: list[tuple[int, int]] = []
    for x in sorted(by_a):
        st.budget.tick()
        best = by_a[x][0]
        cosine, y = -best[0], best[1]
        if cosine < cosine_min or not confident(scores[(x, y)][1], limits):
            continue
        back = by_b[y]
        if cosine - _runner_up(by_a[x]) < margin or back[0][1] != x or -back[0][0] - _runner_up(back) < margin:
            ambiguous.append((x, y))
            continue
        decisions.append((x, y, *_evidence(st, vectors, x, y)))
    return decisions, ambiguous


# ---- P19 buckets ------------------------------------------------------------------------------------------------------------

class _TimeCap(Exception):
    """L-24: the total LAP time is spent; the remaining buckets abstain."""


class _Assigned(NamedTuple):
    accepted: list[tuple[int, int]]
    ambiguous: list[tuple[int, int]]
    solved: int
    too_big: int
    timed_out: bool


def _similarities(st: State, blocked: Blocked) -> dict[tuple[int, int], int]:
    """Jaccard over the union of the two functions' tokens (6.1), in milli units, for every blocked pair. An internal
    ranking aid of this one source: never compared with another engine's score, never persisted."""
    tokens: dict[tuple[str, int], frozenset] = {}

    def token_set(letter: str, fid: int) -> frozenset:
        got = tokens.get((letter, fid))
        if got is None:
            got = tokens[(letter, fid)] = blocked.tokens(letter, fid)
        return got

    similarity: dict[tuple[int, int], int] = {}
    for x, ys in blocked.older.items():
        set_x = token_set('a', x)
        for y in ys:
            st.budget.tick()
            set_y = token_set('b', y)
            shared = len(set_x & set_y)
            similarity[(x, y)] = MILLI * shared // (len(set_x) + len(set_y) - shared)
    return similarity


def _components(st: State, edges: list[tuple[int, int]]) -> list[tuple[list[int], list[int]]]:
    """Connected components of the candidate pairs at or above the floor, as (older fids, newer fids), in the order of
    their smallest older fid. A pair below the floor can never be assigned, so it cannot connect anything."""
    shift = st.a.n
    parent: dict[int, int] = {}

    def find(node: int) -> int:
        root = node
        while parent.setdefault(root, root) != root:
            root = parent[root]
        while parent[node] != root:
            parent[node], node = root, parent[node]
        return root

    for x, y in edges:
        st.budget.tick()
        root_x, root_y = find(x), find(shift + y)
        if root_x != root_y:
            parent[max(root_x, root_y)] = min(root_x, root_y)
    rows: dict[int, set[int]] = {}
    cols: dict[int, set[int]] = {}
    for x, y in edges:
        root = find(x)
        rows.setdefault(root, set()).add(x)
        cols.setdefault(root, set()).add(y)
    return [(sorted(rows[root]), sorted(cols[root])) for root in sorted(rows, key=lambda r: min(rows[r]))]


def _assign(st: State, blocked: Blocked, similarity: dict[tuple[int, int], int]) -> _Assigned:
    """One LAP with reject columns per bucket (<= L-24 functions per side); an assignment is kept only if it beats the
    best alternative of BOTH functions by the L-24 margin. The LAP clock (L-24: 30 s in total) starts here."""
    limits = st.limits
    floor, margin = limits.l24_score_floor_milli, limits.l24_margin_milli
    clock = st.budget.clock
    started = clock()
    accepted: list[tuple[int, int]] = []
    ambiguous: list[tuple[int, int]] = []
    solved = too_big = 0

    def lap_tick(units: int) -> None:
        st.budget.tick(units)
        if clock() - started >= limits.l24_assign_budget_s:
            raise _TimeCap

    for rows, cols in _components(st, [pair for pair, value in similarity.items() if value >= floor]):
        if len(rows) > limits.l24_assign_bucket_cap or len(cols) > limits.l24_assign_bucket_cap:
            too_big += 1
            continue
        matrix = [[similarity.get((x, y), 0) for y in cols] for x in rows]
        try:
            picked = assign_with_rejection(matrix, floor=floor, scale=MILLI, tick=lap_tick)
        except _TimeCap:
            return _Assigned(accepted, ambiguous, solved, too_big, True)
        solved += 1
        for x, column in zip(rows, picked, strict=True):
            if column is None:
                continue
            y = cols[column]
            best = similarity[(x, y)]
            rival_x = max((similarity[(x, other)] for other in blocked.older[x] if other != y), default=0)
            rival_y = max((similarity[(other, y)] for other in blocked.newer[y] if other != x), default=0)
            (accepted if best - rival_x >= margin and best - rival_y >= margin else ambiguous).append((x, y))
    return _Assigned(accepted, ambiguous, solved, too_big, False)


# ---- the passes -----------------------------------------------------------------------------------------------------------------

class _Residual:
    """The four residual passes of one pair of IR sides; holds the mnemonic sources and, per ladder run, the MinHash
    signatures (cached per function, so P16 and P19 read each function's instructions once)."""

    def __init__(self, older: MnemonicSource | None, newer: MnemonicSource | None):
        self._sources = (older, newer)
        self._state: State | None = None
        self._sigs: tuple[Signatures | None, Signatures | None] = (None, None)

    def specs(self) -> tuple[PassSpec, ...]:
        return (dataclasses.replace(P16, run=self.ref_vectors), dataclasses.replace(P17, run=self.bb_votes),
                dataclasses.replace(P18, run=self.layout_gaps), dataclasses.replace(P19, run=self.assignment))

    def _block(self, st: State) -> tuple[Blocked, bool]:
        if self._state is not st:                 # a table reused for another run never sees stale signatures
            hasher, limit = MinHasher(), st.limits.l06_fn_instructions
            older, newer = (None if source is None else Signatures(source, hasher, limit) for source in self._sources)
            self._sigs, self._state = (older, newer), st
        return block(st, *self._sigs), any(sigs is None for sigs in self._sigs)

    @staticmethod
    def _count_blocking(st: State, spec: PassSpec, blocked: Blocked, missing_source: bool) -> None:
        _bump(st, f'blocked-pairs:{spec.id}', blocked.pairs)
        _bump(st, f'blocking-work:{spec.id}', blocked.work)
        _bump(st, f'no-mnemonics:{spec.id}', int(missing_source))
        if blocked.caps:
            st.limit_hit('block-cap', blocked.caps)

    @staticmethod
    def _note_ambiguous(st: State, spec: PassSpec, ambiguous: Sequence[tuple[int, int]]) -> None:
        _bump(st, f'ambiguous:{spec.id}', len(ambiguous))
        for x, y in ambiguous:
            st.note_conflict(x, y, AMBIGUOUS)

    # ---- P16 ----------------------------------------------------------------------------------------------------------------
    def ref_vectors(self, st: State, rnd: int) -> None:
        blocked, missing_source = self._block(st)
        vectors = _Vectors(st)
        scores, evaluated = _score_pairs(st, blocked, vectors)
        decisions, ambiguous = _decide(st, scores, vectors)
        self._count_blocking(st, P16, blocked, missing_source)       # commit: nothing below can raise BudgetExhausted
        _bump(st, f'evaluated:{P16.id}', evaluated)
        for x, y, tier, anchors in decisions:
            if tier == 'B':
                st.accept(x, y, pass_id=P16.id, step=P16.step, tier='B', family=P16.family, cls=P16.cls, rnd=rnd,
                          anchors=anchors)
            else:
                st.add_soft(SoftCand(x, y, P16.id, P16.step, P16.family, P16.cls, rnd, anchors=anchors))
        self._note_ambiguous(st, P16, ambiguous)

    # ---- P17 ----------------------------------------------------------------------------------------------------------------
    def bb_votes(self, st: State, rnd: int) -> None:
        """A rare block (`h1` of >= L-25 instructions, in exactly one unmatched function of each side) votes for that
        pair of functions; a pair needs >= L-25 votes and the majority of the votes of BOTH functions."""
        owners = []
        for letter in ('a', 'b'):
            side = side_of(st, letter)[0]
            owner: dict[int, int] = {}
            for fid in eligible(st, letter):
                st.budget.tick()
                for h1 in side.blocks[fid]:
                    owner[h1] = fid if h1 not in owner else -1      # -1: the block occurs in several functions
            owners.append(owner)
        votes: Counter[tuple[int, int]] = Counter()
        cast_a: Counter[int] = Counter()
        cast_b: Counter[int] = Counter()
        for h1, x in owners[0].items():
            st.budget.tick()
            y = owners[1].get(h1, -1)
            if x >= 0 and y >= 0:
                votes[(x, y)] += 1
                cast_a[x] += 1
                cast_b[y] += 1
        need = st.limits.l25_bb_min_votes
        for x, y, n in sorted((x, y, n) for (x, y), n in votes.items()
                              if n >= need and 2 * n > cast_a[x] and 2 * n > cast_b[y]):
            st.add_soft(SoftCand(x, y, P17.id, P17.step, P17.family, P17.cls, rnd, votes=n))

    # ---- P18 ----------------------------------------------------------------------------------------------------------------
    def layout_gaps(self, st: State, rnd: int) -> None:
        """Between two consecutive accepted pairs whose order is monotone on both sides, a gap of exactly L-26
        unmatched functions per side pairs its functions in order, if every pair passes the size-ratio guard."""
        gap = st.limits.l26_gap_functions
        anchors = sorted((pair.older_fid, pair.newer_fid) for pair in st.pairs)
        chosen: list[tuple[int, int, tuple[tuple[int, int], ...]]] = []
        for (a1, b1), (a2, b2) in zip(anchors, anchors[1:], strict=False):
            st.budget.tick()
            if b2 <= b1 or a2 - a1 - 1 != gap or b2 - b1 - 1 != gap:       # not monotone, or not a gap of L-26 per side
                continue
            slots = list(zip(range(a1 + 1, a2), range(b1 + 1, b2), strict=True))
            if all(self._layout_ok(st, x, y) for x, y in slots):
                chosen.extend((x, y, ((a1, b1), (a2, b2))) for x, y in slots)
        for x, y, bracket in chosen:
            st.add_soft(SoftCand(x, y, P18.id, P18.step, P18.family, P18.cls, rnd, anchors=bracket))

    @staticmethod
    def _layout_ok(st: State, x: int, y: int) -> bool:
        a, b = st.a, st.b
        return (st.mate_b[y] < 0 and a.kind[x] == K_NORMAL and b.kind[y] == K_NORMAL and not a.oversize[x]
                and not b.oversize[y] and not a.hub[x] and not b.hub[y] and not st.icf_a[x] and not st.icf_b[y]
                and ratio_ok(a.size[x], b.size[y], st.limits))

    # ---- P19 ----------------------------------------------------------------------------------------------------------------
    def assignment(self, st: State, rnd: int) -> None:
        blocked, missing_source = self._block(st)
        similarity = _similarities(st, blocked)
        outcome = _assign(st, blocked, similarity)
        self._count_blocking(st, P19, blocked, missing_source)       # commit: nothing below can raise BudgetExhausted
        _bump(st, f'evaluated:{P19.id}', len(similarity))
        _bump(st, 'lap-buckets', outcome.solved)
        if outcome.too_big:
            st.limit_hit('assign-bucket-cap', outcome.too_big)
        if outcome.timed_out:
            st.limit_hit('assign-time-cap')
        for x, y in sorted(outcome.accepted):
            st.add_soft(SoftCand(x, y, P19.id, P19.step, P19.family, P19.cls, rnd))
        self._note_ambiguous(st, P19, sorted(outcome.ambiguous))


# ---- the tables -----------------------------------------------------------------------------------------------------------------

def residual_passes(older: MnemonicSource | None = None, newer: MnemonicSource | None = None) -> tuple[PassSpec, ...]:
    """P16-P19 as `PassSpec`s (stages 5 and 6). `older` / `newer` give each side's mnemonic stream for the MinHash
    tokens; without them blocking still works on the other tokens (stat `no-mnemonics:<pass>`). The table is bound to
    those two sources: build one per pair of IR sides."""
    return _Residual(older, newer).specs()


def pass_table(*, residual: bool = True, older: MnemonicSource | None = None,
               newer: MnemonicSource | None = None) -> tuple[PassSpec, ...]:
    """The ladder's pass table. `residual=False` is the B-07 fallback and is exactly the S2 table `PASSES`."""
    return (*PASSES, *residual_passes(older, newer)) if residual else PASSES


def table_digest(passes: Sequence[PassSpec] = PASSES) -> str:
    """The `pass_table_digest` input of `keys.config_digest` for any table. Without residual passes it IS the S2 digest
    (so the B-07 fallback keeps every existing result key); with them it also covers `RESIDUAL_VERSION`, which stands for
    the rules the pass rows cannot show (MinHash shape, feature weights, the majority and margin rules)."""
    base = pass_table_digest(passes)
    if not any(spec.id in RESIDUAL_IDS for spec in passes):
        return base
    return domain_id('unified-pass-table-residual', 1, {'table': base, 'residual': RESIDUAL_VERSION})
