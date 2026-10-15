"""Blocked candidate generation for the residual stage (SPEC-31 04 s6.1): never an n x m matrix.

Every unmatched, content-eligible, non-hub function gets a set of tokens: called import keys, rare strings, rare
constants, matched callee / caller pair ids and 4 MinHash band signatures over its mnemonic 3-gram shingles, plus a size
bucket `floor(log2(n_insn))` and an n_bb bucket. Functions that share a token share a bucket; a pair is a candidate when
it shares >= 1 MinHash band OR >= 2 other tokens (the two size buckets never make a candidate). Per function and per
direction only the top L-22 candidates by shared-token count are kept (ties: lower rva). A bucket larger than L-23 on
either side is split by the size bucket, then the n_bb bucket; a bucket still too large abstains and is counted.

The mnemonic stream of a function is read on demand through the `MnemonicSource` port, only for unmatched eligible
functions (04 s6.1: "read on demand from `ins`"); an adapter over the real `IrReader` is a one-liner. MinHash, banding and
inverted-index blocking are textbook techniques (Broder 1997; locality-sensitive hashing), written here from the
description: no code of any other tool. All arithmetic is integer and every hash is blake2b, so the result is identical
on every platform and under any hash seed.
"""
from __future__ import annotations

import heapq
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import blake2b
from itertools import chain, islice
from typing import NamedTuple, Protocol

from ..limits import UnifiedLimits
from .side import K_EXTERNAL, SideData
from .state import State

SHINGLE = 3                                   # mnemonics per shingle
PERMUTATIONS = 16                             # MinHash rows: 4 bands x 4 rows
BANDS = 4
ROWS = PERMUTATIONS // BANDS
PADDING = frozenset({'nop', 'int3'})          # alignment padding is not part of a function's shape (A-27)
MNEMONIC_CHARS = 32                           # mnemonic text is untrusted: only a bounded prefix is hashed
_PRIME = (1 << 61) - 1
MAX_CACHED_SHINGLES = 100_000                 # ~700 bytes each: bounds the cache whatever the (untrusted) IR holds
MIN_SHARED = 2                                # non-size tokens that make a candidate without a shared band


class MnemonicSource(Protocol):
    """The mnemonics of one function in address order. The adapter over `IrReader` is
    `(i.mnem for i in reader.instructions(fid))`; the synthetic double reads the generated bodies."""

    def mnemonics(self, fid: int) -> Iterable[str]: ...


def _coefficient(index: int) -> tuple[int, int]:
    digest = blake2b(f'patchtrace/unified/minhash/{index}'.encode('ascii'), digest_size=16).digest()
    return int.from_bytes(digest[:8], 'big') % (_PRIME - 1) + 1, int.from_bytes(digest[8:], 'big') % _PRIME


class MinHasher:
    """MinHash signatures over mnemonic 3-gram shingles: 16 permutations `(a*h + b) mod 2^61-1` of the 64-bit blake2b
    shingle hash `h`. A shingle's 16 values are computed once and cached (up to `max_cached` shingles, then the cache
    restarts), so the cost is the number of DISTINCT shingles, not of functions."""

    def __init__(self, max_cached: int = MAX_CACHED_SHINGLES) -> None:
        self._coefficients = [_coefficient(i) for i in range(PERMUTATIONS)]
        self._rows: dict[tuple[str, ...], tuple[int, ...]] = {}
        self._max_cached = max_cached

    @property
    def cached_shingles(self) -> int:
        return len(self._rows)

    def signature(self, mnemonics: Iterable[str], limit: int) -> tuple[int, ...] | None:
        """The 16 minima, or None when the function has no complete shingle. At most `limit` instructions are read."""
        kept = [text for text in (mnemonic[:MNEMONIC_CHARS] for mnemonic in islice(mnemonics, limit))
                if text.lower() not in PADDING]
        shingles = set(zip(*(kept[offset:] for offset in range(SHINGLE)), strict=False))
        if not shingles:
            return None
        rows = self._rows
        if len(rows) > self._max_cached:          # a pure function: forgetting rows costs time, never changes a result
            rows.clear()
        columns = []
        for shingle in shingles:
            row = rows.get(shingle)
            if row is None:
                row = rows[shingle] = self._permute(shingle)
            columns.append(row)
        return tuple(map(min, zip(*columns, strict=True)))

    def _permute(self, shingle: tuple[str, ...]) -> tuple[int, ...]:
        text = '\x00'.join(shingle).encode('utf-8', 'backslashreplace')
        value = int.from_bytes(blake2b(text, digest_size=8).digest(), 'big') % _PRIME
        return tuple((a * value + b) % _PRIME for a, b in self._coefficients)


class Signatures:
    """The MinHash band tokens of the functions of one side, read through a `MnemonicSource` once per function."""

    def __init__(self, source: MnemonicSource, hasher: MinHasher, limit: int):
        self._source, self._hasher, self._limit = source, hasher, limit
        self._cache: dict[int, tuple[tuple, ...]] = {}

    def bands(self, fid: int) -> tuple[tuple, ...]:
        """`('m', band, (row values...))` per band; empty when the function has no signature."""
        cached = self._cache.get(fid)
        if cached is None:
            signature = self._hasher.signature(self._source.mnemonics(fid), self._limit)
            cached = () if signature is None else tuple(
                ('m', band, signature[band * ROWS:(band + 1) * ROWS]) for band in range(BANDS))
            self._cache[fid] = cached
        return cached


# ---- references and rare-token tables (shared with P16) ---------------------------------------------------------------------

class Refs(NamedTuple):
    """What a function refers to. `pairs` are `('c', pair id)` for matched callees and `('r', pair id)` for matched
    callers, the pair id being the OLDER member's fid on both sides; `unmatched` counts the references to functions
    without a pair; `imports` are the called import keys; `strings` the rare string hashes."""
    pairs: tuple[tuple[str, int], ...]
    unmatched: int
    imports: tuple[str, ...]
    strings: tuple[int, ...]


def import_sets(side: SideData) -> list[tuple[str, ...]]:
    return side.cached('residual:imports', lambda: [tuple(sorted({ikey for _c, ikey, _j in sites if ikey}))
                                                    for sites in side.sites])


def _rare(side: SideData, attr: str, max_functions: int) -> list[tuple[int, ...]]:
    def build() -> list[tuple[int, ...]]:
        counts: Counter[int] = Counter()
        column = getattr(side, attr)
        for items in column:
            counts.update(items)
        return [tuple(v for v in items if counts[v] <= max_functions) for items in column]
    return side.cached(f'residual:rare:{attr}:{max_functions}', build)


def rare_strings(side: SideData, limits: UnifiedLimits) -> list[tuple[int, ...]]:
    return _rare(side, 'strs', limits.l14_string_rare_functions)


def import_refs(side: SideData) -> Counter[str]:
    """How many functions of the side call each import."""
    return side.cached('residual:import-refs', lambda: Counter(chain.from_iterable(import_sets(side))))


def string_refs(side: SideData, limits: UnifiedLimits) -> Counter[int]:
    """How many functions of the side reference each rare string."""
    return side.cached(f'residual:string-refs:{limits.l14_string_rare_functions}',
                       lambda: Counter(chain.from_iterable(rare_strings(side, limits))))


def rare_constants(side: SideData, limits: UnifiedLimits) -> list[tuple[int, ...]]:
    return _rare(side, 'consts', limits.l15_const_rare_functions)


def side_of(st: State, letter: str) -> tuple[SideData, list[int], list[bool]]:
    """(columns, mate array, ICF-suspect flags) of side 'a' (older) or 'b' (newer)."""
    return (st.a, st.mate_a, st.icf_a) if letter == 'a' else (st.b, st.mate_b, st.icf_b)


def eligible(st: State, letter: str) -> list[int]:
    """Unmatched functions the residual stage may pair by content: I6 (normal, not oversize, not tiny), no hubs (only
    P01-P05 match those) and no ICF suspects (their alias names say N:M)."""
    side, mate, icf = side_of(st, letter)
    return [f for f in range(side.n) if mate[f] < 0 and side.content_ok[f] and not side.hub[f] and not icf[f]]


def references(st: State, letter: str, fid: int, *, hubs: bool) -> Refs:
    """The references of one function. A call to an external function is its import key, never a pair; with
    `hubs=False` a matched hub callee is left out (hubs are neither neighbours nor voters, 04 s5)."""
    side, mate, _icf = side_of(st, letter)
    pairs: list[tuple[str, int]] = []
    unmatched = 0
    for callee in side.callees[fid]:
        if side.kind[callee] == K_EXTERNAL:
            continue
        partner = mate[callee]
        if partner < 0:
            unmatched += 1
        elif hubs or not side.hub[callee]:
            pairs.append(('c', callee if letter == 'a' else partner))
    for caller in side.callers[fid]:
        partner = mate[caller]
        if partner < 0:
            unmatched += 1
        else:
            pairs.append(('r', caller if letter == 'a' else partner))
    return Refs(tuple(pairs), unmatched, import_sets(side)[fid], rare_strings(side, st.limits)[fid])


# ---- blocking ---------------------------------------------------------------------------------------------------------------

class Profile(NamedTuple):
    tokens: tuple            # the generative tokens, in a fixed order
    size: int                # floor(log2(n_insn))
    nbb: int                 # floor(log2(n_bb))


@dataclass(frozen=True)
class Blocked:
    """Candidate pairs of one blocking run. `older[x]` / `newer[y]` are the ascending candidate fids of each function:
    the union of both directions' top-K lists, so a function sees every rival that listed it (margins stay sound).
    `pairs` = distinct candidates (<= L-22 x functions), `work` = bucket members enumerated, `caps` = abstained
    buckets (`limits_hit: block-cap`)."""
    older: dict[int, tuple[int, ...]]
    newer: dict[int, tuple[int, ...]]
    pairs: int
    work: int
    caps: int
    profiles_older: dict[int, Profile]
    profiles_newer: dict[int, Profile]

    def tokens(self, letter: str, fid: int) -> frozenset:
        """All tokens of a function, the two size buckets included (the vocabulary of the P19 Jaccard)."""
        profile = (self.profiles_older if letter == 'a' else self.profiles_newer)[fid]
        return frozenset((*profile.tokens, ('z', profile.size), ('b', profile.nbb)))


def _profiles(st: State, letter: str, sigs: Signatures | None) -> dict[int, Profile]:
    side, _mate, _icf = side_of(st, letter)
    constants = rare_constants(side, st.limits)
    out: dict[int, Profile] = {}
    for fid in eligible(st, letter):
        st.budget.tick()
        refs = references(st, letter, fid, hubs=False)
        tokens = [*refs.pairs, *(('i', key) for key in refs.imports), *(('s', h) for h in refs.strings),
                  *(('k', value) for value in constants[fid])]
        if sigs is not None:
            tokens.extend(sigs.bands(fid))
        out[fid] = Profile(tuple(tokens), side.n_insn[fid].bit_length() - 1, max(side.n_bb[fid], 1).bit_length() - 1)
    return out


def _invert(profiles: dict[int, Profile]) -> dict[tuple, list[int]]:
    inverted: dict[tuple, list[int]] = {}
    for fid, profile in profiles.items():                  # ascending fid: every member list ascends
        for token in profile.tokens:
            members = inverted.get(token)
            if members is None:
                inverted[token] = [fid]
            else:
                members.append(fid)
    return inverted


def _group(members: list[int], profiles: dict[int, Profile], field: str) -> dict[int, list[int]]:
    out: dict[int, list[int]] = {}
    for fid in members:
        out.setdefault(getattr(profiles[fid], field), []).append(fid)
    return out


def _place(token: tuple, members_a: list[int], members_b: list[int], profiles_a: dict[int, Profile],
           profiles_b: dict[int, Profile], cap: int, out_a: dict, out_b: dict) -> int:
    """Put the buckets of one token that exist on both sides into `out_*`; return the number of abstained buckets.
    Keys: `token`, `(token, size)` or `(token, size, n_bb)`; a token tuple never has a tuple as first element."""
    if max(len(members_a), len(members_b)) <= cap:
        out_a[token], out_b[token] = members_a, members_b
        return 0
    abstained = 0
    by_size_b = _group(members_b, profiles_b, 'size')
    for size, size_a in _group(members_a, profiles_a, 'size').items():
        size_b = by_size_b.get(size)
        if not size_b:
            continue
        if max(len(size_a), len(size_b)) <= cap:
            out_a[(token, size)], out_b[(token, size)] = size_a, size_b
            continue
        by_nbb_b = _group(size_b, profiles_b, 'nbb')
        for nbb, nbb_a in _group(size_a, profiles_a, 'nbb').items():
            nbb_b = by_nbb_b.get(nbb)
            if not nbb_b:
                continue
            if max(len(nbb_a), len(nbb_b)) <= cap:
                out_a[(token, size, nbb)], out_b[(token, size, nbb)] = nbb_a, nbb_b
            else:
                abstained += 1
    return abstained


def _is_band(key: tuple) -> bool:
    token = key if type(key[0]) is str else key[0]
    return token[0] == 'm'


def _keys_of(buckets: dict[tuple, list[int]]) -> dict[int, list[tuple]]:
    keys: dict[int, list[tuple]] = {}
    for key, members in buckets.items():
        for fid in members:
            keys.setdefault(fid, []).append(key)
    return keys


def _rank(st: State, profiles: dict[int, Profile], own_keys: dict[int, list[tuple]], other_buckets: dict,
          other_profiles: dict[int, Profile], bands: set[tuple]) -> tuple[dict[int, list[int]], int]:
    """The top-K partners per function (K = L-22) by shared-token count, ties to the lower fid; plus the work done."""
    limit = st.limits.l22_candidates_per_function
    top: dict[int, list[int]] = {}
    work = 0
    for fid, profile in profiles.items():
        keys = own_keys.get(fid)
        if not keys:
            st.budget.tick()
            continue
        shared: Counter[int] = Counter()
        banded: set[int] = set()
        spent = 0
        for key in keys:
            members = other_buckets[key]
            spent += len(members)
            shared.update(members)
            if key in bands:
                banded.update(members)
        st.budget.tick(1 + spent)
        work += spent
        ranked = heapq.nsmallest(limit, ((-(count + (profile.size == other_profiles[other].size)
                                              + (profile.nbb == other_profiles[other].nbb)), other)
                                         for other, count in shared.items() if count >= MIN_SHARED or other in banded))
        if ranked:
            top[fid] = [other for _score, other in ranked]
    return top, work


def block(st: State, older_sigs: Signatures | None, newer_sigs: Signatures | None) -> Blocked:
    """Candidate pairs among the unmatched eligible functions of both sides. Read-only on `st`; the caller commits the
    counters. `*_sigs` None means no mnemonic stream is available: the other tokens still work."""
    profiles_a = _profiles(st, 'a', older_sigs)
    profiles_b = _profiles(st, 'b', newer_sigs)
    inverted_a, inverted_b = _invert(profiles_a), _invert(profiles_b)
    cap = st.limits.l23_bucket_cap
    buckets_a: dict[tuple, list[int]] = {}
    buckets_b: dict[tuple, list[int]] = {}
    caps = 0
    for token, members_a in inverted_a.items():
        members_b = inverted_b.get(token)
        if members_b:
            caps += _place(token, members_a, members_b, profiles_a, profiles_b, cap, buckets_a, buckets_b)
    bands = {key for key in buckets_a if _is_band(key)}
    top_a, work_a = _rank(st, profiles_a, _keys_of(buckets_a), buckets_b, profiles_b, bands)
    top_b, work_b = _rank(st, profiles_b, _keys_of(buckets_b), buckets_a, profiles_a, bands)
    pairs = {(x, y) for x, ys in top_a.items() for y in ys} | {(x, y) for y, xs in top_b.items() for x in xs}
    older: dict[int, list[int]] = {}
    newer: dict[int, list[int]] = {}
    for x, y in sorted(pairs):
        older.setdefault(x, []).append(y)
        newer.setdefault(y, []).append(x)
    return Blocked({x: tuple(ys) for x, ys in older.items()}, {y: tuple(xs) for y, xs in sorted(newer.items())},
                   len(pairs), work_a + work_b, caps, profiles_a, profiles_b)
