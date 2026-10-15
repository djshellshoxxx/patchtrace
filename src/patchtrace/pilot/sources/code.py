"""Code-side core of the pilot adapters: Ghidriff rows resolved to RVAs, the candidate universe with its pairing
verdicts, and B1 signals as observations (PIL-integration-plan.md s4, s7, s9 PIL-A3).

A candidate is identified exactly like a SPEC-31 row (`keys.candidate_key`: older/newer SHA-256 plus sorted RVAs), so a
Ghidriff row and the unified row that pairs the same functions are one candidate. The shared pieces live here because
every code-side adapter needs them: `build_observation` (origin tags from the registry, plain text), `CandidateIndex`
(which candidates hold a function) and `GhidriffRows` (match id to candidate key, which is how B1 signals and call labels
find their candidate).

B1 evidence is lexical: it reads Ghidra's decompiled text, so a lead that rests on it alone carries the "text evidence
only" flag (`TEXT_ONLY_REASON`) until typed ChangeFacts are supplied. B1's confidence is a function of the detector
(`enrichment.signals.DETECTORS`); the observation does not repeat it.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from ...enrichment.contracts import SignalSet
from ...enrichment.signals import NOT_APPLICABLE as B1_NOT_APPLICABLE
from ...models import FunctionMatch, FunctionRecord
from ...secondary.contracts import SecondaryMatchSet
from ...secondary.evidence import assess_reports
from ...secondary.reconcile import reconcile
from ...unified.addressing import AddressMap, parse_va_text
from ..contracts import (
    MAX_SIDE_FUNCTIONS,
    Candidate,
    ChannelStatus,
    FunctionRef,
    Nav,
    Observation,
    ObsRef,
    clean_line,
)
from ..keys import candidate_key, make_observation
from ..limits import DEFAULT_LIMITS, Budget, PilotError, PilotLimits
from ..origins import DefaultOriginRegistry
from ..ports import ChangeEvidenceSource, OriginRegistry

MAX_PER_CANDIDATE = 64  # per adapter: four adapters stay inside P-02 (256 observations per lead)
TEXT_ONLY_REASON = 'text evidence only: no typed ChangeFacts, so decompiler-text heuristics are the ceiling'
DEFAULT_REGISTRY = DefaultOriginRegistry()
# s7 identity map, secondary half (the unified half is `unified.IDENTITY_OF_DECISION`): never both sources at once.
IDENTITY_OF_VERDICT: Mapping[str, str] = MappingProxyType({
    'corroborated': 'corroborated', 'contested': 'contested', 'single-engine': 'unassessed',
    'insufficient': 'unassessed'})
_UNUSABLE_SEVERITY = ('not-run', 'stale', 'unsupported', 'failed')  # least to most serious
_USABLE = ('available', 'partial')
Side = Literal['older', 'newer']


def channel_status(channel: str, state: str, reason: str | None = None) -> ChannelStatus:
    text = clean_line(reason, 200) if reason else ''
    return ChannelStatus(channel=channel, state=state, reason=text or None)


def build_observation(registry: OriginRegistry, *, source: str, channel: str, kind: str, role: str, verification: str,
                      evidence_class: str, ref_kind: str, ref_id: str, detail: str, ref_pointer: str | None = None,
                      ref_sha256: str | None = None, nav: Nav | None = None, anchors: Iterable[str] = (),
                      obligations: Iterable[str] = ()) -> Observation:
    """One ledger entry. Origin tags come from the registry by evidence source (an unknown source fails closed), and
    every piece of free text is cut to plain text first: tool, decompiler and symbol text is untrusted."""
    return make_observation(
        channel=channel, kind=kind, role=role, verification=verification, origins=registry.tags_for(source),
        evidence_class=evidence_class, obligations=tuple(sorted(set(obligations))),
        anchor_ids=tuple(sorted(set(anchors))), nav=nav,
        ref=ObsRef(kind=ref_kind, id=clean_line(ref_id, 256) or ref_kind, pointer=ref_pointer, sha256=ref_sha256),
        detail=clean_line(detail) or kind)


def settle(items: Iterable[Observation], limit: int = MAX_PER_CANDIDATE) -> tuple[tuple[Observation, ...], int]:
    """One candidate's observations deduplicated by content, ordered by id (an input order never shows) and cut at
    `limit`; also how many were cut."""
    unique = sorted({o.obs_id: o for o in items}.values(), key=lambda o: o.obs_id)
    return tuple(unique[:limit]), max(0, len(unique) - limit)


def lookup(table: Mapping[str, Sequence[Observation]], candidate_keys: Iterable[str]) -> Iterator[tuple[str, Observation]]:
    """`ChangeEvidenceSource.observations` over a prepared table: requested candidates only, in key order."""
    for key in sorted(set(candidate_keys)):
        for observation in table.get(key, ()):
            yield key, observation


# --- Ghidriff rows resolved to RVAs ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class ResolvedMatch:
    """One Ghidriff row with the RVA of each function (sorted by RVA) and its candidate key."""
    match: FunctionMatch
    older: tuple[tuple[int, FunctionRecord], ...]
    newer: tuple[tuple[int, FunctionRecord], ...]
    candidate_key: str

    def functions(self, side: Side) -> tuple[tuple[int, FunctionRecord], ...]:
        return self.older if side == 'older' else self.newer

    def refs(self, side: Side) -> tuple[FunctionRef, ...]:
        """The first `MAX_SIDE_FUNCTIONS` functions of a side; the key still names all of them."""
        return tuple(FunctionRef(rva=rva, name=clean_line(record.name, 256) or None)
                     for rva, record in self.functions(side)[:MAX_SIDE_FUNCTIONS])

    def wide(self) -> bool:
        return len(self.older) > MAX_SIDE_FUNCTIONS or len(self.newer) > MAX_SIDE_FUNCTIONS

    def pair(self) -> tuple[tuple[int, FunctionRecord], tuple[int, FunctionRecord]] | None:
        """The (older, newer) function of a 1:1 row; None for one-sided and group rows."""
        return (self.older[0], self.newer[0]) if len(self.older) == len(self.newer) == 1 else None


@dataclass(frozen=True)
class GhidriffRows:
    """The rows of one Ghidriff run that can be tied to the two PE images, deduplicated by candidate key.

    A row whose function has no usable address is left out and counted, never guessed; a set of addresses that does not
    fit the images in one consistent basis resolves nothing (the rule of the unified engine, 06 s1)."""
    older_sha256: str
    newer_sha256: str
    run_id: str | None
    rows: tuple[ResolvedMatch, ...]
    by_match: Mapping[str, ResolvedMatch]
    unresolved: int
    state: Literal['available', 'unsupported', 'not-run']
    reason: str | None

    @classmethod
    def resolve(cls, older_sha256: str, newer_sha256: str, matches: Iterable[FunctionMatch], addr: AddressMap | None,
                *, limits: PilotLimits = DEFAULT_LIMITS, budget: Budget | None = None) -> GhidriffRows:
        ordered = sorted(matches, key=lambda m: m.id)
        runs = {m.run_id for m in ordered}
        if len(runs) > 1:
            raise PilotError('PT-PILOT-INPUT', 'The Ghidriff rows belong to more than one analysis run',
                             reason='mixed-runs')
        run_id = next(iter(runs), None)

        def nothing(state: Literal['unsupported', 'not-run'], reason: str) -> GhidriffRows:
            return cls(older_sha256, newer_sha256, run_id, (), MappingProxyType({}), 0, state, reason)
        if not ordered:
            return nothing('not-run', 'there is no completed Ghidriff run')
        if addr is None:
            return nothing('unsupported', 'the PE image layout of a file is unavailable')
        basis = addr.set_basis(*_addresses(ordered))
        if basis == 'not-comparable':
            return nothing('unsupported', 'function addresses do not fit the PE image layouts in one address basis')
        rows: dict[str, ResolvedMatch] = {}
        by_match: dict[str, ResolvedMatch] = {}
        unresolved = 0
        for match in ordered:
            if budget is not None:
                budget.tick()
            found = _resolve(match, addr, basis, older_sha256, newer_sha256)
            if found is None:
                unresolved += 1
                continue
            if found.candidate_key not in rows:
                if len(rows) >= limits.p01_candidates:
                    raise PilotError('PT-PILOT-LIMIT', 'The candidate universe exceeds the limit',
                                     reason='candidates')
                rows[found.candidate_key] = found
            by_match[match.id] = rows[found.candidate_key]
        return cls(older_sha256, newer_sha256, run_id, tuple(rows.values()), MappingProxyType(by_match), unresolved,
                   'available', None)


def _address(record: FunctionRecord) -> int | None:
    """A function's address as an int; a file offset, an `EXTERNAL:` key and junk are no address."""
    return None if record.address_space == 'file-offset' else parse_va_text(record.address)


def _addresses(matches: Iterable[FunctionMatch]) -> tuple[list[int], list[int]]:
    """Every usable address per side, for the basis decision over the whole set."""
    found: dict[str, list[int]] = {'older': [], 'newer': []}
    for match in matches:
        for side, records in (('older', match.older), ('newer', match.newer)):
            found[side] += [v for r in records if (v := _address(r)) is not None]
    return found['older'], found['newer']


def _resolve(match: FunctionMatch, addr: AddressMap, basis: str, older_sha256: str,
             newer_sha256: str) -> ResolvedMatch | None:
    sides: dict[str, tuple[tuple[int, FunctionRecord], ...]] = {}
    for side, records in (('older', match.older), ('newer', match.newer)):
        found = []
        for record in records:
            value = _address(record)
            rva = None if value is None else addr.to_rva(side, value, basis)  # type: ignore[arg-type]
            if rva is None:
                return None
            found.append((rva, record))
        found.sort(key=lambda item: item[0])
        if len({rva for rva, _ in found}) != len(found):
            return None  # two records at one address cannot be told apart
        sides[side] = tuple(found)
    key = candidate_key(older_sha256, newer_sha256, [r for r, _ in sides['older']], [r for r, _ in sides['newer']])
    return ResolvedMatch(match, sides['older'], sides['newer'], key)


class CandidateIndex:
    """Which candidates hold a function (side, RVA): how function-attributed evidence finds its candidates. A function
    can belong to several candidates (alternative pairings, groups); evidence about it attaches to each of them."""

    def __init__(self, candidates: Iterable[Candidate]):
        table: dict[tuple[str, int], set[str]] = {}
        for candidate in candidates:
            for side, refs in (('older', candidate.older), ('newer', candidate.newer)):
                for ref in refs:
                    table.setdefault((side, ref.rva), set()).add(candidate.candidate_key)
        self._table = {where: tuple(sorted(found)) for where, found in table.items()}

    def keys_at(self, side: str, rva: int) -> tuple[str, ...]:
        return self._table.get((side, rva), ())


# --- the candidate universe from Ghidriff rows and secondary-engine verdicts ----------------------------------------------


class GhidriffPairing:
    """`PairingSource` for a project without a current unified result: every resolved Ghidriff row is a candidate and its
    identity comes from the secondary engines (BinDiff, rz-diff) by the cross-engine verdict of `secondary.evidence`.

    Only sets for this exact pair count. A set for another pair, or for the reversed orientation, is ignored and named in
    the status; two usable sets of one engine are an input error. No engine, no verdict: every identity is `unassessed`."""

    def __init__(self, rows: GhidriffRows, secondary: Sequence[SecondaryMatchSet] = ()):
        self._rows = rows
        used, other, reverse = [], 0, 0
        for match_set in sorted(secondary, key=lambda s: (s.engine, s.entry_id)):
            pair = (match_set.older_sha256, match_set.newer_sha256)
            if pair == (rows.older_sha256, rows.newer_sha256):
                used.append(match_set)
            elif pair == (rows.newer_sha256, rows.older_sha256):
                reverse += 1
            else:
                other += 1
        if len({s.engine for s in used}) != len(used):
            raise PilotError('PT-PILOT-INPUT', 'Two secondary sets of one engine were supplied',
                             reason='secondary-sets')
        self._used = tuple(used)
        identity = self._identities(used)
        self._candidates = tuple(sorted((
            Candidate(candidate_key=row.candidate_key, older=row.refs('older'), newer=row.refs('newer'),
                      identity=identity.get(row.match.id, 'unassessed'))  # type: ignore[arg-type]
            for row in rows.rows), key=lambda c: c.candidate_key))
        self._status = self._summary(len(used), other, reverse)

    def _identities(self, used: Sequence[SecondaryMatchSet]) -> dict[str, str]:
        if not used:
            return {}
        reports = tuple(reconcile([row.match for row in self._rows.rows], s) for s in used)
        return {e.match_id: IDENTITY_OF_VERDICT[e.verdict] for e in assess_reports(reports).rows}

    def _summary(self, used: int, other: int, reverse: int) -> ChannelStatus:
        rows = self._rows
        if not rows.rows:
            if rows.state == 'available':  # every row lacked a usable address
                return channel_status('pairing', 'unsupported',
                                      f'{rows.unresolved} row(s) without PE-relative addresses')
            return channel_status('pairing', rows.state, rows.reason)
        notes =[f'identities from {", ".join(s.engine for s in self._used)}' if used
                 else 'Ghidriff only: identities are unassessed']
        if rows.unresolved:
            notes.append(f'{rows.unresolved} row(s) without PE-relative addresses left out')
        wide = sum(row.wide() for row in rows.rows)
        if wide:
            notes.append(f'{wide} row(s) with more than {MAX_SIDE_FUNCTIONS} functions on a side are listed in part')
        if reverse:
            notes.append(f'{reverse} secondary set(s) for the reversed pair ignored')
        if other:
            notes.append(f'{other} secondary set(s) for another pair ignored')
        state = 'available' if used and not rows.unresolved and not wide else 'partial'
        return channel_status('pairing', state, '; '.join(notes))

    def status(self) -> ChannelStatus:
        return self._status

    def candidates(self) -> Iterator[Candidate]:
        return iter(self._candidates)

    def unified_result_id(self) -> str | None:
        return None

    def secondary_set_ids(self) -> tuple[str, ...]:
        return tuple(sorted(s.entry_id for s in self._used))


# --- B1 signals -------------------------------------------------------------------------------------------------------


class B1Evidence:
    """`ChangeEvidenceSource` over stored B1 signal sets: each signal is a `b1:<DETECTOR>` shape observation on the newer
    function (the older one when only that side was located), tool-reported and derived from Ghidra (`D_ghidra`).

    A pair without a signal yields nothing, which is not a "no": coverage is judged by the channel status, and anything
    short of a complete B1 outcome for every 1:1 pair (missing decompiled code, a function over the scan limit, a pair
    without a signal set) makes the channel `partial`."""

    def __init__(self, rows: GhidriffRows, signal_sets: Iterable[SignalSet], *,
                 registry: OriginRegistry = DEFAULT_REGISTRY, budget: Budget | None = None):
        self._rows = rows
        self._sets: dict[str, SignalSet] = {}
        for signal_set in signal_sets:
            if signal_set.match_id in self._sets:
                raise PilotError('PT-PILOT-INPUT', 'Two B1 signal sets describe one match',
                                 reason='duplicate-signal-set')
            self._sets[signal_set.match_id] = signal_set
        self._unmatched = 0
        self._dropped = 0
        per_key: dict[str, list[Observation]] = {}
        for match_id in sorted(self._sets):
            if budget is not None:
                budget.tick()
            row = rows.by_match.get(match_id)
            if row is None:
                self._unmatched += 1
                continue
            per_key.setdefault(row.candidate_key, []).extend(_b1_observations(row, self._sets[match_id], registry))
        self._table: dict[str, tuple[Observation, ...]] = {}
        for key, items in per_key.items():
            self._table[key], dropped = settle(items)
            self._dropped += dropped

    def status(self) -> ChannelStatus:
        rows, sets = self._rows, self._sets
        if not rows.rows or not sets:
            return channel_status('code', 'not-run', 'B1 signals have not been computed for this run')
        if self._unmatched == len(sets):
            return channel_status('code', 'stale', 'the B1 signals do not describe the rows of this run')
        pairs = [row for row in rows.rows if row.pair() is not None]
        gaps = sum(1 for row in pairs if not _covered(sets.get(row.match.id)))
        notes = []
        if gaps:
            notes.append(f'{gaps} of {len(pairs)} pairs lack complete B1 coverage')
        if self._unmatched:
            notes.append(f'{self._unmatched} signal set(s) match no row')
        if self._dropped:
            notes.append(f'{self._dropped} signal(s) beyond the cap of {MAX_PER_CANDIDATE} per candidate not listed')
        return channel_status('code', 'partial' if notes else 'available', '; '.join(notes))

    def observations(self, candidate_keys: Iterable[str]) -> Iterator[tuple[str, Observation]]:
        return lookup(self._table, candidate_keys)


def _covered(signal_set: SignalSet | None) -> bool:
    """True when every B1 detector that applies to the pair finished: a structural exclusion is fine, a missing set,
    missing code, a scan limit or a cancel is not."""
    if signal_set is None:
        return False
    return all(o.status == 'complete' or (o.status == 'unavailable' and o.reason.startswith(B1_NOT_APPLICABLE))
               for o in signal_set.outcomes)


def _b1_observations(row: ResolvedMatch, signal_set: SignalSet, registry: OriginRegistry) -> list[Observation]:
    rva_of = {side: {record.id: rva for rva, record in row.functions(side)} for side in ('older', 'newer')}
    out = []
    for signal in signal_set.signals:
        location = min(signal.locations, key=lambda loc: (loc.side != 'newer', loc.start_line, loc.end_line))
        rva = rva_of[location.side].get(location.function_id)
        nav = None if rva is None else Nav(side=location.side, rva=rva, start_line=location.start_line,
                                           end_line=location.end_line)
        out.append(build_observation(
            registry, source='b1', channel='code', kind=f'b1:{signal.detector}', role='shape',
            verification='tool-reported', evidence_class='E-DECOMP', ref_kind='b1-signal', ref_id=signal.signal_id,
            detail=signal.rationale, nav=nav))
    return out


# --- the code channel -------------------------------------------------------------------------------------------------


def _combined(lexical: ChangeEvidenceSource, typed: ChangeEvidenceSource | None) -> ChannelStatus:
    lex = lexical.status()
    if typed is None:
        reason = TEXT_ONLY_REASON if lex.reason is None else f'{TEXT_ONLY_REASON}; {lex.reason}'
        return channel_status('code', 'partial', reason) if lex.state in _USABLE else lex
    other = typed.status()
    if lex.state == other.state == 'available':
        return channel_status('code', 'available')
    if lex.state in _USABLE or other.state in _USABLE:
        notes = [s.reason for s in (lex, other) if s.reason] or ['one code source did not run']
        return channel_status('code', 'partial', '; '.join(notes))
    return max((lex, other), key=lambda s: _UNUSABLE_SEVERITY.index(s.state))


class CodeEvidence:
    """The code channel: B1 (lexical, always) plus optional typed ChangeFacts (`unified.UnifiedFacts`).

    Without the typed source the channel is `partial` and says "text evidence only": that is the ceiling of what B1
    alone can show. With both sources it is `available` only when both are; if either source saw something it is
    `partial`, and if neither did it is the more serious of the two states."""

    def __init__(self, lexical: ChangeEvidenceSource, typed: ChangeEvidenceSource | None = None):
        self._lexical, self._typed = lexical, typed

    def status(self) -> ChannelStatus:
        return _combined(self._lexical, self._typed)

    def observations(self, candidate_keys: Iterable[str]) -> Iterator[tuple[str, Observation]]:
        wanted = tuple(candidate_keys)
        sources = (self._lexical,) if self._typed is None else (self._lexical, self._typed)
        merged = [item for source in sources for item in source.observations(wanted)]
        merged.sort(key=lambda item: (item[0], item[1].obs_id))
        return iter(merged)
