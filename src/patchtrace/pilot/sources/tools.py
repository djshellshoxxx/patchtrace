"""capa, FLOSS and DiE deltas of a pair as pilot observations (PIL-integration-plan.md s4, s7, s9 PIL-A3).

The tools are inputs, never run here: an adapter reads `ToolDelta` values that T computed from stored runs, plus the
`ToolRun` rows they came from (for cache keys and the capa backend). An engine that has not run, failed or was
unsupported is reported through the channel status and yields nothing: missing evidence is unknown, never a negative.

What may name a function (T6.5): only a capability or string the tool itself placed in a function, and only when T
classified the change as code that changed there (`newly-introduced`, `removed-with-code`; `newly-detectable` is the same
code detected differently). Everything else stays pair-level or is dropped:

* an unlocalized capability (file scope, no function, a link that merely carries an address) never attaches to a
  candidate; it is bounded pair-level context (`capa:unlocalized-added|removed`, at most `MAX_PAIR_OBSERVATIONS`);
* FLOSS static and language strings have an offset, not a function, and never attach; stack, tight and decoded strings
  attach to the function that builds or decodes them (the decoder, not its caller);
* DiE only flags: `die:toolchain-changed|packed|protected` apply to every lead as nuisance context, heuristic-only
  detections are ignored and an unknown toolchain makes the build channel partial. capa quality flags become
  `capa:limitation` and `capa:recovery-shift` context.

Every tool observation is context (capa until a rule row maps its namespace, strings and DiE always). Evidence classes are
PIL's: `E-CAPA`, `E-DATA` (strings) and `E-BUILD`. capa on its Ghidra backend is not independent of Ghidra (`D_ghidra`); an
unknown backend takes that dependent tag.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from ...intelligence.tools.common import LOCALIZED, EvidenceLink, ToolRun, redacted_display
from ...intelligence.tools.delta import QualityFlag, ToolDelta
from ..contracts import ChannelStatus, Nav, Observation, ToolKey
from ..limits import PilotError
from ..ports import OriginRegistry
from .code import DEFAULT_REGISTRY, CandidateIndex, build_observation, channel_status, lookup, settle

MAX_PAIR_OBSERVATIONS = 32
_CHANNEL = {'floss': 'strings', 'capa': 'capa', 'diec': 'build'}
_CHANNEL_ORDER = ('floss', 'capa', 'diec')  # strings, capa, build: the order of `contracts.CHANNELS`
_SIDE = {'added': 'newer', 'removed': 'older'}
_CODE_CHANGED = {'added': 'newly-introduced', 'removed': 'removed-with-code'}
_PLACEABLE_STRINGS = frozenset({'stack', 'tight', 'decoded'})
_DIE_FLAGS = frozenset({'toolchain-changed', 'packed', 'protected'})
_CAPA_FLAGS = {'capa-limitation': 'limitation', 'function-recovery-shift': 'recovery-shift'}
_NOTE_FLAGS = frozenset({'environment-unknown', *_CAPA_FLAGS})
_RVA_MAX = 2**32 - 1


@dataclass(frozen=True)
class ToolInput:
    """One engine's stored result for the pair: T's delta and the two runs it was computed from. A delta that could not
    be computed (a run missing, failed or unsupported) is None; the runs still say why."""
    engine: str
    delta: ToolDelta | None
    older_run: ToolRun | None = None
    newer_run: ToolRun | None = None


def _refuse(code: str, message: str, reason: str) -> PilotError:
    return PilotError(code, message, reason=reason)


def _check(item: ToolInput, older_sha256: str, newer_sha256: str) -> None:
    """Fail closed on a result that does not belong to this pair in this orientation."""
    runs = [run for run in (item.older_run, item.newer_run) if run is not None]
    if item.engine not in _CHANNEL or (item.delta is not None and item.delta.engine != item.engine) or any(
            run.engine != item.engine for run in runs):
        raise _refuse('PT-PILOT-INPUT', 'A tool result names another engine', 'tool-engine')
    if item.delta is not None and item.delta.comparable and len(runs) != 2:
        raise _refuse('PT-PILOT-INPUT', 'A comparable tool delta needs both runs', 'tool-runs-missing')
    if (item.older_run is not None and item.older_run.side != 'older') or (
            item.newer_run is not None and item.newer_run.side != 'newer'):
        raise _refuse('PT-PILOT-INPUT', 'A tool run is on the wrong side', 'tool-run-side')
    older = item.older_run.input_artifact_hash if item.older_run else None
    newer = item.newer_run.input_artifact_hash if item.newer_run else None
    if older_sha256 != newer_sha256 and (older == newer_sha256 or newer == older_sha256):
        raise _refuse('PT-PILOT-ORIENTATION', 'A tool run describes the reversed pair', 'tool-orientation')
    if older not in (None, older_sha256) or newer not in (None, newer_sha256):
        raise _refuse('PT-PILOT-MISMATCH', 'A tool run describes another artifact', 'tool-artifact')


def _function(link: EvidenceLink) -> int | None:
    """RVA of the function the tool itself placed the evidence in; None for anything not genuinely localized."""
    if link.attribution not in LOCALIZED or link.function_id is None:
        return None
    rva = int(link.function_id[len('rva:0x'):], 16)
    return rva if rva <= _RVA_MAX else None


class ToolDeltas:
    """`ToolEvidenceSource` over capa, FLOSS and DiE results (see the module docstring for what attaches where).

    `index` says which candidates hold a function; evidence about a function attaches to each of them."""

    def __init__(self, inputs: Iterable[ToolInput], index: CandidateIndex, *, older_sha256: str, newer_sha256: str,
                 registry: OriginRegistry = DEFAULT_REGISTRY):
        self._inputs: dict[str, ToolInput] = {}
        for item in inputs:
            _check(item, older_sha256, newer_sha256)
            if item.engine in self._inputs:
                raise _refuse('PT-PILOT-INPUT', 'Two results were supplied for one tool engine', 'duplicate-tool-input')
            self._inputs[item.engine] = item
        self._registry = registry
        self._flags = self._collect_flags()
        table: dict[str, list[Observation]] = {}
        unlocalized: dict[tuple[str, str], None] = {}
        for item in self._inputs.values():
            if item.delta is None or not item.delta.comparable:
                continue
            if item.engine == 'capa':
                self._capa(item, index, table, unlocalized)
            elif item.engine == 'floss':
                self._strings(item.delta, index, table)
        self._table: dict[str, tuple[Observation, ...]] = {}
        for key, items in table.items():
            self._table[key], _ = settle(items)
        self._cut = max(0, len(unlocalized) - MAX_PAIR_OBSERVATIONS)
        pair = [self._flag(flag) for flag in self._flags if self._flag_kind(flag)]
        pair += [self._unlocalized(verb, rule) for verb, rule in sorted(unlocalized)[:MAX_PAIR_OBSERVATIONS]]
        self._pair = tuple(sorted({o.obs_id: o for o in pair if o is not None}.values(), key=lambda o: o.obs_id))

    # -- capa, strings, flags --------------------------------------------------------------------------------------

    def _capa_source(self) -> str:
        item = self._inputs['capa']
        backends = {run.manifest.backend for run in (item.older_run, item.newer_run) if run is not None}
        return 'capa' if backends == {'vivisect'} else 'capa-ghidra'

    def _capa(self, item: ToolInput, index: CandidateIndex, table: dict[str, list[Observation]],
              unlocalized: dict[tuple[str, str], None]) -> None:
        for change in item.delta.capabilities:  # type: ignore[union-attr]
            if change.kind != 'capability' or change.change == 'unchanged':
                continue
            if change.classification == 'unlocalized':
                unlocalized[(change.change, change.rule_id)] = None
                continue
            if change.classification != _CODE_CHANGED[change.change]:
                continue
            side = _SIDE[change.change]
            for link in change.newer if change.change == 'added' else change.older:
                rva = _function(link)
                if rva is None:
                    continue
                found = build_observation(
                    self._registry, source=self._capa_source(), channel='capa', kind=f'capa:{change.change}',
                    role='context', verification='tool-reported', evidence_class='E-CAPA', ref_kind='capa-rule',
                    ref_id=change.rule_id, detail=f'capa matches {change.rule_id} in the {side} function only',
                    nav=Nav(side=side, rva=rva))
                for key in index.keys_at(side, rva):
                    table.setdefault(key, []).append(found)

    def _strings(self, delta: ToolDelta, index: CandidateIndex, table: dict[str, list[Observation]]) -> None:
        for change in delta.strings:
            if change.change not in _SIDE:
                continue
            side = _SIDE[change.change]
            types = change.newer_types if change.change == 'added' else change.older_types
            placeable = [t for t in types if t in _PLACEABLE_STRINGS]
            if not placeable:
                continue  # static and language strings have an offset, never a function
            shown = redacted_display(change.display_value, change.secret_kind)
            for link in change.newer if change.change == 'added' else change.older:
                rva = _function(link)
                if rva is None:
                    continue
                found = build_observation(
                    self._registry, source='floss', channel='strings', kind=f'str:{change.change}', role='context',
                    verification='tool-reported', evidence_class='E-DATA', ref_kind='floss-string',
                    ref_id=change.value_hash, ref_sha256=change.value_hash, nav=Nav(side=side, rva=rva),
                    detail=f'{placeable[0]} string {change.change}: {shown}')
                for key in index.keys_at(side, rva):
                    table.setdefault(key, []).append(found)

    def _collect_flags(self) -> tuple[QualityFlag, ...]:
        """The quality flags of every delta, once each. The CLI hands the whole set to every engine's delta, so a flag is
        kept when the engine it describes has a result here."""
        found: dict[tuple[str, str, str], QualityFlag] = {}
        for item in self._inputs.values():
            for flag in () if item.delta is None else item.delta.flags:
                if flag.source in self._inputs:
                    found[(flag.source, flag.code, flag.detail)] = flag
        return tuple(found[k] for k in sorted(found))

    @staticmethod
    def _flag_kind(flag: QualityFlag) -> str | None:
        if flag.source == 'diec' and flag.code in _DIE_FLAGS:
            return f'die:{flag.code}'
        if flag.source == 'capa' and flag.code in _CAPA_FLAGS:
            return f'capa:{_CAPA_FLAGS[flag.code]}'
        return None  # heuristic-only is ignored; environment-unknown is a status note, not an observation

    def _flag(self, flag: QualityFlag) -> Observation:
        die = flag.source == 'diec'
        return build_observation(
            self._registry, source='die' if die else self._capa_source(), channel='build' if die else 'capa',
            kind=self._flag_kind(flag), role='context', verification='tool-reported',  # type: ignore[arg-type]
            evidence_class='E-BUILD' if die else 'E-CAPA', ref_kind='die-flag' if die else 'capa-flag',
            ref_id=flag.code, detail=flag.detail)

    def _unlocalized(self, verb: str, rule: str) -> Observation:
        return build_observation(
            self._registry, source=self._capa_source(), channel='capa', kind=f'capa:unlocalized-{verb}',
            role='context', verification='tool-reported', evidence_class='E-CAPA', ref_kind='capa-rule', ref_id=rule,
            detail=f'capa matches {rule} in the {_SIDE[verb]} build without a function')

    # -- the port --------------------------------------------------------------------------------------------------

    def _status(self, engine: str) -> ChannelStatus:
        channel, item = _CHANNEL[engine], self._inputs.get(engine)
        if item is None:
            return channel_status(channel, 'not-run', f'{engine} has not been run on this pair')
        runs = [run for run in (item.older_run, item.newer_run) if run is not None]
        for run in runs:
            if run.status in ('failed', 'timeout', 'cancelled'):
                return channel_status(channel, 'failed', f'{engine} {run.side} run {run.status}')
        for run in runs:
            if run.status in ('unsupported', 'absent'):
                return channel_status(channel, 'unsupported', f'{engine} {run.side} run {run.status}')
        delta = item.delta
        if delta is None:
            return channel_status(channel, 'not-run', f'{engine} has no result for both files')
        if not delta.comparable:
            return channel_status(channel, 'unsupported', delta.reasons[0] if delta.reasons else
                                  f'the {engine} results cannot be compared')
        notes = [f.detail for f in self._flags if f.source == engine and f.code in _NOTE_FLAGS]
        if delta.truncated:
            notes.append(f'{engine} output was cut, so absence proves nothing')
        if engine != 'diec' and delta.pairing == 'unavailable':
            notes.append('no function pairing, so nothing can be placed in a function')
        if engine == 'capa' and self._cut:
            notes.append(f'{self._cut} unlocalized capability change(s) beyond the cap of {MAX_PAIR_OBSERVATIONS} '
                         'not listed')
        return channel_status(channel, 'partial' if notes else 'available', '; '.join(notes))

    def statuses(self) -> tuple[ChannelStatus, ...]:
        return tuple(self._status(engine) for engine in _CHANNEL_ORDER)

    def observations(self, candidate_keys: Iterable[str]) -> Iterator[tuple[str, Observation]]:
        return lookup(self._table, candidate_keys)

    def pair_observations(self) -> tuple[Observation, ...]:
        return self._pair

    def cache_keys(self) -> tuple[ToolKey, ...]:
        found = {(run.engine, run.side): run.cache_key for item in self._inputs.values()
                 for run in (item.older_run, item.newer_run) if run is not None}
        return tuple(ToolKey(engine=engine, side=side, cache_key=found[engine, side])
                     for engine, side in sorted(found))
