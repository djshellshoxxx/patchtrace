"""Hard-gate checks of a rule candidate (plan s6, s7). Pure: raw measured values with pass/fail, never a score.

`pass`/`fail` are measured, `unknown` means not measured yet (a scan or compile has not run), `waived` means the gate
does not apply to the included features. Thresholds are provisional until calibrated on Tier R. Gates that need the
engine (`uniq`, `sep`, `compile`) start `unknown` and are filled from lint findings and scan cells.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence

from .contracts import BytesFeature, CellResult, Feature, Gate, GateId, LintFinding, PairSource, StringFeature

MIN_LITERAL_BYTES = 16
MIN_LITERAL_RUN = 6
MIN_TEXT_CHARS = 6
MAX_WILDCARD_PERCENT = 40
ALLOWED_WARNING_CODES = frozenset({'text_as_hex'})
BLOCKING_FLAGS = frozenset({'packed', 'protected'})
NOTE_FLAGS = frozenset({'toolchain-changed', 'installer'})
GATE_ORDER: tuple[GateId, ...] = ('elig', 'len', 'wild', 'uniq', 'sep', 'compile', 'secret', 'dist')
ENGINE_GATES: tuple[GateId, ...] = ('uniq', 'sep', 'compile')
PENDING = 'not scanned or compiled yet'


def _bytes(features: Iterable[Feature]) -> list[BytesFeature]:
    return [f for f in features if isinstance(f, BytesFeature) and f.included]


def _text(features: Iterable[Feature]) -> list[StringFeature]:
    return [f for f in features if isinstance(f, StringFeature) and f.included]


def eligibility_gate(pair: PairSource) -> Gate:
    if pair.materiality == 'material':
        return Gate(gate_id='elig', state='pass', measured='material', detail='reviewed and material')
    if pair.analyst_confirmed_material:
        return Gate(gate_id='elig', state='waived', measured='confirmed',
                    detail='material by analyst confirmation only; the rule is flagged unvetted')
    return Gate(gate_id='elig', state='fail', measured=pair.materiality or None,
                detail='the pair is neither material nor confirmed by the analyst')


def length_gate(features: Sequence[Feature]) -> Gate:
    """A rule needs a content pattern; a bare import or capability gate matches any file that uses the API."""
    windows, texts = _bytes(features), _text(features)
    if not windows and not texts:
        return Gate(gate_id='len', state='fail', detail='no byte or text pattern is included')
    weak = [f'bytes at {w.window_rva:#x}: {w.literal} literal, longest run {w.longest_run}' for w in windows
            if w.literal < MIN_LITERAL_BYTES or w.longest_run < MIN_LITERAL_RUN]
    weak += [f'text of {t.length} characters' for t in texts if t.length < MIN_TEXT_CHARS]
    measured = min([w.literal for w in windows] + [t.length for t in texts])
    if weak:
        return Gate(gate_id='len', state='fail', measured=measured, detail='too short: ' + '; '.join(weak))
    return Gate(gate_id='len', state='pass', measured=measured,
                detail=f'needs {MIN_LITERAL_BYTES} literal bytes with a run of {MIN_LITERAL_RUN}, '
                       f'text of {MIN_TEXT_CHARS} characters')


def wildcard_gate(features: Sequence[Feature]) -> Gate:
    windows = _bytes(features)
    if not windows:
        return Gate(gate_id='wild', state='waived', detail='not applicable: no byte pattern')
    worst = max(100 * (w.length - w.literal) // w.length for w in windows)
    state = 'pass' if worst <= MAX_WILDCARD_PERCENT else 'fail'
    return Gate(gate_id='wild', state=state, measured=worst, detail=f'wildcards in percent, at most {MAX_WILDCARD_PERCENT}')


def secret_gate(excluded: int) -> Gate:
    return Gate(gate_id='secret', state='pass', measured=excluded,
                detail='secret-like strings are never offered as patterns; the number left out is shown')


def distortion_gate(flag_codes: Iterable[str]) -> Gate:
    codes = sorted(set(flag_codes))
    blocking = [c for c in codes if c in BLOCKING_FLAGS]
    noted = [c for c in codes if c in NOTE_FLAGS]
    if blocking:
        return Gate(gate_id='dist', state='fail', measured=', '.join(blocking),
                    detail='a packed or protected build distorts the comparison')
    if noted:
        return Gate(gate_id='dist', state='unknown', measured=', '.join(noted),
                    detail='the comparison may be distorted; check before accepting')
    return Gate(gate_id='dist', state='pass', measured='', detail='no distortion flag')


def _pending(gate_id: GateId) -> Gate:
    return Gate(gate_id=gate_id, state='unknown', detail=PENDING)


def evaluate(pair: PairSource, features: Sequence[Feature], *, secrets_excluded: int = 0,
             flag_codes: Iterable[str] = ()) -> tuple[Gate, ...]:
    return (eligibility_gate(pair), length_gate(features), wildcard_gate(features), _pending('uniq'),
            _pending('sep'), _pending('compile'), secret_gate(secrets_excluded), distortion_gate(flag_codes))


def regate(previous: Sequence[Gate], features: Sequence[Feature]) -> tuple[Gate, ...]:
    """A toggled revision keeps the pair-level gates and re-runs the rest; engine gates start unknown again."""
    kept = {g.gate_id: g for g in previous if g.gate_id in ('elig', 'secret', 'dist')}
    fresh = {'len': length_gate(features), 'wild': wildcard_gate(features), **{g: _pending(g) for g in ENGINE_GATES}}
    return tuple((kept.get(g) or fresh[g]) for g in GATE_ORDER)


def _replace(gates: Sequence[Gate], *new: Gate) -> tuple[Gate, ...]:
    by_id = {g.gate_id: g for g in gates} | {g.gate_id: g for g in new}
    return tuple(by_id[g] for g in GATE_ORDER if g in by_id)


def with_compile(gates: Sequence[Gate], findings: Iterable[LintFinding]) -> tuple[Gate, ...]:
    bad = [f for f in findings if f.severity == 'error' or f.code not in ALLOWED_WARNING_CODES]
    if bad:
        return _replace(gates, Gate(gate_id='compile', state='fail', measured=len(bad),
                                    detail='; '.join(sorted({f'{f.severity} {f.code}' for f in bad}))))
    return _replace(gates, Gate(gate_id='compile', state='pass', measured=0, detail='no blocking warning'))


def _scanned(cell: CellResult | None) -> bool:
    return cell is not None and cell.state in ('hit', 'no-hit')


def with_scan(gates: Sequence[Gate], features: Sequence[Feature], own: CellResult | None,
              other: CellResult | None) -> tuple[Gate, ...]:
    """`sep`: a hit in the build the rule is for and none in the other. An unscanned cell stays `unknown`."""
    windows = _bytes(features)
    if not windows:
        uniq = Gate(gate_id='uniq', state='waived', detail='not applicable: no byte pattern')
    elif not _scanned(own):
        uniq = _pending('uniq')
    else:
        state = 'pass' if own.hits == 1 else 'fail'
        uniq = Gate(gate_id='uniq', state=state, measured=own.hits, detail='exactly one hit in the source build')
    if not (_scanned(own) and _scanned(other)):
        sep = Gate(gate_id='sep', state='unknown', detail='a build was not scanned')
    else:
        moved = bool(windows) and bool(own.rvas) and windows[0].window_rva not in own.rvas
        ok = own.state == 'hit' and other.state == 'no-hit' and not moved
        detail = ('hit in the source build only' if ok else
                  'no hit in the source build' if own.state == 'no-hit' else
                  'also hits the other build' if other.state == 'hit' else 'hit away from the expected address')
        sep = Gate(gate_id='sep', state='pass' if ok else 'fail', measured=f'{own.hits}/{other.hits}', detail=detail)
    return _replace(gates, uniq, sep)


def refused(gates: Iterable[Gate]) -> list[GateId]:
    """Gates that block accept or export; `unknown` and `waived` never block."""
    return [g.gate_id for g in gates if g.state == 'fail']
