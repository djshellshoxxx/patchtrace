"""The eight checks of a candidate (YRX-integration-plan section 7 `Gate`, section 8 "Key copy"): measured numbers in,
`Gate` out. Pure and total: every function maps its inputs to exactly one state, and an input that is missing (a build
that could not be scanned, a tool that did not run) is `unknown`, never `pass` and never `fail`.

Raw numbers only. No score, no percent of "quality": a gate is a pass/fail check with the number it measured, and the
candidate shows the number beside the check.

Thresholds are the card's, provisional until they are calibrated on Tier R (plan s6, "Generic windows"): a window needs
at least 16 literal (unmasked) bytes and a literal run of 6, at most 40 % wildcards, and exactly one hit in the build it
was taken from. A gate in `BLOCKING` keeps a candidate out of the proposal unless it passes; `dist` is informational
(a toolchain change is a banner, never a reason to hide a rule).
"""
from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Sequence

from .contracts import GATE_IDS, CellResult, Gate, LintResult

MIN_LITERAL_BYTES = 16
MIN_LITERAL_RUN = 6
MAX_WILDCARD_PERCENT = 40
WINDOW_GROWTH_CAP = 128   # bytes: a window grown by context stops here (plan s7 step 2)
ALLOWED_WARNINGS = frozenset({'text_as_hex'})   # style note: the compile gate tolerates exactly this one
BLOCKING = ('len', 'wild', 'uniq', 'sep', 'compile', 'secret')
LABELS = {
    'elig': 'Change reviewed as material', 'len': 'Long enough', 'wild': 'Not mostly wildcards',
    'uniq': 'Appears in one place in its own build', 'sep': 'Does not appear in the other build',
    'compile': 'Compiles with YARA-X', 'secret': 'No secret-looking strings', 'dist': 'Builds share one toolchain'}
TOOLCHAIN_FLAGS = ('toolchain-changed', 'packed', 'protected')


def sentence(gate: Gate) -> str:
    """"Long enough: 20 literal bytes, longest run 15" - the label and what was measured."""
    return f'{LABELS[gate.gate_id]}: {gate.detail}' if gate.detail else LABELS[gate.gate_id]


def passed(gate: Gate) -> bool:
    return gate.state in ('pass', 'waived')


def eligibility(materiality: str, analyst_confirmed: bool) -> Gate:
    """`pass` for a change reviewed as material; `waived` when only the analyst says so (the candidate is then
    `unvetted`); `fail` otherwise, and then nothing is proposed."""
    if materiality == 'material':
        return Gate(gate_id='elig', state='pass', measured='material', detail='Change reviewed as material')
    if analyst_confirmed:
        return Gate(gate_id='elig', state='waived', measured='confirmed',
                    detail='Not reviewed as material; confirmed by the analyst')
    return Gate(gate_id='elig', state='fail', measured=materiality, detail=f'Change reviewed as {materiality}')


def long_enough(literal: int, longest_run: int) -> Gate:
    state = 'pass' if literal >= MIN_LITERAL_BYTES and longest_run >= MIN_LITERAL_RUN else 'fail'
    return Gate(gate_id='len', state=state, measured=literal,
                detail=f'{literal} literal bytes, longest run {longest_run}')


def not_mostly_wildcards(length: int, literal: int) -> Gate:
    wild = length - literal
    state = 'pass' if wild * 100 <= MAX_WILDCARD_PERCENT * length else 'fail'
    return Gate(gate_id='wild', state=state, measured=wild * 100 // length,
                detail=f'{wild} of {length} bytes are wildcards')


def one_place(source_hits: int | None) -> Gate:
    """The window is found exactly once in the build it came from (executable sections)."""
    if source_hits is None:
        return Gate(gate_id='uniq', state='unknown', detail='hits in its own build were not counted')
    detail = {0: 'not found in its own build', 1: 'found once in its own build'}.get(
        source_hits, f'found {source_hits} times in its own build')
    return Gate(gate_id='uniq', state='pass' if source_hits == 1 else 'fail', measured=source_hits, detail=detail)


def absent_elsewhere(other_hits: int | None) -> Gate:
    """A window's own separation, measured by counting its pattern in the other build (the rule-level check is `separates`,
    which scans the finished rule)."""
    if other_hits is None:
        return Gate(gate_id='sep', state='unknown', detail='hits in the other build were not counted')
    detail = 'not found in the other build' if other_hits == 0 else f'also found {other_hits} times in the other build'
    return Gate(gate_id='sep', state='pass' if other_hits == 0 else 'fail', measured=other_hits, detail=detail)


def _unscanned(cell: CellResult) -> str | None:
    return None if cell.state in ('hit', 'no-hit') else (cell.reason or cell.state)


def separates(own: CellResult | None, other: CellResult | None, expected_rva: int | None = None) -> Gate:
    """The rule hits the build it describes (at `expected_rva` when it has a byte window) and misses the other build.
    A build that could not be scanned makes the gate `unknown`: a file nobody scanned is not a clean file."""
    if own is None or other is None:
        return Gate(gate_id='sep', state='unknown', detail='the pair was not scanned')
    for cell, name in ((own, 'its own'), (other, 'the other')):
        reason = _unscanned(cell)
        if reason is not None:
            return Gate(gate_id='sep', state='unknown', detail=f'{name} build was not scanned: {reason}'[:300])
    if other.state == 'hit':
        return Gate(gate_id='sep', state='fail', measured=other.hits,
                    detail=f'also matches the other build ({other.hits} times)')
    if own.state != 'hit':
        return Gate(gate_id='sep', state='fail', measured=0, detail='does not match its own build')
    if expected_rva is not None and expected_rva not in own.rvas:
        return Gate(gate_id='sep', state='fail', measured=0,
                    detail=f'matches its own build, but not at 0x{expected_rva:x}')
    return Gate(gate_id='sep', state='pass', measured=0, detail='matches its own build, not the other one')


def compiles(lint: LintResult | None) -> Gate:
    """No error and no warning other than the style note `text_as_hex`."""
    if lint is None:
        return Gate(gate_id='compile', state='unknown', detail='the rule was not compiled')
    blocking = [*lint.errors, *(w for w in lint.warnings if w.code not in ALLOWED_WARNINGS)]
    if blocking:
        first = blocking[0]
        return Gate(gate_id='compile', state='fail', measured=len(blocking),
                    detail=f'{first.code}: {first.title}'[:300])
    return Gate(gate_id='compile', state='pass', measured=0,
                detail='only the style note text_as_hex' if lint.warnings else 'no warnings')


def no_secret(texts: Iterable[bytes], detect: Callable[[str], str | None]) -> Gate:
    """None of the included strings looks like a credential (the SPEC-29 detector, applied to the real bytes)."""
    count = sum(1 for text in texts if detect(text.decode('latin-1')))
    return Gate(gate_id='secret', state='fail' if count else 'pass', measured=count,
                detail=f'{count} secret-looking strings' if count else 'no secret-looking strings')


def one_toolchain(flags: Collection[str] | None) -> Gate:
    """`flags` are the DiE quality-flag codes of the pair, or `None` when DiE did not run (then the answer is unknown)."""
    if flags is None:
        return Gate(gate_id='dist', state='unknown', detail='toolchain not checked')
    changed = sorted(set(flags) & set(TOOLCHAIN_FLAGS))
    if changed:
        return Gate(gate_id='dist', state='fail', measured=len(changed), detail=', '.join(changed))
    if 'environment-unknown' in flags:
        return Gate(gate_id='dist', state='unknown', detail='no signature-level toolchain detection on a build')
    return Gate(gate_id='dist', state='pass', measured=0, detail='same toolchain on both builds')


def first_blocking(gates: Sequence[Gate]) -> Gate | None:
    """The gate that keeps the candidate out of the proposal: the first blocking gate, in canonical order, that failed,
    else the first that is `unknown` (a rule that could not be tested on the pair is not offered as separating it). A
    definite failure comes first because it explains the unknowns after it: a rule that does not compile cannot be
    scanned."""
    by_id = {gate.gate_id: gate for gate in gates}
    open_gates = [by_id[i] for i in GATE_IDS if i in BLOCKING and i in by_id and not passed(by_id[i])]
    return next((gate for gate in open_gates if gate.state == 'fail'), open_gates[0] if open_gates else None)
