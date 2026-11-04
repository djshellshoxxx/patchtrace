"""Native receipts for release gate RB-03 (SPEC-28 §17): live status JSON -> `secondary-native-receipt/1`.

usage: native_receipt.py build --input FILE... --out DIR
       native_receipt.py check FILE... [--require-pass]

Dev-only and stdlib-only: it reads what the live producers wrote (`tools/live_rzdiff_check.py`,
`tests/test_live_bindiff.py`) and never runs an engine. A receipt is PASS only for a non-mocked run at a valid
exact head whose engine version equals the pin, on two different sources, with a passed identity check, at
least one match and every check passed. Unusable inputs become FAIL receipts and are never dropped.
`check` exits 2 when a receipt is malformed or inconsistent, 3 with `--require-pass` when one is not PASS or
names another head than PATCHTRACE_SOURCE_HEAD/GITHUB_SHA, else 0.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

CONTRACT = 'secondary-native-receipt/1'
GATE = 'RB-03'
ENGINES = ('rz-diff', 'bindiff', 'binexport2')
OUTCOMES = ('PASS', 'FAIL', 'INSUFFICIENT_DATA', 'BLOCKED')
STATUSES = ('passed', 'failed', 'blocked')
GATE_CHECKS = ('gate.source', 'gate.head_sha', 'gate.not_mocked', 'gate.pinned_version', 'gate.distinct_sources',
               'gate.identity')
COUNT_KEYS = ('case_count', 'evaluated_count', 'passed_count', 'failed_count', 'blocked_count')
KEYS = frozenset({'contract', 'gate', 'engine', 'repository', 'head_sha', 'workflow_run_id', 'run_attempt',
                  'platform', 'mocked', 'engine_version', 'pin', 'tool_sha256', 'source_pair_sha256',
                  'input_pair_sha256', 'output_sha256', 'match_count', 'checks', *COUNT_KEYS, 'outcome',
                  'limitations', 'source_file', 'source_sha256'})
SYNTHETIC = 'synthetic fixture pair; not real-binary evidence'
NO_BINEXPORT = 'no Ghidra/IDA-produced .BinExport, C3-7'
SOURCE_TEXT = {'rz-diff': 'strict JSON live-rzdiff document', 'bindiff': 'strict JSON bindiff live-status document',
               'binexport2': 'strict JSON binexport2 live-status document'}
# Producer texts the mapping depends on (tools/live_rzdiff_check.py, tests/test_live_bindiff.py).
RZ_ZERO = 'AssertionError: rz-diff produced zero function matches'
RZ_UNBOUND = 'match set hashes do not round-trip'
BD_ZERO = 'zero matches'
BD_UNBOUND = 'match set is not bound to the project artifact hashes'
NOTHING_TO_EVALUATE = 'zero matches: nothing to evaluate (see match_count)'
MAX_INPUT = 8 * 1024 * 1024
MAX_REASON = 300
MAX_TEXT = 120
MAX_CHECKS = 64
PIN_FILE = Path(__file__).resolve().parent / 'bindiff_pin.json'
_SHA256 = re.compile(r'[0-9a-f]{64}')
_HEAD = re.compile(r'[0-9a-f]{40}')
_CASE = re.compile(r'[a-z0-9_]{1,64}')
_INT = re.compile(r'[0-9]{1,18}')


class Malformed(ValueError):
    """The input is not strict JSON of a recognised shape."""


# ---- bounded values -------------------------------------------------------------------------------------------

def _bounded(value: object, limit: int = MAX_TEXT) -> str | None:
    if not isinstance(value, str):
        return None
    return ''.join(ch if ch.isprintable() else ' ' for ch in value[:limit])


def _digest(value: object) -> str | None:
    return value if isinstance(value, str) and _SHA256.fullmatch(value) else None


def _pair(value: object) -> dict | None:
    if isinstance(value, dict) and set(value) == {'older', 'newer'} and all(map(_digest, value.values())):
        return {'older': value['older'], 'newer': value['newer']}
    return None


def _count(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _check(name: str, status: str, reason: object) -> dict:
    return {'name': name, 'status': status, 'reason': _bounded(reason, MAX_REASON) or ''}


# ---- strict input ---------------------------------------------------------------------------------------------

def _reject_constant(name: str):
    raise Malformed(f'non-finite number {name}')


def _finite(text: str) -> float:
    value = float(text)
    if value in (float('inf'), float('-inf')):
        raise Malformed(f'non-finite number {text[:20]}')
    return value


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise Malformed('duplicate object key')
    return result


def load_strict(raw: bytes) -> object:
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise Malformed(f'not UTF-8 ({exc.reason})') from None
    try:
        return json.loads(text, parse_constant=_reject_constant, parse_float=_finite, object_pairs_hook=_unique)
    except Malformed:
        raise
    except json.JSONDecodeError as exc:
        raise Malformed(f'not strict JSON: {exc.msg} at line {exc.lineno} column {exc.colno}') from None
    except (ValueError, RecursionError) as exc:   # integer digit limit, nesting depth
        raise Malformed(f'not strict JSON: {type(exc).__name__}') from None


def _read(path: Path) -> bytes:
    with open(path, 'rb') as handle:
        raw = handle.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise Malformed(f'larger than {MAX_INPUT} bytes')
    return raw


def _describe(exc: Exception) -> str:
    if isinstance(exc, OSError):
        return f'{type(exc).__name__}: {exc.strerror or "unreadable"}'   # no path: receipts are path-independent
    return str(exc)


# ---- producer mappings ----------------------------------------------------------------------------------------

def _rz_help(flags: object) -> dict:
    name = 'rz-diff.help_flags'
    if flags is None:
        return _check(name, 'blocked', 'not recorded: the live check stopped earlier')
    if not isinstance(flags, dict) or not flags or not all(isinstance(v, bool) for v in flags.values()):
        return _check(name, 'failed', 'help_flags is not a map of flag -> declared')
    missing = sorted(flag for flag, declared in flags.items() if not declared)
    if missing:
        return _check(name, 'failed', f'rz-diff -h does not declare {", ".join(missing)}')
    return _check(name, 'passed', f'rz-diff -h declares {", ".join(sorted(flags))}')


def _rz_run(run: object) -> dict:
    name = 'rz-diff.engine_run'
    if run is None:
        return _check(name, 'blocked', 'not recorded: the live check stopped earlier')
    if not isinstance(run, dict):
        return _check(name, 'failed', 'engine_run is not an object')
    if run.get('status') == 'ok':
        return _check(name, 'passed', 'run_engines status ok')
    return _check(name, 'failed', f'run_engines status {_bounded(run.get("status"))} '
                                  f'({_bounded(run.get("error_code"))})')


def _rzdiff(doc: dict) -> dict:
    status, errors = doc.get('status'), doc.get('errors')
    if status not in ('passed', 'failed') or not isinstance(errors, list) \
            or not all(isinstance(error, str) for error in errors):
        raise Malformed('live-rzdiff document needs status passed|failed and an errors list of strings')
    match_count = _count(doc.get('match_count'))
    if status == 'passed':
        verdict = _check('rz-diff.verdict', 'failed' if errors else 'passed',
                         'status passed with recorded errors' if errors else 'live_rzdiff_check passed')
        identity = ('passed', 'live_rzdiff_check asserted the match-set hashes equal the fixture pair')
    else:
        zero_only = errors == [RZ_ZERO] and match_count == 0
        verdict = _check('rz-diff.verdict', 'blocked' if zero_only else 'failed',
                         NOTHING_TO_EVALUATE if zero_only else '; '.join(errors) or 'failed without a recorded error')
        identity = (('failed', f'live_rzdiff_check: {RZ_UNBOUND}') if any(RZ_UNBOUND in e for e in errors)
                    else ('blocked', 'not evaluated: live_rzdiff_check stopped before the identity check'))
    return {'mocked': doc.get('mocked'), 'platform': doc.get('os'), 'engine_version': doc.get('rizin_version'),
            'pin': doc.get('pin'), 'tool_sha256': doc.get('archive_sha256'),
            'source_pair_sha256': doc.get('fixture_sha256'), 'output_sha256': doc.get('output_sha256'),
            'match_count': match_count, 'synthetic': True, 'identity': identity,
            'cases': [_rz_help(doc.get('help_flags')), _rz_run(doc.get('engine_run')), verdict]}


def _overall(statuses: list[str]) -> str:
    """The live BinDiff test's own rule (tests/test_live_bindiff.py `_overall`)."""
    return 'failed' if 'failed' in statuses else 'passed' if set(statuses) == {'passed'} else 'blocked'


def _status_cases(engine: str, doc: dict, reclassify: Callable | None = None) -> tuple[list[dict], dict]:
    status, reason, raw = doc.get('status'), doc.get('reason'), doc.get('checks', {})
    if status not in STATUSES or not isinstance(reason, str):
        raise Malformed(f'{engine} status file needs status passed|failed|blocked and a reason')
    if not isinstance(raw, dict) or len(raw) > MAX_CHECKS:
        raise Malformed(f'checks must be an object of at most {MAX_CHECKS} checks')
    for name, item in raw.items():
        if not _CASE.fullmatch(name) or name == 'status' or not isinstance(item, dict) \
                or item.get('status') not in STATUSES or not isinstance(item.get('reason'), str):
            raise Malformed(f'check {_bounded(name, 64)!r} needs a [a-z0-9_] name, a status and a reason')
    cases = []
    for name in sorted(raw):
        item = raw[name]
        case_status, case_reason = reclassify(name, item) if reclassify else (item['status'], item['reason'])
        cases.append(_check(f'{engine}.{name}', case_status, case_reason))
    expected = _overall([item['status'] for item in raw.values()]) if raw else 'passed'
    if status != expected:   # a verdict with no case behind it, or one that disagrees with its checks
        cases.append(_check(f'{engine}.status', 'failed', f'status {status!r} disagrees with its checks ({expected})')
                     if raw else _check(f'{engine}.status', status, reason))
    return cases, raw


def _bindiff_case(name: str, item: dict) -> tuple[str, str]:
    """Zero matches is no evidence (INSUFFICIENT_DATA via match_count), not a failure; other problems still fail."""
    problems = item['reason'].split('; ')
    if name == 'end_to_end' and item['status'] == 'failed' and _count(item.get('matches')) == 0 \
            and BD_ZERO in problems:
        rest = [problem for problem in problems if problem != BD_ZERO]
        return ('failed', '; '.join(rest)) if rest else ('blocked', NOTHING_TO_EVALUATE)
    return item['status'], item['reason']


def _synthetic(doc: dict) -> bool:
    label = doc.get('input')
    return doc.get('synthetic') is True or (isinstance(label, str) and label.startswith('SYNTHETIC'))


def _bindiff_pin() -> str | None:
    try:
        text = json.loads(PIN_FILE.read_text(encoding='utf-8')).get('version_text')
    except (OSError, ValueError, AttributeError):
        return None
    return text.removeprefix('BinDiff ') if isinstance(text, str) and text.startswith('BinDiff ') else None


def _bindiff(doc: dict) -> dict:
    cases, raw = _status_cases('bindiff', doc, _bindiff_case)
    probe, e2e = raw.get('probe', {}), raw.get('end_to_end', {})
    matches = _count(e2e.get('matches'))
    if matches is None:
        identity = ('blocked', 'not evaluated: no end-to-end run')
    elif BD_UNBOUND in e2e['reason'].split('; '):
        identity = ('failed', f'end_to_end: {BD_UNBOUND}')
    else:
        identity = ('passed', 'end_to_end bound the match set to the source pair')
    return {'mocked': doc.get('mocked'), 'platform': doc.get('os'), 'engine_version': probe.get('version'),
            'pin': _bindiff_pin(), 'tool_sha256': probe.get('executable_sha256'),
            'source_pair_sha256': doc.get('source_pair_sha256'), 'input_pair_sha256': doc.get('input_pair_sha256'),
            'output_sha256': e2e.get('output_sha256'), 'match_count': matches, 'synthetic': _synthetic(doc),
            'identity': identity, 'cases': cases}


def _binexport2(doc: dict) -> dict:
    """No producer exists yet (C3-7): the live-status shape with the receipt's fields at top level."""
    cases, raw = _status_cases('binexport2', doc)
    identity = raw.get('identity')
    fields = {key: doc.get(key) for key in ('mocked', 'engine_version', 'pin', 'tool_sha256', 'source_pair_sha256',
                                            'input_pair_sha256', 'output_sha256', 'match_count')}
    return {**fields, 'platform': doc.get('os'), 'synthetic': _synthetic(doc), 'cases': cases,
            'identity': (identity['status'], identity['reason']) if identity
            else ('blocked', 'no identity check recorded')}


MAPPERS: dict[str, Callable[[dict], dict]] = {'rz-diff': _rzdiff, 'bindiff': _bindiff, 'binexport2': _binexport2}


def _detect(doc: object) -> str | None:
    if not isinstance(doc, dict):
        return None
    if doc.get('kind') == 'live-rzdiff':
        return 'rz-diff'
    return doc['engine'] if doc.get('engine') in ('bindiff', 'binexport2') else None


def _engine_from_name(name: str) -> str:
    lowered = name.lower()
    for needle, engine in (('rzdiff', 'rz-diff'), ('rz-diff', 'rz-diff'), ('binexport', 'binexport2'),
                           ('bindiff', 'bindiff')):
        if needle in lowered:
            return engine
    return 'unknown'


# ---- receipt --------------------------------------------------------------------------------------------------

def _head(environ: Mapping[str, str]) -> tuple[str | None, str]:
    for key in ('PATCHTRACE_SOURCE_HEAD', 'GITHUB_SHA'):
        value = environ.get(key, '')
        if value:   # no fallback past an invalid first value
            if _HEAD.fullmatch(value):
                return value, f'exact head from {key}'
            return _bounded(value, 64), f'{key} is not a 40-character lowercase hex SHA'
    return None, 'no head: set PATCHTRACE_SOURCE_HEAD or GITHUB_SHA'


def _env_int(environ: Mapping[str, str], key: str) -> int | None:
    value = environ.get(key, '')
    return int(value) if _INT.fullmatch(value) else None


def _gate_checks(receipt: dict, head_reason: str = '') -> list[dict]:
    """The gate checks that are pure functions of the receipt's fields (`check` re-derives them)."""
    head = receipt['head_sha']
    head_ok = isinstance(head, str) and _HEAD.fullmatch(head) is not None
    mocked, version, pin, pair = receipt['mocked'], receipt['engine_version'], receipt['pin'], \
        receipt['source_pair_sha256']
    if mocked is None:
        not_mocked = ('blocked', 'mocked flag not recorded')
    else:
        not_mocked = ('failed', 'mocked run: not live evidence') if mocked else ('passed', 'live run (mocked is false)')
    if not version or not pin:
        pinned = ('blocked', 'engine version not recorded' if not version else 'no pin recorded')
    else:
        pinned = (('passed', 'engine version equals the pin') if version == pin
                  else ('failed', f'engine version {version!r} is not the pin {pin!r}'))
    if pair is None:
        distinct = ('blocked', 'source pair not recorded')
    else:
        distinct = (('passed', 'older and newer source digests differ') if pair['older'] != pair['newer']
                    else ('failed', 'older and newer sources are identical'))
    return [_check('gate.head_sha', 'passed' if head_ok else 'failed', head_reason),
            _check('gate.not_mocked', *not_mocked), _check('gate.pinned_version', *pinned),
            _check('gate.distinct_sources', *distinct)]


def _counts(cases: list[dict]) -> dict:
    passed, failed, blocked = (sum(case['status'] == status for case in cases) for status in STATUSES)
    return {'case_count': len(cases), 'evaluated_count': passed + failed, 'passed_count': passed,
            'failed_count': failed, 'blocked_count': blocked}


def derive_outcome(checks: list[dict], match_count: int | None, evaluated: int) -> str:
    statuses = {item['status'] for item in checks}
    if 'failed' in statuses:
        return 'FAIL'
    if 'blocked' in statuses and match_count is None:
        return 'BLOCKED'           # no result: the blocked check says why
    if evaluated == 0 or match_count is None or match_count < 1:
        return 'INSUFFICIENT_DATA'
    return 'BLOCKED' if 'blocked' in statuses else 'PASS'


def _assemble(engine: str, fields: dict, environ: Mapping[str, str], source: dict, source_file: str | None,
              source_sha256: str | None) -> dict:
    head, head_reason = _head(environ)
    mocked = fields.get('mocked')
    receipt = {
        'contract': CONTRACT, 'gate': GATE, 'engine': engine,
        'repository': _bounded(environ.get('GITHUB_REPOSITORY') or None), 'head_sha': head,
        'workflow_run_id': _env_int(environ, 'GITHUB_RUN_ID'), 'run_attempt': _env_int(environ, 'GITHUB_RUN_ATTEMPT'),
        'platform': (_bounded(fields.get('platform')) or _bounded(environ.get('RUNNER_OS'))
                     or _bounded(platform.system()) or 'unknown'),
        'mocked': mocked if isinstance(mocked, bool) else None,
        'engine_version': _bounded(fields.get('engine_version')), 'pin': _bounded(fields.get('pin')),
        'tool_sha256': _digest(fields.get('tool_sha256')),
        'source_pair_sha256': _pair(fields.get('source_pair_sha256')),
        'input_pair_sha256': _pair(fields.get('input_pair_sha256')),
        'output_sha256': _digest(fields.get('output_sha256')), 'match_count': _count(fields.get('match_count')),
        'limitations': [SYNTHETIC] if engine == 'rz-diff' or fields.get('synthetic') else [],
        'source_file': source_file, 'source_sha256': source_sha256}
    cases = fields['cases']
    receipt['checks'] = [source, *_gate_checks(receipt, head_reason), _check('gate.identity', *fields['identity']),
                         *cases]
    receipt.update(_counts(cases))
    receipt['outcome'] = derive_outcome(receipt['checks'], receipt['match_count'], receipt['evaluated_count'])
    return receipt


def build_receipt(path: Path, environ: Mapping[str, str]) -> dict:
    raw = doc = None
    try:
        raw = _read(path)
        doc = load_strict(raw)
        engine = _detect(doc)
        if engine is None:
            raise Malformed('not a live-rzdiff, bindiff or binexport2 status document')
        fields = MAPPERS[engine](doc)
        source = _check('gate.source', 'passed', SOURCE_TEXT[engine])
    except (OSError, Malformed) as exc:
        engine = _detect(doc) or _engine_from_name(path.name)
        fields = {'identity': ('blocked', 'not evaluated: the status file is unusable'), 'cases': []}
        source = _check('gate.source', 'failed', f'unusable status file: {_describe(exc)}')
    source_sha256 = hashlib.sha256(raw).hexdigest() if raw is not None else None
    return _assemble(engine, fields, environ, source, _bounded(path.name, 255), source_sha256)


def absent_binexport2(environ: Mapping[str, str]) -> dict:
    fields = {'identity': ('blocked', 'not evaluated: no status file'), 'cases': []}
    return _assemble('binexport2', fields, environ, _check('gate.source', 'blocked', NO_BINEXPORT), None, None)


def render(receipt: dict) -> str:
    return json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + '\n'


# ---- validation -----------------------------------------------------------------------------------------------

def _text_ok(value: object, limit: int, *, optional: bool = True) -> bool:
    if value is None:
        return optional
    return isinstance(value, str) and len(value) <= limit and value.isprintable()


def _shape_problems(receipt: dict) -> list[str]:
    problems = []

    def need(condition: bool, message: str) -> None:
        if not condition:
            problems.append(message)

    need(receipt['contract'] == CONTRACT, 'contract is not ' + CONTRACT)
    need(receipt['gate'] == GATE, 'gate is not ' + GATE)
    need(receipt['engine'] in (*ENGINES, 'unknown'), 'unknown engine value')
    need(receipt['outcome'] in OUTCOMES, 'unknown outcome value')
    need(_text_ok(receipt['platform'], MAX_TEXT, optional=False) and bool(receipt['platform']), 'platform')
    for key, limit in (('repository', MAX_TEXT), ('engine_version', MAX_TEXT), ('pin', MAX_TEXT),
                       ('head_sha', 64), ('source_file', 255)):
        need(_text_ok(receipt[key], limit), f'{key} must be bounded printable text or null')
    for key in ('workflow_run_id', 'run_attempt', 'match_count'):
        need(receipt[key] is None or _count(receipt[key]) is not None, f'{key} must be a non-negative integer or null')
    for key in COUNT_KEYS:
        need(_count(receipt[key]) is not None, f'{key} must be a non-negative integer')
    need(receipt['mocked'] is None or isinstance(receipt['mocked'], bool), 'mocked must be a boolean or null')
    for key in ('tool_sha256', 'output_sha256', 'source_sha256'):
        need(receipt[key] is None or _digest(receipt[key]) is not None, f'{key} must be a SHA-256 or null')
    for key in ('source_pair_sha256', 'input_pair_sha256'):
        need(receipt[key] is None or _pair(receipt[key]) == receipt[key], f'{key} must be {{older, newer}} or null')
    limitations = receipt['limitations']
    need(isinstance(limitations, list) and all(_text_ok(item, MAX_REASON, optional=False) for item in limitations),
         'limitations must be a list of bounded text')
    checks = receipt['checks']
    if not isinstance(checks, list) or len(checks) > len(GATE_CHECKS) + MAX_CHECKS + 1 or not all(
            isinstance(item, dict) and set(item) == {'name', 'status', 'reason'} and item['status'] in STATUSES
            and _text_ok(item['name'], 80, optional=False) and _text_ok(item['reason'], MAX_REASON, optional=False)
            for item in checks):
        return [*problems, 'checks must be a bounded list of {name, status, reason}']
    names = [item['name'] for item in checks]
    need(len(set(names)) == len(names), 'duplicate check names')
    need(tuple(names[:len(GATE_CHECKS)]) == GATE_CHECKS, 'the six gate checks must come first, in order')
    prefix = f'{receipt["engine"]}.'
    need(all(name.startswith(prefix) and _CASE.fullmatch(name[len(prefix):]) for name in names[len(GATE_CHECKS):]),
         f'engine cases must be named {prefix}<case>')
    return problems


def validate(receipt: object) -> list[str]:
    """Problems with a receipt (empty when well-formed and self-consistent)."""
    if not isinstance(receipt, dict) or set(receipt) != KEYS:
        found = set(receipt) if isinstance(receipt, dict) else set()
        missing, extra = sorted(KEYS - found), sorted(str(key)[:40] for key in found - KEYS)[:5]
        return [f'keys differ from {CONTRACT} (missing {missing}, unexpected {extra})']
    problems = _shape_problems(receipt)
    if problems:
        return problems
    checks, cases = receipt['checks'], receipt['checks'][len(GATE_CHECKS):]
    recorded = {item['name']: item['status'] for item in checks}
    for derived in _gate_checks(receipt):
        if recorded[derived['name']] != derived['status']:
            problems.append(f'{derived["name"]} is {recorded[derived["name"]]} but the fields give {derived["status"]}')
    if {key: receipt[key] for key in COUNT_KEYS} != _counts(cases):
        problems.append('case counts do not match the engine cases')
    expected = derive_outcome(checks, receipt['match_count'], _counts(cases)['evaluated_count'])
    if receipt['outcome'] != expected:
        problems.append(f'outcome {receipt["outcome"]} but the checks give {expected}')
    if receipt['engine'] == 'unknown' and recorded['gate.source'] != 'failed':
        problems.append('engine unknown on a readable source')
    if receipt['engine'] == 'rz-diff' and SYNTHETIC not in receipt['limitations']:
        problems.append('rz-diff receipts run on the repository fixture pair and must say so')
    return problems


# ---- CLI ------------------------------------------------------------------------------------------------------

def _file_part(text: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]', '_', text)[:40]


def build(inputs: list[Path], out: Path, environ: Mapping[str, str]) -> list[tuple[Path, dict]]:
    receipts = [build_receipt(path, environ) for path in inputs]
    if not any(receipt['engine'] == 'binexport2' for receipt in receipts):
        receipts.append(absent_binexport2(environ))
    out.mkdir(parents=True, exist_ok=True)
    used: set[str] = set()
    written = []
    for receipt in receipts:
        stem = f'{receipt["engine"]}-{_file_part(receipt["platform"])}'
        name, number = f'{stem}.json', 1
        while name.lower() in used:   # case-insensitive file systems
            number += 1
            name = f'{stem}-{number}.json'
        used.add(name.lower())
        with open(out / name, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(render(receipt))
        written.append((out / name, receipt))
    return written


def check(paths: list[Path], require_pass: bool, environ: Mapping[str, str]) -> int:
    expected = environ.get('PATCHTRACE_SOURCE_HEAD') or environ.get('GITHUB_SHA') or None
    malformed = not_pass = False
    for path in paths:
        label = _bounded(path.name, 255)
        try:
            raw = _read(path)
            receipt = load_strict(raw)
            problems = validate(receipt)
            if not problems and raw != render(receipt).encode('ascii'):
                problems = ['not the canonical serialisation (sorted keys, two-space indent, LF)']
        except (OSError, Malformed) as exc:
            problems = [f'unreadable: {_describe(exc)}']
        if problems:
            malformed = True
            print(f'{label}: MALFORMED: {_bounded("; ".join(problems), 1000)}')
            continue
        line = f'{label}: {receipt["engine"]} {receipt["outcome"]} at {receipt["head_sha"]}'
        if expected is not None and receipt['head_sha'] != expected:
            line += f' (wrong head: expected {_bounded(expected, 64)})'
            not_pass = True
        not_pass = not_pass or receipt['outcome'] != 'PASS'
        print(line)
    if malformed:
        return 2
    return 3 if require_pass and not_pass else 0


def main(argv: list[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    environ = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(description='RB-03 native receipts (SPEC-28 §17)')
    commands = parser.add_subparsers(dest='command', required=True)
    build_cmd = commands.add_parser('build', help='convert live status JSON into receipts')
    build_cmd.add_argument('--input', type=Path, nargs='+', action='extend', required=True)
    build_cmd.add_argument('--out', type=Path, required=True)
    check_cmd = commands.add_parser('check', help='validate receipts')
    check_cmd.add_argument('files', type=Path, nargs='+')
    check_cmd.add_argument('--require-pass', action='store_true')
    args = parser.parse_args(argv)
    if args.command == 'check':
        return check(args.files, args.require_pass, environ)
    try:
        written = build(args.input, args.out, environ)
    except OSError as exc:
        print(f'cannot write receipts: {_describe(exc)}', file=sys.stderr)
        return 2
    for path, receipt in written:
        print(f'{path.name}: {receipt["engine"]} {receipt["outcome"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
