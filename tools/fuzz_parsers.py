"""Hostile-input fuzz harness for every untrusted-input parser (RB-06 / WS-H). Not a test dependency.

usage: fuzz_parsers.py --target NAME|all [--iterations N] [--seed S] [--time-budget SECONDS] [--crash-dir DIR]
       fuzz_parsers.py --list

Each target is (entry callable, seed builder, allowed rejection types). The oracle: the entry either returns or
raises one of its declared rejection types. Anything else is a finding: an undeclared exception type, an input that
takes longer than --deadline seconds (measured, never interrupted: the inputs are size- and nesting-bounded instead),
or a result whose repr exceeds the target's cap. Findings are written to --crash-dir as <target>-<sha256>.bin.

Seeds come only from the hermetic fixtures under tests/fixtures (and the synthetic PE builder in tests); there is no
network and no real binary. Mutation is deterministic for a given --seed. The BinExport2 parser has its own harness,
tools/fuzz_binexport.py.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import random
import sys
import tempfile
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests' / 'fixtures'
for _path in (ROOT / 'src', ROOT / 'tests'):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

MAX_INPUT_BYTES = 1 << 20          # mutated inputs never exceed this, so a hang is bounded by size, not by a kill
MAX_NEST = 300                     # deepest nesting a mutation adds
DEFAULT_DEADLINE = 5.0             # seconds per input
DEFAULT_RESULT_CHARS = 16 << 20    # repr() cap on a returned value
NOW = '2099-01-01T00:00:00Z'

Entry = Callable[[bytes], object]


@dataclass(frozen=True)
class Target:
    name: str
    build: Callable[[ExitStack, Path], Entry]   # (resources, scratch dir) -> entry; hermetic, no network
    seeds: Callable[[], list[bytes]]
    allowed: tuple[type[BaseException], ...]
    max_result_chars: int = DEFAULT_RESULT_CHARS
    note: str = ''


def _read(*parts: str) -> bytes:
    return FIXTURES.joinpath(*parts).read_bytes()


def _glob(pattern: str, *, exclude: tuple[str, ...] = ()) -> list[bytes]:
    return [p.read_bytes() for p in sorted(FIXTURES.glob(pattern)) if p.is_file() and p.suffix != '.md'
            and not any(part in p.parts for part in exclude)]


# --- entries ------------------------------------------------------------------------------------------------

def _strict_json(_stack: ExitStack, _tmp: Path) -> Entry:
    from patchtrace.persistence import strict_json
    return lambda data: strict_json(data.decode('utf-8', 'replace'))


def _ghidriff(_stack: ExitStack, _tmp: Path) -> Entry:
    from callgraph_fixtures import project_for_fixtures

    from patchtrace.normalization import normalize_ghidriff
    from patchtrace.persistence import strict_json

    def entry(data: bytes):
        project, run_id = project_for_fixtures()
        return normalize_ghidriff(strict_json(data.decode('utf-8', 'replace')), project, run_id)
    return entry


def _csaf(_stack: ExitStack, _tmp: Path) -> Entry:
    from patchtrace.intelligence.csaf.normalize import normalize
    from patchtrace.intelligence.csaf.validate import load_document

    def entry(data: bytes):
        doc, report = load_document(data)
        return normalize(doc, report, hashlib.sha256(data).hexdigest())
    return entry


def _kb_import(_stack: ExitStack, _tmp: Path) -> Entry:
    from patchtrace.kbcorrelation.sources.importer import import_bytes
    return lambda data: import_bytes(data, now=NOW)


def _kev(_stack: ExitStack, _tmp: Path) -> Entry:
    from patchtrace.kev.parse import parse_catalog
    return lambda data: parse_catalog(data, source='local-import', retrieved_at=NOW)


def _winbindex_rows(_stack: ExitStack, _tmp: Path) -> Entry:
    from patchtrace.acquisition.winbindex import parse_rows
    return lambda data: parse_rows(data, 'afd.sys', '2099-01-01', compressed=False)


def _winbindex_candidates(_stack: ExitStack, _tmp: Path) -> Entry:
    from patchtrace.acquisition.winbindex import parse
    return lambda data: parse(data, 'afd.sys', '2099-01-01', compressed=False)


def _winbindex_gz(_stack: ExitStack, _tmp: Path) -> Entry:
    from patchtrace.acquisition.winbindex import parse_rows

    def entry(data: bytes):
        # Valid gzip around mutated JSON on odd lengths (reaches the parser), raw mutated bytes otherwise.
        blob = data if data[:2] == b'\x1f\x8b' or len(data) % 2 == 0 else gzip.compress(data)
        return parse_rows(blob, 'afd.sys', '2099-01-01', compressed=True)
    return entry


def _pe_context(stack: ExitStack, tmp: Path, pair: str, side: str):
    import hashlib as _h

    from test_intel_tools_pe import PAIRS

    from patchtrace.artifact_bytes import VerifiedArtifactReader
    from patchtrace.intelligence.tools.normalize import PeMap
    from patchtrace.intelligence.tools.process import ArtifactCopy
    data = dict(zip(('older', 'newer'), PAIRS[pair](), strict=True))[side]
    path = tmp / f'{pair}-{side}.bin'
    path.write_bytes(data)
    copy = ArtifactCopy(path, _h.sha256(data).hexdigest(), _h.md5(data).hexdigest(), _h.sha1(data).hexdigest(),
                        len(data))
    reader = VerifiedArtifactReader.open_path(path, copy.sha256)
    stack.callback(reader.close)
    return copy, reader, PeMap.from_reader(reader)


def _capa(stack: ExitStack, tmp: Path) -> Entry:
    from patchtrace.intelligence.tools import capa
    from patchtrace.intelligence.tools.common import DEFAULT_LIMITS
    copy, _reader, pe = _pe_context(stack, tmp, 'capa-api', 'older')
    ctx = capa.ParseContext('run-older', 'older', copy, 'c' * 64, 'd' * 64, pe, DEFAULT_LIMITS['capa'])
    return lambda data: capa.parse(data, ctx)


def _floss(stack: ExitStack, tmp: Path) -> Entry:
    from patchtrace.intelligence.tools import floss
    from patchtrace.intelligence.tools.common import DEFAULT_LIMITS
    copy, reader, pe = _pe_context(stack, tmp, 'floss-decode', 'older')
    ctx = floss.ParseContext('run-older', 'older', copy, 'c' * 64, 'd' * 64, pe, reader, DEFAULT_LIMITS['floss'],
                             True)
    return lambda data: floss.parse(data, ctx)


def _diec(_stack: ExitStack, _tmp: Path) -> Entry:
    from patchtrace.intelligence.tools import diec
    from patchtrace.intelligence.tools.common import DEFAULT_LIMITS
    ctx = diec.ParseContext('run-older', 'older', 'a' * 64, 'c' * 64, 'd' * 64, DEFAULT_LIMITS['diec'])
    return lambda data: diec.parse(data, ctx)


# --- targets ------------------------------------------------------------------------------------------------

def _targets() -> dict[str, Target]:
    from patchtrace.acquisition.contracts import AcquisitionError
    from patchtrace.intelligence.contracts import IntelError
    from patchtrace.intelligence.tools.common import ToolError
    from patchtrace.kbcorrelation.sources.cvrf import SourceError
    from patchtrace.kev.contracts import KevError

    json_seeds = (_glob('callgraph/*.json') + _glob('kev/*.json') + [b'{"a": [1, 2.5, "x", null, true]}', b'[]'])
    kev_seeds = (_glob('kev/*.json') + [_read('kbcorrelation', 'kev-synthetic.json'),
                 b'cveID,vendorProject,product\nCVE-2099-0001,v,p\n'])
    csaf_seeds = (_glob('csaf/*.json') + _glob('csaf/injection/*.json') + [_read('kbcorrelation', 'csaf-kb-valid.json'),
                  _read('kbcorrelation', 'csaf-kb.json')])
    kb_seeds = (_glob('kbcorrelation/cvrf-*.json') + _glob('kbcorrelation/cvrf-*.xml') + csaf_seeds[-2:]
                + [gzip.compress(_read('kbcorrelation', 'cvrf-2099-Feb.json'))])
    winbindex = _glob('winbindex/*.json') + _glob('kbcorrelation/winbindex/*.json')
    tools = FIXTURES / 'intel_tools'
    items = [
        Target('strict_json', _strict_json, lambda: json_seeds, (ValueError,),
               note='patchtrace.persistence.strict_json'),
        Target('ghidriff', _ghidriff, lambda: _glob('callgraph/*.json', exclude=('golden',)), (ValueError,),
               note='normalization.normalize_ghidriff behind strict_json'),
        Target('csaf', _csaf, lambda: csaf_seeds, (IntelError,),
               note='intelligence.csaf load_document + normalize (ValidationFailed is an IntelError)'),
        Target('kb_import', _kb_import, lambda: kb_seeds, (SourceError,),
               note='kbcorrelation.sources.importer.import_bytes (CVRF JSON/XML, CSAF, gzip)'),
        Target('kev', _kev, lambda: kev_seeds, (KevError,), note='kev.parse.parse_catalog (a CSV is refused)'),
        Target('winbindex_rows', _winbindex_rows, lambda: winbindex, (AcquisitionError,),
               note='acquisition.winbindex.parse_rows'),
        Target('winbindex_parse', _winbindex_candidates, lambda: winbindex, (AcquisitionError,),
               note='acquisition.winbindex.parse'),
        Target('winbindex_gz', _winbindex_gz, lambda: winbindex + [gzip.compress(b'0' * (80 << 20), 1)], (AcquisitionError,),
               note='acquisition.winbindex.parse_rows through the bounded gunzip'),
        Target('capa', _capa, lambda: [p.read_bytes() for p in sorted((tools / 'capa').glob('capa-api-*.json'))],
               (ToolError,), note='intelligence.tools.capa.parse'),
        Target('floss', _floss, lambda: [p.read_bytes() for p in sorted((tools / 'floss').glob('floss-decode-*.json'))],
               (ToolError,), note='intelligence.tools.floss.parse'),
        Target('diec', _diec, lambda: [p.read_bytes() for p in sorted((tools / 'diec').glob('*.json'))
                                       if p.name != 'vocabulary.json'],
               (ToolError,), note='intelligence.tools.diec.parse'),
    ]
    return {item.name: item for item in items}


TARGETS_SKIPPED = {
    'kb_csv': 'no KB CSV parser exists: the only CSV handling is kev.parse, which refuses a CSV (covered by kev)',
}

# --- mutation -----------------------------------------------------------------------------------------------

HOSTILE_TEXT = ['\x00', '\u202e', '\u2066', '\u200b', '\ufeff', '\x1b[2J', '\x07', '\r\n', '\ud800', '\ufffe',
                '../../x', '%s%n', '\u0000\u0001\u0002', 'A' * 4096, '\u00c3\u00a9']
HUGE_NUMBERS = ['1e999', '-1e999', '99999999999999999999999999999999', '-99999999999999999999999999',
                '1' + '0' * 5000, '0.' + '0' * 400 + '1', '4294967296', '18446744073709551616', '-1', '-0',
                '9007199254740993', '1E-999', 'NaN', 'Infinity', '-Infinity']


def _walk(node, path=()):
    yield path, node
    if isinstance(node, dict):
        for key, child in node.items():
            yield from _walk(child, (*path, key))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from _walk(child, (*path, index))


def _replace(root, path, value):
    if not path:
        return value
    parent = root
    for step in path[:-1]:
        parent = parent[step]
    parent[path[-1]] = value
    return root


def _structural(rng: random.Random, data: bytes) -> bytes | None:
    """Replace, drop or duplicate one node of a JSON seed; None when the seed is not JSON."""
    try:
        root = json.loads(data.decode('utf-8-sig'))
    except (ValueError, RecursionError):
        return None
    nodes = [item for item in _walk(root)]
    path, node = rng.choice(nodes)
    kind = rng.randrange(9)
    if kind == 0:
        value = rng.choice(['', 'x' * rng.choice([300, 5000, 70000]), rng.choice(HOSTILE_TEXT), 'CVE-2099-0001'])
    elif kind == 1:
        value = None
    elif kind == 2:
        value = rng.choice([True, False, 0, -1, 2**31, 2**63, 2**64, 10**30, 1.5, -0.0])
    elif kind == 3:
        depth = rng.randint(2, MAX_NEST)
        value = '[' * depth + ']' * depth
        text = json.dumps(_replace(root, path, '\x00NEST')).replace('"\\u0000NEST"', value)
        return text.encode('utf-8')[:MAX_INPUT_BYTES]
    elif kind == 4:
        value = [] if isinstance(node, dict) else {}
    elif kind == 5 and path:
        parent = root
        for step in path[:-1]:
            parent = parent[step]
        if isinstance(parent, dict):
            del parent[path[-1]]
        elif isinstance(parent, list):
            del parent[path[-1]]
        return json.dumps(root).encode('utf-8')
    elif kind == 6:
        value = node if not isinstance(node, (dict, list)) else [node, node]
    elif kind == 7 and isinstance(node, dict) and node:
        key = rng.choice(sorted(node))
        node[rng.choice(HOSTILE_TEXT) + key] = node[key]
        return json.dumps(root).encode('utf-8')
    else:
        value = [node] * rng.choice([2, 50, 400])
    return json.dumps(_replace(root, path, value)).encode('utf-8')[:MAX_INPUT_BYTES]


def mutate(rng: random.Random, data: bytes) -> bytes:
    """One deterministic hostile variant of ``data`` (always <= MAX_INPUT_BYTES)."""
    if rng.random() < 0.5:
        out = _structural(rng, data)
        if out is not None:
            return out
    buf = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        op = rng.randrange(9)
        if op == 0 and buf:
            buf[rng.randrange(len(buf))] ^= 1 << rng.randrange(8)
        elif op == 1 and buf:
            del buf[rng.randrange(len(buf)):]
        elif op == 2 and buf:
            a = rng.randrange(len(buf))
            buf[a:a] = buf[a:rng.randrange(a, len(buf) + 1)] * rng.randint(2, 20)
        elif op == 3:
            at = rng.randrange(len(buf) + 1)
            buf[at:at] = rng.choice(HOSTILE_TEXT).encode('utf-8', 'surrogatepass')
        elif op == 4:
            at = rng.randrange(len(buf) + 1)
            buf[at:at] = rng.choice(HUGE_NUMBERS).encode('ascii')
        elif op == 5:
            depth = rng.randint(2, MAX_NEST)
            at = rng.randrange(len(buf) + 1)
            buf[at:at] = rng.choice([b'[', b'{"a":']) * depth
        elif op == 6:
            at = rng.randrange(len(buf) + 1)
            buf[at:at] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
        elif op == 7 and buf:
            start = rng.randrange(len(buf))
            buf[start:start + rng.randint(1, 32)] = b''
        elif buf:
            buf[rng.randrange(len(buf))] = rng.randrange(256)
    return bytes(buf[:MAX_INPUT_BYTES])


# --- running ------------------------------------------------------------------------------------------------

@dataclass
class Finding:
    target: str
    kind: str          # 'exception' | 'slow' | 'blowup'
    detail: str
    data: bytes

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclass
class Report:
    target: str
    iterations: int = 0
    seconds: float = 0.0
    rejected: int = 0
    findings: list[Finding] = None  # type: ignore[assignment]

    def __post_init__(self):
        self.findings = []

    @property
    def rate(self) -> float:
        return self.iterations / self.seconds if self.seconds else 0.0


def check_one(target: Target, entry: Entry, data: bytes, deadline: float) -> tuple[Finding | None, bool]:
    """Run one input. Returns (finding or None, rejected-by-declared-type)."""
    started = time.monotonic()
    rejected = False
    try:
        result = entry(data)
    except target.allowed:
        result, rejected = None, True
    except RecursionError as exc:
        return Finding(target.name, 'exception', f'RecursionError: {str(exc)[:160]}', data), False
    except Exception as exc:  # noqa: BLE001 - the oracle: any undeclared type is a finding
        return Finding(target.name, 'exception', f'{type(exc).__name__}: {str(exc)[:160]}', data), False
    elapsed = time.monotonic() - started
    if elapsed > deadline:
        return Finding(target.name, 'slow', f'{elapsed:.1f}s > {deadline:.1f}s', data), rejected
    if result is not None and len(repr(result)) > target.max_result_chars:
        return Finding(target.name, 'blowup', f'result repr exceeds {target.max_result_chars} chars', data), rejected
    return None, rejected


def run_target(target: Target, *, iterations: int, seed: int, time_budget: float | None,
               deadline: float = DEFAULT_DEADLINE, crash_dir: Path | None = None) -> Report:
    report = Report(target.name)
    rng = random.Random(f'{seed}:{target.name}')
    seeds = target.seeds() or [b'{}']
    stop = time.monotonic() + time_budget if time_budget else None
    seen: set[str] = set()
    with ExitStack() as stack:
        scratch = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='fuzz-parsers-')))
        entry = target.build(stack, scratch)
        started = time.monotonic()
        # The unmutated seeds first: a seed that is not accepted or rejected cleanly is a finding too.
        for index in range(iterations):
            if stop is not None and time.monotonic() >= stop:
                break
            data = seeds[index] if index < len(seeds) else mutate(rng, rng.choice(seeds))
            finding, rejected = check_one(target, entry, data, deadline)
            report.iterations += 1
            report.rejected += rejected
            if finding is not None and finding.digest not in seen:
                seen.add(finding.digest)
                report.findings.append(finding)
                if crash_dir is not None:
                    crash_dir.mkdir(parents=True, exist_ok=True)
                    (crash_dir / f'{target.name}-{finding.digest}.bin').write_bytes(data)
        report.seconds = time.monotonic() - started
    return report


def run(targets: dict[str, Target], names: list[str], *, iterations: int, seed: int, time_budget: float | None,
        deadline: float = DEFAULT_DEADLINE, crash_dir: Path | None = None) -> list[Report]:
    reports = []
    for position, name in enumerate(names):
        share = None
        if time_budget:
            share = time_budget / (len(names) - position)  # unused time rolls forward
        report = run_target(targets[name], iterations=iterations, seed=seed, time_budget=share,
                            deadline=deadline, crash_dir=crash_dir)
        if time_budget:
            time_budget = max(time_budget - report.seconds, 0.001)
        reports.append(report)
    return reports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--target', default='all', help='target name or "all"')
    parser.add_argument('--iterations', type=int, default=1000)
    parser.add_argument('--seed', type=int, default=0)
    parser.add_argument('--time-budget', type=float, default=None, help='total wall-clock seconds across targets')
    parser.add_argument('--deadline', type=float, default=DEFAULT_DEADLINE, help='per-input seconds before "slow"')
    parser.add_argument('--crash-dir', type=Path, default=Path(tempfile.gettempdir()) / 'patchtrace-fuzz-crashes')
    parser.add_argument('--list', action='store_true')
    args = parser.parse_args(argv)
    targets = _targets()
    if args.list:
        for name, target in targets.items():
            print(f'{name}: {target.note}')
        for name, why in TARGETS_SKIPPED.items():
            print(f'{name}: SKIPPED - {why}')
        return 0
    names = list(targets) if args.target == 'all' else [args.target]
    unknown = [name for name in names if name not in targets]
    if unknown:
        print(f'unknown target {unknown[0]}; choose from {", ".join(targets)}', file=sys.stderr)
        return 2
    reports = run(targets, names, iterations=args.iterations, seed=args.seed, time_budget=args.time_budget,
                  deadline=args.deadline, crash_dir=args.crash_dir)
    failed = 0
    for report in reports:
        print(f'{report.target}: {report.iterations} inputs, {report.rejected} rejected, {report.rate:.0f}/s, '
              f'{len(report.findings)} findings')
        for finding in report.findings:
            failed += 1
            print(f'  finding {finding.digest[:16]} [{finding.kind}] {finding.detail}', file=sys.stderr)
    if failed:
        print(f'{failed} findings saved under {args.crash_dir}', file=sys.stderr)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
