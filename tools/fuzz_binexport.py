"""Nightly/offline BinExport2 fuzz harness (SPEC-10b §10.2). Not CI-gating; never a test dependency.

usage: fuzz_binexport.py [--seconds N] [--corpus DIR] [--crashes DIR] [-- atheris/libFuzzer args]

The oracle: `inspect_bytes` either returns or raises SecondaryError, within a time bound. Anything else is a
finding, saved under --crashes for triage into a regression test. With `atheris` installed (Linux/macOS only;
it does not support Windows) coverage-guided fuzzing runs; otherwise a seeded byte-mutation loop runs, which
is weaker but needs no extra dependency. Seeds: the committed synthetic goldens plus --corpus.
"""
from __future__ import annotations

import argparse
import hashlib
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from patchtrace.secondary.binexport_limits import BinExportLimits, Budget  # noqa: E402
from patchtrace.secondary.binexport_pipeline import inspect_bytes  # noqa: E402
from patchtrace.secondary.contracts import SecondaryError  # noqa: E402

LIMITS = BinExportLimits(max_file_bytes=4 << 20, max_record_bytes=1 << 20, wall_seconds=10)
SLOW_SECONDS = 10.0


def one(data: bytes) -> None:
    started = time.monotonic()
    try:
        inspect_bytes(data, LIMITS, Budget.for_seconds(LIMITS.wall_seconds))
    except SecondaryError:
        pass
    if time.monotonic() - started > SLOW_SECONDS:
        raise RuntimeError('slow input')


def seeds(corpus: Path | None) -> list[bytes]:
    found = sorted((ROOT / 'tests' / 'fixtures' / 'binexport').glob('*.BinExport'))
    if corpus:
        found += sorted(p for p in corpus.iterdir() if p.is_file())
    return [p.read_bytes() for p in found] or [b'\x0a\x00\x42\x00']


def mutate(rng: random.Random, data: bytes) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        op = rng.randrange(4)
        if op == 0 and buf:
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        elif op == 1 and buf:
            del buf[rng.randrange(len(buf)):]
        elif op == 2:
            at = rng.randrange(len(buf) + 1)
            buf[at:at] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
        elif buf:
            a = rng.randrange(len(buf))
            b = rng.randrange(a, len(buf) + 1)
            buf[a:a] = buf[a:b]
    return bytes(buf)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--seconds', type=float, default=1800)
    parser.add_argument('--corpus', type=Path)
    parser.add_argument('--crashes', type=Path, default=Path('binexport-fuzz-crashes'))
    parser.add_argument('rest', nargs='*')
    args = parser.parse_args(argv)
    try:
        import atheris  # type: ignore[import-not-found]
    except ImportError:
        atheris = None
    if atheris is not None:
        atheris.Setup([sys.argv[0], f'-max_total_time={int(args.seconds)}', *args.rest], one)
        atheris.Fuzz()
        return 0
    rng = random.Random(0xB1E)
    pool = seeds(args.corpus)
    deadline, runs, findings = time.monotonic() + args.seconds, 0, 0
    while time.monotonic() < deadline:
        data = mutate(rng, rng.choice(pool))
        runs += 1
        try:
            one(data)
        except Exception as exc:  # the finding: anything but SecondaryError
            findings += 1
            args.crashes.mkdir(parents=True, exist_ok=True)
            name = hashlib.sha256(data).hexdigest()[:16]
            (args.crashes / f'{name}.bin').write_bytes(data)
            print(f'finding {name}: {type(exc).__name__}: {str(exc)[:200]}', file=sys.stderr)
    print(f'{runs} inputs, {findings} findings (random-mutation mode; install atheris on Linux for coverage)')
    return 1 if findings else 0


if __name__ == '__main__':
    sys.exit(main())
