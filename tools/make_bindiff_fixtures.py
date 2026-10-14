"""Generate the SYNTHETIC `.BinDiff` golden fixtures (SPEC-29 §9.3) from the shared test builder.

usage: python tools/make_bindiff_fixtures.py [--out tests/fixtures/secondary]

Writes `bindiff-synthetic-pair.BinDiff`, `bindiff-synthetic-stdout.txt` and `bindiff-synthetic.json`
(provenance: generator, inputs, SHA-256). These are NOT produced by BinDiff: they follow the table layout
the importer requires and stand in until the live job (`.github/workflows/live-bindiff.yml`) produces a real
v8 golden on a provisioned runner. SQLite bytes may differ across SQLite versions, so tests compare the
imported content, and check the committed file against its recorded SHA-256.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))

from bindiff_builder import build  # noqa: E402

OLDER = hashlib.sha256(b'patchtrace synthetic older artifact').hexdigest()
NEWER = hashlib.sha256(b'patchtrace synthetic newer artifact').hexdigest()
VERSION = 'BinDiff 8 (synthetic fixture, not produced by BinDiff)'
CREATED = '2026-10-14 00:00:00'
ALGORITHMS = ((1, 'function: name hash matching'), (2, 'function: hash matching'),
              (3, 'function: edges flowgraph MD index'), (4, 'function: call reference matching'))
FUNCTIONS = [
    (1, 0x140001000, 'DriverEntry', 0x140001000, 'DriverEntry', 1.0, 0.99, 0, 1),
    (2, 0x140001200, 'DispatchIoctl', 0x140001240, 'DispatchIoctl', 0.8125, 0.93, 1 | 2 | 64, 3),
    (3, 0x140001800, 'ParseBuffer', 0x140001880, 'ParseBuffer', 0.5, 0.71, 4 | 8 | 16, 3),
    (4, 0x140002000, None, 0x140002100, None, 0.25, 0.4, 32, 4),
    (5, 0x8000000000001000, 'HighHalf', 0x8000000000001010, 'HighHalf', 0.9, 0.9, 0, 2),
]
STDOUT = ('BinDiff 8 (synthetic fixture)\n'
          'matched: 5 of 7/8 (primary/secondary, 6/7 non-library)\n'
          'Similarity: 61.4% (Confidence: 83.7%)\n')


def sqlite_functions(rows):
    """BinDiff stores uint64 addresses in signed BIGINT; mirror that for high-half addresses."""
    return [(i, a1 - (1 << 64) if a1 >= 1 << 63 else a1, n1, a2 - (1 << 64) if a2 >= 1 << 63 else a2, *rest)
            for i, a1, n1, a2, *rest in rows]


def generate(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    target = out / 'bindiff-synthetic-pair.BinDiff'
    target.unlink(missing_ok=True)
    build(target, hashes=(OLDER, NEWER), version=VERSION, functions=sqlite_functions(FUNCTIONS),
          algorithms=ALGORITHMS, created=CREATED)
    db = sqlite3.connect(target)
    db.execute('VACUUM')
    db.close()
    (out / 'bindiff-synthetic-stdout.txt').write_text(STDOUT, encoding='utf-8', newline='\n')
    record = {'file': target.name, 'file_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
              'size': target.stat().st_size, 'synthetic': True, 'produced_by': 'tools/make_bindiff_fixtures.py',
              'sqlite_version': sqlite3.sqlite_version, 'older_sha256': OLDER, 'newer_sha256': NEWER,
              'metadata_version': VERSION, 'functions': len(FUNCTIONS),
              'note': 'Not produced by BinDiff; replace with the live v8 golden (SPEC-29 section 9.3).'}
    (out / 'bindiff-synthetic.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n',
                                                encoding='utf-8', newline='\n')
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=ROOT / 'tests' / 'fixtures' / 'secondary')
    print(json.dumps(generate(parser.parse_args().out), indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
