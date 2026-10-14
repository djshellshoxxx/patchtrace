"""Reproducible search-index benchmark (WB1 section 10 budgets): FTS5 name and trigram tables over synthetic names.

Synthetic, labelled workload: N CamelCase and `FUN_` names. Measures table build time and the p95 of a word
query and a substring query. Run from the repository root:

    python tools/bench_search.py [--names 100000] [--repeat 3] [--json]

`--repeat N` reports the best of N timings per measurement (shared hosts are noisy).
"""
from __future__ import annotations

import argparse
import json
import platform
import sqlite3
import sys
import time

_VERBS = ('Copy', 'Probe', 'Query', 'Alloc', 'Free', 'Read', 'Write', 'Open', 'Close', 'Map')
_NOUNS = ('Memory', 'Token', 'Buffer', 'Handle', 'Object', 'Section', 'Process', 'Thread', 'File', 'Key')


def synthetic_names(count: int) -> list[str]:
    names = []
    for i in range(count):
        if i % 5 == 0:
            names.append(f'FUN_{0x140001000 + i * 16:x}')
        else:
            names.append(f'Rtl{_VERBS[i % 10]}{_NOUNS[(i // 10) % 10]}{i}')
    return names


def words(name: str) -> str:
    out, current = [], ''
    for char in name.replace('_', ' '):
        if char.isupper() and current and not current[-1].isupper():
            out.append(current)
            current = ''
        current += char
    return ' '.join([*out, current])


def build(names: list[str]) -> tuple[sqlite3.Connection, float]:
    start = time.perf_counter()
    db = sqlite3.connect(':memory:')
    db.execute("CREATE VIRTUAL TABLE fts_name USING fts5(raw, words, tokenize='unicode61 remove_diacritics 2')")
    db.execute("CREATE VIRTUAL TABLE tri_name USING fts5(name, tokenize='trigram')")
    db.executemany('INSERT INTO fts_name(rowid, raw, words) VALUES (?, ?, ?)',
                   ((i, n.casefold(), words(n).casefold()) for i, n in enumerate(names)))
    db.executemany('INSERT INTO tri_name(rowid, name) VALUES (?, ?)', ((i, n.casefold()) for i, n in enumerate(names)))
    return db, time.perf_counter() - start


def p95_ms(db: sqlite3.Connection, sql: str, queries: list[str]) -> float:
    timings = []
    for query in queries:
        start = time.perf_counter()
        db.execute(sql, (query,)).fetchall()
        timings.append((time.perf_counter() - start) * 1000)
    return sorted(timings)[int(len(timings) * 0.95) - 1]


def measure(count: int) -> dict:
    db, build_s = build(synthetic_names(count))
    word_sql = 'SELECT rowid FROM fts_name WHERE fts_name MATCH ? LIMIT 200'
    sub_sql = 'SELECT rowid FROM tri_name WHERE tri_name MATCH ? LIMIT 200'
    return {'names': count, 'build_s': round(build_s, 3),
            'word_p95_ms': round(p95_ms(db, word_sql, [f'"{v.casefold()}" "{n.casefold()}"' for v in _VERBS for n in _NOUNS]), 3),
            'substring_p95_ms': round(p95_ms(db, sub_sql, [f'"{v.casefold()[1:]}{n.casefold()[:2]}"' for v in _VERBS for n in _NOUNS]), 3)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--names', type=int, default=100_000)
    parser.add_argument('--repeat', type=int, default=3)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    runs = [measure(args.names) for _ in range(max(1, args.repeat))]
    best = {key: (min(run[key] for run in runs) if key != 'names' else args.names) for key in runs[0]}
    best.update(sqlite=sqlite3.sqlite_version, python=platform.python_version())
    if args.json:
        print(json.dumps(best, sort_keys=True))
    else:
        print(' '.join(f'{key}={value}' for key, value in best.items()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
