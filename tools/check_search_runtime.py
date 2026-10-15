"""CI/dev guard (WB1 S0): this Python's SQLite can run the search index (FTS5, unicode61, trigram).

usage: check_search_runtime.py [--json] [--require-native-rapidfuzz]
Exits 0 when the index is usable, 1 otherwise (and, with the flag, when RapidFuzz is absent or pure Python).
Prints one line, or one JSON document. The frozen build runs the same probe through `patchtrace search --probe`.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--require-native-rapidfuzz', action='store_true')
    args = parser.parse_args(argv)
    from patchtrace.search.capability import probe_capability
    capability = probe_capability()
    ok = capability.usable and (capability.rapidfuzz_native or not args.require_native_rapidfuzz)
    if args.json:
        print(json.dumps({**dataclasses.asdict(capability), 'usable': capability.usable, 'ok': ok}, sort_keys=True))
    else:
        print(f'search-runtime: {"ok" if ok else "FAIL"} sqlite={capability.sqlite_version} fts5={capability.fts5} '
              f'unicode61={capability.unicode61} trigram={capability.trigram} '
              f'rapidfuzz={capability.rapidfuzz_version or "absent"}/{capability.rapidfuzz_backend or "-"}')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
