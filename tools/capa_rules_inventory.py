"""Build a capa rules inventory (CAP-7): rule name, namespace, scopes, lib flag and sha256 of the rule file; no rule
text. Stdlib only, no network, never runs capa.

usage:
  capa_rules_inventory.py --rules-dir DIR --capa-version 9.4.0 [-o OUT]
  capa_rules_inventory.py --from-results RESULT.json [RESULT.json ...] --capa-version 9.4.0 [-o OUT]

`--rules-dir` reads a capa-rules checkout (`*.yml`) and yields `status: complete`. `--from-results` reads capa
`-j` result files and can only see the rules that matched, so it yields `status: derived-unverified`: a subset,
not the rule pack. The meta block is read with a small line parser (no YAML dependency); rules whose meta cannot
be read are listed under `skipped`, never guessed.

Exit codes: 0 written; 2 usage or unreadable input; 3 no rule could be read.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

CONTRACT = 'capa-rules-inventory/1'
_KEY = re.compile(r'^(?P<indent> *)(?P<key>[A-Za-z_]+):(?: +(?P<value>.*))?$')


def _scalar(text: str | None) -> str | None:
    if text is None:
        return None
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in '\'"':
        return text[1:-1].replace("''", "'") if text[0] == "'" else text[1:-1]
    return text.split(' #')[0].strip() or None


def _meta_lines(text: str) -> list[tuple[int, str, str | None]]:
    """(indent, key, value) of the lines between `meta:` and the next key at the same level."""
    out: list[tuple[int, str, str | None]] = []
    meta_indent: int | None = None
    for line in text.splitlines():
        match = _KEY.match(line.rstrip())
        if match is None:
            continue
        indent, key = len(match['indent']), match['key']
        if meta_indent is None:
            if key == 'meta':
                meta_indent = indent
            continue
        if indent <= meta_indent:
            break
        out.append((indent, key, match['value']))
    return out


def parse_rule_file(data: bytes) -> dict | None:
    """The inventory entry of one rule file, or None when name or scopes cannot be read."""
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return None
    lines = _meta_lines(text)
    if not lines:
        return None
    base = lines[0][0]
    top = {key: _scalar(value) for indent, key, value in lines if indent == base}
    scopes: dict[str, str] = {}
    in_scopes = False
    for indent, key, value in lines:
        if indent == base:
            in_scopes = key == 'scopes'
        elif in_scopes and key in ('static', 'dynamic') and _scalar(value):
            scopes[key] = _scalar(value)
    if 'scope' in top and top['scope'] and 'static' not in scopes:
        scopes['static'] = top['scope']
    if not top.get('name') or not scopes:
        return None
    return {'name': top['name'], 'namespace': top.get('namespace'), 'scopes': scopes,
            'lib': (top.get('lib') or '').lower() == 'true', 'rule_sha256': hashlib.sha256(data).hexdigest()}


def scan_rules(rules_dir: Path) -> tuple[list[dict], list[str]]:
    entries: list[dict] = []
    skipped: list[str] = []
    for path in sorted(rules_dir.rglob('*.yml')):
        entry = parse_rule_file(path.read_bytes())
        if entry is None:
            skipped.append(path.relative_to(rules_dir).as_posix())
        else:
            entries.append(entry)
    return entries, skipped


def from_results(paths: list[Path]) -> list[dict]:
    """Entries of the rules that matched in capa `-j` results, deduplicated by name. `source` is the rule file text."""
    found: dict[str, dict] = {}
    for path in paths:
        document = json.loads(path.read_text(encoding='utf-8'))
        for name, rule in sorted(document['rules'].items()):
            meta = rule['meta']
            found[name] = {'name': name, 'namespace': meta.get('namespace'),
                           'scopes': {k: v for k, v in meta['scopes'].items() if k in ('static', 'dynamic')},
                           'lib': bool(meta.get('lib')),
                           'rule_sha256': hashlib.sha256(rule['source'].encode('utf-8')).hexdigest()}
    return list(found.values())


def build_inventory(entries: list[dict], capa_version: str, *, complete: bool, source: str,
                    skipped: list[str] | None = None) -> dict:
    document = {
        'contract': CONTRACT, 'capa_version': capa_version,
        'status': 'complete' if complete else 'derived-unverified',
        'provenance': source,
        'rules': sorted(entries, key=lambda e: e['name']),
    }
    if not complete:
        document['warning'] = ('DERIVED/UNVERIFIED: only rules that matched in the listed capa results; the capa-rules '
                               'pack was not available, so absence here does not mean a rule does not exist.')
    if skipped:
        document['skipped'] = skipped
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--rules-dir', type=Path)
    source.add_argument('--from-results', type=Path, nargs='+')
    parser.add_argument('--capa-version', required=True)
    parser.add_argument('-o', '--output', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.rules_dir is not None:
            entries, skipped = scan_rules(args.rules_dir)
            document = build_inventory(entries, args.capa_version, complete=True, skipped=skipped,
                                       source=f'capa-rules directory {args.rules_dir.name}')
        else:
            entries = from_results(args.from_results)
            names = ', '.join(p.name for p in args.from_results)
            document = build_inventory(entries, args.capa_version, complete=False,
                                       source=f'real capa {args.capa_version} results on a synthetic PE pair: {names}')
    except (OSError, ValueError, KeyError) as error:
        print(f'cannot read input: {error}', file=sys.stderr)
        return 2
    if not entries:
        print('no rule could be read', file=sys.stderr)
        return 3
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    if args.output is None:
        sys.stdout.write(text)
    else:
        with open(args.output, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
