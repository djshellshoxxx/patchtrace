"""Validate the Windows before/after pins file (`rq-win-pins/1`) and optionally cross-check it against case manifests.

Stdlib only, offline, never executes or fetches anything. Can also emit an `rq-case-manifest/1` overlay (id, older,
newer) that tools/research_qualification/winpairs.py consumes directly.
Exit codes: 0 ok, 1 pins differ from the schema or the manifests, 2 usage/blocked (bad args, unreadable file).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from tools.research_qualification.pathguard import PathGuardError, confine

SCHEMA = 'rq-win-pins/1'
CASE_SCHEMA = 'rq-case-manifest/1'
ARCHES = frozenset({'amd64', 'x86', 'arm64'})
SIDE_KEYS = ('version', 'kb', 'sha256', 'timestamp', 'virtual_size', 'release_date', 'windows_version', 'arch')
_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
_VER = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
_KB = re.compile(r'^KB\d{6,8}$')
_SHA = re.compile(r'^[0-9a-f]{64}$')
_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')


class PinsError(ValueError):
    """Unreadable or structurally unusable input (maps to exit code 2)."""


def _side_problems(tag: str, s: Any) -> list[str]:
    if not isinstance(s, dict):
        return [f'{tag}: must be an object']
    out = [f'{tag}: missing key {k}' for k in SIDE_KEYS if k not in s]
    out += [f'{tag}: unknown key {k}' for k in s if k not in SIDE_KEYS]
    if out:
        return out
    if not isinstance(s['version'], str) or not _VER.match(s['version']):
        out.append(f'{tag}: version must be dotted a.b.c.d')
    if s['kb'] is not None and not (isinstance(s['kb'], str) and _KB.match(s['kb'])):
        out.append(f'{tag}: kb must be null or KB<digits>')
    if not isinstance(s['sha256'], str) or not _SHA.match(s['sha256']):
        out.append(f'{tag}: sha256 must be 64 lower-case hex')
    for k, lo in (('timestamp', 0), ('virtual_size', 1)):
        v = s[k]
        if isinstance(v, bool) or not isinstance(v, int) or v < lo or v >= 2**32:
            out.append(f'{tag}: {k} must be an unsigned 32-bit integer' + (' > 0' if lo else ''))
    if s['release_date'] is not None and not (isinstance(s['release_date'], str) and _DATE.match(s['release_date'])):
        out.append(f'{tag}: release_date must be null or YYYY-MM-DD')
    if not isinstance(s['windows_version'], str) or not s['windows_version']:
        out.append(f'{tag}: windows_version must be a non-empty string')
    if s['arch'] not in ARCHES:
        out.append(f'{tag}: arch must be one of {sorted(ARCHES)}')
    return out


def _fetch_problems(tag: str, e: dict[str, Any]) -> list[str]:
    fc = e.get('fetch_check')
    if fc is None:
        return []
    if not isinstance(fc, dict):
        return [f'{tag}: fetch_check must be an object']
    out: list[str] = []
    for side in ('before', 'after'):
        r = fc.get(side)
        pin = e.get(side)
        if not isinstance(r, dict) or not isinstance(pin, dict):
            out.append(f'{tag}: fetch_check.{side} must be an object next to a pinned side')
            continue
        got = r.get('sha256')
        if got is not None and got.lower() == pin.get('sha256') and r.get('sha256_matches') is not True:
            out.append(f'{tag}: fetch_check.{side}.sha256_matches contradicts equal hashes')
        if got is not None and got.lower() != pin.get('sha256') and r.get('sha256_matches') is not False:
            out.append(f'{tag}: fetch_check.{side}.sha256_matches contradicts differing hashes')
        if got is None and r.get('sha256_matches') is not False:
            out.append(f'{tag}: fetch_check.{side} has no sha256 so sha256_matches must be false')
    return out


def entry_problems(i: int, e: Any) -> list[str]:
    tag = f'entries[{i}]'
    if not isinstance(e, dict):
        return [f'{tag}: must be an object']
    cid = e.get('case_id')
    tag = f'entries[{i}] {cid}'
    out: list[str] = []
    if not isinstance(cid, str) or not _NAME.match(cid):
        out.append(f'{tag}: case_id missing or unsafe')
    if not isinstance(e.get('file'), str) or not _NAME.match(e['file']):
        out.append(f'{tag}: file missing or unsafe')
    if not isinstance(e.get('reason'), str) or not e['reason'].strip():
        out.append(f'{tag}: reason must be a non-empty string')
    if 'caveats' in e and not (isinstance(e['caveats'], list) and all(isinstance(c, str) for c in e['caveats'])):
        out.append(f'{tag}: caveats must be a list of strings')
    src = e.get('source')
    if not (isinstance(src, dict) and str(src.get('url', '')).startswith('https://winbindex.m417z.com/')
            and _DATE.match(str(src.get('fetched', '')))):
        out.append(f'{tag}: source needs a winbindex https url and a fetched date')
    status = e.get('status')
    if status == 'unpinned':
        if e.get('before') is not None or e.get('after') is not None:
            out.append(f'{tag}: unpinned entries must have before and after null')
        return out
    if status != 'pinned':
        return [*out, f'{tag}: status must be pinned or unpinned']
    sides = [_side_problems(f'{tag} {k}', e.get(k)) for k in ('before', 'after')]
    out += [p for s in sides for p in s]
    if any(sides):
        return out
    b, a = e['before'], e['after']
    if b['sha256'] == a['sha256']:
        out.append(f'{tag}: before and after sha256 are identical')
    if b['version'] == a['version']:
        out.append(f'{tag}: file version does not change between before and after')
    if b['arch'] != a['arch'] or b['windows_version'] != a['windows_version']:
        out.append(f'{tag}: before and after must share arch and windows_version')
    if b['release_date'] and a['release_date'] and b['release_date'] >= a['release_date']:
        out.append(f'{tag}: before release_date must precede after release_date')
    if b['kb'] and a['kb'] and b['kb'] == a['kb']:
        out.append(f'{tag}: before and after name the same KB')
    return out + _fetch_problems(tag, e)


def validate(doc: Any) -> list[str]:
    if not isinstance(doc, dict):
        return ['top level must be an object']
    out: list[str] = []
    if doc.get('schema') != SCHEMA:
        out.append(f'schema must be {SCHEMA}')
    if not _DATE.match(str(doc.get('generated', ''))):
        out.append('generated must be YYYY-MM-DD')
    entries = doc.get('entries')
    if not isinstance(entries, list) or not entries:
        return [*out, 'entries must be a non-empty list']
    seen: set[str] = set()
    for i, e in enumerate(entries):
        out += entry_problems(i, e)
        cid = e.get('case_id') if isinstance(e, dict) else None
        if isinstance(cid, str):
            if cid in seen:
                out.append(f'duplicate case_id {cid}')
            seen.add(cid)
    return out


def manifest_files(manifest: Any) -> dict[str, str]:
    """case id -> file name as the case spells it (first token of older.ref, else older.file)."""
    if not isinstance(manifest, dict) or manifest.get('schema') != CASE_SCHEMA or not isinstance(manifest.get('cases'), list):
        raise PinsError(f'manifest schema must be {CASE_SCHEMA}')
    out: dict[str, str] = {}
    for c in manifest['cases']:
        side = c.get('older') or {}
        ref = str(side.get('ref', '')).replace(',', ' ').split()
        out[str(c.get('id'))] = str(side.get('file') or (ref[0] if ref else ''))
    return out


def cross_check(doc: dict[str, Any], files: dict[str, str]) -> list[str]:
    out = []
    pins = {e['case_id']: e for e in doc['entries'] if isinstance(e, dict) and 'case_id' in e}
    out += [f'case {c} has no pins entry' for c in sorted(set(files) - set(pins))]
    out += [f'pins entry {c} matches no case in the manifests' for c in sorted(set(pins) - set(files))]
    for c in sorted(set(pins) & set(files)):
        if files[c].lower() != str(pins[c].get('file', '')).lower():
            out.append(f'{c}: file {pins[c].get("file")} differs from the case file {files[c]}')
    return out


def to_case_manifest(doc: dict[str, Any]) -> dict[str, Any]:
    """rq-case-manifest/1 overlay for winpairs: pinned entries only, sha256-exact, with kb/month hints when known."""
    cases = []
    for e in doc['entries']:
        if e.get('status') != 'pinned':
            continue
        sides = {}
        for key, pin in (('older', e['before']), ('newer', e['after'])):
            s: dict[str, Any] = {'file': e['file'], 'version': pin['version'], 'sha256': pin['sha256'],
                                 'machine': pin['arch']}
            if pin['kb']:
                s['kb'] = pin['kb']
            if pin['release_date']:
                s['month'] = pin['release_date'][:7]
            sides[key] = s
        cases.append({'id': e['case_id'], **sides})
    return {'schema': CASE_SCHEMA, 'cases': cases}


def _load(path: Path, what: str) -> Any:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        raise PinsError(f'cannot read {what} {path.name}: {e}') from None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog='pins_check', description=__doc__.split('\n')[0])
    ap.add_argument('--pins', required=True, help='windows-pins.json (rq-win-pins/1)')
    ap.add_argument('--manifest', action='append', default=[], help='rq-case-manifest/1 to cross-check (repeatable)')
    ap.add_argument('--emit-case-manifest', default='', help='write the winpairs-ready rq-case-manifest/1 overlay here')
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    try:
        doc = _load(confine(a.pins, 'pins'), 'pins')
        problems = validate(doc)
        if not problems and a.manifest:
            files: dict[str, str] = {}
            for m in a.manifest:
                files.update(manifest_files(_load(confine(m, 'manifest'), 'manifest')))
            problems = cross_check(doc, files)
        if problems:
            for p in problems:
                print(f'pins_check: {p}', file=sys.stderr)
            return 1
        if a.emit_case_manifest:
            out = confine(a.emit_case_manifest, 'emit-case-manifest')
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(to_case_manifest(doc), indent=2, sort_keys=True) + '\n', encoding='utf-8')
    except (PathGuardError, PinsError, OSError) as e:
        print(f'pins_check: blocked: {e}', file=sys.stderr)
        return 2
    pinned = sum(e['status'] == 'pinned' for e in doc['entries'])
    print(f'pins_check: ok; {pinned} pinned, {len(doc["entries"]) - pinned} unpinned')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
