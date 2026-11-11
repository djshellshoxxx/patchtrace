"""Validator for the L1 KB/CVE join candidate manifest (schema rq-l1-manifest/1).

usage: python -m tools.research_qualification.l1_check [docs/research/accuracy-cases/l1-join-candidates.json]

Structural checks only (stdlib). It does not fetch anything and does not prove a fact is true; it enforces that every
case carries the evidence fields the scoring rule needs. See docs/research/accuracy-cases/l1-join-candidates.md.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from . import pathguard as PG

SCHEMA = 'rq-l1-manifest/1'
FACTS = ('verified', 'unverified')
STRATA = ('baseline-driver', 'baseline-usermode', 'shared-file-kb', 'multi-product-kb', 'supersedence',
          'rollup-vs-security-only', 'no-kb', 'non-windows-kb', 'oracle-disagreement', 'file-unstated')
NO_FILE_STRATA = ('no-kb', 'non-windows-kb', 'file-unstated', 'rollup-vs-security-only')
REQUIRED = {'id', 'month', 'cve', 'kb', 'product', 'expected_files', 'oracle_urls', 'stratum', 'facts', 'notes'}
OPTIONAL = {'products_for_kb'}
DEFAULT_PATH = Path(__file__).resolve().parents[2] / 'docs' / 'research' / 'accuracy-cases' / 'l1-join-candidates.json'
_ID = re.compile(r'^l1-[0-9a-z.-]{1,100}$')
_MONTH = re.compile(r'^20[0-9]{2}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$')
_CVE = re.compile(r'^CVE-[0-9]{4}-[0-9]{4,7}$')
_KB = re.compile(r'^KB[0-9]{6,8}$')
_FILE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$')
_URL = re.compile(r'^https://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(/\S*)?$')


def _strs(v: Any, name: str, cid: str) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError(f'{cid}: {name} must be a list of strings')
    return v


def check_case(c: Any) -> str:
    """Validate one case and return its id. Raises ValueError on the first problem."""
    if not isinstance(c, dict):
        raise ValueError('case must be an object')
    cid = c.get('id', '?')
    missing, extra = REQUIRED - set(c), set(c) - REQUIRED - OPTIONAL
    if missing or extra:
        raise ValueError(f'{cid}: missing keys {sorted(missing)} unexpected keys {sorted(extra)}')
    if not isinstance(cid, str) or not _ID.match(cid):
        raise ValueError(f'{cid}: id must match {_ID.pattern}')
    if not (isinstance(c['month'], str) and _MONTH.match(c['month'])):
        raise ValueError(f'{cid}: month must look like 2024-Aug')
    if not (isinstance(c['cve'], str) and _CVE.match(c['cve'])):
        raise ValueError(f'{cid}: bad cve')
    if c['stratum'] not in STRATA:
        raise ValueError(f'{cid}: stratum must be one of {STRATA}')
    if c['facts'] not in FACTS:
        raise ValueError(f'{cid}: facts must be one of {FACTS}')
    kb = c['kb']
    if c['stratum'] == 'no-kb':
        if kb != '':
            raise ValueError(f'{cid}: a no-kb case must have kb ""')
    elif not (isinstance(kb, str) and _KB.match(kb)):
        raise ValueError(f'{cid}: kb must look like KB5041585')
    if not isinstance(c['product'], str) or not c['product'].strip():
        raise ValueError(f'{cid}: product must be a non-empty string')
    files = _strs(c['expected_files'], 'expected_files', cid)
    if len(set(files)) != len(files) or files != sorted(files) or not all(_FILE.match(f) for f in files):
        raise ValueError(f'{cid}: expected_files must be unique, sorted bare file names')
    if c['stratum'] in NO_FILE_STRATA and files:
        raise ValueError(f'{cid}: stratum {c["stratum"]} must have empty expected_files')
    if c['stratum'] not in NO_FILE_STRATA and not files:
        raise ValueError(f'{cid}: stratum {c["stratum"]} needs at least one expected file')
    urls = _strs(c['oracle_urls'], 'oracle_urls', cid)
    if len(set(urls)) != len(urls) or not all(_URL.match(u) for u in urls):
        raise ValueError(f'{cid}: oracle_urls must be unique https URLs')
    if c['facts'] == 'verified' and not urls:
        raise ValueError(f'{cid}: a verified case needs at least one oracle URL')
    if not isinstance(c['notes'], str) or not c['notes'].strip():
        raise ValueError(f'{cid}: notes must be non-empty')
    if 'products_for_kb' in c:
        prods = _strs(c['products_for_kb'], 'products_for_kb', cid)
        if prods != sorted(set(prods)):
            raise ValueError(f'{cid}: products_for_kb must be sorted and unique')
        if prods and c['product'] not in prods:
            raise ValueError(f'{cid}: product must be a member of products_for_kb')
    return cid


def check_manifest(m: Any) -> dict[str, Any]:
    """Validate a whole manifest. Returns a summary dict; raises ValueError on the first problem."""
    if not isinstance(m, dict) or m.get('schema') != SCHEMA or not isinstance(m.get('cases'), list):
        raise ValueError(f'manifest must be an object with schema {SCHEMA} and a cases list')
    ids = [check_case(c) for c in m['cases']]
    if len(set(ids)) != len(ids):
        raise ValueError('duplicate case ids: ' + ', '.join(sorted(i for i, n in Counter(ids).items() if n > 1)))
    if ids != sorted(ids):
        raise ValueError('cases must be sorted by id (freeze-friendly order)')
    return {'cases': len(ids), 'manifest_sha256': manifest_hash(m),
            'strata': dict(sorted(Counter(c['stratum'] for c in m['cases']).items())),
            'facts': dict(sorted(Counter(c['facts'] for c in m['cases']).items()))}


def manifest_hash(m: dict[str, Any]) -> str:
    """sha256 of the canonical JSON form (sorted keys, no whitespace); record it when the manifest is frozen."""
    blob = json.dumps(m, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return hashlib.sha256(blob).hexdigest()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        path = PG.confine(args[0], 'manifest') if args else DEFAULT_PATH
        summary = check_manifest(json.loads(path.read_text(encoding='utf-8')))
    except PG.PathGuardError as exc:
        print(f'l1_check: error: {exc}', file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f'l1_check: FAILED: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
