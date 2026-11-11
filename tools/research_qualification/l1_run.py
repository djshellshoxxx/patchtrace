"""L1 advisory-join runner over a frozen rq-l1-manifest/1 manifest (receipt contract rq-l1-run/1).

usage: python -m tools.research_qualification l1-run MANIFEST --months DIR --out RECEIPT --frozen-sha SHA256
           --evidence-class {synthetic,live} [--winbindex DIR --winbindex-date YYYY-MM-DD]
       python -m tools.research_qualification l1-run MANIFEST --dry-run

For every `facts: verified` case the runner asks PatchTrace's own offline join, through the same entry points as
`patchtrace kb index import`, `kb search` and `kb pairs`, three questions: (a) does the month list the expected
CVE -> KB edge, (b) does that edge carry the expected product scope, (c) only with --winbindex: does the supplied file
index resolve each expected file for that KB and product. It never re-implements the join, never fetches and never
executes a target. It scores this checkout's `src/patchtrace` only (run with PYTHONPATH=src). Exit codes: 0 every
asked case passed, 1 at least one case failed, 2 blocked or usage error.

Honesty limits (repeated in every receipt):
- L1 only. An L1 result is never blended with L2 or L3 figures.
- A case marked `facts: unverified` is listed under `excluded`, never asked and in no count.
- BLOCKED means the case was not answered (month not loaded, file-index record not supplied, or the join raised).
  It is not a miss and it is in no pass/fail count.
- The join takes the file name as input and does not predict file sets, so the manifest's "file set equality" rule
  is not evaluated; leg (c) only says whether the expected name resolves. For `non-windows-kb` cases only legs (a)
  and (b) are asked; "no Windows pair" is not evaluated.
- `evidence_class` comes from the operator's flag and is never guessed. With `synthetic` the receipt proves mechanics
  only and carries no accuracy figure. Real MSRC months cannot be fetched in the build sandbox, so this module has
  been exercised on the synthetic month of tests/fixtures/kbcorrelation/ only; no accuracy number exists yet.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
import tempfile
from collections import Counter
from itertools import islice
from pathlib import Path
from typing import Any

from . import l1_check as L1
from . import pathguard as PG
from . import receipt as R
from . import sample_size as SS

SCHEMA = 'rq-l1-run/1'
EVIDENCE_CLASSES = ('synthetic', 'live')
MONTH_SUFFIXES = ('.json', '.xml', '.json.gz', '.xml.gz')
RECORD_SUFFIXES = ('.json', '.json.gz')
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_CASES = 5000
MAX_MONTH_FILES = 240
MAX_RECORD_FILES = 2000
MAX_DIR_ENTRIES = 10_000
MAX_SHOWN = 20
TEXT_LIMIT = 300
REPO = Path(__file__).resolve().parents[2]
# The join runs in a throw-away workspace. A fixed instant keeps it off the wall clock; it only stamps "retrieved at".
FIXED_NOW = '2000-01-01T00:00:00Z'
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_DATE = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}$')
FILE_RULE = ('pass = `kb pairs` returns at least one pair candidate that is not hard-blocked (grade X) for the KB and '
             'file under the expected product, and the file index does not say the file was unchanged in that KB')
LIMITS = (
    'L1 advisory join only; never blend this with L2 or L3 figures.',
    'Cases marked facts: unverified are listed under excluded, were never asked and are in no count.',
    'BLOCKED cases were not answered; they are not misses and are in no pass/fail count.',
    'The join takes the file name as input, so file-set equality is not evaluated; the file leg only says whether '
    'the expected name resolves. For non-windows-kb cases "no Windows pair" is not evaluated.',
)
SYNTHETIC_LIMIT = 'evidence_class synthetic: fixtures only; this receipt proves mechanics and carries no accuracy figure.'


class RunBlocked(Exception):
    """The run cannot start or finish as asked (usage, unfrozen manifest, unusable input): exit 2."""


def _clip(text: object, limit: int = TEXT_LIMIT) -> str:
    return str(text)[:limit]


class _FixedClock:
    def now_utc(self) -> str:
        return FIXED_NOW


# ---------------------------------------------------------------------------------------------- the product

class ProductJoin:
    """PatchTrace's offline join behind its public entry points. One workspace per release month keeps a lookup from
    re-parsing every other month; each search is still scoped to its month, as `kb search --months` is."""

    def __init__(self, root: Path):
        try:
            import patchtrace
            from patchtrace.kbcorrelation import cli, components, products
            from patchtrace.kbcorrelation.service import KbService
            from patchtrace.kbcorrelation.store import KbcStoreError
            from patchtrace.kbcorrelation.wiring import build_env
        except ImportError as exc:
            raise RunBlocked(f'PatchTrace is not importable ({exc.name}); install its dependencies first') from None
        local = REPO / 'src' / 'patchtrace'
        if local.is_dir() and not Path(patchtrace.__file__).resolve().parent.samefile(local):
            # tools/ imports whatever `patchtrace` the environment offers, which can be another checkout's.
            raise RunBlocked('the importable patchtrace package is not this checkout\'s src/patchtrace; run with '
                             'PYTHONPATH=src so the receipt describes the code it scored')
        self._cli, self._components, self._products = cli, components, products
        self._service, self._store_error = KbService, KbcStoreError
        self._env = build_env(clock=_FixedClock())
        self._root = root
        self._home: dict[str, Path] = {}
        self._records: dict[tuple[Path, str], str] = {}

    def _kb(self, argv: list[str]) -> tuple[int, dict]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err):
            code = self._cli.main(argv, env=self._env, stdout=out, stderr=err)
        try:
            doc = json.loads(out.getvalue())
        except ValueError:
            doc = {}
        return code, doc if isinstance(doc, dict) else {}

    @staticmethod
    def _failure(doc: dict) -> str:
        rejected = (doc.get('result') or {}).get('rejected') or []
        if rejected:
            return _clip(f'{rejected[0].get("code")}: {rejected[0].get("message")}')
        return _clip(doc.get('error') or 'the import failed')

    def import_month(self, index: int, path: Path) -> dict:
        """`kb index import FILE` into the workspace of the file's release month."""
        try:
            entry = {'file': path.name, 'sha256': R.sha256_file(path)}
        except OSError:
            return {'file': path.name, 'sha256': None, 'status': 'rejected', 'reason': 'the file cannot be read'}
        probe = self._root / f'doc{index:04d}'
        code, doc = self._kb(['index', 'import', '--json', '--workspace', str(probe), str(path)])
        documents = (doc.get('result') or {}).get('documents') or []
        if code != 0 or len(documents) != 1:
            return {**entry, 'status': 'rejected', 'reason': self._failure(doc)}
        info = documents[0]
        release = info.get('release_id')
        if release:
            home = self._home.setdefault(release, probe)
            if home != probe:  # another revision of the same month: both go to one workspace, the product picks
                self._kb(['index', 'import', '--json', '--workspace', str(home), str(path)])
        return {**entry, 'status': 'loaded', 'release_id': release, 'kind': info.get('kind'),
                'doc_id': info.get('doc_id'), 'edges': info.get('edges'), 'problems': info.get('problems')}

    def search(self, cve: str, month: str) -> dict | None:
        """`kb search CVE --months MONTH`; None when no loaded document belongs to that month."""
        home = self._home.get(month)
        return None if home is None else self._service(home, self._env).search(cve, months=month).result

    def scope_id(self, product: str) -> str:
        """The scope identity the product's own catalogue gives a product name."""
        return self._products.scope_id_for(self._products.derive(product))

    def _record(self, home: Path, name: str, record: Path, data_date: str) -> str:
        key = (home, name)
        if key not in self._records:
            code, doc = self._kb(['index', 'import', '--json', '--workspace', str(home), '--winbindex', name,
                                  '--data-date', data_date, str(record)])
            self._records[key] = '' if code == 0 else f'the file-index record was rejected: {self._failure(doc)}'
        return self._records[key]

    def resolve_file(self, month: str, investigation: str, scope_id: str, kb: str, name: str, record: Path | None,
                     data_date: str) -> dict:
        """`kb pairs INV --product SCOPE --file NAME` over the supplied record, reduced to one verdict."""
        try:
            self._components.normalise_name(name)
        except ValueError as exc:
            return {'name': name, 'result': 'fail', 'detail': _clip(f'the product refuses this file name: {exc}')}
        if record is None:
            return {'name': name, 'result': 'blocked', 'detail': 'no record for this file in --winbindex'}
        home = self._home[month]
        problem = self._record(home, name, record, data_date)
        if problem:
            return {'name': name, 'result': 'blocked', 'detail': problem}
        try:
            result = self._service(home, self._env).pairs(investigation, product=scope_id, files=[name]).result
        except Exception as exc:  # an unanswered question is BLOCKED, never a miss and never a traceback
            return {'name': name, 'result': 'blocked', 'detail': self.describe(exc)}
        return _file_verdict(result, kb, name)

    def describe(self, exc: Exception) -> str:
        """The product's fixed-template error text, or only the type of an unexpected exception (its message may
        hold local paths, which a receipt must not carry)."""
        if isinstance(exc, self._store_error):
            return _clip(f'the join could not answer: {exc.code}: {exc.message}')
        return f'the join raised {type(exc).__name__}'


def _file_verdict(result: dict, kb: str, name: str) -> dict:
    if result.get('reason') or name in result.get('files_without_record', []):
        return {'name': name, 'result': 'blocked',
                'detail': _clip(result.get('reason') or 'the file index holds no record for this file')}
    mine = [r for r in result.get('resolutions', []) if r['kb'] == kb and r['file_name'] == name]
    usable = [p for p in result.get('pairs', []) if p['kb'] == kb and p['file_name'] == name and p['grade'] != 'X']
    changed = mine[0]['changed_in_kb'] if mine else 'unknown'
    detail = ''
    if changed == 'no':
        detail = f'the file index says the file did not change in {kb} (last changed in {mine[0]["last_changed_in"]})'
    elif not usable:
        detail = (mine[0]['note'] or ', '.join(mine[0]['blockers'])) if mine else ''
        detail = detail or 'no usable pair candidate'
    return {'name': name, 'result': 'fail' if detail else 'pass', 'changed_in_kb': changed,
            'candidates': len(usable), 'detail': _clip(detail)}


# ---------------------------------------------------------------------------------------------- inputs

def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError('strict JSON only: an object repeats a key')
    return dict(pairs)


def _reject_constant(name: str) -> Any:
    raise ValueError(f'strict JSON only: {name} is not allowed')


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        with open(path, 'rb') as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ValueError(f'the manifest is larger than {MAX_MANIFEST_BYTES} bytes')
        manifest = json.loads(raw.decode('utf-8'), object_pairs_hook=_strict_object, parse_constant=_reject_constant)
        L1.check_manifest(manifest)
    except (OSError, ValueError) as exc:
        raise RunBlocked(f'manifest: {exc}') from None
    if len(manifest['cases']) > MAX_CASES:
        raise RunBlocked(f'the manifest has more than {MAX_CASES} cases')
    return manifest


def require_frozen(manifest: dict[str, Any], frozen_sha: str | None) -> str:
    """A scored run needs the freeze hash recorded before the run; an absent or different hash is refused."""
    if not frozen_sha:
        raise RunBlocked('the manifest is not frozen: pass --frozen-sha with the manifest_sha256 recorded at freeze '
                         'time (see l1_check), or use --dry-run')
    if not _HEX64.match(frozen_sha):
        raise RunBlocked('the frozen sha must be 64 lowercase hex characters')
    if L1.manifest_hash(manifest) != frozen_sha:
        raise RunBlocked('the manifest does not match its frozen hash; it changed after it was frozen')
    return frozen_sha


def _listing(directory: Path, suffixes: tuple[str, ...], limit: int, what: str) -> list[Path]:
    if not directory.is_dir():
        raise RunBlocked(f'{what} is not a directory')
    try:
        entries = list(islice(directory.iterdir(), MAX_DIR_ENTRIES + 1))
        names = sorted(p.name for p in entries if p.name.lower().endswith(suffixes) and p.is_file())
    except OSError as exc:
        raise RunBlocked(f'{what} cannot be listed ({type(exc).__name__})') from None
    if len(entries) > MAX_DIR_ENTRIES:
        raise RunBlocked(f'{what} holds more than {MAX_DIR_ENTRIES} entries')
    if len(names) > limit:
        raise RunBlocked(f'{what} holds more than {limit} usable files')
    return [PG.confine(directory / name, what) for name in names]  # a link out of the allowed roots is refused


def _records(directory: Path) -> dict[str, Path]:
    """Winbindex records by file name: `<file>.json` or `<file>.json.gz`, as Winbindex publishes them."""
    found: dict[str, Path] = {}
    for path in _listing(directory, RECORD_SUFFIXES, MAX_RECORD_FILES, '--winbindex'):
        lowered = path.name.lower()
        name = lowered[:-len('.json.gz')] if lowered.endswith('.json.gz') else lowered[:-len('.json')]
        if name in found:
            raise RunBlocked(f'--winbindex holds two records for {name}')
        found[name] = path
    return found


def _split(manifest: dict[str, Any]) -> tuple[list[dict], list[dict]]:
    cases = manifest['cases']
    excluded = [{'id': c['id'], 'reason': 'facts: unverified', 'stratum': c['stratum']}
                for c in cases if c['facts'] != 'verified']
    return [c for c in cases if c['facts'] == 'verified'], excluded


def plan(manifest: dict[str, Any], frozen_sha: str | None) -> dict[str, Any]:
    """What a scored run would ask. Asks nothing and writes nothing."""
    asked, excluded = _split(manifest)
    sha = L1.manifest_hash(manifest)
    return {'dry_run': True, 'manifest_sha256': sha,
            'frozen': 'not-given' if not frozen_sha else ('match' if frozen_sha == sha else 'mismatch'),
            'would_ask': [{'id': c['id'], 'search': c['cve'], 'month': c['month'], 'expect_kb': c['kb'],
                           'expect_product': c['product'], 'files': list(c['expected_files'])} for c in asked],
            'excluded': excluded}


# ---------------------------------------------------------------------------------------------- one case

def _row(case: dict, outcome: str, reason: str, checks: dict[str, str] | None = None, files: list[dict] | None = None,
         observed: dict | None = None) -> dict:
    return {'id': case['id'], 'month': case['month'], 'cve': case['cve'], 'kb': case['kb'],
            'product': _clip(case['product'], 200), 'stratum': case['stratum'], 'outcome': outcome,
            'reason': _clip(reason), 'files': files or [], 'observed': observed or {},
            'checks': {'edge': 'not-asked', 'scope': 'not-asked', 'file': 'not-asked', **(checks or {})}}


def _shown(values: set[str]) -> list[str]:
    return sorted(values)[:MAX_SHOWN]


def run_case(case: dict, join: ProductJoin, records: dict[str, Path] | None, data_date: str) -> dict:
    try:
        result = join.search(case['cve'], case['month'])
    except Exception as exc:  # an unanswered case is BLOCKED, never a miss and never a traceback
        return _row(case, 'BLOCKED', join.describe(exc))
    if result is None:
        return _row(case, 'BLOCKED', f'month {case["month"]} is not present in --months')
    coverage = result['coverage']['state']
    if coverage != 'complete_in_scope':
        return _row(case, 'BLOCKED', f'month {case["month"]} was not fully checked (coverage {coverage})')
    edges = result['edges']
    observed = {'coverage': coverage, 'cve_listed': bool(result['cards']), 'kbs': _shown({e['kb'] for e in edges})}
    if case['kb'] == '':  # stratum no-kb: the expectation is that the advisory names no KB for the CVE
        if edges:
            return _row(case, 'FAIL', f'the join lists KB edges for a no-kb case: {", ".join(observed["kbs"])}',
                        {'edge': 'fail'}, observed=observed)
        return _row(case, 'PASS', 'no KB edge for the CVE, as expected', {'edge': 'pass'}, observed=observed)
    mine = [e for e in edges if e['kb'] == case['kb']]
    if not mine:
        return _row(case, 'FAIL', f'edge {case["cve"]} -> {case["kb"]} not found in {case["month"]} (KBs the join '
                    f'lists for the CVE: {", ".join(observed["kbs"]) or "none"})', {'edge': 'fail'}, observed=observed)
    observed['products'] = _shown({_clip(e['product'], 200) for e in mine})
    match, how = next((e for e in mine if e['product'] == case['product']), None), 'name'
    if match is None:  # several advisory names can share one scope and show its smallest name
        wanted = join.scope_id(case['product'])
        match, how = next((e for e in mine if e['scope_id'] == wanted), None), 'scope-id'
    if match is None:
        return _row(case, 'FAIL', f'{case["kb"]} is not listed for the expected product',
                    {'edge': 'pass', 'scope': 'fail'}, observed=observed)
    observed['scope_match'] = how
    checks = {'edge': 'pass', 'scope': 'pass'}
    if records is None or not case['expected_files']:
        return _row(case, 'PASS', 'edge and product scope found; file leg not asked', checks, observed=observed)
    files = [join.resolve_file(case['month'], result['investigation_id'], match['scope_id'], case['kb'], name.lower(),
                               records.get(name.lower()), data_date) for name in case['expected_files']]
    worst = next((v for v in ('fail', 'blocked') if any(f['result'] == v for f in files)), 'pass')
    checks['file'] = worst
    if worst == 'pass':
        return _row(case, 'PASS', 'edge, product scope and expected files found', checks, files, observed)
    first = next(f for f in files if f['result'] == worst)
    return _row(case, 'FAIL' if worst == 'fail' else 'BLOCKED', f'{first["name"]}: {first["detail"]}', checks, files,
                observed)


# ---------------------------------------------------------------------------------------------- receipt

def product_bound(rows: list[dict], evidence_class: str) -> dict | None:
    """One-sided exact lower bound over independent products (never raw case counts). None for synthetic evidence:
    fixtures yield no accuracy figure."""
    if evidence_class != 'live':
        return None
    units: dict[str, list[bool]] = {}
    for row in rows:
        if row['outcome'] in ('PASS', 'FAIL'):
            units.setdefault(row['product'], []).append(row['outcome'] == 'PASS')
    n, correct = len(units), sum(all(v) for v in units.values())
    return {'unit': 'product', 'n': n, 'correct': correct, 'alpha': 0.05,
            'lower_bound': round(SS.lower_bound(correct, n), 3) if n else None,
            'method': 'one-sided exact (Clopper-Pearson) lower bound, sample_size.lower_bound',
            'rule': 'a product is correct only when every scored case of it passed; blocked cases are not scored'}


def _counts(total: int, rows: list[dict], excluded: list[dict]) -> dict[str, Any]:
    tally = Counter(r['outcome'] for r in rows)
    checks = {}
    for leg in ('edge', 'scope', 'file'):
        seen = Counter(r['checks'][leg] for r in rows)
        checks[leg] = {'asked': seen['pass'] + seen['fail'], 'passed': seen['pass']}
    checks['file']['blocked'] = sum(r['checks']['file'] == 'blocked' for r in rows)
    strata: dict[str, dict[str, int]] = {}
    for key, stratum in [(r['outcome'], r['stratum']) for r in rows] + [('excluded', e['stratum']) for e in excluded]:
        strata.setdefault(stratum, {'PASS': 0, 'FAIL': 0, 'BLOCKED': 0, 'excluded': 0})[key] += 1
    return {'cases': total, 'excluded_unverified': len(excluded), 'asked': len(rows), 'PASS': tally['PASS'],
            'FAIL': tally['FAIL'], 'BLOCKED': tally['BLOCKED'], 'scored': tally['PASS'] + tally['FAIL'],
            'checks': checks, 'by_stratum': dict(sorted(strata.items()))}


def _status(counts: dict[str, Any]) -> tuple[str, str]:
    if counts['FAIL']:
        return 'FAIL', f'{counts["FAIL"]} of {counts["scored"]} scored cases failed'
    if counts['BLOCKED'] or not counts['scored']:
        return 'BLOCKED', f'{counts["BLOCKED"]} of {counts["asked"]} asked cases were not answered'
    return 'PASS', f'all {counts["scored"]} asked cases passed'


def run(manifest: dict[str, Any], frozen_sha: str, evidence_class: str, months: Path, winbindex: Path | None,
        data_date: str) -> dict[str, Any]:
    """Ask the join for every verified case and return the rq-l1-run/1 receipt document."""
    asked, excluded = _split(manifest)
    month_files = _listing(months, MONTH_SUFFIXES, MAX_MONTH_FILES, '--months')
    records = None if winbindex is None else _records(winbindex)
    with tempfile.TemporaryDirectory(prefix='rq-l1-', ignore_cleanup_errors=True) as scratch:
        join = ProductJoin(Path(scratch))
        loaded = [join.import_month(i, path) for i, path in enumerate(month_files)]
        rows = [run_case(case, join, records, data_date) for case in asked]
    counts = _counts(len(manifest['cases']), rows, excluded)
    status, stop_reason = _status(counts)
    index = None if records is None else {
        'data_date': data_date,
        'records': [{'name': name, 'file': path.name, 'sha256': R.sha256_file(path)}
                    for name, path in sorted(records.items())]}
    return {'schema': SCHEMA, 'layer': 'L1', 'tool': 'tools.research_qualification.l1_run', 'status': status,
            'stop_reason': stop_reason, 'evidence_class': evidence_class,
            'evidence_class_source': 'operator flag --evidence-class',
            'limits': [*LIMITS, *([SYNTHETIC_LIMIT] if evidence_class == 'synthetic' else [])],
            'file_rule': FILE_RULE, 'patchtrace_sha': R.git_head(REPO),
            'manifest': {'schema': manifest['schema'], 'sha256': L1.manifest_hash(manifest),
                         'frozen_sha256': frozen_sha},
            'inputs': {'months': loaded, 'winbindex': index},
            'counts': counts, 'bound': product_bound(rows, evidence_class), 'cases': rows, 'excluded': excluded}


def write_receipt(document: dict[str, Any], target: Path) -> None:
    """Exclusive create: an earlier receipt is a prior result and is never overwritten."""
    data = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + '\n'
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, 'x', encoding='utf-8', newline='\n') as handle:
            handle.write(data)
    except FileExistsError:
        raise RunBlocked(f'the receipt {target.name} exists; prior results are never overwritten') from None
    except OSError as exc:
        raise RunBlocked(f'the receipt cannot be written ({type(exc).__name__})') from None


# ---------------------------------------------------------------------------------------------- command line

def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('manifest', help='rq-l1-manifest/1 file')
    parser.add_argument('--months', metavar='DIR', help='saved CVRF month documents (.json/.xml, optionally .gz)')
    parser.add_argument('--out', metavar='RECEIPT', help='receipt file to create (never overwritten)')
    parser.add_argument('--frozen-sha', metavar='SHA256', help='manifest_sha256 recorded when the manifest was frozen')
    parser.add_argument('--evidence-class', choices=EVIDENCE_CLASSES,
                        help='synthetic for fixtures, live for real vendor documents; never guessed')
    parser.add_argument('--winbindex', metavar='DIR', help='saved Winbindex records (<file>.json[.gz]) for the file leg')
    parser.add_argument('--winbindex-date', metavar='YYYY-MM-DD', help='data date of the --winbindex records')
    parser.add_argument('--dry-run', action='store_true', help='list what would be asked; asks and writes nothing')


def _scored(a: argparse.Namespace, manifest: dict[str, Any]) -> int:
    for flag, value in (('--months', a.months), ('--out', a.out), ('--evidence-class', a.evidence_class)):
        if not value:
            raise RunBlocked(f'a scored run needs {flag} (or use --dry-run)')
    if a.winbindex and not (a.winbindex_date and _DATE.match(a.winbindex_date)):
        raise RunBlocked('--winbindex needs --winbindex-date YYYY-MM-DD (the data date of the records)')
    if a.winbindex_date and not a.winbindex:
        raise RunBlocked('--winbindex-date applies only with --winbindex')
    months, target = PG.confine(a.months, '--months'), PG.confine(a.out, '--out')
    winbindex = PG.confine(a.winbindex, '--winbindex') if a.winbindex else None
    frozen = require_frozen(manifest, a.frozen_sha)
    if target.exists():
        raise RunBlocked(f'the receipt {target.name} exists; prior results are never overwritten')
    document = run(manifest, frozen, a.evidence_class, months, winbindex, a.winbindex_date or '')
    write_receipt(document, target)
    print(json.dumps({'status': document['status'], 'stop_reason': document['stop_reason'],
                      'evidence_class': document['evidence_class'], 'counts': document['counts'],
                      'bound': document['bound'], 'receipt': target.name}, indent=2, sort_keys=True))
    return {'PASS': 0, 'FAIL': 1, 'BLOCKED': 2}[document['status']]


def cmd(a: argparse.Namespace) -> int:
    path = PG.confine(a.manifest, 'manifest')
    try:
        manifest = load_manifest(path)
        if a.dry_run:
            print(json.dumps(plan(manifest, a.frozen_sha), indent=2, sort_keys=True))
            return 0
        return _scored(a, manifest)
    except RunBlocked as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
