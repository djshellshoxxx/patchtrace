"""L3 diff-and-score orchestrator for the manual diff-and-score workflow. Stdlib only; executes nothing.

    python -m tools.research_qualification.scorerun plan  --pair-manifest PM --cases CASES [--out FILE]
    python -m tools.research_qualification.scorerun score --pair-manifest PM --cases CASES --reports DIR
                                                          --out DIR [--k 5] [--engine ghidriff]

`plan` prints the job matrix `{"include": [{"id", "older", "newer"}], "count": N}`: found pairs whose case is in the
manifest, layer L3 and `facts: verified`. `score` converts each case's engine report with the adapter and scores it
with scoring.score_case. Per case the verdict is PASS (expected function in the top k, or no_change with no
candidates), FAIL (a miss or a false positive) or BLOCKED. BLOCKED is never a miss and never enters the score:
unverified facts, a layer other than L3, no/failed pair, sha mismatch, no report, a tool failure or timeout recorded in
`pt-run-status.json`, an ambiguous or unparseable report. Holdout cases are aggregated separately from the rest.

Exit codes: 0 scored and no FAIL, 1 at least one FAIL, 2 nothing scored (all BLOCKED) or blocked/usage error.
Every file argument goes through pathguard.confine. This is an L3 (real-binary, function-level) claim only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from . import cases as CS
from . import receipt as R
from . import scoring as SC
from .adapters import PARSERS
from .pathguard import PathGuardError, confine
from .sample_size import lower_bound

PAIR_SCHEMA = 'rq-pair-manifest/1'
STATUS_FILE = 'pt-run-status.json'
RESULTS_FILE = 'scorerun-results.json'
LAYER = 'L3'
_SAFE_REL = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}(/[A-Za-z0-9][A-Za-z0-9._-]{0,63}){1,3}$')
_HEX = re.compile(r'^[0-9a-f]{64}$')
UNVERIFIED = [
    'workflow never ran on a GitHub runner',
    'ghidriff and Ghidra install steps untested on a runner',
    'runtime per pair unknown (can take hours)',
    'tool.executable_sha256',
]


class ScoreRunError(ValueError):
    """Bad input to the orchestrator (exit 2)."""


def _read_json(path: str, what: str) -> Any:
    p = confine(path, what)
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        raise ScoreRunError(f'{what} unreadable: {e}') from e


def load_pairs(path: str) -> dict[str, dict[str, Any]]:
    data = _read_json(path, 'pair-manifest')
    if not isinstance(data, dict) or data.get('schema') != PAIR_SCHEMA or not isinstance(data.get('cases'), list):
        raise ScoreRunError(f'pair manifest must be an object with schema {PAIR_SCHEMA}')
    return {c['id']: c for c in data['cases'] if isinstance(c, dict) and isinstance(c.get('id'), str)}


def load_cases(path: str) -> dict[str, Any]:
    m = _read_json(path, 'cases')
    try:
        CS.validate_manifest(m)
    except ValueError as e:
        raise ScoreRunError(f'case manifest invalid: {e}') from e
    return m


def _rel_path(side: Any) -> str | None:
    p = side.get('path') if isinstance(side, dict) else None
    ok = isinstance(p, str) and _SAFE_REL.match(p) and '..' not in p.split('/')
    return p if ok else None


def pair_problem(case: dict[str, Any], pair: dict[str, Any] | None) -> str | None:
    """Reason a case cannot be diffed, or None. Pure; shared by plan and score."""
    if case['facts'] != 'verified':
        return 'unverified'
    if case['layer'] != LAYER:
        return 'layer_not_l3'
    if pair is None or pair.get('status') != 'found':
        return 'missing_pair'
    for k in ('older', 'newer'):
        if _rel_path(pair.get(k)) is None:
            return 'missing_pair'
        want, got = case[k].get('sha256'), pair[k].get('sha256')
        if want and (not isinstance(got, str) or not _HEX.match(got) or got != want):
            return 'sha_mismatch'
    return None


def plan(pairs: dict[str, dict[str, Any]], manifest: dict[str, Any]) -> dict[str, Any]:
    include = []
    for c in manifest['cases']:
        pair = pairs.get(c['id'])
        if pair_problem(c, pair) is None:
            include.append({'id': c['id'], 'older': pair['older']['path'], 'newer': pair['newer']['path']})
    return {'include': include, 'count': len(include)}


def _find_report(case_dir: Path, root: Path) -> tuple[Path | None, str]:
    found: dict[str, list[Path]] = {'json': [], 'md': []}
    for p in sorted(case_dir.rglob('*')):
        if p.is_symlink() or not p.is_file():
            continue
        if not p.resolve().is_relative_to(root):
            continue
        if p.name.endswith('.ghidriff.json'):
            found['json'].append(p)
        elif p.suffix == '.md':
            found['md'].append(p)
    for kind in ('json', 'md'):
        if len(found[kind]) == 1:
            return found[kind][0], ''
        if len(found[kind]) > 1:
            return None, 'ambiguous_report'
    return None, 'missing_report'


def _run_status(case_dir: Path) -> str | None:
    f = case_dir / STATUS_FILE
    if f.is_symlink() or not f.is_file():
        return None
    try:
        st = json.loads(f.read_text(encoding='utf-8'))
        rc, to = st['rc'], st.get('timed_out', False)
        if isinstance(rc, bool) or not isinstance(rc, int) or not isinstance(to, bool):
            raise ValueError('rc/timed_out types')
    except (OSError, ValueError, KeyError, TypeError):
        return 'bad_run_status'
    if to:
        return 'timeout'
    return 'tool_failed' if rc != 0 else None


def _row(c: dict[str, Any], outcome: str, reason: str = '', **extra: Any) -> dict[str, Any]:
    return {'id': c['id'], 'project': c['project'], 'stratum': c['stratum'], 'holdout': c['holdout'],
            'verdict': outcome, 'reason': reason, **extra}


def judge_case(c: dict[str, Any], pair: dict[str, Any] | None, reports: Path, k: int, engine: str
               ) -> dict[str, Any]:
    problem = pair_problem(c, pair)
    if problem:
        return _row(c, 'BLOCKED', problem)
    case_dir = reports / c['id']
    if not case_dir.is_dir() or case_dir.is_symlink():
        return _row(c, 'BLOCKED', 'missing_report')
    bad = _run_status(case_dir)
    if bad:
        return _row(c, 'BLOCKED', bad)
    report, why = _find_report(case_dir, reports)
    if report is None:
        return _row(c, 'BLOCKED', why)
    try:
        names = PARSERS[engine](report)
    except PathGuardError:
        raise
    except ValueError as e:
        return _row(c, 'BLOCKED', 'unparseable_report', detail=str(e)[:200])
    s = SC.score_case(c, names, k)
    return _row(c, 'PASS' if s['outcome'] == 'HIT' else 'FAIL', s['outcome'].lower(), rank=s['rank'],
                candidates=len(names))


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = {v: sum(r['verdict'] == v for r in rows) for v in ('PASS', 'FAIL', 'BLOCKED')}
    scored = n['PASS'] + n['FAIL']
    reasons: dict[str, int] = {}
    for r in rows:
        if r['verdict'] == 'BLOCKED':
            reasons[r['reason']] = reasons.get(r['reason'], 0) + 1
    return {'cases': len(rows), 'scored': scored, 'pass': n['PASS'], 'fail': n['FAIL'], 'blocked': n['BLOCKED'],
            'blocked_reasons': dict(sorted(reasons.items())),
            'lower_bound': round(lower_bound(n['PASS'], scored), 3) if scored else None}


def score_all(pairs: dict[str, dict[str, Any]], manifest: dict[str, Any], reports: Path, k: int, engine: str
              ) -> dict[str, Any]:
    if k < 1:
        raise ScoreRunError('k must be >= 1')
    if engine not in PARSERS:
        raise ScoreRunError(f'unknown engine {engine!r}')
    rows = [judge_case(c, pairs.get(c['id']), reports, k, engine) for c in manifest['cases']]
    return {'schema': 'rq-scorerun/1', 'layer': LAYER, 'engine': engine, 'k': k,
            'manifest_sha256': CS.canonical_hash(manifest),
            'development': _aggregate([r for r in rows if not r['holdout']]),
            'holdout': _aggregate([r for r in rows if r['holdout']]),
            'rows': rows,
            'caveat': 'L3 only. BLOCKED cases are excluded from the score and are never misses. The bound assumes '
                      'scored cases are independent (distinct projects); holdout is reported separately.'}


def exit_for(result: dict[str, Any]) -> int:
    parts = (result['development'], result['holdout'])
    if any(p['fail'] for p in parts):
        return 1
    return 0 if any(p['scored'] for p in parts) else 2


def write_outputs(result: dict[str, Any], out: Path, started: str) -> tuple[Path, Path]:
    out.mkdir(parents=True, exist_ok=True)
    rpath = out / RESULTS_FILE
    try:
        with open(rpath, 'x', encoding='utf-8', newline='\n') as f:
            f.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
    except FileExistsError as e:
        raise ScoreRunError(f'refusing to overwrite {RESULTS_FILE} in {out.name}') from e
    code = exit_for(result)
    status = {0: 'PASS', 1: 'FAIL', 2: 'BLOCKED'}[code]
    d, h = result['development'], result['holdout']
    blocked = {**d['blocked_reasons']}
    for key, v in h['blocked_reasons'].items():
        blocked[key] = blocked.get(key, 0) + v
    rec = R.build_receipt(
        experiment_id='rq-diffscore', scenario_id=f'l3-{result["engine"]}-k{result["k"]}',
        tool_name=f'scorerun+{result["engine"]}', status=status, exit_code=code if status == 'PASS' else None,
        stop_reason=(f'dev {d["pass"]}/{d["scored"]} pass, holdout {h["pass"]}/{h["scored"]} pass, '
                     f'{d["blocked"] + h["blocked"]} blocked'),
        patchtrace_sha=R.git_head(Path(__file__).resolve().parents[2]),
        fixture_source='winbindex+msdl', fixture_license='Microsoft binaries, not redistributed',
        publication_permitted=False, options={'k': result['k'], 'engine': result['engine']},
        network_policy='none',
        validations_run=['adapter_parse', 'rank_score', 'blocked_excluded_from_score'] if status == 'PASS' else [],
        unverified=UNVERIFIED,
        blocked_reasons=[f'{n} case(s): {r}' for r, n in sorted(blocked.items())] if status == 'BLOCKED' else [],
        result_hashes={'scorerun_results': R.sha256_file(rpath), 'case_manifest': result['manifest_sha256']},
        counters={'cases': d['cases'] + h['cases'], 'scored': d['scored'] + h['scored'],
                  'pass': d['pass'] + h['pass'], 'fail': d['fail'] + h['fail'],
                  'blocked': d['blocked'] + h['blocked'], 'holdout_scored': h['scored']},
        observed={'started_utc': started, 'ended_utc': R.utc_now()},
        artifacts=[{'path': RESULTS_FILE, 'sha256': R.sha256_file(rpath), 'bytes': rpath.stat().st_size}],
    )
    return rpath, R.write_receipt(rec, out)


def summary_markdown(result: dict[str, Any]) -> str:
    lines = [f'### L3 diff and score ({result["engine"]}, k={result["k"]})', '',
             '| set | cases | scored | pass | fail | blocked | lower bound |', '|---|---|---|---|---|---|---|']
    for name in ('development', 'holdout'):
        a = result[name]
        lines.append(f'| {name} | {a["cases"]} | {a["scored"]} | {a["pass"]} | {a["fail"]} | {a["blocked"]} | '
                     f'{a["lower_bound"]} |')
    lines += ['', '| case | holdout | verdict | reason |', '|---|---|---|---|']
    lines += [f'| {r["id"]} | {r["holdout"]} | {r["verdict"]} | {r["reason"]} |' for r in result['rows']]
    lines += ['', 'BLOCKED cases are excluded from the score and are not misses. L3 claim only.']
    return '\n'.join(lines) + '\n'


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog='scorerun', description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('plan')
    s = sub.add_parser('score')
    for sp in (p, s):
        sp.add_argument('--pair-manifest', required=True)
        sp.add_argument('--cases', required=True)
    p.add_argument('--out')
    s.add_argument('--reports', required=True)
    s.add_argument('--out', required=True)
    s.add_argument('--k', type=int, default=5)
    s.add_argument('--engine', default='ghidriff')
    s.add_argument('--summary', help='also write the markdown summary to this file (append)')
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    try:
        pairs, manifest = load_pairs(a.pair_manifest), load_cases(a.cases)
        if a.cmd == 'plan':
            doc = plan(pairs, manifest)
            text = json.dumps(doc, sort_keys=True)
            if a.out:
                confine(a.out, 'out').write_text(text + '\n', encoding='utf-8')
            print(text)
            return 0
        started = R.utc_now()
        reports = confine(a.reports, 'reports')
        out = confine(a.out, 'out')
        result = score_all(pairs, manifest, reports, a.k, a.engine)
        _, rpath = write_outputs(result, out, started)
        md = summary_markdown(result)
        if a.summary:
            with open(confine(a.summary, 'summary'), 'a', encoding='utf-8') as f:
                f.write(md)
        print(md)
        print(f'receipt: {rpath.name}')
        return exit_for(result)
    except (PathGuardError, ScoreRunError, R.ReceiptError, OSError) as e:
        print(f'scorerun: blocked: {e}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
