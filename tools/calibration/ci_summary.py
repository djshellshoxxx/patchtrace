"""Never-silent CI status for a Tier R run (LBL-14; LBL integration plan s2, s9).

`summarize` reads the shard artifacts and always writes a `tier-r-ci-summary/1` JSON, even when the shard set is damaged:
an unreadable or incomplete set is status `error`, never a missing file. It counts attempted, completed, blocked and failed
pairs per engine and per stratum, warns when an engine completes under 90% of its pairs (stop-and-ask 5), and carries the
merged `report_sha256`. `determinism` compares that digest between two merges of the same shards. Counts only: no label,
feature or binary content is read into the summary."""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .tier_r import shard as S

CONTRACT = 'tier-r-ci-summary/1'
COMPLETION_WARNING = 0.9          # same threshold as tier_r.evaluate; PREREG stop-and-ask 5
OK, FINDINGS, USAGE = S.OK, S.FINDINGS, S.USAGE
EXIT = {'ok': OK, 'warning': OK, 'failed': FINDINGS, 'error': USAGE}
OK_CASE = ('ok', 'findings', 'skipped')


def _tally() -> dict[str, int]:
    return {'attempted': 0, 'completed': 0, 'blocked': 0, 'failed': 0}


def _count(cell: dict[str, int], status: str) -> None:
    cell['attempted'] += 1
    cell['completed' if status == 'ok' else 'blocked' if status == 'blocked' else 'failed'] += 1


def _rate(cell: dict[str, int]) -> float | None:
    return round(cell['completed'] / cell['attempted'], 6) if cell['attempted'] else None


def tally_pairs(docs: list[dict]) -> tuple[dict[str, dict], dict[str, dict[str, dict]]]:
    """(per engine, per engine and stratum) counts from every pair row of every shard report."""
    engines: dict[str, dict] = {}
    strata: dict[str, dict[str, dict]] = {}
    for doc in docs:
        for engine in doc['engines']:
            engines.setdefault(engine, _tally())
        for report in doc['reports']:
            for row in report['pairs']:
                _count(engines.setdefault(row['engine'], _tally()), row['status'])
                _count(strata.setdefault(row['engine'], {}).setdefault(row['stratum'], _tally()), row['status'])
    return engines, strata


def tally_cases(docs: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for doc in docs:
        for case in doc['cases']:
            out[case['status']] = out.get(case['status'], 0) + 1
    return dict(sorted(out.items()))


def _warnings(engines: dict[str, dict]) -> list[str]:
    notes = []
    for name, cell in sorted(engines.items()):
        if not cell['attempted']:
            notes.append(f'{name}: no pair was attempted (engine blocked or not evaluated)')
        elif cell['completed'] / cell['attempted'] < COMPLETION_WARNING:
            notes.append(f'{name}: only {cell["completed"]} of {cell["attempted"]} pairs completed (below 90%)')
    return notes


def _merged_digest(docs: list[dict]) -> tuple[str | None, str | None]:
    try:
        return S.merge(docs)[0]['report_sha256'], None
    except (S.ShardError, KeyError, ValueError) as exc:
        return None, f'merge failed: {exc}'


def summarize(shards: Path, plan: dict | None = None) -> dict:
    """The status document. Never raises on bad input: a failure is recorded as status `error` with its reason."""
    try:
        docs = S.load_shards(shards, plan=plan)
    except (S.ShardError, OSError, ValueError) as exc:
        return {'contract': CONTRACT, 'status': 'error', 'reason': f'shard set rejected: {exc}', 'report_sha256': None,
                'shards': 0, 'cases': {}, 'engines': [], 'warnings': []}
    engines, strata = tally_pairs(docs)
    digest, problem = _merged_digest(docs)
    cases = tally_cases(docs)
    warnings = _warnings(engines)
    failed_cases = sum(n for status, n in cases.items() if status not in OK_CASE and status != 'blocked')
    status = ('error' if problem else 'failed' if failed_cases else 'warning' if warnings else 'ok')
    rows = [{'engine': name, **cell, 'completion': _rate(cell),
             'strata': [{'stratum': s, **c, 'completion': _rate(c)} for s, c in sorted(strata.get(name, {}).items())]}
            for name, cell in sorted(engines.items())]
    return {'contract': CONTRACT, 'status': status, 'reason': problem, 'report_sha256': digest, 'shards': len(docs),
            'plan_sha256': docs[0]['plan_sha256'], 'subset': docs[0]['subset'], 'cases': cases, 'engines': rows,
            'warnings': warnings}


def write_summary(doc: dict, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, sort_keys=True, indent=1, allow_nan=False) + '\n').encode())


def render_markdown(doc: dict) -> str:
    lines = [f'### Tier R CI status: {doc["status"]}', '']
    if doc.get('reason'):
        lines += [f'Reason: {doc["reason"]}', '']
    lines += [f'report_sha256: `{doc["report_sha256"] or "none"}`', '']
    if doc['engines']:
        lines += ['| engine | stratum | attempted | completed | blocked | failed |', '|---|---|---|---|---|---|']
        for row in doc['engines']:
            for cell in [{**row, 'stratum': 'all'}, *row['strata']]:
                lines.append(f'| {row["engine"]} | {cell["stratum"]} | {cell["attempted"]} | {cell["completed"]} | '
                             f'{cell["blocked"]} | {cell["failed"]} |')
    lines += ['', *(f'- WARNING {w}' for w in doc['warnings'])]
    return '\n'.join(lines) + '\n'


def _aggregate_digest(directory: Path) -> str:
    path = directory / 'tier-r-aggregate.json'
    try:
        value = json.loads(path.read_text(encoding='utf-8'))['report_sha256']
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise S.ShardError(f'{path}: no readable report_sha256 ({exc})') from None
    if not isinstance(value, str) or len(value) != 64:
        raise S.ShardError(f'{path}: malformed report_sha256')
    return value


def determinism(first: Path, second: Path) -> dict:
    """Equal report_sha256 across two merges of the same shards, or a mismatch record (stop-and-ask 3)."""
    a, b = _aggregate_digest(first), _aggregate_digest(second)
    return {'contract': CONTRACT, 'check': 'determinism', 'status': 'ok' if a == b else 'failed',
            'first_report_sha256': a, 'second_report_sha256': b}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='tools.calibration.ci_summary', description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('summarize', help='write the never-silent status JSON (and Markdown) for a shard directory')
    s.add_argument('--shards', type=Path, required=True)
    s.add_argument('--plan', type=Path)
    s.add_argument('--out', type=Path, required=True, help='summary JSON path; a .md file is written beside it')
    d = sub.add_parser('determinism', help='compare report_sha256 of two merged directories')
    d.add_argument('first', type=Path)
    d.add_argument('second', type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == 'determinism':
            doc = determinism(args.first, args.second)
            print(json.dumps(doc, sort_keys=True))
            return OK if doc['status'] == 'ok' else FINDINGS
        plan = json.loads(args.plan.read_text(encoding='utf-8')) if args.plan else None
        doc = summarize(args.shards, plan)
        write_summary(doc, args.out)
        args.out.with_suffix('.md').write_text(render_markdown(doc), encoding='utf-8', newline='\n')
        print(json.dumps({'status': doc['status'], 'report_sha256': doc['report_sha256'], 'warnings': len(doc['warnings'])},
                         sort_keys=True))
        return EXIT[doc['status']]
    except (S.ShardError, ValueError, OSError) as exc:
        print(f'ci_summary: {exc}', file=sys.stderr)
        return USAGE


if __name__ == '__main__':
    raise SystemExit(main())
