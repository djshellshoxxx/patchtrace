"""Aggregate live-acceptance status files (SPEC-29 §9.4) into a Markdown table.

usage: check_live_status.py [--dir build/live-status] [--summary FILE] [--fail-on-failed]

Each `*.json` must be strict JSON with `engine`, `status` in passed|failed|blocked and `reason`. Missing
or malformed files are reported as `failed` rows, never dropped. Blocked rows are printed as
`LIVE ACCEPTANCE BLOCKED`; the table text is what the integrator copies into docs/qa.md.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

STATUSES = ('passed', 'failed', 'blocked')


def _reject_constant(name: str):
    raise ValueError(f'non-finite number {name}')


def load(directory: Path) -> list[dict]:
    rows: list[dict] = []
    for path in sorted(directory.glob('*.json')) if directory.is_dir() else []:
        try:
            data = json.loads(path.read_text(encoding='utf-8'), parse_constant=_reject_constant)
            if not isinstance(data, dict) or data.get('status') not in STATUSES \
                    or not isinstance(data.get('engine'), str) or not isinstance(data.get('reason'), str):
                raise ValueError('missing engine/status/reason')
        except (OSError, ValueError) as exc:
            data = {'engine': path.stem, 'status': 'failed', 'reason': f'unreadable status file: {exc}'}
        data['file'] = path.name
        rows.append(data)
    return rows


def _cell(text: object) -> str:
    return str(text).replace('|', '/').replace('\n', ' ')[:300]


def render(rows: list[dict]) -> str:
    if not rows:
        return '### Live acceptance\n\nNo live status files were written (treat as blocked).\n'
    lines = ['### Live acceptance (not mocked)', '', '| file | engine | status | reason |', '|---|---|---|---|']
    lines += [f'| {_cell(r["file"])} | {_cell(r["engine"])} | {_cell(r["status"])} | {_cell(r["reason"])} |'
              for r in rows]
    lines += [f'LIVE ACCEPTANCE BLOCKED: {_cell(r["engine"])} ({_cell(r["reason"])})'
              for r in rows if r['status'] == 'blocked']
    return '\n'.join(lines) + '\n'


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', type=Path, default=Path('build') / 'live-status')
    parser.add_argument('--summary', type=Path, default=None)
    parser.add_argument('--fail-on-failed', action='store_true')
    args = parser.parse_args(argv)
    rows = load(args.dir)
    text = render(rows)
    print(text)
    if args.summary is not None:
        with open(args.summary, 'a', encoding='utf-8') as summary:
            summary.write(text)
    return 1 if args.fail_on_failed and any(r['status'] == 'failed' for r in rows) else 0


if __name__ == '__main__':
    sys.exit(main())
