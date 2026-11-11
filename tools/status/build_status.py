"""Regenerate docs/status/{status.json,README.md,inventory.md,defects.md} from the committed analyst inventories.

Stdlib only; no network, no clock (the date comes from docs/status/meta.json or --as-of). Analyst files are data:
unexpected values are reported as `nonconforming`, a missing required key stops the run (exit 2). Nothing is averaged
across workstreams: every completion figure is carried with its own basis."""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
import unicodedata
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KEYS = ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I1', 'I2', 'I3', 'J', 'K', 'L', 'R', 'T1', 'T2')
STATUSES = ('implemented', 'partial', 'missing', 'blocked-external', 'deferred-by-design')
SEVERITIES = ('critical', 'high', 'medium', 'low')
EVIDENCE_CLASSES = ('mocked', 'synthetic', 'fixture', 'live-native', 'none')
BLOCKER_TYPES = ('external-tool', 'windows-only', 'live-network', 'owner-decision', 'other-lane')
GENERATED = ('status.json', 'README.md', 'inventory.md', 'defects.md')
REQUIRED = ('workstream', 'title', 'features', 'actionable_now')
REQUIRED_FEATURE = ('id', 'name', 'status', 'implementation_pct', 'validation_pct', 'evidence_class')
MEASURE_LABELS = {'F': 'gui-cli-parity', 'I1': 'security-backlog', 'T1': 'tracker-lines', 'T2': 'tracker-lines'}
MAX_BYTES = 8 * 1024 * 1024
MAX_ROWS = 5000
NOT_STATED = 'not stated'
EFFORT_LABEL = 'analyst estimate, hours'


class InputError(Exception):
    pass


def number(value):
    ok = isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    return value if ok else None


def tidy(value):
    value = round(value, 2)
    return int(value) if value == int(value) else value


def read_json(path: Path, label: str):
    try:
        if path.stat().st_size > MAX_BYTES:
            raise InputError(f'{label}: larger than {MAX_BYTES} bytes')
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError, RecursionError) as exc:
        raise InputError(f'{label}: {exc}') from exc


def validate(key: str, data) -> tuple[list[str], list[str]]:
    """Return (fatal, nonconforming) problems of one inventory."""
    if not isinstance(data, dict):
        return ['top level is not an object'], []
    fatal = [f'missing required key "{k}"' for k in REQUIRED if k not in data]
    if data.get('workstream', key) != key:
        fatal.append(f'workstream is {data["workstream"]!r} but the file is named {key}')
    for name in ('features', 'actionable_now'):
        if name in data and not isinstance(data[name], list):
            fatal.append(f'"{name}" is not a list')
    if fatal:
        return fatal, []
    if len(data['features']) > MAX_ROWS:
        return [f'more than {MAX_ROWS} features'], []
    odd = []
    completion = data.get('completion')
    if completion is not None and not isinstance(completion, dict):
        odd.append('completion is not an object')
    for k, v in (completion.items() if isinstance(completion, dict) else ()):
        if k.endswith('_pct') and not (number(v) is not None and 0 <= v <= 100):
            odd.append(f'completion.{k} = {v!r} is not a number within 0..100')
    for i, feature in enumerate(data['features']):
        if not isinstance(feature, dict):
            return [f'feature #{i} is not an object'], []
        missing = [k for k in REQUIRED_FEATURE if k not in feature]
        if missing:
            return [f'feature #{i} ({feature.get("id")!r}) misses required keys: {", ".join(missing)}'], []
        odd += feature_oddities(feature)
    return [], odd[:MAX_ROWS]


def feature_oddities(feature: dict) -> list[str]:
    fid, odd = feature['id'], []
    for name, allowed in (('status', STATUSES), ('evidence_class', EVIDENCE_CLASSES)):
        if feature[name] not in allowed:
            odd.append(f'{fid}: {name} {feature[name]!r} is not one of {", ".join(allowed)}')
    for name in ('implementation_pct', 'validation_pct'):
        if not (number(feature[name]) is not None and 0 <= feature[name] <= 100):
            odd.append(f'{fid}: {name} {feature[name]!r} is not a number within 0..100')
    if 'effort_hours' in feature and number(feature['effort_hours']) is None:
        odd.append(f'{fid}: effort_hours {feature["effort_hours"]!r} is not a number')
    for defect in defects_of_feature(feature, odd, fid):
        if defect.get('severity') not in SEVERITIES:
            odd.append(f'{fid}: defect severity {defect.get("severity")!r} is not one of {", ".join(SEVERITIES)}')
    for blocker in list_of_dicts(feature.get('blockers'), odd, fid, 'blockers'):
        if blocker.get('type') not in (*BLOCKER_TYPES, 'none'):
            odd.append(f'{fid}: blocker type {blocker.get("type")!r} is not one of {", ".join(BLOCKER_TYPES)}, none')
    return odd


def list_of_dicts(value, odd: list[str], fid: str, name: str) -> list[dict]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        odd.append(f'{fid}: {name} is not a list of objects (ignored)')
        return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []
    return value


def defects_of_feature(feature: dict, odd: list[str], fid: str) -> list[dict]:
    return list_of_dicts(feature.get('defects'), odd, fid, 'defects')


def all_defects(data: dict) -> list[tuple[str, dict]]:
    """(feature ids, defect) for features[].defects and a workstream-level defects[]. A defect with the same id and
    summary listed on several features is one defect."""
    found: dict[tuple, tuple[list[str], dict]] = {}
    pairs = [(f['id'], d) for f in data['features'] for d in defects_of_feature(f, [], f['id'])]
    pairs += [(data['workstream'], d) for d in list_of_dicts(data.get('defects'), [], data['workstream'], 'defects')]
    for n, (fid, defect) in enumerate(pairs):
        key = (defect.get('id'), defect.get('summary')) if defect.get('id') else (n,)
        found.setdefault(key, ([], defect))[0].append(str(fid))
    return [(', '.join(fids), d) for fids, d in found.values()]


def ordered(counter: Counter, canonical: tuple = ()) -> dict:
    return {**{k: counter.get(k, 0) for k in canonical}, **{k: counter[k] for k in sorted(counter) if k not in canonical}}


def summarise(key: str, data: dict) -> dict:
    features = data['features']
    open_features = [f for f in features if f['status'] != 'implemented']
    hours = [number(f.get('effort_hours')) for f in open_features]
    blockers = Counter(str(b.get('type')) for f in features for b in list_of_dicts(f.get('blockers'), [], '', '')
                       if b.get('type') != 'none')
    out = {
        'title': data['title'],
        'features': len(features),
        'features_by_status': ordered(Counter(str(f['status']) for f in features), STATUSES),
        'completion': data['completion'] if isinstance(data.get('completion'), dict) else None,
        'effort_hours_not_implemented': tidy(sum(h for h in hours if h is not None)),
        'effort_basis': EFFORT_LABEL,
        'effort_features': len(open_features),
        'features_by_evidence_class': ordered(Counter(str(f['evidence_class']) for f in features), EVIDENCE_CLASSES),
        'defects_by_severity': ordered(Counter(str(d.get('severity')) for _, d in all_defects(data)), SEVERITIES),
        'blockers_by_type': ordered(blockers, BLOCKER_TYPES),
        'actionable_now': len(data['actionable_now']),
    }
    for extra in ('external_blockers', 'summary'):
        if extra in data:
            out[extra] = data[extra]
    return out


def measures(inventories: dict) -> list[dict]:
    out = []
    for key, data in inventories.items():
        c = data.get('completion')
        if isinstance(c, dict) and c.get('basis'):
            out.append({'measure': MEASURE_LABELS.get(key, 'workstream-features'), 'workstream': key,
                        'title': data['title'], 'implementation_pct': c.get('implementation_pct'),
                        'validation_pct': c.get('validation_pct'), 'basis': c['basis']})
    return out


def build_status(inventories: dict, meta: dict, nonconforming: dict) -> dict:
    ws = {k: summarise(k, d) for k, d in inventories.items()}
    totals = {'features': sum(w['features'] for w in ws.values()),
              'actionable_now': sum(w['actionable_now'] for w in ws.values())}
    for name, canonical in (('features_by_status', STATUSES), ('defects_by_severity', SEVERITIES),
                            ('blockers_by_type', BLOCKER_TYPES), ('features_by_evidence_class', EVIDENCE_CLASSES)):
        total = Counter()
        for w in ws.values():
            total.update(w[name])
        totals[name] = ordered(total, canonical)
    totals['effort_hours_not_implemented'] = tidy(sum(w['effort_hours_not_implemented'] for w in ws.values()))
    totals['effort_basis'] = EFFORT_LABEL
    return {
        'schema': 'patchtrace-status/1', **{k: meta[k] for k in ('baseline_commit', 'baseline_date', 'as_of', 'session')},
        'workstreams': ws,
        'not_inventoried': [k for k in KEYS if k not in inventories],
        'tracker': {k: d['counts'] for k, d in inventories.items() if isinstance(d.get('counts'), dict)},
        'totals': totals,
        'completion_measures': measures(inventories),
        'nonconforming': nonconforming,
    }


# ---- markdown -------------------------------------------------------------------------------------------------

ESCAPES = {ord(c): '\\' + c for c in '\\`<>[]|'}  # the pipe too: every value lands in a table cell


def clean(value, limit: int | None = None) -> str:
    """Data to one safe markdown line: no control or format characters, no markup, optionally shortened."""
    if value is None or value == '':
        return NOT_STATED
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = ''.join(' ' if unicodedata.category(c) in ('Cc', 'Zl', 'Zp') else '' if unicodedata.category(c)[0] == 'C'
                   else c for c in text)
    text = ' '.join(text.split())
    if limit and len(text) > limit:
        text = text[:limit - 3].rstrip() + '...'
    return text.translate(ESCAPES) or NOT_STATED


def shorten(value, limit: int) -> str:
    """Raw text cut to `limit` characters; escaping is left to the single `clean` call around it."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = ' '.join(text.split())
    return text if len(text) <= limit else text[:limit - 3].rstrip() + '...'


def pct(value) -> str:
    n = number(value)
    return NOT_STATED if n is None else f'{tidy(n)}%'


def table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = ['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join('---' for _ in headers) + ' |']
    return lines + ['| ' + ' | '.join(r) + ' |' for r in rows] + ['']


def counts_table(title: str, counts: dict) -> list[str]:
    return table([title, 'Count'], [[clean(k), str(v)] for k, v in counts.items()])


def readme(status: dict, inventories: dict, slices: list) -> str:
    ws = status['workstreams']
    lines = ['# PatchTrace project status', '',
             f'Baseline commit {clean(status["baseline_commit"])} ({clean(status["baseline_date"])}); '
             f'status as of {clean(status["as_of"])}. Generated by `tools/status/build_status.py`; do not edit.', '',
             '## How to read this', '',
             '- Evidence classes (mocked, synthetic, fixture, live-native) are never mixed; only live-native is live evidence.',
             '- Implementation and validation are different numbers and are never merged into one.',
             '- Every percentage is one analyst\'s counted figure for one workstream; nothing is averaged across them.',
             '- A workstream that is not yet inventoried is listed as such; it is not zero and not complete.',
             '- Hours are analyst estimates, not measurements. Full text and every count: `status.json`.', '',
             '## Completion by workstream', '']
    rows = []
    for key, w in ws.items():
        by, c = w['features_by_status'], w['completion'] or {}
        cells = [str(by[s]) if w['features'] else '-' for s in STATUSES]
        rows.append([clean(f'{key} {w["title"]}', 60), str(w['features']), *cells, pct(c.get('implementation_pct')),
                     pct(c.get('validation_pct')), clean(c.get('basis'), 160)])
    lines += table(['Workstream', 'Features', 'Implemented', 'Partial', 'Missing', 'Blocked-external', 'Deferred',
                    'Implementation', 'Validation', 'Basis (shortened)'], rows)
    lines += ['## Remaining effort', '', f'Hours ({EFFORT_LABEL}) are summed over features not yet implemented.', '']
    rows = [[clean(k), str(w['effort_features']) if w['features'] else NOT_STATED,
             str(w['effort_hours_not_implemented']) if w['features'] else NOT_STATED] for k, w in ws.items()]
    rows.append(['Sum over inventoried workstreams', str(sum(w['effort_features'] for w in ws.values())),
                 str(status['totals']['effort_hours_not_implemented'])])
    lines += table(['Workstream', 'Features covered', 'Hours'], rows)
    lines += ['## Open defects by severity', '', 'A defect listed on several features is counted once.', ''] + counts_table('Severity', status['totals']['defects_by_severity'])
    rows = [[clean(d.get('id')), clean(d.get('severity')), clean(k if fid == k else f'{k} {fid}'), clean(d.get('summary'), 200),
             clean(d.get('evidence'), 120)] for k, fid, d in defect_rows(inventories)
            if d.get('severity') in ('critical', 'high')]
    lines += table(['Id', 'Severity', 'Workstream / feature', 'Summary', 'Evidence'], rows) if rows else [
        'No critical or high defect is listed.', '']
    lines += ['## External blockers', ''] + blocker_lines(inventories)
    lines += ['## Tracker', ''] + tracker_lines(status['tracker'])
    lines += ['## Slices built by the completion session', ''] + slice_lines(slices)
    missing = status['not_inventoried']
    lines += ['## Not yet inventoried', '',
              (f'Workstreams not yet inventoried: {", ".join(missing)}.' if missing else 'Every workstream is inventoried.'),
              f'Nonconforming values reported by the inventories: {sum(map(len, status["nonconforming"].values()))} '
              '(listed in `status.json`).', '',
              '## How to regenerate', '', '```', 'python tools/status/build_status.py', 'python tools/status/build_status.py --check',
              '```', '',
              'Inputs: `docs/status/inventory/<KEY>.json`, `docs/status/meta.json` (baseline commit, baseline date, as_of, '
              'session) and `docs/status/slices.json`, a hand-maintained JSON list of objects with the keys `id`, `title`, '
              '`state`, `branch`, `pr` and `evidence` (any key may be absent and prints as "not stated"). '
              '`--check` writes nothing, prints the generated files that differ and exits 1; exit 2 means bad arguments '
              'or a malformed input.', '']
    return '\n'.join(lines)


def defect_rows(inventories: dict) -> list[tuple[str, str, dict]]:
    rows = [(k, fid, d) for k, data in inventories.items() for fid, d in all_defects(data)]
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    return sorted(rows, key=lambda r: (rank.get(r[2].get('severity'), len(rank)), str(r[2].get('id', '')), r[0], r[1]))


def blocker_lines(inventories: dict) -> list[str]:
    groups: dict[str, dict[str, set]] = {}
    for key, data in inventories.items():
        for feature in data['features']:
            for b in list_of_dicts(feature.get('blockers'), [], '', ''):
                if b.get('type') != 'none':
                    groups.setdefault(str(b.get('type')), {}).setdefault(clean(b.get('detail'), 220), set()).add(key)
    if not groups:
        return ['No external blocker is recorded.', '']
    lines = []
    for kind in [*BLOCKER_TYPES, *sorted(k for k in groups if k not in BLOCKER_TYPES)]:
        if kind in groups:
            lines += [f'### {clean(kind)} ({len(groups[kind])})', '']
            lines += [f'- {detail} (workstreams: {", ".join(sorted(who))})' for detail, who in sorted(groups[kind].items())]
            lines.append('')
    return lines


def tracker_lines(tracker: dict) -> list[str]:
    if not tracker:
        return ['No tracker workstream is inventoried.', '']
    lines = []
    for key, counts in tracker.items():
        lines += [f'### {clean(key)}', '', f'Open-box lines listed: {clean(counts.get("total_open_listed"))}.', '']
        for name, title in (('by_state', 'State'), ('by_blocked_by', 'Blocked by')):
            if isinstance(counts.get(name), dict):
                lines += counts_table(title, dict(sorted(counts[name].items())))
    return lines


def slice_lines(slices: list) -> list[str]:
    if not slices:
        return ['No slice is recorded in `slices.json`.', '']
    rows = [[clean(s.get('id')), clean(s.get('title'), 120), clean(s.get('state')),
             clean(', '.join(str(s[k]) for k in ('branch', 'pr') if s.get(k)) or None), clean(s.get('evidence'), 300)]
            for s in slices]
    return table(['Id', 'Title', 'State', 'Branch or PR', 'Verification evidence'], rows)


def inventory_md(inventories: dict) -> str:
    lines = ['# Feature inventory', '', 'Generated by `tools/status/build_status.py` from `docs/status/inventory/`; do not edit.', '']
    headers = ['Id', 'Name', 'Status', 'Impl %', 'Valid %', 'Evidence', 'Remaining (first two)', 'Blockers', 'Hours',
               'Confidence', 'Lane overlap']
    for key, data in inventories.items():
        lines += [f'## {clean(key)}: {clean(data["title"], 120)}', '']
        if not data['features']:
            lines += ['This workstream has no feature rows; see the Tracker section of `README.md`.', '']
            continue
        rows = []
        for f in data['features']:
            remaining = f.get('remaining') if isinstance(f.get('remaining'), list) else [f.get('remaining')]
            kinds = sorted({str(b.get('type')) for b in list_of_dicts(f.get('blockers'), [], '', '')} - {'none'})
            rows.append([clean(f['id']), clean(f['name'], 80), clean(f['status']), pct(f['implementation_pct']),
                         pct(f['validation_pct']), clean(f['evidence_class']),
                         clean('; '.join(shorten(r, 90) for r in remaining[:2] if r) or None), clean(', '.join(kinds) or 'none'),
                         clean(f.get('effort_hours')), clean(f.get('confidence')), clean(f.get('active_lane_overlap'))])
        lines += table(headers, rows)
    return '\n'.join(lines)


def defects_md(inventories: dict) -> str:
    lines = ['# Open defects', '', 'Generated by `tools/status/build_status.py`; cells are shortened to 300 characters, '
             'the full text is in `docs/status/inventory/`.', '']
    headers = ['Id', 'Severity', 'Workstream', 'Summary', 'Evidence', 'Failure scenario', 'Proposed fix', 'Regression test']
    rows = [[clean(d.get('id')), clean(d.get('severity')), clean(k if fid == k else f'{k} {fid}'), *(clean(d.get(f), 300) for f in (
        'summary', 'evidence', 'failure_scenario', 'proposed_fix', 'regression_test'))]
        for k, fid, d in defect_rows(inventories)]
    return '\n'.join(lines + (table(headers, rows) if rows else ['No defect is listed.', '']))


# ---- driver ---------------------------------------------------------------------------------------------------

def load(root: Path, as_of: str | None):
    base = root / 'docs' / 'status'
    meta = read_json(base / 'meta.json', 'docs/status/meta.json')
    if not isinstance(meta, dict) or [k for k in ('baseline_commit', 'baseline_date', 'as_of', 'session') if k not in meta]:
        raise InputError('docs/status/meta.json: needs baseline_commit, baseline_date, as_of and session')
    meta['as_of'] = as_of or meta['as_of']
    for k in ('baseline_date', 'as_of'):
        if not (isinstance(meta[k], str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}', meta[k])):
            raise InputError(f'docs/status/meta.json: {k} must be YYYY-MM-DD')
        date.fromisoformat(meta[k])
    slices = read_json(base / 'slices.json', 'docs/status/slices.json')
    if not isinstance(slices, list) or not all(isinstance(s, dict) for s in slices):
        raise InputError('docs/status/slices.json: must be a list of objects')
    files = {p.stem: p for p in (base / 'inventory').glob('*.json')}
    inventories, nonconforming = {}, {}
    for key in [*(k for k in KEYS if k in files), *sorted(k for k in files if k not in KEYS)]:
        label = f'docs/status/inventory/{key}.json'
        data = read_json(files[key], label)
        fatal, odd = validate(key, data)
        if fatal:
            raise InputError(f'{label}: {"; ".join(fatal[:3])}')
        inventories[key] = data
        if odd:
            nonconforming[key] = odd
    return meta, inventories, nonconforming, slices


def render(root: Path, as_of: str | None) -> dict[str, bytes]:
    meta, inventories, nonconforming, slices = load(root, as_of)
    status = build_status(inventories, meta, nonconforming)
    texts = {'status.json': json.dumps(status, indent=1) + '\n', 'README.md': readme(status, inventories, slices),
             'inventory.md': inventory_md(inventories), 'defects.md': defects_md(inventories)}
    return {name: (text.rstrip('\n') + '\n').encode('utf-8') for name, text in texts.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--root', type=Path, default=ROOT, help='repository root (default: this checkout)')
    parser.add_argument('--as-of', help='YYYY-MM-DD, overrides docs/status/meta.json')
    parser.add_argument('--check', action='store_true', help='write nothing; exit 1 listing generated files that differ')
    args = parser.parse_args(argv)
    try:
        if args.as_of and not re.fullmatch(r'\d{4}-\d{2}-\d{2}', args.as_of):
            raise InputError('--as-of must be YYYY-MM-DD')
        outputs = render(args.root, args.as_of)
    except (InputError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    base = args.root / 'docs' / 'status'
    stale = [n for n, data in outputs.items() if not (base / n).is_file() or (base / n).read_bytes() != data]
    if args.check:
        for name in stale:
            print(f'docs/status/{name} differs from the generated output')
        return 1 if stale else 0
    for name in stale:
        (base / name).write_bytes(outputs[name])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
