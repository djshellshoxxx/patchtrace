"""Value gate G-DIE-1 for the build-environment overlay (DIE plan s10, T6.4). Counts only, no network, no tools run.

usage: buildenv_value_gate.py --input PAIRS.json --out REPORT.json

Input `buildenv-value-gate-input/1`: pairs of a Tier R M4 stratum (`toolchain-variant`, `aa`, `o0-vs-o2`) with the
toolchain verdict of the pair and its function rows (`verdict`, change `classes`, `deltas_omitted`, ground-truth
`truth`). The real overlay rules (`noise_map.tag_rows`) decide which rows get the "Build differs" tag; this tool only
counts. Truth `unknown` and `ambiguous` are not votes: those tagged rows are counted apart. Report
`buildenv-value-gate/1` holds raw counts per stratum and the two preregistered checks (targets are [inf] proposals):
no tag on the `aa` and `o0-vs-o2` control strata, and no tag on a truth-`changed` function the engine flags. A check
with nothing to measure is `no-data`, never `met`. No false-lead-reduction claim is made from these counts.

Exit codes: 0 report written, 2 invalid input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from patchtrace.buildenv.noise_map import RowFacts, tag_rows

INPUT_SCHEMA = 'buildenv-value-gate-input/1'
REPORT_SCHEMA = 'buildenv-value-gate/1'
STRATA = ('toolchain-variant', 'aa', 'o0-vs-o2')
CONTROLS = ('aa', 'o0-vs-o2')
TOOLCHAINS = ('same', 'differs', 'unknown')
TRUTHS = ('same', 'cosmetic', 'changed', 'ambiguous', 'unknown')
NOISE_TRUTHS = ('same', 'cosmetic')
MAX_PAIRS, MAX_FUNCTIONS, MAX_CLASSES = 10_000, 200_000, 16
CLAIMS = 'counts only; no false-lead-reduction claim'


class GateInputError(ValueError):
    """The input does not match `buildenv-value-gate-input/1`."""


def _require(ok: bool, what: str) -> None:
    if not ok:
        raise GateInputError(what)


def _rows(pair: dict[str, Any]) -> list[tuple[RowFacts, str]]:
    functions = pair.get('functions')
    _require(isinstance(functions, list), 'functions must be a list')
    out = []
    for item in functions:
        classes = item.get('classes')
        _require(isinstance(classes, list) and len(classes) <= MAX_CLASSES
                 and all(isinstance(c, str) for c in classes), 'classes must be a short list of strings')
        _require(item.get('truth') in TRUTHS, 'unknown truth label')
        _require(isinstance(item.get('id'), str) and isinstance(item.get('verdict'), str), 'id and verdict are text')
        omitted = item.get('deltas_omitted', 0)
        _require(isinstance(omitted, int) and omitted >= 0, 'deltas_omitted must be a count')
        out.append((RowFacts(item['id'], str(item.get('group', '')), item['verdict'], tuple(classes), omitted),
                    item['truth']))
    return out


def _validate(data: dict[str, Any]) -> list[dict[str, Any]]:
    _require(isinstance(data, dict) and data.get('schema') == INPUT_SCHEMA, f'schema must be {INPUT_SCHEMA}')
    pairs = data.get('pairs')
    _require(isinstance(pairs, list) and len(pairs) <= MAX_PAIRS, 'pairs must be a bounded list')
    ids = [p.get('pair_id') for p in pairs]
    _require(all(isinstance(i, str) for i in ids) and len(set(ids)) == len(ids), 'pair ids are unique text')
    _require(all(p.get('stratum') in STRATA for p in pairs), f'stratum must be one of {STRATA}')
    _require(all(p.get('toolchain') in TOOLCHAINS for p in pairs), f'toolchain must be one of {TOOLCHAINS}')
    _require(sum(len(p.get('functions') or ()) for p in pairs) <= MAX_FUNCTIONS, 'too many functions')
    return pairs


def _count(pairs: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for pair in pairs:
        stratum = counts[pair['stratum']]
        stratum['pairs'] += 1
        rows = _rows(pair)
        tags = tag_rows([row for row, _ in rows], pair['toolchain'])
        for row, truth in rows:
            flagged = row.verdict == 'review'
            tagged = row.row_id in tags
            stratum['tagged_total'] += tagged
            if truth in NOISE_TRUTHS:
                stratum['flagged_noise'] += flagged
                stratum['tagged_noise'] += tagged and flagged
            elif truth == 'changed':
                stratum['flagged_changed'] += flagged
                stratum['tagged_changed'] += tagged and flagged
            elif tagged:
                stratum['tagged_unknown'] += 1
    return counts


FIELDS = ('pairs', 'flagged_noise', 'tagged_noise', 'flagged_changed', 'tagged_changed', 'tagged_unknown',
          'tagged_total')


def _checks(strata: dict[str, dict[str, int]]) -> list[dict[str, Any]]:
    controls = [strata[name] for name in CONTROLS if name in strata]
    control_tags = sum(s['tagged_total'] for s in controls)
    flagged = sum(s['flagged_changed'] for s in strata.values())
    leaked = sum(s['tagged_changed'] for s in strata.values())
    return [
        {'id': 'zero-tags-on-controls', 'target': 'no tag on aa and o0-vs-o2 pairs',
         'status': 'no-data' if not controls else 'met' if control_tags == 0 else 'not-met',
         'observed': {'tagged_total': control_tags}},
        {'id': 'semantic-leakage-zero', 'target': 'no tag on a flagged truth-changed function',
         'status': 'no-data' if not flagged else 'met' if leaked == 0 else 'not-met',
         'observed': {'tagged_changed': leaked, 'flagged_changed': flagged}}]


def evaluate(data: dict[str, Any]) -> dict[str, Any]:
    """Deterministic report; pair order in the input does not matter."""
    counts = _count(_validate(data))
    strata = {name: {field: counts[name][field] for field in FIELDS} for name in STRATA if name in counts}
    body = {'schema': REPORT_SCHEMA, 'claims': CLAIMS,
            'strata': [{'stratum': name, **values} for name, values in strata.items()],
            'checks': _checks(strata)}
    canonical = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
    return {**body, 'report_sha256': hashlib.sha256(canonical).hexdigest()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = evaluate(json.loads(args.input.read_text(encoding='utf-8')))
    except (OSError, ValueError, AttributeError) as exc:  # GateInputError and JSON errors are ValueErrors
        print(f'invalid input: {type(exc).__name__}', file=sys.stderr)
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({check['id']: check['status'] for check in report['checks']}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
