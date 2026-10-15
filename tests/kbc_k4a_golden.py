"""Baseline numbers, golden projection and text sweep for the K4a synergy test (plan s5). SYNTHETIC; offline."""
from __future__ import annotations

import json
from pathlib import Path

from patchtrace import cli as main_cli

BANNED = ('probab', 'likelihood', 'confidence', 'proven', 'certain', 'safe', 'secure', 'is fixed', 'was fixed',
          'patched', 'exploitable')
GOLDEN = Path(__file__).resolve().parent / 'fixtures' / 'kbcorrelation' / 'expected' / 'synergy-leads.json'


def snapshot_file(path: Path, cwes: dict[str, str]) -> Path:
    """One ``CveSnapshot`` per CVE carrying a single msrc CWE, retrieved 2099-02-14 (plan s5 baseline)."""
    from patchtrace.enrichment.cve import (
        _snapshot_id,  # imported snapshots must carry their real identity (ACQ-10)
    )
    items = [{'contract': 'enrichment/1', 'snapshot_id': _snapshot_id(cve, 1, {'msrc': '0' * 64}), 'cve_id': cve,
              'normalization_version': 1,
              'response_digests': {'msrc': '0' * 64}, 'retrieved_at': '2099-02-14T00:00:00+00:00',
              'cwes': [{'contract': 'enrichment/1', 'source': 'msrc', 'value': cwe}]}
             for index, (cve, cwe) in enumerate(sorted(cwes.items()), 1)]
    path.write_text(json.dumps(items), encoding='utf-8')
    return path


def _json(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


def baseline_scores(project: Path, scratch: Path, capsys) -> dict[str, dict[str, int]]:
    """The numbers the existing tools give today: ``rank --dry-run`` and ``correlate --cve ... --dry-run`` scores."""
    assert main_cli.main(['rank', str(project), '--json', '--dry-run']) == 0
    ranked = _json(capsys)['result']['entries']
    names = {e['match_id']: e['function'] for e in ranked}
    out = {'rank': {e['function']: e['score'] for e in ranked}}
    for label, cwes in (('correlate_20001', {'CVE-2099-20001': 'CWE-125'}),
                        ('correlate_20001_20002', {'CVE-2099-20001': 'CWE-125', 'CVE-2099-20002': 'CWE-190'})):
        snap = snapshot_file(scratch / f'{label}.json', cwes)
        argv = ['correlate', str(project), '--snapshot', str(snap), '--dry-run', '--json']
        for cve in sorted(cwes):
            argv += ['--cve', cve]
        assert main_cli.main(argv) == 0
        entries = _json(capsys)['result']['entries']
        out[label] = {names[e['match_id']]: e['context_score'] for e in entries}
    return out


def projection(report: dict) -> dict:
    """The deterministic part of a ``kb leads`` result: ids that derive from random uuids are dropped."""
    def lead(row: dict) -> dict:
        return {'subject': row['subject'], 'group': row['group'], 'rank_basis': row['rank_basis'],
                'chips': [[c['channel'], c['state'], c['text']] for c in row['chips']], 'hooks': row['hooks'],
                'stale': row['stale'], 'navigable': row['nav']['match_id'] is not None}
    return {'state': report['state'], 'text': report['text'], 'coverage_text': report['coverage_text'],
            'groups': [{'group': g['group'], 'kev': g['kev'], 'kev_text': g['kev_text'], 'cwe_text': g['cwe_text'],
                        'hypotheses': g['hypotheses'], 'leads': [lead(r) for r in g['leads']]}
                       for g in report['groups']],
            'unattributed': [lead(r) for r in report['unattributed']],
            'not_applicable': [n['text'] for n in report['not_applicable']], 'mention_only': report['mention_only'],
            'unknowns': report['unknowns'], 'limitations': report['limitations'], 'hooks': report['hooks']}


def all_text(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [t for v in value.values() for t in all_text(v)]
    if isinstance(value, (list, tuple)):
        return [t for v in value for t in all_text(v)]
    return []


def banned_in(texts: list[str]) -> list[str]:
    return sorted({f'{word!r} in {text[:60]!r}' for text in texts for word in BANNED if word in text.lower()})
