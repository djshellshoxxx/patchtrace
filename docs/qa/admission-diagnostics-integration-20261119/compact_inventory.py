"""Render a small index; the complete immutable inventory stays in evidence.zip."""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent
MEMBER = 'branch-refresh/inventory.json'
manifest = json.loads((ROOT / 'manifest.json').read_text())
expected = next(r for r in manifest['payloads'] if r['path'] == MEMBER)
with zipfile.ZipFile(ROOT / 'evidence.zip') as archive:
    raw = archive.read(MEMBER)
assert len(raw) == expected['bytes'] and hashlib.sha256(raw).hexdigest() == expected['sha256']
full = json.loads(raw)
rows = []
for original in full['branches']:
    row = {k: v for k, v in original.items() if not k.startswith('historical_')}
    row['complete_record'] = {'archive_member': MEMBER, 'branch': original['branch']}
    prior = original.get('historical_complete_inventory')
    if prior:
        row['historical_inventory_summary'] = {k: prior[k] for k in (
            'head_sha', 'main', 'main_merge_base', 'main_unique_commits', 'main_ancestor',
            'candidate', 'candidate_merge_base', 'candidate_unique_commits', 'candidate_ancestor',
            'classification', 'scope') if k in prior}
        for k in ('main_unmatched_nonmerge', 'candidate_unmatched_nonmerge'):
            if k in prior:
                row['historical_inventory_summary'][k + '_count'] = len(prior[k])
    followup = original.get('historical_followup_disposition')
    if followup:
        row['historical_followup_summary'] = {k: followup[k] for k in (
            'head', 'tree', 'pr', 'comparison_base', 'merge_base', 'scope', 'disposition', 'qualification') if k in followup}
    scoped = original.get('historical_scoped_semantic_review')
    if scoped:
        row['historical_scoped_review'] = {k: scoped[k] for k in ('path', 'comparison_source')}
        detail = scoped['historical_scoped_review']
        row['historical_scoped_review']['assessment'] = {k: detail[k] for k in (
            'classification', 'disposition', 'status', 'focus', 'assessed_scope', 'recommendation',
            'residue', 'remaining_qualification') if k in detail}
    rows.append(row)
result = {
    'representation': 'Compact index; full original records, patches and semantic details remain in the sealed archive member.',
    'full_inventory': expected,
    'summary': full['summary'],
    'semantic_sources': full['semantic_sources'],
    'branches': rows,
}
assert len(rows) == len({r['branch'] for r in rows}) == 316
(ROOT / 'branch-inventory.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'branches': len(rows), 'compact_bytes': (ROOT / 'branch-inventory.json').stat().st_size,
                  'complete_inventory_bytes': len(raw), 'complete_inventory_sha256': expected['sha256']}))
