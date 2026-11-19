"""Independent local control for global native revision admission before finite scope.

Uses a committed factual fixture with authored mutations. No target or network work.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

checkout = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(checkout / 'src'))

from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.sources.scope import files_scope

fixture = checkout / 'tests/fixtures/kbcve/msrc/2024-Aug-CVE-2024-38193.facts.json'
original = fixture.read_bytes()
now = '2026-11-18T00:00:00Z'
cases = []
for zoned in (False, True):
    positive = json.loads(original)
    positive['DocumentTracking']['CurrentReleaseDate'] = '2026-10-28T01:48:49' + ('Z' if zoned else '')
    negative = copy.deepcopy(positive)
    negative['Vulnerability'][0]['Remediations'] = []
    documents = [import_bytes(json.dumps(value).encode(), now=now) for value in (positive, negative)]
    index = ReverseIndex()
    index.add(documents[0])
    control = index.lookup_cve('CVE-2024-38193', now=now)
    index.add(documents[1])
    unscoped = index.lookup_cve('CVE-2024-38193', now=now)
    scoped = index.lookup_cve('CVE-2024-38193', scope=files_scope((documents[0].doc_id,)), now=now)
    row = {'zoned': zoned, 'positive_control_edges': len(control.edges),
           'unscoped_edges': len(unscoped.edges), 'unscoped_disputed': len(unscoped.disputed),
           'selected_edges': len(scoped.edges), 'selected_disputed': len(scoped.disputed),
           'selected_conflict_warning': any(w.startswith('REVISION_EDGE_CONFLICT:') for w in scoped.warnings),
           'both_active': index.active_ids() == {d.doc_id for d in documents}}
    row['passed'] = (row['positive_control_edges'] > 0 and row['both_active']
                     and row['unscoped_edges'] == 0 and row['unscoped_disputed'] > 0
                     and row['selected_edges'] == 0 and row['selected_disputed'] > 0
                     and row['selected_conflict_warning'])
    cases.append(row)
receipt = {'source': subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip(),
           'python': sys.executable, 'python_version': sys.version,
           'fixture_sha256': hashlib.sha256(original).hexdigest(), 'cases': cases,
           'passed': all(case['passed'] for case in cases)}
output.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
print(json.dumps(receipt, indent=2))
raise SystemExit(0 if receipt['passed'] else 1)
