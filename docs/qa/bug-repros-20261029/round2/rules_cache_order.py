"""rules test cache: same file set in another order reuses cached cells by position -> hits shown for the wrong files."""
import sys, tempfile
sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from pathlib import Path
import rules_fixtures as rf
from rules_store_support import accepted, candidate_of, rule_store
from patchtrace.rules import matrix
from patchtrace.rules.runner import ScanOutcome
from patchtrace.rules.contracts import CellResult, EngineStamp
tmp = Path(tempfile.mkdtemp())
bench = rf.Bench(tmp)
cand = candidate_of(bench)
rules = rule_store(tmp)
_, version = accepted(cand)
a, b = tmp/'a.bin', tmp/'b.bin'
a.write_bytes(b'MATCHME' + b'\0'*20); b.write_bytes(b'nothing here' + b'\0'*20)
stamp = EngineStamp(version='1.21.0', version_source='pin')
def fake_scan(rules_, targets, **kw):
    cells = []
    for t in targets:
        hit = b'MATCHME' in Path(t.path).read_bytes()
        cells.append(CellResult(state='hit', hits=1, offsets=(0,), rvas=(None,)) if hit else CellResult(state='no-hit', hits=0))
    return ScanOutcome(stamp, (), tuple(cells))
anchors = {}
def grid(extra):
    entries, notes = matrix.gather(version.source, anchors, extra=extra)
    return entries
e1 = grid([a, b])
key1 = matrix.cache_key([version], [e.target for e in e1], '1.21.0', 30)
run = matrix.run_matrix(e1, [version], scan=fake_scan)
rules.add_test(run, version.source)
e2 = grid([b, a])                                  # same files, other order
key2 = matrix.cache_key([version], [e.target for e in e2], '1.21.0', 30)
print('same cache key:', key1 == key2)
cached = rules.find_test(key2)
shown = matrix.rescored(cached, [e.target for e in e2], [version])
for t, c in zip(shown.targets, shown.cells):
    print(f'{t.label}: {c.state}')
print('expected: a.bin hit, b.bin no-hit')
bench.close()
