import sys; sys.path.insert(0, __file__.rsplit('/',1)[0])
from cg_support import make
from patchtrace.callgraph.snapshot import build_snapshot
from patchtrace.callgraph.query import neighbourhood, find_node
from patchtrace.callgraph.export_json import build_export
from patchtrace.callgraph.dot import render_dot
callees = [f'callee_{i:03d}' for i in range(100)]
data = make([('main', callees)], [('main', callees)])
snap = build_snapshot(data)
v = neighbourhood(snap, 'older', [find_node(snap, 'older', 'main').id], 'out', 1)
print('nodes shown', len(v.nodes), 'truncated', v.truncated, 'more', v.more, 'limits has cap note:', any('capped' in l for l in v.limitations))
exp = build_export(snap, 'm0', 1)
print('export.truncated', exp.truncated, '| DOT callee nodes:', render_dot(exp).count('callee_')//1)
