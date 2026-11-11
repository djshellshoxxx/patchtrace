import sys, random, collections, re, traceback
sys.path.insert(0, __file__.rsplit('/',1)[0])
from cg_support import make
from patchtrace.callgraph.snapshot import build_snapshot
from patchtrace.callgraph.query import neighbourhood
from patchtrace.callgraph.export_json import build_export, to_json
from patchtrace.callgraph.dot import render_dot
from patchtrace.callgraph.delta import compute_deltas
from patchtrace.callgraph.leads import build_leads
from patchtrace.callgraph.limits import GraphError
random.seed(7)
bits = ['a','b','FUN_1000','FUN_','EXTERNAL:1234','::','kernel32.dll::CreateFileW','lib.sys::#5','thunk_','thunk_x','x-1','x-','-5','\\','"','\\N','\n','\r','\t','\x00','\u2028','\u202e','\ud800','é','<','>','{','}',';','/*','//','\x85','\u200b','FUN_zz', 'A'*600, ' ', '#', 'n1 -> n2', '"];}digraph{', 'x-' + '1'*30]
def lab():
    return ''.join(random.choice(bits) for _ in range(random.choice([1,1,2,3,4])))
errs = collections.Counter()
for it in range(1500):
    labels = [lab() for _ in range(random.randint(2,8))]
    def calls(): return [random.choice(labels + [lab()]) for _ in range(random.randint(0,4))]
    older = [(l, calls()) for l in random.sample(labels, random.randint(1, len(labels)))]
    newer = [(l, calls()) for l in random.sample(labels, random.randint(1, len(labels)))]
    try:
        data = make(older, newer)
        snap = build_snapshot(data)
        deltas = compute_deltas(snap)
        build_leads(snap, deltas)
        for m in {e.match_id for e in data.entries}:
            try: exp = build_export(snap, m, 2)
            except GraphError: continue
            dot = render_dot(exp); to_json(exp)
            # structure check: every line must be whitelisted
            for line in dot.split('\n'):
                if not re.fullmatch(r'(//.*|digraph patchtrace_calls \{|\}|  rankdir=LR;|  node \[shape=box, fontname="Helvetica"\];|\s*subgraph cluster_(older|newer) \{|\s*label="(Older|Newer) build";|\s*n\d+ \[label="(?:[^"\\]|\\.)*", color="#[0-9a-f]{6}"(, style=dashed)?\];|\s*n\d+ -> n\d+( \[style=dashed\]| \[style=dotted, constraint=false, arrowhead=none\])?;|  \}|)', line):
                    errs[('badline', line[:80])] += 1
    except GraphError as e:
        errs[('GraphError', e.code)] += 1
    except Exception as e:
        errs[(type(e).__name__, str(e)[:90])] += 1
print(errs)
