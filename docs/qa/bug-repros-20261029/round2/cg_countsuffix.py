import sys; sys.path.insert(0, __file__.rsplit('/',1)[0])
from cg_support import make
from patchtrace.callgraph.snapshot import build_snapshot
data = make([('main', ['helper-' + '9'*5000])])
try:
    build_snapshot(data)
    print('ok')
except Exception as e:
    print(type(e).__name__, str(e)[:100])
