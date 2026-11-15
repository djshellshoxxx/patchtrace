import sys, pathlib, shutil
sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from test_nway_support import PairBuilder, HASHES, fn
from patchtrace.nway.graph import extract_chains, series_id
from patchtrace.nway.contracts import *
from patchtrace.nway import series as S
root = pathlib.Path(sys.argv[1]); shutil.rmtree(root, ignore_errors=True); root.mkdir(parents=True)
h = HASHES[:3]
evil = 'ok\x1b]0;PWNED-TITLE\x07\x1b[2J‮exe.txt'
p1 = PairBuilder(h[0], h[1]).one(fn(evil, 0x1000), fn(evil, 0x2000)).build()
p2 = PairBuilder(h[1], h[2]).one(fn(evil, 0x2000), fn(evil, 0x3000)).build()
chains, n = extract_chains(h, [p1, p2])
refs = tuple(PairRef(from_ordinal=i, to_ordinal=i+1, path=f'pair{i}', project_id='p', revision=0) for i in range(2))
s = Series(series_id=series_id(h), builds=tuple(BuildRef(ordinal=i, label=('lbl\x1b[31mRED' if i==0 else f'b{i}'), artifact_sha256=x) for i,x in enumerate(h)),
           pair_projects=refs, node_count=n, chains=tuple(chains))
S.save(s, root/'series.json')
print('saved')
