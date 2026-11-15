import sys, tempfile, pathlib, json
from patchtrace.nway.contracts import Series, BuildRef, PairRef
from patchtrace.nway.graph import series_id
from patchtrace.nway import series as S
root = pathlib.Path(tempfile.mkdtemp())
hashes = [c*64 for c in 'abc']
refs = []
for i in range(2):
    d = root/f'pair{i}'; d.mkdir()
    (d/'project.sqlite3').write_bytes(b'this is not a sqlite database' * 100)
    refs.append(PairRef(from_ordinal=i, to_ordinal=i+1, path=f'pair{i}', project_id='p', revision=0))
s = Series(series_id=series_id(hashes), builds=tuple(BuildRef(ordinal=i,label=f'b{i}',artifact_sha256=h) for i,h in enumerate(hashes)),
           pair_projects=tuple(refs), node_count=0)
S.save(s, root/'series.json')
print(root)
