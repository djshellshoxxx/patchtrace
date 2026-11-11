import sys, pathlib
from patchtrace.nway.contracts import Series, BuildRef, PairRef
from patchtrace.nway.graph import series_id
from patchtrace.nway import series as S
root = pathlib.Path(sys.argv[1])
hashes = [c*64 for c in 'abc']   # NOT the hashes of the files inside pair0 / pair1
refs = tuple(PairRef(from_ordinal=i, to_ordinal=i+1, path=f'pair{i}', project_id='some-other-project-id', revision=99) for i in range(2))
s = Series(series_id=series_id(hashes), builds=tuple(BuildRef(ordinal=i,label=f'build-{i}',artifact_sha256=h) for i,h in enumerate(hashes)), pair_projects=refs, node_count=0)
S.save(s, root/'series.json')
