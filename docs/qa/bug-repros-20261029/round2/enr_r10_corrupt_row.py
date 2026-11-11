import sys, tempfile, pathlib, io, json, hashlib
sys.path[:0] = [__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from patchtrace.service import ProjectService
from patchtrace.enrichment import pipeline
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.search import cli
tmp = pathlib.Path(tempfile.mkdtemp())
svc = ProjectService.sample(tmp/'case')
store = EnrichmentStore(svc.store)
res = pipeline.run(svc.project)
pipeline.publish(store, svc.project, res)
print('load_default ok:', pipeline.load_default(store, svc.project)[2] == '')
root = svc.root
mode = sys.argv[1]
db = svc.store.connection
if mode == 'hash':      # bit-rot in ANY derived row (here: an old/unrelated 'wil' row)
    db.execute("UPDATE enrichment_entries SET body = body || ' ' WHERE kind='ranking'"); db.commit()
elif mode == 'nostage':  # pipeline row valid + consistent hash, but stage_ids stripped
    row = db.execute("SELECT id, body FROM enrichment_entries WHERE kind='pipeline'").fetchone()
    body = json.loads(row[1]); del body['stage_ids']
    t = json.dumps(body, sort_keys=True, separators=(',',':'), ensure_ascii=False)
    db.execute("UPDATE enrichment_entries SET body=?, body_sha256=? WHERE id=?", (t, hashlib.sha256(t.encode()).hexdigest(), row[0])); db.commit()
elif mode == 'listbody':
    row = db.execute("SELECT id FROM enrichment_entries WHERE kind='pipeline'").fetchone()
    t='[]'
    db.execute("UPDATE enrichment_entries SET body=?, body_sha256=? WHERE id=?", (t, hashlib.sha256(t.encode()).hexdigest(), row[0])); db.commit()
svc.close()
out, err = io.StringIO(), io.StringIO()
code = cli.main([str(root), '--cache-dir', str(tmp/'cache'), '--query', 'sample', '--json'], stdout=out, stderr=err)
print(mode, 'exit', code, err.getvalue().strip(), out.getvalue()[:150].strip())
