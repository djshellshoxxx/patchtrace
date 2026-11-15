import sys, json, tempfile, pathlib
sys.path[:0] = [__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from patchtrace.service import ProjectService
from patchtrace.enrichment import pipeline, cve
tmp = pathlib.Path(tempfile.mkdtemp())
svc = ProjectService.sample(tmp/'case')
snap = {"contract":"enrichment/1","snapshot_id":"a"*64,"cve_id":"CVE-2026-1234","normalization_version":1,
        "response_digests":{"nvd":"b"*64},"retrieved_at":"9999-12-31T23:59:59-05:00",
        "descriptions":[{"source":"nvd","lang":"en","text":"overflow in parser"}]}
snaps = cve.parse_snapshots(json.dumps(snap).encode())   # accepted by the strict importer
print('imported:', snaps[0].retrieved_at)
try:
    pipeline.run(svc.project, pipeline.PipelineOptions(snapshots=tuple(snaps)))
    print('run OK')
except Exception as e:
    print('RAISED', type(e).__name__, e)
svc.close()
