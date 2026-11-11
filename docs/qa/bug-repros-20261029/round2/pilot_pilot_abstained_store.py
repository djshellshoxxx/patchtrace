import sys, dataclasses, pathlib, tempfile; sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from datetime import UTC, datetime
from pilot_localize_support import *
from pilot_synergy_support import StaticKev
from patchtrace.service import ProjectService
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.pilot import store, keys
d = pathlib.Path(tempfile.mkdtemp())
with ProjectService.sample(d/'case') as svc:
    en = EnrichmentStore(svc.store)
    sha_of = {a.side: a.sha256 for a in svc.project.artifacts}; r = svc.project.runs[-1]
    b = build([], [])
    inputs = dataclasses.replace(b, project_id=svc.project.id, revision=svc.project.revision, older_sha256=sha_of['older'], newer_sha256=sha_of['newer'], ghidriff_run_id=r.id, raw_sha256=r.raw_sha256)
    a = run(inputs, keys.default_config(), clock=lambda: datetime(2099,1,1,tzinfo=UTC))
    print('status', a.status, a.limitations)
    try:
        p = store.publish(en, a, keys.default_config(), current=store.current_guard(svc.project, a.result_id))
        print('published', p.pointer.status)
        print(store.load(en).state)
    except Exception as e:
        print('ERR', type(e).__name__, e)
