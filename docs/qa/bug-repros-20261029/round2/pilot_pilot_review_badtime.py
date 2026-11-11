import tempfile, pathlib
from patchtrace.service import ProjectService
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.pilot import review, store, keys
d = pathlib.Path(tempfile.mkdtemp())
with ProjectService.sample(d/'case') as svc:
    en = EnrichmentStore(svc.store)
    en.ensure()
    body = {'contract':'pilot-review/1','candidate_key':'a'*64,'cve':None,'action':'pin','text':'','created_utc':'2026-13-45T99:99:99Z'}
    from patchtrace.pilot.contracts import ReviewEvent
    ReviewEvent.model_validate(body)  # passes validation
    g = Guard(svc.project.id, review.GUARD_RUN, 'a'*64, 'b'*64)
    en.publish(store.KIND, g, g, 1, 'complete', body, 'pilot-review:11111111-1111-4111-8111-111111111111')
    try:
        print(review.read(en))
    except Exception as e:
        print('CRASH', type(e).__name__, e)
