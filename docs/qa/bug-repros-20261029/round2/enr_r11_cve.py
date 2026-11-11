import sys, json, hashlib
sys.path[:0] = [__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from datetime import datetime, UTC
from patchtrace.enrichment import cve
from patchtrace.enrichment.contracts import EnrichmentError
CVE='CVE-2026-1234'
def nvd(score):
    return ('{"vulnerabilities":[{"cve":{"id":"%s","descriptions":[{"lang":"en","value":"x"}],'
            '"metrics":{"cvssMetricV31":[{"source":"a","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":%s,"baseSeverity":"HIGH"}}]}}}]}' % (CVE, score)).encode()
for score in ['9.8', '1e99999999999999999999', '1e-99999999999999999999']:
    try:
        cve.normalize(CVE, {'nvd': nvd(score)}, '2026-10-12T00:00:00Z'); print(score, 'OK')
    except EnrichmentError as e: print(score, 'EnrichmentError', e.code)
    except Exception as e: print(score, 'UNTYPED', type(e).__module__, type(e).__name__, str(e)[:60])
# timestamp overflow
snap = cve.normalize(CVE, {'nvd': nvd('9.8')}, '2026-10-12T00:00:00Z')
for ts in ['9999-12-31T23:59:59-05:00', '0001-01-01T00:00:00+05:00']:
    s2 = snap.model_copy(update={'retrieved_at': ts})
    try:
        print(ts, cve.is_stale(s2, datetime.now(UTC), 30))
    except EnrichmentError as e: print(ts, 'EnrichmentError')
    except Exception as e: print(ts, 'UNTYPED', type(e).__name__, e)
    try:
        cve.select_latest([s2, snap.model_copy(update={'snapshot_id':'1'*64,'response_digests':{'msrc':'2'*64}})]); print(ts,'select_latest OK')
    except EnrichmentError as e: print(ts, 'select EnrichmentError')
    except Exception as e: print(ts, 'select UNTYPED', type(e).__name__, e)
# contract \d unicode
d = json.loads(snap.model_dump_json()); d['cve_id'] = 'CVE-٢٠٢٦-١٢٣٤'
try:
    print('unicode cve id accepted:', cve.parse_snapshots(json.dumps(d).encode())[0].cve_id)
except EnrichmentError as e: print('unicode id rejected', e)
