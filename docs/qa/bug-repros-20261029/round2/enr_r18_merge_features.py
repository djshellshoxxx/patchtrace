import sys, json
sys.path[:0] = [__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from patchtrace.enrichment import cve
def snap(sid, prov, ts, feats):
    d = {"contract":"enrichment/1","snapshot_id":sid*64,"cve_id":"CVE-2026-1234","normalization_version":1,
         "response_digests":{prov:"b"*64},"retrieved_at":ts,"feature_ids":feats,
         "descriptions":[{"source":prov,"lang":"en","text":"x"}]}
    return cve.parse_snapshots(json.dumps(d).encode())[0]
a = snap('1','nvd','2026-10-01T00:00:00Z',[7]); b = snap('2','msrc','2026-10-02T00:00:00Z',[])
kept,_ = cve.select_latest([a])      ; print('single contributor  feature_ids =', kept[0].feature_ids)
kept,_ = cve.select_latest([a, b])   ; print('merged with msrc    feature_ids =', kept[0].feature_ids)
