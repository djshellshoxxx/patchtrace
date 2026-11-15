import sys, random, collections, traceback; sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from pilot_localize_support import *
from patchtrace.pilot import report, read_model, why, keys, contracts as c, store
from patchtrace.pilot.limits import PilotError
random.seed(int(sys.argv[1]) if len(sys.argv)>1 else 1)
RULES_ = list(K_RULES)
KINDS = ['b1:BND','b1:SIZE','b1:OVF','b1:SCRUB','b1:VAL','b1:ERR','b1:INT','cf:comparison','cf:condition','cf:constant','cf:callee','cf:call-added','cf:string','cf:cosmetic','cf:unchanged','cf:register-only','cf:cfg','call:added','call:removed','die:toolchain-changed','die:packed','str:added','capa:added','capa:unlocalized-added','pair:thunk','pair:truncated','pair:hub']
ROLES = ['shape','shape','shape','conflict','context','local','counter']
VERIFS = ['tool-reported','label-only','verified-bytes']
APIS = ['memcpy','HeapFree','ProbeForRead','RtlCopyMemory','strcpy','x']
errs = collections.Counter()
def obs(kind):
    pre = kind.split(':')[0]
    role = random.choice(ROLES)
    if pre in ('die','str'): role='context'
    if kind in ('cf:cosmetic','cf:unchanged'): role = random.choice(['conflict','context'])
    ver = random.choice(VERIFS)
    ref = random.choice(APIS) if pre=='call' else f'r{random.randint(0,5)}'
    org = random.choice([None, ('D_ghidra',), ('D_pe_tables',), ('D_vendor_text',), ('D_bytes','D_ghidra')]) 
    obl = random.choice([(),(),('second-channel',)])
    try:
        return observation(kind, role=role, verification=ver, origins=org, ref=ref, obligations=obl, line=random.choice([None,3,14]), ref_kind=('call-label' if (pre=='call' and ver=='label-only') else None))
    except Exception as e:
        return None
for it in range(int(sys.argv[2]) if len(sys.argv)>2 else 150):
    n = random.randint(1, 12)
    cands = []
    for i in range(n):
        mode = random.random()
        cands.append(candidate(i, random.choice([None,'FUN_00401000','ReadItem','CopyBuffer','sub_1234']), identity=random.choice(['corroborated','contested','unassessed']), older_only=mode<.1, newer_only=.1<=mode<.2))
    ev = []
    for cd in cands:
        for _ in range(random.randint(0,6)):
            o = obs(random.choice(KINDS))
            if o: ev.append((cd, o))
    ncve = random.randint(0,3)
    cves = {}
    ctxs = []
    for k in range(ncve):
        cve = f'CVE-2099-{40001+k}'
        hs = {}
        for _ in range(random.randint(0,3)):
            h = hypothesis(random.choice(RULES_), random.choice(['CWE-787','CWE-125','CWE-190']), random.choice(['explicit-csaf-cwe','cwe-id-in-text','curated-vocabulary']), cve); hs[h.hypothesis_id]=h
        cves[cve] = tuple(hs.values())
    cvelist = sorted(cves)
    for cve in cvelist:
        gate = random.choice(['applies','applies','asserted','unverified','conflict','not-applicable'])
        win = random.choice(['no','unknown','yes']) 
        ctxs.append(context(cve, gate=gate, window='yes' if win=='yes' and len(cvelist)>1 else ('unknown' if win=='yes' else win), window_cves=cvelist if win=='yes' and len(cvelist)>1 else ()))
    entries = {cve: (advisory_entry(cve),) for cve in cvelist if random.random()<.7}
    cfg = keys.default_config(lexical_moderate=random.random()<.7, locality_min_tokens=random.randint(1,3))
    try:
        b = build(cands, ev, cves=cves, contexts=ctxs, entries=entries, code=random.choice(['available','partial','stale']), calls=random.choice(['available','partial','unsupported']), capa=random.choice(['not-run','available']), build_state=random.choice(['not-run','available','partial']), binary=[o for o in [obs('die:toolchain-changed')] if o and random.random()<.3])
        a = run(b, cfg)
    except Exception as e:
        errs['localize '+type(e).__name__+' '+str(e)[:100].replace('\n',' ')] += 1
        if errs['localize '+type(e).__name__+' '+str(e)[:100].replace('\n',' ')] == 1: traceback.print_exc(limit=4)
        continue
    try:
        report.to_markdown(a); report.to_json(a)
        m = read_model.LeadsModel(a)
        for ctx in m.contexts:
            for row in m.rows(ctx.cve):
                m.detail(row); m.observations(row)
        e = why.Explainer(a)
        for l in a.leads: e.explain(l)
        # store roundtrip
        data = keys.canonical_bytes(a)
        a2 = c.PilotAssessment.model_validate_json(data)
        keys.verify_assessment(a2)
        mf = keys.make_manifest(a, cfg, created_utc='2099-01-01T00:00:00Z'); keys.verify_manifest(mf, a2)
    except Exception as e:
        errs['render '+type(e).__name__+' '+str(e)[:100].replace('\n',' ')] += 1
        if errs['render '+type(e).__name__+' '+str(e)[:100].replace('\n',' ')] == 1: traceback.print_exc(limit=5)
print(errs)
