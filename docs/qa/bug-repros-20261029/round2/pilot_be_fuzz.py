import random, hashlib, traceback, collections
from typing import get_args
from patchtrace.buildenv.contracts import *
from patchtrace.buildenv.delta import compute_delta
from patchtrace.buildenv.report import build_section, render_markdown, render_html, section_data
from patchtrace.buildenv.view_model import build_view
from patchtrace.buildenv.anchors import anchors_for
random.seed(7)
KEYS = get_args(FactKey); SRC = get_args(FactSource); CERT = get_args(Certainty)
VALS = ['a','b','1.0','x'*200,'y'*199+'\n','', '<b>&|', 'a; b', 'ü']
def rnd_fact(die_ok):
    src = random.choice([s for s in SRC if die_ok or s != 'diec'])
    raw = ()
    if random.random()<.5: raw = (('checksum', random.choice(['ok','failed','unknown'])), ('raw_type', random.choice(['packer','virtual machine','protector','obfuscator'])))
    return BuildFact(key=random.choice(KEYS), value=random.choice(VALS), version=random.choice(['','3.21','v'*120]), source=src, certainty=random.choice(CERT), raw=raw)
def rnd_pe():
    if random.random()<.2: return None
    rich = None
    if random.random()<.5:
        rich = RichFacts(offset=1,key=1,checksum_ok=random.choice([True,False,None]),entries=tuple(RichEntry(product_id=i,build=i,count=1) for i in range(random.randint(0,80))),truncated=False,signature='a'*64)
    clr = ClrFacts(header_size=1,runtime_major=1,runtime_minor=1,flags=(),il_only=random.random()<.5,has_native_header=random.random()<.5,metadata_version=random.choice([None,'v4']))if random.random()<.3 else None
    return PeBuildFacts(linker_field=(14,0),os_field=None,image_field=None,subsystem_field=None,subsystem=None,dll_characteristics=(),guard_flags=None,security_cookie_set=None,debug_entry_types=(),repro=False,rich=rich,clr=clr,runtime_families=(),entropy_exec_max=None,overlay_size=random.choice([0,5,10**7]),overlay_entropy=None,sampled=False,anomalies=tuple(f'a{i}' for i in range(random.randint(0,16))))
def rnd_fp(side, sha):
    produced = random.random()<.7
    die = None
    if random.random()<.9:
        st = 'ok' if produced else random.choice(['failed','timeout','absent','not-run'])
        die = DieSummary(status=st, run_id='r', tool_version=random.choice(['3.21','3.20',None]), db_label=None, db_sha256=random.choice([None,'a'*64]), argv_version='diec/1', heuristics=random.random()<.2, cache_key='b'*64 if st=='ok' else None)
    p = rnd_pe()
    facts = tuple(rnd_fact(die is not None and die.produced()) for _ in range(random.randint(0,40)))
    return BuildFingerprint(artifact_sha256=sha, side=side, pe=p, die=die, facts=facts, anomalies=(), built_from=BuiltFrom(pe_facts_version='pe-build-facts/1', die_cache_key=die.cache_key if die and die.produced() else None))
errs = collections.Counter()
for i in range(3000):
    try:
        o, n = rnd_fp('older','1'*64), rnd_fp('newer','2'*64)
    except Exception as e:
        errs['construct '+type(e).__name__]+=1; continue
    try:
        d = compute_delta(o, n)
        v = build_view(o, n, d, technical=True)
        anchors_for(o)
    except Exception as e:
        errs['delta/view '+type(e).__name__+' '+str(e)[:80]]+=1
        if errs['delta/view '+type(e).__name__+' '+str(e)[:80]]==1: traceback.print_exc()
        continue
    for tech in (False, True):
        try:
            s = build_section(o, n, d, technical=tech)
            data = section_data(s); render_markdown(data); render_html(data)
        except Exception as e:
            errs[f'section tech={tech} '+type(e).__name__+' '+str(e)[:80].replace('\n',' ')]+=1
print(errs)
