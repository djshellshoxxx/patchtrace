from h import *
import random
from patchtrace.pe_overview.build_facts import collect_build_facts
from patchtrace.pe_overview.tables import PeTables, PeTableError
from collections import Counter
spec = PeSpec(imports={'KERNEL32.dll': ['CreateFileW', 7], 'USER32.dll': ['MessageBoxA']},
              exports=('lib.dll', ['zeta', 'alpha']), rsds=(bytes(range(16)), 3, 'C:\\build\\app.pdb'),
              overlay=b'TAIL' * 50, cert_payloads=[b'sig' * 10])
base, info = build_pe_ex(spec)
random.seed(int(sys.argv[1]))
seen=Counter(); worst=0
import pathlib
for it in range(int(sys.argv[2])):
    b = bytearray(base)
    for _ in range(random.randint(1,12)):
        mode=random.random()
        pos = random.randrange(0, min(len(b), 0x400)) if mode<0.8 else random.randrange(len(b))
        if random.random()<0.5: b[pos]=random.choice([0,0xff,0x80,0x7f,random.randrange(256)])
        else:
            n=random.choice([2,4]); 
            for k in range(n):
                if pos+k<len(b): b[pos+k]=random.choice([0xff,0,0x80])
    if random.random()<0.1: b = b[:random.randrange(len(b))]
    p=pathlib.Path('fz.bin'); p.write_bytes(bytes(b))
    try:
        with VerifiedArtifactReader.open_path(p) as r:
            t=time.time(); ov=inspect_pe(r); dt=time.time()-t
            worst=max(worst,dt)
            for w in ov.warnings:
                if w.code.startswith('internal_error'): seen[w.code+w.message]+=1; open('crash_%s.bin'%w.code,'wb').write(bytes(b))
            try: collect_build_facts(r, ov)
            except Exception as e: seen['bf '+type(e).__name__]+=1
            try:
                pt=PeTables(r, ov); pt.runtime_functions(); pt.relocations(); pt.import_slots()
            except PeTableError: pass
            except Exception as e: seen['tables '+type(e).__name__+str(e)[:40]]+=1; open('crash_tables.bin','wb').write(bytes(b))
    except Exception as e:
        seen['EXC '+type(e).__name__+str(e)[:50]]+=1; open('crash_exc.bin','wb').write(bytes(b))
print(seen, worst)
