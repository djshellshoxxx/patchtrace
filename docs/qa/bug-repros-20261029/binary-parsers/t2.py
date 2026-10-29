from h import *
from patchtrace.pe_overview.tables import PeTables
import pathlib, resource
N=int(sys.argv[1])  # entries
# one block with N entries (block size field is u32) 
body = struct.pack('<II', 0x1000, 8+2*N) + struct.pack('<H', 0x3000)*N
d,info = build_pe_ex(PeSpec(sections=[SectionSpec(), SectionSpec('.reloc', body, RDATA)], extra_directories={5:(0x2000, len(body))}))
p=pathlib.Path('t2.bin'); p.write_bytes(d)
with VerifiedArtifactReader.open_path(p) as r:
    t=PeTables.open(r)
    t0=time.time()
    try: rv=t.relocations(); print('ok',len(rv[0]))
    except Exception as e: print('EXC', type(e).__name__, e)
    print('t=%.1fs maxrss=%dMB'%(time.time()-t0, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss//1024))
