import sys, hashlib, time
sys.path.insert(0,'tests')
from strings_pe import builtin_table
from patchtrace.strings.sources import SourceRow
from patchtrace.strings.links import _link_xrefs, GhidriffStrings, GhidriffString, SideFunctions
from patchtrace.intelligence.tools.normalize import FunctionPairing
N=int(sys.argv[1]); E=int(sys.argv[2]); big=int(sys.argv[3])
def row(i,length,rva):
    v=('s%d'%i).encode(); return SourceRow(hashlib.sha256(v).digest(),'s%d'%i,length,'static','ASCII',rva,rva,None,None,None,None,'verified-bytes')
rows=[row(i,6,0x10000+8*i) for i in range(N)]
if big: rows.append(row(N,1_000_000,0x10000-1_000_000+0 if False else 0x1000))   # one 1 MB run (max_run)
t=builtin_table('older','a'*64,rows)
sf=SideFunctions('older',(),{},{})
gs=GhidriffStrings(tuple(GhidriffString('older',0x10000+8*((i*97)%N)+3,('f',)) for i in range(E)),'x')   # rva inside a string, not at its start
t0=time.time()
_link_xrefs('older',t,sf,FunctionPairing.empty(),gs,'g',{})
print('N=%d E=%d big=%d: %.2fs'%(N,E,big,time.time()-t0))
from patchtrace.strings.links import _join_row
located=sorted(((r.rva,r.length,r) for r in t if r.rva!=0xFFFFFFFF),key=lambda x:x[:2]); starts=[x[0] for x in located]; widest=max(x[1] for x in located)
print(widest, len(located), _join_row(0x10000+8*5000+3, located, starts, widest)[1])
t0=time.time()
for k in range(200): _join_row(0x10000+8*19999+3, located, starts, widest)
print('200 lookups at end: %.3f'%(time.time()-t0))
print(len(gs.entries), set(e.side for e in gs.entries))
