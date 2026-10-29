import sys, hashlib, time
sys.path.insert(0,'tests')
from strings_pe import builtin_table
from patchtrace.strings.sources import SourceRow
from patchtrace.strings.table import StringTable
from patchtrace.strings.delta import compute_delta
from patchtrace.intelligence.tools.normalize import FunctionPairing
N=int(sys.argv[1])
disp='%'+'0'*N
r=SourceRow(hashlib.sha256(b'x').digest(),disp,N+1,'static','ASCII',0,None,None,None,None,None,'verified-bytes')
older=builtin_table('older','a'*64,[]); 
newer=StringTable.from_bytes(builtin_table('newer','b'*64,[r]).to_bytes())   # round-trips through the hostile-sidecar parser
t=time.time()
try: compute_delta(older,newer,pairing=FunctionPairing.empty())
except Exception as e: print(type(e).__name__, str(e).splitlines()[0][:100])
print('N=%d %.2fs'%(N,time.time()-t))
