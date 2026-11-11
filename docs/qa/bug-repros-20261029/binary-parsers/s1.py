import sys
sys.path.insert(0,'tests')
from strings_pe import builtin_table
from patchtrace.strings.sources import SourceRow
from patchtrace.strings.table import StringTable
import hashlib
row=SourceRow(hashlib.sha256(b'x').digest(),'ABCDEFGH',8,'static','ASCII',0,None,None,None,None,None,'verified-bytes')
t=builtin_table('older','a'*64,[row])
blob=bytearray(t.to_bytes())
i=blob.index(b'ABCDEFGH'); 
blob[i]=0xff   # invalid UTF-8 in display pool
try: StringTable.from_bytes(bytes(blob))
except Exception as e: print(type(e).__mro__[:3], e)
# also truncated at every prefix
import collections
c=collections.Counter()
good=t.to_bytes()
for n in range(len(good)):
    try: StringTable.from_bytes(good[:n])
    except Exception as e: c[type(e).__name__]+=1
print(c)
