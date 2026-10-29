import hashlib
from patchtrace.kbcorrelation.sources import scope
for n in (10, 1000, 100000):
    txt='\n'.join(hashlib.sha256(str(i).encode()).hexdigest() for i in range(n))
    try: s=scope.parse_scope_file(txt); print(n,'ok',s.kind,len(s.doc_ids))
    except Exception as e: print(n,'ERR',type(e).__name__, str(e)[:100].replace('\n',' '))
for txt in ('2099-Feb\n'+'a'*64, '2099-Feb\n2099-Feb', '2099-Jan,2099-Feb', 'A'*64):
    try: s=scope.parse_scope_file(txt); print(repr(txt[:30]),'ok',s.kind)
    except Exception as e: print(repr(txt[:30]),'ERR',type(e).__name__, str(e)[:80])
