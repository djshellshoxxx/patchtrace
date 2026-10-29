import time
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.sources.cvrf import SourceError
NOW='2099-03-01T00:00:00Z'
def t(label, raw):
    s=time.time()
    try: import_bytes(raw, now=NOW); r='accepted'
    except SourceError as e: r=f'{e.code} {e.message[:60]}'
    except BaseException as e: r=f'UNHANDLED {type(e).__name__}: {str(e)[:60]}'
    print(f'{label:34s} {r} ({time.time()-s:.2f}s)')
t('json depth 200000', b'{"a":'+b'['*200000+b']'*200000+b'}')
t('json nan', b'{"dialect":NaN}')
t('json 1e999', b'{"dialect":1e999}')
t('json -Infinity', b'{"dialect":-Infinity}')
t('json huge int', b'{"dialect":'+b'9'*5000+b'}')
t('json dup key', b'{"dialect":1,"dialect":2}')
t('json lone surrogate key', b'{"\\ud800":1}')
t('json trailing garbage', b'{"a":1} x')
t('json empty', b'{}')
t('whitespace only', b'   ')
t('xml depth', b'<a>'*100000)
t('xml 2M empty elems', b'<a>'+b'<b/>'*2_000_000+b'</a>')
t('xml billion laughs', b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "x">]><l>&a;</l>')
t('xml ent in comment', b'<!-- <!ENTITY --><a/>')
t('xml many attrs', b'<a '+b' '.join(b'a%d="1"'%i for i in range(200000))+b'/>')
import gzip
t('gzip of gzip', gzip.compress(gzip.compress(b'{}')))
t('gzip bomb 100MiB', gzip.compress(b'0'*(100*1024*1024), 1))
