import tempfile, os
from pathlib import Path
from patchtrace.kbcorrelation.service import KbService, SCOPE_FILE_BYTES
from patchtrace.kbcorrelation.index import ReverseIndex
svc = KbService.__new__(KbService); ix = ReverseIndex()
tmp = Path(tempfile.mkdtemp())
def t(label, text):
    p = tmp/'s.json'; p.write_bytes(text if isinstance(text, bytes) else text.encode())
    try: s = svc._scope(ix, None, p); r = f'ok {s.kind if s else None} months={getattr(s,"months",None)} ids={len(getattr(s,"doc_ids",()))}'
    except Exception as e: r = f'{type(e).__name__}: {str(e)[:70]}'
    print(f'{label:36s} {r}')
print('SCOPE_FILE_BYTES', SCOPE_FILE_BYTES)
t('months has nested list', '{"months": [["x"]]}')
t('months mixes str and int', '{"months": ["2099-Feb", 5]}')
t('doc_ids has nested list', '{"doc_ids": [["x"]]}')
t('doc_ids mixes str/int', '{"doc_ids": ["%s", 5]}' % ('a'*64))
t('months is a string', '{"months": "2099-Feb"}')
t('duplicate key (last wins?)', '{"months": ["2099-Jan"], "months": ["2099-Feb"]}')
t('NaN accepted?', '{"months": ["2099-Feb"], "x": NaN}')
t('invalid utf8 replaced?', b'{"months": ["2099-Feb"], "x": "\xff"}')
t('deep nesting', '[' * (SCOPE_FILE_BYTES - 10))
t('deep nesting in object', '{"x":' + '[' * 100000 + '}')
