import tempfile, json, pathlib
from patchtrace.kbcorrelation.wiring import save_winbindex_record
SHA='a'*64
doc=('{"%s":{"fileInfo":{"sha256":"%s","size":1000,"machineType":34404,"timestamp":1,"virtualSize":4096},"note":"\\ud800"}}' % (SHA,SHA)).encode()
d=pathlib.Path(tempfile.mkdtemp()); (d/'rec.json').write_bytes(doc)
try: save_winbindex_record(d/'ws', d/'rec.json', 'ntdll.dll', '2026-01-01')
except BaseException as e: print('RAISED', type(e).__module__+'.'+type(e).__name__, str(e)[:80])
