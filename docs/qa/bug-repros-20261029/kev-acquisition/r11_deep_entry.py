import gzip, json
from patchtrace.acquisition import winbindex
SHA='a'*64
def doc(depth):
    nest = '1'
    for _ in range(depth): nest = '[' + nest + ']'
    info = '{"sha256":"%s","size":1000,"machineType":34404,"timestamp":1,"virtualSize":4096}' % SHA
    return gzip.compress(('{"%s":{"fileInfo":%s,"x":%s}}' % (SHA, info, nest)).encode())
for depth in (100, 900, 950, 970, 985, 995):
    for name, fn in (('parse', winbindex.parse), ('parse_rows', winbindex.parse_rows)):
        try: fn(doc(depth), 'ntdll.dll', '2026-01-01'); res='ok'
        except BaseException as e: res = f'{type(e).__name__}'
        print(depth, name, res)
