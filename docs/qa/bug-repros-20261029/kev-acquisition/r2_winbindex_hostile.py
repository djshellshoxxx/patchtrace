import gzip, json
from patchtrace.acquisition import winbindex
SHA = 'a'*64
def gz(entry_extra=None, info_extra=None, windows=None, date='2024-01-01'):
    info = {'sha256': SHA, 'size': 1000, 'machineType': 34404, 'timestamp': 1, 'virtualSize': 4096}
    info.update(info_extra or {})
    e = {'fileInfo': info, 'windowsVersions': windows if windows is not None else {}}
    e.update(entry_extra or {})
    return gzip.compress(json.dumps({SHA: e}, ensure_ascii=True).encode())

def run(label, fn):
    try:
        print(label, '->', fn())
    except BaseException as ex:
        print(label, 'RAISED', type(ex).__name__, str(ex)[:100])

# 1 lone surrogate in any entry value (json \ud800 escape is accepted by json.loads)
data = gz(entry_extra={'x': '\ud800'})
run('parse lone surrogate', lambda: winbindex.parse(data, 'ntdll.dll', '2026-01-01').candidates[:1] and 'ok')
run('parse_rows lone surrogate', lambda: len(winbindex.parse_rows(data, 'ntdll.dll', '2026-01-01').rows))

# 2 version string with terminal escape; kb key with escape
esc = '\x1b]0;PWNED\x07\x1b[2J'
data = gz(info_extra={'version': esc}, windows={'22H2': {'KB5000001'+esc: {'updateInfo': {'releaseDate': '2024-01-01', 'releaseVersion': esc}}}})
r = winbindex.parse(data, 'ntdll.dll', '2026-01-01')
c = r.candidates[0]
print('version repr:', repr(c.version)); print('kb repr:', repr(c.kbs[0].kb), 'release_version', repr(c.kbs[0].release_version))

# 3 unicode digits / impossible dates
data = gz(windows={'22H2': {'KB5000001': {'updateInfo': {'releaseDate': '٢٠٢٤-٠١-٠١'}}},
                   '21H2': {'KB5000002': {'updateInfo': {'releaseDate': '2024-99-99'}}}})
r = winbindex.parse(data, 'ntdll.dll', '2026-01-01')
print('parse release_dates:', [(k.kb, k.release_date) for k in r.candidates[0].kbs])
rr = winbindex.parse_rows(data, 'ntdll.dll', '2026-01-01')
print('rows release_dates:', [(x.kb, x.release_date) for x in rr.rows])
# data_date itself
run('data_date unicode', lambda: winbindex.parse(data, 'ntdll.dll', '٢٠٢٤-٠١-٠١').candidates[0].source)
run('data_date 9999-99-99', lambda: winbindex.parse(data, 'ntdll.dll', '9999-99-99').candidates[0].source)
# heading with line separator
data = gz(windows={'22H2': {'KB5000001': {'updateInfo': {'heading': 'a b c', 'releaseDate': '2024-01-01'}}}})
rr = winbindex.parse_rows(data, 'ntdll.dll', '2026-01-01')
print('heading repr:', repr(rr.rows[0].heading))
