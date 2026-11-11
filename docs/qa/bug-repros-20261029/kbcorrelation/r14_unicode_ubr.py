from patchtrace.kbcorrelation.lineage import index_rows
from patchtrace.kbcorrelation.resolver import resolve
from patchtrace.kbcorrelation.products import scope_for
row = lambda kb, sha, d, ubr: {'sha256': sha*64, 'kb': kb, 'version_key':'11-24H2', 'release_date': d, 'release_version': ubr,
   'heading':'h','heading_class':'standard','variant':'full','download':'direct','record_sha256':'c'*64,'size':1,'machine_type':0x8664}
rows=[row('KB5000001','a','2099-01-01','26100.1'), row('KB5000002','b','2099-02-01','٢٦١٠٠.٢')]   # Arabic-Indic digits in release_version
scope = scope_for('a'*64,'P','Windows 11 Version 24H2 for x64-based Systems')
r, rejected = index_rows(rows, file_name='ntdll.dll')
print('rows accepted:', len(r), 'rejected:', rejected, [x.build.release_version for x in r])
try:
    res = resolve(r, kb='KB5000002', scope=scope, file_name='ntdll.dll')
    print(res.pairs)
except Exception as e:
    print('CRASH', type(e).__name__, str(e).splitlines()[:3])
# also date with unicode digits
rows2=[row('KB5000001','a','2099-01-01','26100.1'), row('KB5000002','b','٢٠٩٩-٠٢-٠١','26100.2')]
r2, rej2 = index_rows(rows2, file_name='ntdll.dll'); print('unicode date: rows', len(r2), 'rejected', rej2, [x.build.release_date for x in r2])
