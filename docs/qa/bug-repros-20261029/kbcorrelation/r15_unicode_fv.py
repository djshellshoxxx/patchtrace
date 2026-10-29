from patchtrace.kbcorrelation.lineage import index_rows
from patchtrace.kbcorrelation.resolver import resolve
from patchtrace.kbcorrelation.products import scope_for
row = lambda kb, sha, d, ubr, fv: {'sha256': sha*64, 'kb': kb, 'version_key':'11-24H2', 'release_date': d, 'release_version': ubr, 'file_version': fv,
   'heading':'h','heading_class':'standard','variant':'full','download':'direct','record_sha256':'c'*64,'size':1,'machine_type':0x8664}
rows=[row('KB5000001','a','2099-01-01','26100.1','10.0.26100.1'), row('KB5000002','b','2099-02-01','26100.2','١٠.٠.٢٦١٠٠.٢')]
scope = scope_for('a'*64,'P','Windows 11 Version 24H2 for x64-based Systems')
r, rejected = index_rows(rows, file_name='ntdll.dll')
print('accepted', len(r), 'rejected', rejected, [x.file_version for x in r])
try: resolve(r, kb='KB5000002', scope=scope, file_name='ntdll.dll'); print('ok')
except Exception as e: print('CRASH', type(e).__name__)
