from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.sources.cvrf import SourceError
NS='https://example.invalid/synthetic-cvrf/1'
big='<Vulnerability CVE="CVE-2099-0002" Title="' + 'y'*300_000 + '"/>'
for n in (2000, 200000, 2_000_000):
    deep='<Vulnerability CVE="CVE-2099-0001">' + '<n>'*n + '</n>'*n + '</Vulnerability>'
    raw=(f'<?xml version="1.0" encoding="UTF-8"?><CvrfDoc xmlns="{NS}" ReleaseId="2099-Feb"><Vulnerabilities>{big}{deep}</Vulnerabilities></CvrfDoc>').encode()
    try: import_bytes(raw, now='2099-03-01T00:00:00Z'); r='ACCEPTED'
    except SourceError as e: r=f'{e.code}: {e.message[:60]}'
    print(f'big token then {n} nested elements ->', r)
