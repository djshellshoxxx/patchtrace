from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.sources.cvrf import SourceError
NS='https://example.invalid/synthetic-cvrf/1'
def doc(pad, body):
    return (f'<?xml version="1.0" encoding="UTF-8"?><CvrfDoc xmlns="{NS}" ReleaseId="2099-Feb" Pad="{"x"*pad}">'
            f'<Vulnerabilities>{body}</Vulnerabilities></CvrfDoc>').encode()
deep = '<Vulnerability CVE="CVE-2099-0001">' + '<n>'*2000 + '</n>'*2000 + '</Vulnerability>'
longtext = '<Vulnerability CVE="CVE-2099-0002" Title="' + 'y'*2_000_000 + '"/>'
for label, pad, body in (('depth 2000 (limit 64), small pad', 100, deep), ('depth 2000, 300k pad before it', 300000, deep),
                         ('2 MB attribute (limit 1 MiB), small pad', 100, longtext), ('2 MB attribute, 300k pad before it', 300000, longtext)):
    try:
        d = import_bytes(doc(pad, body), now='2099-03-01T00:00:00Z'); r = 'ACCEPTED'
    except SourceError as e: r = f'{e.code}: {e.message[:60]}'
    print(f'{label:44s} -> {r}')
