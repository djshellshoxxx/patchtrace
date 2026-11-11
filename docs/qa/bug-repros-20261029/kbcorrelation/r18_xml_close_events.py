import sys
import xml.etree.ElementTree as ET
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.sources.cvrf import SourceError
NS='https://example.invalid/synthetic-cvrf/1'
def doc(pad):
    return (f'<?xml version="1.0" encoding="UTF-8"?><CvrfDoc xmlns="{NS}" ReleaseId="2099-Feb" Pad="{"x"*pad}">'
            '<Vulnerabilities/></CvrfDoc>').encode()
print('python', sys.version.split()[0], 'expat', '', __import__('pyexpat').EXPAT_VERSION)
for pad in (1000, 70000, 140000, 400000):
    try:
        d = import_bytes(doc(pad), now='2099-03-01T00:00:00Z'); r = 'accepted release=' + d.source.release_id
    except SourceError as e: r = f'{e.code}: {e.message[:70]}'
    print(f'root start tag with {pad:>6}-char extra attribute ->', r)
