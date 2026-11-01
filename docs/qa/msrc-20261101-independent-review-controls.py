"""Independent offline review of the native adapter; no production source changes."""
import copy
import hashlib
import io
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from patchtrace.kbcorrelation.limits import KbcLimits
from patchtrace.kbcorrelation.sources.cvrf import SourceError
from patchtrace.kbcorrelation.sources.importer import import_bytes

ROOT = Path('/workspace/scratch/142cb233d750')
FIX = ROOT / 'wt-msrc/tests/fixtures/kbcve/msrc'
CAP = ROOT / 'msrc-captures'
NOW = '2026-11-01T13:00:00Z'
name = '2024-Aug-CVE-2024-38193'
prov = json.loads((FIX / (name + '.provenance.json')).read_bytes())
fixture_raw = (FIX / (name + '.facts.json')).read_bytes()
fixture = json.loads(fixture_raw)
if not (hashlib.sha256(fixture_raw).hexdigest() == prov['fixture_sha256']):
    raise RuntimeError('independent evidence check failed at original line 20')

scalar_count = 0
def subset(a, b):
    global scalar_count
    if isinstance(a, dict):
        if not (isinstance(b, dict)):
            raise RuntimeError('independent evidence check failed at original line 26')
        for k, v in a.items():
            if not (k in b):
                raise RuntimeError(k)
            subset(v, b[k])
    elif isinstance(a, list):
        if not (isinstance(b, list) and len(a) == len(b)):
            raise RuntimeError('independent evidence check failed at original line 31')
        for x, y in zip(a, b, strict=True):
            subset(x, y)
    else:
        if not (type(a) is type(b) and a == b):
            raise RuntimeError((a, b))
        scalar_count += 1

raw2024 = (CAP / '2024-Aug.json').read_bytes()
actual = json.loads(raw2024)
projected = copy.deepcopy(actual)
projected['Vulnerability'] = [actual['Vulnerability'][i] for i in prov['upstream_index_maps']['Vulnerability']]
projected['ProductTree']['FullProductName'] = [actual['ProductTree']['FullProductName'][i]
    for i in prov['upstream_index_maps']['ProductTree/FullProductName']]
subset(fixture, projected)
print(json.dumps({'projection_exact_scalar_matches': scalar_count}))

xml_raw = (CAP / '2024-Aug.xml').read_bytes()
if not (hashlib.sha256(xml_raw).hexdigest() == prov['semantic_evidence']['paired_xml_capture']['sha256']):
    raise RuntimeError('independent evidence check failed at original line 48')
xml = ET.fromstring(xml_raw)
# Namespace identifiers are read from the hash-verified local capture, not fetched.
namespaces = dict(value for _, value in ET.iterparse(io.BytesIO(xml_raw), events=('start-ns',)))
ns = {'c': namespaces['cvrf'], 'v': namespaces['vuln']}
if not (xml.find('c:DocumentTracking/c:Status', ns).text == 'Final'):
    raise RuntimeError('independent evidence check failed at original line 51')
if not (actual['DocumentTracking']['Status'] == 2):
    raise RuntimeError('independent evidence check failed at original line 52')
jstatus = {(v['CVE'], p) for v in actual['Vulnerability'] for s in v.get('ProductStatuses', [])
           if s['Type'] == 3 for p in s.get('ProductID', [])}
xstatus = {(v.find('v:CVE', ns).text, p.text) for v in xml.findall('v:Vulnerability', ns)
           for s in v.findall('v:ProductStatuses/v:Status', ns) if s.attrib['Type'] == 'Known Affected'
           for p in s.findall('v:ProductID', ns)}
if not (jstatus == xstatus):
    raise RuntimeError('independent evidence check failed at original line 58')
print(json.dumps({'paired_xml_type3_memberships': len(jstatus), 'document_status2': 'Final'}))

def resolve(value, pointer):
    for token in pointer.split('/')[1:]:
        token = token.replace('~1', '/').replace('~0', '~')
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value

for release in ['2024-Aug', '2026-Oct']:
    raw = (CAP / (release + '.json')).read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    expected = prov['full_capture_checks'][release]
    if not (sha == expected['capture']['sha256']):
        raise RuntimeError('independent evidence check failed at original line 71')
    doc = import_bytes(raw, now=NOW)
    if not (doc.counts() == expected['counts']):
        raise RuntimeError('independent evidence check failed at original line 73')
    if not (doc.source.sha256 == sha and doc.source.authenticity == 'unverified-local-file'):
        raise RuntimeError('independent evidence check failed at original line 74')
    value = json.loads(raw)
    for e in doc.edges:
        rem = resolve(value, e.ref.pointer)
        if not (e.cve == value['Vulnerability'][int(e.ref.pointer.split('/')[2])]['CVE']):
            raise RuntimeError('independent evidence check failed at original line 78')
        if not (rem['Type'] == 2 and e.kb in {'KB'+line.strip() for line in rem['Description']['Value'].split('\n')}):
            raise RuntimeError('independent evidence check failed at original line 79')
        if not (e.product_status.value == 'Known Affected'):
            raise RuntimeError('independent evidence check failed at original line 80')
        if not (resolve(value, e.product_status.pointer) in rem['ProductID']):
            raise RuntimeError('independent evidence check failed at original line 81')
    for s in doc.statuses:
        resolve(value, s.pointer)
    for p in doc.problems:
        resolve(value, p.pointer)
    print(json.dumps({'release':release, 'sha256':sha, 'bytes':len(raw), 'counts':doc.counts(),
                      'all_edges_statuses_problems_resolved':True}))

def encoded(v):
    return json.dumps(v, ensure_ascii=True).encode()

def refused(value, limits):
    try:
        import_bytes(encoded(value), now=NOW, limits=limits)
    except SourceError as exc:
        if not (exc.code == 'PT-KBC-LIMIT'):
            raise RuntimeError(exc.code)
    else:
        raise AssertionError('limit was not enforced')

refused(fixture, KbcLimits(cvrf_doc_bytes=len(fixture_raw)//2))
refused(fixture, KbcLimits(cvrf_json_nodes=10))
refused(fixture, KbcLimits(cvrf_depth=2))
refused(fixture, KbcLimits(cvrf_edges_per_doc=1))
large=copy.deepcopy(fixture); large['unknown'] = 'x' * 1_048_577
refused(large, KbcLimits())
for kind in [-1, 0, 1, 2, 4, 5, 99, 10**1000]:
    hostile=copy.deepcopy(fixture)
    hostile['Vulnerability'][0]['ProductStatuses']=[{'Type':kind,'ProductID':
        [p['ProductID'] for p in hostile['ProductTree']['FullProductName']]}]
    doc=import_bytes(encoded(hostile), now=NOW)
    if not (not doc.edges and all(s.klass == 'unknown' for s in doc.statuses)):
        raise RuntimeError('independent evidence check failed at original line 111')
print(json.dumps({'independent_limit_controls':5, 'unknown_enum_controls':8, 'result':'pass'}))
