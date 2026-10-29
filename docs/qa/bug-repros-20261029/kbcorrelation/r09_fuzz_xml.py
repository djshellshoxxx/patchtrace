import random, traceback, collections
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.sources.cvrf import SourceError
NS='https://example.invalid/synthetic-cvrf/1'
base=f'''<?xml version="1.0" encoding="UTF-8"?>
<CvrfDoc xmlns="{NS}" ReleaseId="2099-Feb" CurrentReleaseDate="2099-02-13">
<DocumentTracking Identification="PT-1"/>
<ProductTree><FullProductName ProductID="A" Family="windows-client" Architecture="amd64">Windows 11 Version 24H2 for x64-based Systems</FullProductName>
<FullProductName ProductID="B">Other</FullProductName></ProductTree>
<Vulnerabilities>
<Vulnerability CVE="CVE-2099-0001" Title="t"><CWE ID="CWE-125"/>
<Remediations><Remediation Type="2" FixedBuild="26100.9001" Supersedes="KB1234 KB5555" SubType="x"><Description>KB5000001
KB5000002</Description><ProductID>A</ProductID><ProductID>B</ProductID></Remediation>
<Remediation Type="5"><Description>see KB7777 known</Description><ProductID>A</ProductID></Remediation></Remediations>
<ProductStatuses><ProductStatus Type="Fixed"><ProductID>A</ProductID></ProductStatus><ProductStatus Type="Not affected"><ProductID>B</ProductID></ProductStatus></ProductStatuses>
</Vulnerability></Vulnerabilities></CvrfDoc>'''
print(import_bytes(base.encode(), now='2099-03-01T00:00:00Z').counts())
toks=['<','>','/','"',' ','&amp;','&#x0;','&#65;','<![CDATA[x]]>','<!--c-->','\x00','é','‮','Type="x"','Type="-1"','Type="٢"','CVE=""','ProductID="A"','<Remediation/>','<Vulnerability/>','</Vulnerability>','<?pi x?>','xmlns:a="u"','<a:b/>']
random.seed(2); seen=collections.Counter(); ex={}
for n in range(8000):
    s=base
    for _ in range(random.choice([1,2,3])):
        i=random.randrange(len(s)); op=random.random()
        if op<.4: s=s[:i]+random.choice(toks)+s[i:]
        elif op<.7: j=min(len(s),i+random.randrange(1,30)); s=s[:i]+s[j:]
        else: j=random.randrange(len(s)); k=min(len(s),j+random.randrange(5,80)); s=s[:i]+s[j:k]+s[i:]
    try: raw=s.encode('utf-8')
    except Exception: continue
    try: import_bytes(raw, now='2099-03-01T00:00:00Z')
    except SourceError: pass
    except Exception as e:
        tb=traceback.extract_tb(e.__traceback__)[-1]
        key=(type(e).__name__, tb.filename.split('/')[-1], tb.lineno); seen[key]+=1; ex.setdefault(key,(str(e)[:100], s))
for k,c in seen.items(): print(c,k,ex[k][0])
print('crashes', sum(seen.values()))
