import json, traceback
from patchtrace.kbcorrelation.sources import cvrf
def doc(vuln, products=None):
    return json.dumps({'dialect':'cvrf-json/0','document':{'release_id':'2099-Feb'},
      'product_tree': products if products is not None else [{'product_id':'P1','name':'Windows 11 Version 24H2 for x64-based Systems'}],
      'vulnerabilities':[vuln]}).encode()
cases = {
 'remediations=5': {'cve':'CVE-2099-0001','remediations':5},
 'remediations=true': {'cve':'CVE-2099-0001','remediations':True},
 'remediations=3.5': {'cve':'CVE-2099-0001','remediations':3.5},
 'remediations="abc"': {'cve':'CVE-2099-0001','remediations':'abc'},
 'remediations={}': {'cve':'CVE-2099-0001','remediations':{'a':1}},
 'cwe=str': {'cve':'CVE-2099-0001','cwe':'CWE-1'},
 'rem.fixed_build=[1]': {'cve':'CVE-2099-0001','remediations':[{'type':2,'description':'KB1234','product_ids':['P1'],'fixed_build':[1]}]},
 'rem.supersedes=str': {'cve':'CVE-2099-0001','remediations':[{'type':2,'description':'KB1234','product_ids':['P1'],'supersedes':'KB1111'}]},
 'rem.type=huge': {'cve':'CVE-2099-0001','remediations':[{'type':10**300,'description':'KB1234','product_ids':['P1']}]},
 'sub_type=obj': {'cve':'CVE-2099-0001','remediations':[{'type':2,'description':'KB1234','product_ids':['P1'],'sub_type':{}}]},
}
for name, v in cases.items():
    try:
        d = cvrf.parse_cvrf(doc(v))
        e = cvrf.build_edges(d, 'a'*64)
        print('OK  ', name, len(e.edges), [p.code for p in e.problems])
    except cvrf.SourceError as x:
        print('SRCERR', name, x.code)
    except Exception as x:
        print('CRASH', name, type(x).__name__, str(x)[:80])
