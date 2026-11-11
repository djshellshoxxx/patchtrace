from patchtrace.kbcorrelation.sources.csaf_bridge import kb_tokens_of
from patchtrace.kbcorrelation.sources import cvrf, scope
from patchtrace.kbcorrelation import ids
from patchtrace.kbcorrelation.products import clean_text
print('1 url trailing LF ->', kb_tokens_of({'url':'https://support.microsoft.com/help/1234\n'}))
print('1b url w/ bad loc ->', kb_tokens_of({'url':'https://support.microsoft.com/EN-US/help/1234'}), kb_tokens_of({'url':'https://support.microsoft.com/help/1234#x'}))
# Type 2 description with control / unicode separators
import json
def edges(desc):
    d={'dialect':'cvrf-json/0','document':{'release_id':'2099-Feb'},'product_tree':[{'product_id':'A','name':'Windows 11 Version 24H2 for x64-based Systems'}],
       'vulnerabilities':[{'cve':'CVE-2099-0001','remediations':[{'type':2,'description':desc,'product_ids':['A']}]}]}
    doc=cvrf.parse_cvrf(json.dumps(d).encode()); e=cvrf.build_edges(doc,'a'*64)
    return sorted({x.kb for x in e.edges}), [p.code for p in e.problems]
for label,desc in [('VT','KB5000001\x0bKB5000002'),('FS 0x1c','KB5000001\x1cKB5000002'),('U+2028','KB5000001 KB5000002'),('NEL','KB5000001\x85KB5000002'),('NBSP pad','KB5000001 '),('bare 4 digit year','2024'),('build 26100.9001','26100.9001'),('slash','KB5000001/KB5000002')]:
    print('2', label, edges(desc))
print('3 clean_text U+2028/zwsp:', repr(clean_text('a b​c⁦d')))
for t in ['2099-Feb\n','２０９９-Feb','2099-02 ','0000-Jan','9999-12']:
    try: print('4', repr(t), scope.parse_release(t))
    except Exception as e: print('4', repr(t), 'ERR', type(e).__name__)
for t in ['CVE-2099-0001\n','cve-2099-0001 ','CVE-２０９９-0001']:
    try: print('5', repr(t), ids.normalise_cve(t))
    except Exception as e: print('5', repr(t), 'ERR', type(e).__name__)
for t in ['KB1234\n','kb-1234','KB１２３４',' 1234','1234 ']:
    try: print('6', repr(t), ids.normalise_kb_edge(t))
    except Exception as e: print('6', repr(t), 'ERR', type(e).__name__)
