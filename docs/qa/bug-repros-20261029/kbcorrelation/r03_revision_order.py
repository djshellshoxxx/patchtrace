import json
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.index import ReverseIndex
def mk(date, kb):
    return json.dumps({'dialect':'cvrf-json/0','document':{'release_id':'2099-Feb','current_release_date':date},
      'product_tree':[{'product_id':'A','name':'Windows 11 Version 24H2 for x64-based Systems'}],
      'vulnerabilities':[{'cve':'CVE-2099-0001','remediations':[{'type':2,'description':kb,'product_ids':['A']}]}]}).encode()
NOW='2099-03-01T00:00:00Z'
def active(d1, d2):
    ix = ReverseIndex()
    a = import_bytes(mk(d1,'KB1111'), now=NOW); b = import_bytes(mk(d2,'KB2222'), now=NOW)
    ix.add(a); ix.add(b)
    act = ix.active_ids()
    return 'KB1111(%s)'%d1 if a.doc_id in act else 'KB2222(%s)'%d2
# true order: second is newer in every pair
print('1) same instant ordering: 00:00:00Z (old) vs 00:00:00.5Z (newer by 0.5s) ->', active('2099-02-13T00:00:00Z','2099-02-13T00:00:00.5Z'), '(expected KB2222)')
print('2) 10:00+05:00 (=05:00Z, older) vs 08:00Z (newer) ->', active('2099-02-13T10:00:00+05:00','2099-02-13T08:00:00Z'), '(expected KB2222)')
try:
    import_bytes(mk('2099-13-45','KB1111'), now=NOW); print('3) invalid date 2099-13-45 accepted')
except Exception as e: print('3) invalid date ->', type(e).__name__)
try:
    import_bytes(mk('2099-02-13T25:61:61Z','KB1111'), now=NOW); print('4) 25:61:61 accepted')
except Exception as e: print('4)', type(e).__name__)
