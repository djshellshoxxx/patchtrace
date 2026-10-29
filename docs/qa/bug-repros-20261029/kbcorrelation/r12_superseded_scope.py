import json
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.sources.scope import files_scope, months_scope
def mk(date, kb):
    return json.dumps({'dialect':'cvrf-json/0','document':{'release_id':'2099-Feb','current_release_date':date},
      'product_tree':[{'product_id':'A','name':'Windows 11 Version 24H2 for x64-based Systems'}],
      'vulnerabilities':[{'cve':'CVE-2099-0001','remediations':[{'type':2,'description':kb,'product_ids':['A']}]}]}).encode()
NOW='2099-03-01T00:00:00Z'
old=import_bytes(mk('2099-02-01','KB1111'),now=NOW); new=import_bytes(mk('2099-02-13','KB2222'),now=NOW)
ix=ReverseIndex(); ix.add(old); ix.add(new)
r=ix.lookup_kb('KB1111', scope=files_scope([old.doc_id]), now=NOW)
print('provided_files=[old doc], KB1111 (present in that very file): status=%s exit=%d coverage=%s edges=%d superseded=%d' % (r.status, r.exit_code, r.coverage.state, len(r.edges), len(r.superseded)))
r=ix.lookup_kb('KB1111', scope=months_scope(['2099-Feb']), now=NOW)
print('months=[2099-Feb], KB1111: status=%s superseded=%d'%(r.status,len(r.superseded)))
