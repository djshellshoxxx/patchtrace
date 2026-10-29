import json
from patchtrace.kbcorrelation.sources import cvrf
NAME='Windows 11 Version 24H2 for x64-based Systems'
def run(order):
    d = {'dialect':'cvrf-json/0','document':{'release_id':'2099-Feb'},
     'product_tree':[{'product_id':'A','name':NAME},{'product_id':'B','name':NAME}],
     'vulnerabilities':[{'cve':'CVE-2099-0001',
        'product_statuses':{'Not affected':['A'],'Fixed':['B']},
        'remediations':[{'type':2,'description':'KB5000001','product_ids':order}]}]}
    doc = cvrf.parse_cvrf(json.dumps(d).encode())
    e = cvrf.build_edges(doc, 'a'*64)
    print(order, 'scopes:', len(e.scopes), 'distinct scope ids:', len({s.scope_id for s in e.scopes}),
          [(x.relation, x.product_status.value) for x in e.edges])
run(['A','B']); run(['B','A'])
