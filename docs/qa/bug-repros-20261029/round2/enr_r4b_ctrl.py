from enr_h import *
s, svc = make()
r = search(s, 'ClfsReadBlock')
print(r.status, [h.evidence[0].title for h in r.hits])
f = svc.project.matches[1].newer[0]
f.address = 'ffffffffffffff00'; f.address_space = 'relative'
s2,_ = make(); s2.service.project.matches[1].newer[0].address='ffffffffffffff00'; s2.service.project.matches[1].newer[0].address_space='relative'
rep = s2.build()
print([(e.group,e.status,e.reason) for e in rep.coverage if e.group=='fn'])
