from enr_h import *
s, svc = make()
# one relative-space function with a 64-bit address >= 2**63 (parse_address accepts < 2**64)
f = svc.project.matches[1].newer[0]
f.address = 'ffffffffffffff00'; f.address_space = 'relative'
r = search(s, 'ClfsReadBlock')
print([(e.group, e.status, e.reason) for e in r.coverage if e.group=='fn'])
print(r.status, [h.evidence[0].title for h in r.hits])
