from enr_h import *
for label, addr, space in [('negative relative', '-10', 'relative'), ('negative virtual', '-10', 'virtual')]:
    s, svc = make()
    f = svc.project.matches[1].newer[0]
    f.address = addr; f.address_space = space
    try:
        r = search(s, 'ClfsCopyRecordHeader'); print(label, 'OK', r.status, len(r.hits))
    except Exception as e:
        print(label, 'RAISED', type(e).__name__, str(e).splitlines()[0][:90], '|', str(e).splitlines()[1][:60] if len(str(e).splitlines())>1 else '')
