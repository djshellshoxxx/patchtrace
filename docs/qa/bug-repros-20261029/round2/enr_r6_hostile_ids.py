from enr_h import *
import copy
for label, newid in [('space', 'f new 1'), ('unicode', 'f-é'), ('trailing-newline', 'abc\n')]:
    s, svc = make()
    m = svc.project.matches[1]   # m-f2 ClfsCopyRecordHeader
    m.newer[0].id = newid
    try:
        r = search(s, 'ClfsCopyRecordHeader')
        print(label, 'OK', r.status, len(r.hits))
    except Exception as e:
        print(label, 'RAISED', type(e).__name__, str(e).splitlines()[0][:100])
# match id
s, svc = make(); svc.project.matches[1].id = 'm f2'
try: r = search(s,'ClfsCopyRecordHeader'); print('match id space OK', r.status)
except Exception as e: print('match id space RAISED', type(e).__name__, str(e).splitlines()[0][:100])
