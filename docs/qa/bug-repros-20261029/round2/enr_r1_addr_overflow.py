from enr_h import *
s, svc = make()
for q in ['0xffffffffffffffff', '18446744073709551615', '0x8000000000000000']:
    try:
        r = search(s, q); print(q, 'OK', r.status)
    except Exception as e:
        print(q, 'RAISED', type(e).__mro__[:2], e)
