from enr_h import *
import base64, json
s, svc = make()
for body in [b'{"o": 1e999}', b'{"o": Infinity}']:
    cur = base64.urlsafe_b64encode(body).decode().rstrip('=')
    try:
        r = search(s, 'container', cursor=cur); print('OK', r.status)
    except Exception as e:
        print(body, 'RAISED', type(e).__name__, e)
