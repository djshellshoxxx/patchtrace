# Retry-After HTTP-date with absurd year -> uncaught exception type?
from datetime import UTC, datetime
import email.utils
from patchtrace.kev import transport as kt
from patchtrace.acquisition import transport as at
now = datetime(2026,10,29,tzinfo=UTC)
for label, fn in (('kev', kt._retry_after), ('acq', at._retry_after)):
    for v in ('Wed, 21 Oct 99999999999999999999 07:28:00 GMT', 'Wed, 21 Oct 0001 07:28:00 GMT',
              'Wed, 21 Oct 9999 23:59:59 GMT', 'Wed, 21 Oct 2026 07:28:00 +99999'):
        try:
            print(label, repr(v), '->', fn(v, now))
        except BaseException as e:
            print(label, repr(v), 'RAISED', type(e).__name__, e)
