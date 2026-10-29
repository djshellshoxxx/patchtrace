import sys, tempfile
from pathlib import Path
sys.path.insert(0, 'tests')
import test_kbc_recovery as t
from patchtrace.kbcorrelation.store import ProjectAttachment
tmp = Path(tempfile.mkdtemp())
ws, request = t.prepared(tmp)
with ws:
    port = t.adapter(tmp / 'project')
    orig = port.create_project
    def create(*a, **k):
        r = orig(*a, **k)
        (tmp / 'project' / 'kb').write_text('i am a file')   # makes sidecar mkdir fail with an OS error
        return r
    port.create_project = create
    try:
        r = ProjectAttachment(ws, port).attach(request)
        print('result', r.status, [i.code for i in r.issues])
    except Exception as e:
        print('ESCAPED', type(e).__name__, '- project exists, journal state:', [(o, s) for o, s, _ in ws.journal_ops()])
