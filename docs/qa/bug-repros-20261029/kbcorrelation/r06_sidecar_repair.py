import sys, tempfile
from pathlib import Path
sys.path.insert(0, 'tests')
import test_kbc_recovery as t
from patchtrace.kbcorrelation.limits import KbcLimits
from patchtrace.kbcorrelation.recovery import repair
from patchtrace.kbcorrelation.store import ProjectAttachment
tmp = Path(tempfile.mkdtemp())
ws, request = t.prepared(tmp, limits=KbcLimits(project_sources_bytes=1))   # sidecar budget too small
with ws:
    port = t.adapter(tmp / 'project')
    r = ProjectAttachment(ws, port).attach(request)
    print('attach  :', r.status, [i.code for i in r.issues], r.value.state)
    src = tmp / 'project' / 'kb' / 'sources'
    print('sources after failed attach:', list(src.glob('*')) if src.exists() else 'dir missing')
    # operator frees budget and repairs with a rebuilt context
    ws.limits = KbcLimits()
    rep = repair(ws, port, context_for=lambda op, body: ((t.CONTEXT_KEY, t.CONTEXT_BODY.encode()),))
    print('repair  :', rep.status, rep.value[0].state, [i.code for i in rep.issues])
    print('sources after repair says attached:', list(src.glob('*')) if src.exists() else 'dir missing')
