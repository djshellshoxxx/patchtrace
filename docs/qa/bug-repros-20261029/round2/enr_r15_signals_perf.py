import sys, time, signal
sys.path[:0] = [__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from patchtrace.models import FunctionMatch, FunctionRecord
from patchtrace.enrichment.views import match_view
from patchtrace.enrichment import signals
def view(old, new):
    rec = lambda side, code: FunctionRecord(artifact_id=side, run_id='r', name='f', code=code)
    m = FunctionMatch(run_id='r', category='modified', older=[rec('a-old', old)], newer=[rec('a-new', new)])
    return match_view(m, '0'*64, {'older':'a-old','newer':'a-new'})
class TO(Exception): pass
def alarm(*_): raise TO
signal.signal(signal.SIGALRM, alarm)
def timed(label, old, new, limit=60):
    v = view(old, new); signal.alarm(limit); t=time.time()
    try:
        signals.detect(v); print(f'{label}: {time.time()-t:.1f}s', flush=True)
    except TO: print(f'{label}: >{limit}s TIMEOUT (killed)', flush=True)
    finally: signal.alarm(0)
base = 'int f(int a) {\n  return a;\n}'
for n in (5_000, 10_000, 20_000):
    timed(f'cmp-unbalanced-paren n={n} ({n*3} chars)', base, 'int f(int a) {\n  x = ' + 'a<(' * n + ';\n  return a;\n}', 120)
for n in (10_000, 20_000, 40_000):
    timed(f'nested-call n={n} ({n*2} chars)', base, 'int f(int a) {\n  x = ' + 'f(' * n + ';\n  return a;\n}', 120)
