"""Read-only evidence check. No benchmark children or target execution."""
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import subprocess
from tools.unified import bench

root=Path('/workspace/scratch/142cb233d750/wt-bench')
qa=root/'docs/qa'
source='1f5f0b808149a30d222a35937667b36a5407bc0d'
evidence=json.loads((qa/'gt12-evidence-20261101.json').read_bytes())
if not (evidence['source_commit']==source):
    raise RuntimeError('independent evidence check failed at original line 13')
for name, wanted in evidence['files'].items():
    actual=hashlib.sha256((qa/name).read_bytes()).hexdigest()
    if not (actual==wanted):
        raise RuntimeError(name)
print(f'PASS: all {len(evidence["files"])} retained-file SHA-256 values match')

reports=[]
intervals=[]
for name, stage in [('facts','facts'),('read-model','read_model'),('ui-calls','ui_calls')]:
    raw=(qa/f'gt12-{name}-20261101.json').read_bytes()
    report=bench.load(raw)
    env=report.environment
    if not (env['source_commit']==source and env['source_tracked_dirty']==0):
        raise RuntimeError('independent evidence check failed at original line 25')
    if not (all(r.stage==stage and r.status=='measured' for r in report.rows)):
        raise RuntimeError('independent evidence check failed at original line 26')
    if not (all(r.counts['seed']==1 and r.counts['requested_insns']==50 for r in report.rows)):
        raise RuntimeError('independent evidence check failed at original line 27')
    if not (all(c.ok for r in report.rows for c in r.checks)):
        raise RuntimeError('independent evidence check failed at original line 28')
    if not (all(g.verdict=='pass' for r in report.rows for g in r.gates)):
        raise RuntimeError('independent evidence check failed at original line 29')
    inv=json.loads((qa/f'gt12-{name}-20261101.invocation.json').read_bytes())
    if not (inv['before']==inv['after']=={'commit':source,'dirty_tracked':[]}):
        raise RuntimeError('independent evidence check failed at original line 31')
    if not (inv['returncode']==0):
        raise RuntimeError('independent evidence check failed at original line 32')
    if not (inv['argv'][inv['argv'].index('--stages')+1]==stage):
        raise RuntimeError('independent evidence check failed at original line 33')
    original=Path(inv['argv'][inv['argv'].index('--out')+1])
    if not (original.read_bytes()==raw):
        raise RuntimeError('independent evidence check failed at original line 35')
    start=datetime.fromisoformat(inv['started_utc'])
    end=start+timedelta(seconds=inv['elapsed_seconds'])
    intervals.append((start,end))
    reports.append(report)
    print(f'PASS: {stage} report strict/digest valid, copied bytes unchanged, exact clean source, interval {start.isoformat()} to {end.isoformat()}')
if not (all(intervals[i][1] < intervals[i+1][0] for i in range(2))):
    raise RuntimeError('independent evidence check failed at original line 41')
print('PASS: three stage invocation intervals are serial')
rows=[r.model_dump(mode='json') for report in reports for r in report.rows]
combined=bench.load((qa/'gt12-combined-20261101.json').read_bytes())
rebuilt=bench.report(bench.evaluate(rows),reports[0].environment)
if not (rebuilt==combined):
    raise RuntimeError('independent evidence check failed at original line 46')
if not (combined.verdict=='pass' and not combined.pending):
    raise RuntimeError('independent evidence check failed at original line 47')
if not ({(r.stage,r.n) for r in combined.rows}=={
    ('facts',5000),('read_model',10000),('read_model',100000),('ui_calls',10000),('ui_calls',100000)}):
    raise RuntimeError('independent evidence check failed at original line 48')
print('PASS: combined report exactly equals fresh aggregation/re-evaluation of unchanged initial rows')
for row in combined.rows:
    if row.stage=='facts':
        if not (row.counts['pairs']==row.counts['machine_changed']==row.counts['with_deltas']==row.counts['nonbenign']==5000):
            raise RuntimeError('independent evidence check failed at original line 53')
        if not (row.counts['older_instructions']==row.counts['newer_instructions']==237000):
            raise RuntimeError('independent evidence check failed at original line 54')
        if not (row.counts['limited']==0):
            raise RuntimeError('independent evidence check failed at original line 55')
        if not (abs(row.seconds['context']+row.seconds['facts']-row.seconds['total'])<1e-9):
            raise RuntimeError('independent evidence check failed at original line 56')
    if row.stage in ('read_model','ui_calls'):
        if not (row.counts['rows']==row.counts['unique_rows']==row.counts['facts_records']==row.n):
            raise RuntimeError('independent evidence check failed at original line 58')
        if not (row.counts['populated_cells']==3*row.n):
            raise RuntimeError('independent evidence check failed at original line 59')
    if row.stage=='ui_calls':
        for op in ('first_paint','sort','filter'):
            if not (row.counts[op+'_data_calls']==504):
                raise RuntimeError('independent evidence check failed at original line 62')
            if not (row.counts[op+'_visible_cells']==72):
                raise RuntimeError('independent evidence check failed at original line 63')
            if not (row.counts[op+'_paints']==1):
                raise RuntimeError('independent evidence check failed at original line 64')
            if not (7*72*6//5+20==624):
                raise RuntimeError('independent evidence check failed at original line 65')
        if not (row.counts['filtered_rows']==row.n//10):
            raise RuntimeError('independent evidence check failed at original line 66')
        if row.n==100000:
            if not (row.seconds['sort']*1000>150):
                raise RuntimeError('independent evidence check failed at original line 68')
            if not (row.seconds['sort']*1000<=750):
                raise RuntimeError('independent evidence check failed at original line 69')
            if not (all(c.ok for c in row.checks if c.name.endswith('independent-of-n'))):
                raise RuntimeError('independent evidence check failed at original line 70')
print('PASS: exact counts/paint/selectivity/cross-size checks hold; 100k raw sort target miss and CI allowance pass both retained')
initial=bench.load((qa/'gt12-smoke-initial-20261101.json').read_bytes())
smoke=bench.load((qa/'gt12-smoke-4c8f9a6-20261101.json').read_bytes())
if not (initial.verdict=='fail'):
    raise RuntimeError('independent evidence check failed at original line 74')
if not (smoke.verdict=='insufficient-data' and len(smoke.pending)==3):
    raise RuntimeError('independent evidence check failed at original line 75')
print('PASS: failed initial smoke retained; later tiny smoke remains insufficient-data')
for p, expected in [('tools/unified/bench.py','24fadbe540794d0080cd4d46bedb187b37b320434534115f0b2a508b3037f623'),
                    ('tools/unified/bench_workloads.py','939f14cbd5a343644be1198f006a67715550e44a1bcc3b9edb9c0e2e53ccf227')]:
    if not (hashlib.sha256((root/p).read_bytes()).hexdigest()==expected):
        raise RuntimeError('independent evidence check failed at original line 79')
if not (not subprocess.check_output(['git','diff',source,'HEAD','--','tools/unified'],cwd=root)):
    raise RuntimeError('independent evidence check failed at original line 80')
print('PASS: evidence commits do not alter independently reviewed/measured harness bytes')
