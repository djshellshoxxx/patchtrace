"""Two decisions in the same second: the one 'in force' is chosen by hash order, not by which came last."""
import sys, tempfile
sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from pathlib import Path
import rules_fixtures as rf
from rules_store_support import candidate_of, rule_store
from patchtrace.rules import store
tmp = Path(tempfile.mkdtemp()); bench = rf.Bench(tmp); cand = candidate_of(bench)
T = '2026-10-14T09:00:00+00:00'
for order in (('accept', 'reject'), ('reject', 'accept')):
    r = rule_store(Path(tempfile.mkdtemp()))
    r.add_candidate(cand)
    for act in order:
        d = store.decision_for(cand, act, T, label='L' if act == 'accept' else None)
        r.add_decision(d, cand.source)
    print('issued', order, '-> in force:', r.decisions(cand.candidate_id)[-1].action, '| pending accepts:', len(r.pending_accepts()))
bench.close()
