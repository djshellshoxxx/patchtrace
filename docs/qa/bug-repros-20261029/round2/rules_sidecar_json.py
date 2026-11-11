import sys, tempfile, hashlib, json
sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from pathlib import Path
import rules_fixtures as rf
from rules_store_support import accepted, candidate_of, rule_store
from test_rules_store import a_run
from patchtrace.rules import store
tmp = Path(tempfile.mkdtemp())
bench = rf.Bench(tmp)
cand = candidate_of(bench)
rules = rule_store(tmp)
_, version = accepted(cand)
run = a_run(version)
store.INLINE_LIMIT = 10
rules.add_test(run, cand.source)
(side,) = (tmp/'project'/'rules'/'tests').glob('*.json')
bad = b'not json {'
side.write_bytes(bad)
# attacker also fixes the hash recorded in the row
row = rules.enrichment.store.connection.execute("select id, body from enrichment_entries where kind='rule-test'").fetchone()
body = json.loads(row[1]); body['sidecar_sha256'] = hashlib.sha256(bad).hexdigest()
text = json.dumps(body, sort_keys=True, separators=(',',':'))
rules.enrichment.store.connection.execute('UPDATE enrichment_entries SET body=?, body_sha256=? WHERE id=?', (text, hashlib.sha256(text.encode()).hexdigest(), row[0]))
try:
    print(rules.tests(), rules.skipped)
except Exception as e:
    print('RAISED', type(e).__name__, e)
bench.close()
