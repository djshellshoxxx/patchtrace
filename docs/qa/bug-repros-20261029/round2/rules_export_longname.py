"""export.write(): the file is created, then ExportRecord(basename=...) is validated; a name over 128 chars (or with a control char)
raises pydantic.ValidationError (untyped) AFTER the .yar is on disk and before the export row is stored."""
import sys, tempfile
sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from pathlib import Path
import rules_fixtures as rf
from rules_store_support import accepted, candidate_of
from patchtrace.rules import export
tmp = Path(tempfile.mkdtemp()); bench = rf.Bench(tmp)
cand = candidate_of(bench); _, version = accepted(cand)
plan = export.ExportPlan(text=version.rule_text, warnings=(), rule_name=cand.rule_name)
out = tmp / (('long-descriptive-name-' * 7) + '.yar')
print('name length', len(out.name))
try:
    export.write(plan, version, out)
except Exception as e:
    print('RAISED', type(e).__module__ + '.' + type(e).__name__)
print('file left on disk:', out.exists())
bench.close()
