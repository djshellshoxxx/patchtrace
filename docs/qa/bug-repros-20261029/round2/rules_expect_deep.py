import tempfile
from pathlib import Path
from patchtrace.rules import matrix
p = Path(tempfile.mkdtemp())/'e.json'
p.write_text('[' * 200000 + ']' * 200000)
try:
    matrix.read_expectations(p)
except Exception as e:
    print(type(e).__name__, str(e)[:80])
