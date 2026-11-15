import tempfile, pathlib
from patchtrace.nway import series
d = pathlib.Path(tempfile.mkdtemp())
p = d/'series.json'
p.write_text('['*100000 + ']'*100000)
try:
    series.load(p)
except Exception as e:
    print(type(e).__name__, str(e)[:100])
