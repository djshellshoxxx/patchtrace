import sys, struct, time, tempfile, os
sys.path.insert(0, 'tests')
from pe_builder import *
from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import inspect_pe
def run(data, **kw):
    p = tempfile.mktemp()
    open(p,'wb').write(data)
    try:
        with VerifiedArtifactReader.open_path(__import__('pathlib').Path(p)) as r:
            t=time.time(); ov = inspect_pe(r, **kw); return ov, time.time()-t
    finally: os.unlink(p)
