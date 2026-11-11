from h import *
from patchtrace.pe_overview.tables import PeTables, PeTableError
import pathlib, resource
# Exception dir 20MB backed -> read_too_large?
big = SectionSpec('.pdata', b'\0'*(20*1024*1024), RDATA)
d,info = build_pe_ex(PeSpec(sections=[SectionSpec(), big], extra_directories={3:(0x2000, 20*1024*1024)}))
p=pathlib.Path('t1.bin'); p.write_bytes(d)
with VerifiedArtifactReader.open_path(p) as r:
    t=PeTables.open(r)
    try: print(len(t.runtime_functions()))
    except Exception as e: print('EXC', type(e).__name__, e)
