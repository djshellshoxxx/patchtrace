from h import *
from patchtrace.pe_overview.exports_table import parse_export_entries
d,info=build_pe_ex(PeSpec(exports=('lib.dll',['a','b'])))
d=bytearray(d)
eoff=info['export_dir_off']
nameptrs_rva=struct.unpack_from('<I',d,eoff+32)[0]
# file offset of nameptrs: section rva->off
sec=[s for s in info['sections'] if s[0]=='.idata'][0]
off=sec[3]+(nameptrs_rva-sec[1])
struct.pack_into('<I',d,off,0)   # first name pointer -> RVA 0
ov,_=run(bytes(d))
print(ov.exports)
