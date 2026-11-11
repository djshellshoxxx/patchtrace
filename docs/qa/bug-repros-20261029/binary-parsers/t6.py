from h import *
d,info=build_pe_ex(PeSpec(imports={'KERNEL32.dll':['CreateFileW']}))
d=bytearray(d); off=info['import_desc_off']
struct.pack_into('<I',d,off+12,0)   # Name RVA = 0
ov,_=run(bytes(d)); print([ (x.name,x.functions) for x in ov.imports.dlls], [w.code for w in ov.warnings])
