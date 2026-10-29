import time
from patchtrace.pe_overview.manifest import observe_manifest
from patchtrace.pe_overview.resources import ResourceLeaf
leaf=ResourceLeaf(24,'RT_MANIFEST',1,0x409,0,0,0,0)
NS='xmlns="urn:schemas-microsoft-com:asm.v1"'
for n in (290000,):
  v='<assembly %s>'%NS + '<a>'*n + '</a>'*n + '</assembly>'
  t=time.time(); o=observe_manifest(leaf,v.encode()); print(len(v),o.warnings,o.identity,'%.2f'%(time.time()-t))
# many small files 
v='<assembly %s>'%NS + '<file name="x"/>'*130000 + '</assembly>'
t=time.time(); o=observe_manifest(leaf,v.encode()); print(len(v),o.warnings,len(o.files),'%.2f'%(time.time()-t))
# utf-16 'strict' with BOM + odd-length
print(observe_manifest(leaf,b'\xff\xfe<\0a\0').warnings)
print(observe_manifest(leaf,b'\xff\xfe<\0a\0>').warnings)
print(observe_manifest(leaf,b'<assembly \xef\xbb\xbf/>').warnings)
print(observe_manifest(leaf,b'').warnings, observe_manifest(leaf,b'\0'*10).warnings)
