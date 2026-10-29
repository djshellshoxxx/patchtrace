import time, sys
from patchtrace.strings.scan import scan_bytes
ml=int(sys.argv[1]); L=ml-1; mb=int(sys.argv[2])
blk=(b'A'*L+b'\0')
data=blk*((mb<<20)//len(blk))
for name,d,kw in (('ascii runs just below min',data,{}),('wide runs just below min',(b'A\0'*L)+b'\xff' ,{})):
    if name.startswith('wide'): d=((b'A\0'*L)+b'\xff\xff')*((mb<<20)//(2*L+2))
    t=time.time(); r=scan_bytes(d,min_length=ml); print(name,'min_length=%d size=%dMB rows=%d: %.2fs'%(ml,len(d)>>20,len(r.rows),time.time()-t))
