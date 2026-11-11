import gzip, io, os, zlib, resource, time
from patchtrace.acquisition import winbindex
# gzip bomb 300 MiB of zeros
c = zlib.compressobj(9, zlib.DEFLATED, 31)
buf = io.BytesIO(); z = b'\0'*(1<<20)
for _ in range(300): buf.write(c.compress(z))
buf.write(c.flush()); bomb = buf.getvalue()
t=time.time()
try: winbindex.decompress(bomb)
except Exception as e: print('bomb ->', type(e).__name__, e, 'compressed', len(bomb), 'secs %.1f'%(time.time()-t), 'maxrss MB', resource.getrusage(resource.RUSAGE_SELF).ru_maxrss//1024)
