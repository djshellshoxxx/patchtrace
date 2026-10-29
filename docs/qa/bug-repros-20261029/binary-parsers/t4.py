from h import *
import pefile, random
from patchtrace.pe_overview import Limits
random.seed(5)
bad=0
for i in range(60):
    pad=random.choice([0,1,3,5,100,70001,1048576*2+7])
    d=bytearray(build_pe(PeSpec(overlay=random.randbytes(pad), checksum=random.randrange(1<<32))))
    for lim in (Limits(), Limits(chunk=4096), Limits(chunk=4097)):
        ov,_=run(bytes(d), limits=lim)
        pe=pefile.PE(data=bytes(d),fast_load=True)
        want=pe.generate_checksum()
        if ov.checksum.computed!=want: bad+=1; print('MISMATCH',pad,lim.chunk,hex(ov.checksum.computed),hex(want))
print('bad',bad)
