import random, struct, time, sys
from collections import Counter
from patchtrace.pe_overview.version_info import _Parser
from patchtrace.pe_overview.resources import DEFAULT_RESOURCE_LIMITS as L
from patchtrace.pe_overview.rich_header import parse_rich_header, DANS
def node(key, value=b'', typ=0, children=b'', vlen=None):
    k=(key+'\0').encode('utf-16-le')
    hdr=6+len(k); pad=(-hdr)%4
    body=struct.pack('<HHH',0,len(value) if vlen is None else vlen,typ)+k+b'\0'*pad+value
    body+=b'\0'*((-len(body))%4)+children
    return struct.pack('<H',len(body)+0)[:2]+body[2:] if False else struct.pack('<H',len(body))+body[2:]
fixed=struct.pack('<13I',0xFEEF04BD,0x10000,1<<16|2,3<<16|4,1<<16|2,3<<16|4,0x3f,0,4,1,0,0,0)
st=node('StringTable',children=node('FileVersion',('1.2.3.4\0').encode('utf-16-le'),1,vlen=8)+node('X',('abc\0').encode('utf-16-le'),1),) 
st=node('040904B0',children=node('FileVersion',('1.2.3.4\0').encode('utf-16-le'),1,vlen=8))
sfi=node('StringFileInfo',children=st)
vfi=node('VarFileInfo',children=node('Translation',struct.pack('<HH',0x409,0x4b0)))
seed=node('VS_VERSION_INFO',fixed,0,sfi+vfi)
p=_Parser(seed,False,L); print(p.run(),p.fixed is not None,p.strings,p.translations,p.warnings)
random.seed(int(sys.argv[1])); seen=Counter(); worst=0
for i in range(int(sys.argv[2])):
    b=bytearray(seed)
    for _ in range(random.randint(1,8)):
        pos=random.randrange(len(b)); b[pos]=random.choice([0,0xff,random.randrange(256),0x7f,3])
    if random.random()<.2: b=b[:random.randrange(len(b))]
    t=time.time()
    try: _Parser(bytes(b),random.random()<.2,L).run()
    except Exception as e: seen[type(e).__name__+str(e)[:40]]+=1; open('crash_ver.bin','wb').write(bytes(b))
    worst=max(worst,time.time()-t)
print(seen,worst)
# rich
seen=Counter()
for i in range(20000):
    n=random.randint(0,600)
    b=bytearray(random.choice([0,0x52,0x69,0x63,0x68,0x44,0x61,0x6e,0x53])for _ in range(n)) if random.random()<.5 else bytearray(random.randbytes(n))
    if random.random()<.5 and n>80:
        k=random.randrange(1<<32); d=random.randrange(0x40,n-8,4) if n>96 else 0x40
        b[d:d+4]=struct.pack('<I',DANS^k)
        r=random.randrange(d+4,n-4) & ~3
        if r>d: b[r:r+4]=b'Rich'; b[r+4:r+8]=struct.pack('<I',k)
    try: parse_rich_header(bytes(b))
    except Exception as e: seen[type(e).__name__+str(e)[:60]]+=1; open('crash_rich.bin','wb').write(bytes(b))
print(seen)
