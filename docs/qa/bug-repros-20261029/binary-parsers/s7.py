import random, re, sys
from patchtrace.strings.scan import scan_bytes
random.seed(int(sys.argv[1]))
def ref(data, ml, max_run):
    out=[]
    a=re.compile(rb'[\x20-\x7e\t]{%d,}'%ml)
    for m in a.finditer(data):
        s,e=m.span()
        while e-s>max_run:
            out.append(('ASCII',s,data[s:s+max_run].decode())); s+=max_run
        if e-s>=ml: out.append(('ASCII',s,data[s:e].decode()))
    w=re.compile(rb'(?:[\x20-\x7e\t]\x00){%d,}'%ml)
    cut=max_run-max_run%2
    for m in w.finditer(data):
        s,e=m.span()
        while e-s>cut:
            out.append(('UTF-16LE',s,data[s:s+cut].decode('utf-16-le'))); s+=cut
        if e-s>=2*ml: out.append(('UTF-16LE',s,data[s:e].decode('utf-16-le')))
    return out
bad=0
for it in range(4000):
    n=random.randint(0,200)
    data=bytes(random.choice([0x41,0x42,0x20,0,0,0x0a,0x80,0x09,0x7e]) for _ in range(n))
    ml=random.choice([1,2,3,4,5,8,9])
    mr=random.choice([2*ml,2*ml+1,10,16,1000])
    if mr<2*ml: continue
    cb=random.choice([1,2,3,5,7,64,10**6])
    r=scan_bytes(data,chunk_bytes=cb,min_length=ml,max_run=mr)
    got=sorted((x.encoding,x.offset,x.value) for x in r.rows)
    want=sorted(ref(data,ml,mr))
    if got!=want:
        bad+=1
        if bad<4: print('MISMATCH',data,ml,mr,cb,got[:4],want[:4])
print('bad',bad)
