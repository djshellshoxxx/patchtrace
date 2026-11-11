import os, tempfile, hashlib
from pathlib import Path
from patchtrace.acquisition import transport as tr
from patchtrace.acquisition.contracts import PlannedDownload, symbol_server_url
data=b'x'*100
url=symbol_server_url('a.dll',1,4096)
p=PlannedDownload(side='older',file_name='a.dll',sha256=hashlib.sha256(data).hexdigest(),size=100,url=url,record_sha256='b'*64)
class R:
    status=200; headers={}
    def __init__(s): s.b=data
    def read1(s,n): o,s.b=s.b[:n],s.b[n:]; return o
    read=read1
    def close(s): pass
t=tr.Transport(opener=lambda m,u,h,to: R(), sleep=lambda s,c:None)
c=tr.AcquisitionConsent.for_urls([url])
d=Path(tempfile.mkdtemp())
n0=len(os.listdir('/proc/self/fd'))
def boom(done,total): raise RuntimeError('ui')
for _ in range(20):
    try: t.download(p,c,d,boom)
    except RuntimeError: pass
print('fds leaked:', len(os.listdir('/proc/self/fd'))-n0, 'leftover files', os.listdir(d))
