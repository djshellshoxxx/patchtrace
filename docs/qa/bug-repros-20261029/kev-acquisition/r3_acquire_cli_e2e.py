import gzip, json, sys, io, contextlib
from patchtrace import cli
from patchtrace.acquisition import transport as tr
SHA='a'*64
class Resp:
    def __init__(s,status,body=b'',headers=None): s.status,s.headers,s._b=status,headers or {},body
    def read(s,n): o,s._b=s._b[:n],s._b[n:]; return o
    def close(s): pass
def run(entry_extra, info_extra):
    info={'sha256':SHA,'size':1000,'machineType':34404,'timestamp':1,'virtualSize':4096}; info.update(info_extra)
    e={'fileInfo':info}; e.update(entry_extra)
    body=gzip.compress(json.dumps({SHA:e}).encode())
    cli._acquire_transport=lambda factory,cancel: tr.Transport(opener=lambda m,u,h,t: Resp(200,body),cancel=cancel,sleep=lambda s,c:None)
    out,err=io.StringIO(),io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try: code=cli.main(['acquire','search','ntdll.dll','--consent-hosts','winbindex.m417z.com'])
        except BaseException as ex: code='RAISED '+type(ex).__name__
    return code,out.getvalue(),err.getvalue()
code,out,err=run({}, {'version':'1.0\x1b[2J\x1b]0;PWNED\x07'})
print('ANSI case exit',code,'stdout repr:',repr(out[:120]))
code,out,err=run({'x':'\ud800'}, {})
print("surrogate case ->", code, "| stderr:", repr(err[:200]))
