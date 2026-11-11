import sys,time,resource
from patchtrace.pe_overview.manifest import observe_manifest
from patchtrace.pe_overview.resources import ResourceLeaf
leaf=ResourceLeaf(24,'RT_MANIFEST',1,0x409,0,0,0,0)
NS='xmlns="urn:schemas-microsoft-com:asm.v1"'
cases={
 'deep': '<assembly %s>'%NS + '<a>'*600000 + '</a>'*600000 + '</assembly>',
 'attrs': '<assembly %s '%NS + ' '.join('a%d="1"'%i for i in range(150000)) + '/>',
 'nsdecl': '<assembly %s '%NS + ' '.join('xmlns:p%d="u%d"'%(i,i) for i in range(100000)) + '/>',
 'siblings': '<assembly %s>'%NS + '<file name="x"/>'*150000 + '</assembly>',
 'longtext': '<assembly %s><a>'%NS + 'x'*2000000 ,
 'amp': '<assembly %s>'%NS + '<a>' + '&amp;'*300000+'</a></assembly>',
}
for k,v in cases.items():
    raw=v.encode()[:2097152]
    t=time.time()
    try: o=observe_manifest(leaf,raw); r=o.warnings
    except BaseException as e: r='EXC %s'%type(e).__name__
    print(k,len(raw),r,'%.2fs'%(time.time()-t), resource.getrusage(resource.RUSAGE_SELF).ru_maxrss//1024,'MB')
