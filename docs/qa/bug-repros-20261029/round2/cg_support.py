from patchtrace.callgraph.project_input import Entry, ProjectInput, EmittedPair
from patchtrace.callgraph.raw_matches import RawMatchesResult
def make(older, newer=()):
    """older/newer: list of (label, callees)"""
    entries=[]
    for side, items in (('older', older), ('newer', newer)):
        for i,(label,callees) in enumerate(items):
            entries.append(Entry(side,label,f'f-{side}-{i}',f'm{i}',0x1000+i,False,tuple(callees),()))
    return ProjectInput('p',1,'r','v',None,'a'*64,'b'*64,tuple(entries),(),'d',RawMatchesResult(None,'absent',()))
