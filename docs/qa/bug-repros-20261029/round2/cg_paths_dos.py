import sys, time
from patchtrace.callgraph.csr import build_csr
from patchtrace.callgraph.algo import simple_paths
K=int(sys.argv[1]); D=int(sys.argv[2])
# nodes: 0 src, 1 dst, 2 z, 3 hub, A: 4..4+K, B: next K, dead: D
A=list(range(4,4+K)); B=list(range(4+K,4+2*K)); dead=list(range(4+2*K,4+2*K+D))
n=4+2*K+D
e=[(0,2),(2,1),(3,0)]  # src->z->dst ; hub->src (blocked)
e+=[(0,a) for a in A]+[(a,b) for a in A for b in B]+[(b,3) for b in B]+[(3,d) for d in dead]
g=build_csr(n,e)
t=time.time(); r=simple_paths(g,0,1); print(K,D,len(e),'edges',r.paths,r.truncated,'%.2fs'%(time.time()-t))
