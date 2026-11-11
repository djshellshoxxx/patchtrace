import sys, time, resource
sys.path[:0] = [__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from patchtrace.search.tokenize import name_words
from patchtrace.search.sources.base import name_fields
for mb in (1, 4):
    name = 'aB' * (mb * 512 * 1024)   # mb MiB of CamelCase
    t = time.time(); out = name_fields(name); 
    print(f'{mb} MiB symbol name: {time.time()-t:.1f}s, words field {len(out["name_words"])} chars, peak RSS {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss//1024} MiB', flush=True)
