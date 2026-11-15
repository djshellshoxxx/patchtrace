import sys; sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from pilot_localize_support import *
from patchtrace.pilot import report, contracts as c
names = ['a|b', '<img src=x onerror=1>', '[click](http://evil.example)', '![i](http://e/x.png)', '`code`', 'x\\', '&lt;', 'line1  ', '# head', '> quote', '- item', 'http://evil.example/x', 'A‮B', 'foo bar', '<!-- c -->', '~~~', '***', '====', 'a b', '﻿z', '​zw', '@user', ':smile:']
cands=[]
for i,n in enumerate(names):
    try: cands.append(candidate(i,n))
    except Exception as e: print('rejected', repr(n))
bundle = build(cands, [(cands[0], observation('b1:BND', ref='s1', line=14, detail='<b>x</b> | y\n'.replace('\n','')))], cves={CVE_A: (hypothesis('R-MEMORY-READ','CWE-125'),)})
a = run(bundle)
md = report.to_markdown(a)
import re
bad = [l for l in md.splitlines() if re.search(r'<[a-z!]|\]\(|^#|^>', l.replace('> This','')) ]
for l in md.splitlines():
    if any(k in l for k in ('evil','onerror','<!--','‮',' ','&lt;')): print(repr(l)[:200])
print('----')
print(md[:1500])
