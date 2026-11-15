import sys; sys.path.insert(0, __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'))
from test_nway_support import PairBuilder, HASHES, fn
from patchtrace.nway.graph import extract_chains
for label, name in (('long-5000', 'N' * 5000), ('empty', '')):
    h = HASHES[:3]
    p1 = PairBuilder(h[0], h[1]).one(fn(name, 0x1000), fn(name, 0x2000)).build()
    p2 = PairBuilder(h[1], h[2]).one(fn(name, 0x2000), fn(name, 0x3000)).build()
    try:
        chains, n = extract_chains(h, [p1, p2])
        print(label, 'ok', len(chains))
    except Exception as e:
        print(label, type(e).__module__, type(e).__name__, str(e).splitlines()[0][:100])
