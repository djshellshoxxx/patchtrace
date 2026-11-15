import sys, json, tempfile, pathlib, hashlib
sys.path[:0] = [__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from patchtrace.enrichment.cache import CacheConfig, DerivedCache
root = pathlib.Path(tempfile.mkdtemp())
c = DerivedCache(CacheConfig(root=root))
key = 'ab'*32
assert c.put('signals', key, b'hello', {'k': 'v'})
mf = root/'v1'/'signals'/key[:2]/key/'manifest.json'
base = json.loads(mf.read_text())
for size in [2**70, 2**45]:
    d = dict(base, size=size); mf.write_text(json.dumps(d))
    for name, fn in [('get', lambda: c.get('signals', key)), ('verify', c.verify), ('put', lambda: c.put('signals', key, b'hello', {}))]:
        try: print(f'size={size} {name}:', fn())
        except BaseException as e: print(f'size={size} {name}: RAISED', type(e).__name__, e)
    mf.write_text(json.dumps(base))
