import random, string, collections
from patchtrace.fabric import ids
from patchtrace.fabric.contracts import KINDS
from patchtrace.fabric.limits import FabricError
random.seed(1)
alpha = string.printable + 'éßİK\ud800​ ١ KB!#.:=_-' + 'ａ' + '\U0001F600'
seen = collections.Counter()
def rnd():
    n = random.choice([0,1,2,3,5,8,20,70,300])
    return ''.join(random.choice(alpha) for _ in range(n))
seeds = ['CVE-2024-1234', 'kernel32.dll!#12', 'a!#99999', 'pair:'+'0'*64, 'image:'+'a'*64+':rva:0x10', 'KB123456', '12', 'cwe-79', 'CWE79', 'foo.bar!CreateFileW', '#1', 'x!#']
for i in range(60000):
    v = random.choice(seeds) if random.random() < .3 else rnd()
    if random.random() < .3: v = v + random.choice(['\n', ' ', '\t', '\x00'])
    for kind in KINDS:
        try: ids.key_for_value(kind, v)
        except FabricError: pass
        except Exception as e: seen[(kind, type(e).__name__, str(e)[:60])] += 1
    for fn in (ids.api_key, ids.cve_key, ids.cwe_key, ids.kb_key, ids.string_key):
        try: fn(v)
        except FabricError: pass
        except Exception as e: seen[(fn.__name__, type(e).__name__, str(e)[:60])] += 1
    try: ids.ordinal_key(v, random.choice([0,1,65535,65536,-1]))
    except FabricError: pass
    except Exception as e: seen[('ordinal_key', type(e).__name__)] += 1
print(seen)
