from patchtrace.buildenv.contracts import *
from patchtrace.buildenv.delta import compute_delta
def fp(side, sha, sig):
    f = BuildFact(key='rich_signature', value=sig, source='rich-header', certainty='derived', raw=(('checksum','ok'),))
    return BuildFingerprint(artifact_sha256=sha, side=side, pe=None, die=None, facts=(f,), anomalies=(),
                            built_from=BuiltFrom(pe_facts_version='pe-build-facts/1', die_cache_key=None))
# Both objects pass BuildFingerprint validation (this is also what a stored row looks like when read back).
o, n = fp('older','1'*64,'a'*64), fp('newer','2'*64,'b'*64)
try:
    compute_delta(o, n)
except Exception as e:
    print(type(e).__name__, str(e).splitlines()[1])
