from patchtrace.buildenv.contracts import *
from patchtrace.buildenv.fingerprint import _managed_fact
from patchtrace.buildenv.preflight import _managed
def pe(clr):
    return PeBuildFacts(linker_field=None, os_field=None, image_field=None, subsystem_field=None, subsystem=None,
        dll_characteristics=(), guard_flags=None, security_cookie_set=None, debug_entry_types=(), repro=False,
        rich=None, clr=clr, runtime_families=(), entropy_exec_max=None, overlay_size=0, overlay_entropy=None,
        sampled=False, anomalies=())
clr = ClrFacts(header_size=72, runtime_major=2, runtime_minor=5, flags=(), il_only=False, has_native_header=False, metadata_version='v4.0.30319')
facts = tuple(_managed_fact(pe(clr)))
print(facts[0].value)
fp = BuildFingerprint(artifact_sha256='1'*64, side='newer', pe=pe(clr), die=None, facts=facts, anomalies=(),
                      built_from=BuiltFrom(pe_facts_version='pe-build-facts/1', die_cache_key=None))
for w in _managed(fp): print(w.severity, w.summary, '|', w.detail)
