from patchtrace.buildenv.contracts import *
from patchtrace.buildenv.delta import compute_delta
from patchtrace.buildenv.report import build_section, render_markdown, section_data
from patchtrace.buildenv.view_model import provenance_block, build_view

def pe(n_entries, n_anom):
    rich = RichFacts(offset=0x80, key=1, checksum_ok=True, signature='a'*64, truncated=False,
                     entries=tuple(RichEntry(product_id=i, build=i, count=1) for i in range(n_entries)))
    return PeBuildFacts(linker_field=(14,0), os_field=None, image_field=None, subsystem_field=None, subsystem=None,
        dll_characteristics=(), guard_flags=None, security_cookie_set=None, debug_entry_types=(), repro=False,
        rich=rich, clr=None, runtime_families=(), entropy_exec_max=None, overlay_size=0, overlay_entropy=None,
        sampled=False, anomalies=tuple(f'anom-{i}' for i in range(n_anom)))

def fp(side, sha, n, a):
    p = pe(n, a)
    return BuildFingerprint(artifact_sha256=sha, side=side, pe=p, die=None, facts=(), anomalies=tuple(f"x-{i}" for i in range(a)),
                            built_from=BuiltFrom(pe_facts_version=p.facts_version, die_cache_key=None))

o, n = fp('older','1'*64,64,3), fp('newer','2'*64,64,3)
d = compute_delta(o, n)
print('provenance repr:', repr(provenance_block(o, n))[:200])
try:
    s = build_section(o, n, d, technical=True)
    print('ok', len(s.technical))
except Exception as e:
    print(type(e).__name__, str(e)[:300])

o2, n2 = fp('older','1'*64,3,0), fp('newer','2'*64,3,0)
d2 = compute_delta(o2, n2)
md = render_markdown(section_data(build_section(o2, n2, d2)))
i = md.index('### Provenance'); print(md[i:i+260])
