# Random audit 1 (RAND-AUDIT, 2026-10-14)

Scope: 12 randomly drawn modules of the merged tree (base `7f4f89f`, after `git merge --ff-only work/a`). Read-only: nothing
under `src/`, `tests/` or `tools/` was modified and the full suite was not run; scripts lived in the scratchpad.
Environment: Linux x86-64, uid 0, Python 3.13.16 (project targets 3.12), pydantic 2.13.5, protobuf 7.36.2 (upb). Windows-only
code was read, not run. Every finding below was reproduced here; anything that could not be is listed in section 5 and not counted.
Repro commands need `PYTHONPATH=src` from the repo root: the editable install in this environment resolves `patchtrace`
to `/home/user/patchtrace/src` (the main checkout), not to the worktree.
Focused existing tests of the audited modules (`test_pe_overview*`, `test_kbc_cvrf`, `test_binexport_check`, `test_release_gate`,
`test_intel_transport`, `test_interpretation`, `test_backend_bundle`, `test_offline_bundle`): 470 passed, 1 skipped. None covers a finding.

## 1. Draw (seed 20261014)

Candidates: 269 `.py` files under `src/patchtrace` and `tools` minus UI, tooltips, generated schema data, `__init__`, site tooling.
Weights: 5 untrusted-input parsers, subprocess/jobs, SQLite/persistence, network; 4 path/archive/ingestion, CLI; 1 other; x0.35 for
files already covered by an earlier 2026-10-14 audit (acquisition, csaf, tools adapters, jobs, service/persistence, unified S0a).
Weighted sampling without replacement (Efraimidis-Spirakis, `random.random() ** (1 / w)`), script in appendix A. Order drawn:
1 `pe_overview/inspect.py`, 2 `kbcorrelation/sources/cvrf.py`, 3 `secondary/binexport_check.py`, 4 `providers.py`,
5 `intelligence/tools/diec.py`, 6 `tools/release_gate.py`, 7 `intelligence/csaf/transport.py`, 8 `tools/calibration/common.py`,
9 `unified/ladder/ports.py`, 10 `backend_bundle.py`, 11 `tools/calibration/ood_fit.py`, 12 `tools/bench_enrichment.py`;
reserve 13 `diagnostics.py`, 14 `pe_overview/imports_exports.py`, 15 `intelligence/cli.py` (not needed: 12 targets and 10 findings reached).
The draw hit no SQLite store and no CLI envelope; those classes are untested by this audit.

| # | Target (neighbours read) | Class | Verdict | Evidence |
|---|---|---|---|---|
| 1 | `pe_overview/inspect.py` (headers, sections, entropy, imports_exports, debug_info, certificates, compare, authenticode) | parser | RA-1, RA-8, RA-9 | 8,000 byte/field mutations of PE32 and PE32+ (seeds 1014/1015): 0 escapes, 0 `internal_error_*`, none over 1 s; 20,000 export or import names parse in 0.5 s / 0.3 s; PE checksum equals pefile's algorithm in 400/400 random cases (odd sizes, carries, chunk 2 B to 1 MiB) |
| 2 | `kbcorrelation/sources/cvrf.py` (importer, contracts) | parser | RA-2, RA-5, RA-6 | read plus existing tests: DOCTYPE/entity, BOM, UTF-16, duplicate JSON keys, depth and node bounds hold; XML with markup declarations never reaches expat |
| 3 | `secondary/binexport_check.py` (prescan, pipeline, identity, limits) | parser | clean | 90,121 structure-aware mutations of the 4 committed fixtures through the real upb message (indices at 0, n-1, n, 2^31, 2^64-1, NUL, NaN, 70 kB strings, element add/delete/duplicate; seed 20261014): all outcomes `SecondaryError` or accepted (29,396), 0 other exceptions, 0 over 1 s |
| 4 | `providers.py` (`netutil.py`, `interpretation.py`) | network | RA-7 | endpoint matrix run (`localhost.`, `127.1`, `0.0.0.0`, decimal IP, `\@` userinfo refused; `[::ffff:127.0.0.1]` accepted as loopback); read, no defect: redirect refusal, `interruptible` cancel race, `validate_response` (extra=forbid, duplicate keys, evidence ownership) |
| 5 | `intelligence/tools/diec.py` (`process.py` helpers) | subprocess | RA-8 | earlier TA-1/3/6 fixes present (`parse` wraps ValidationError, sorted truncation, `verify_executable`, database digest re-check); database copy refuses links and non-regular files |
| 6 | `tools/release_gate.py` | path/archive | clean | 57 test functions pass; code read in full; fails open by design; a `\x1e` in a commit message makes `parse_git_log` raise (GateError, publish): same privilege as `[release]`, not counted |
| 7 | `intelligence/csaf/transport.py` | network | RA-3, RA-4 | 17-case `check_url` bypass matrix (userinfo, `%2e`, `//`, `..`, port, trailing dot, http, tab, backslash, fragment, query, non-ASCII, scheme-relative and `/\` Location): only the two legal forms accepted |
| 8 | `tools/calibration/common.py` | other | clean | `weighted_quantile([], [], q)` raises IndexError, all-zero weights return the minimum, `det_uniform(1, 'a\|b') == det_uniform(1, 'a', 'b')`; no current caller reaches any of them |
| 9 | `unified/ladder/ports.py` (`side.py`) | other | clean | types only; `SideData._build` validates fid range and duplicates, rva order, thunk and call ranges |
| 10 | `backend_bundle.py` (`offline_bundle.py` validators) | path/archive | clean | read plus existing tests (`test_offline_bundle` covers the hostile-archive cases): `_safe_relative`, NFC+casefold collisions, 200:1 ratio, symlink and junction refusal, `O_NOFOLLOW` hashing, work-dir containment hold; Windows-only notes in section 5 |
| 11 | `tools/calibration/ood_fit.py` (`calibration/ood.py`, `artifact._semantic`) | other | clean | shape, positivity, finiteness, expiry gates present; run: NaN lands in `hard:range` for pipeline-built specs (every name has a range); a hand-built spec with no range for a Mahalanobis feature returns no flag for NaN (validator allows it; not counted) |
| 12 | `tools/bench_enrichment.py` | other | RA-10 | |

## 2. Findings (10 reproduced: 4 Medium, 6 Low, 0 High)

| ID | file:line | Sev | Repro (ran; recipe in section 3) | Proposed fix | Owner track |
|---|---|---|---|---|---|
| RA-1 | `pe_overview/sections.py:33`, `entropy.py:22`; spec `pe-overview.md:43` | Medium | R1: 8.4 MB PE32+ whose 96 section headers all claim raw 0x400 + 8 MiB: `inspect_pe` 34.3 s (30-42 s over four runs), status `ok`, no warning; honest one-section file of the same size 0.5 s (24 sections 10.3 s). The entropy cap is per section, so overlapping sections multiply work up to 96 x 8 MiB. Reached without `cancel` from `unified/addressing.py:44`, `unified/ir/pe_tables.py:317`, `intelligence/tools/normalize.py:43` | Per-file entropy budget (merge raw ranges, measure each byte once, or total <= `entropy_cap`); set `sampled`, warn `entropy_budget_exhausted`; amend the spec limits row; header-only mode for callers that need ImageBase only | SPEC-26 D (PE inspection) |
| RA-2 | `kbcorrelation/sources/cvrf.py:540,587` | Medium | R2: children are mapped by local name, last wins. Two `ProductStatuses` containers `[Not affected, Fixed]` give `vendor-remediation`; `[Fixed, Not affected]` or both in one container give `disputed`. A second `Vulnerabilities` container silently replaces the first (only CVE-2099-30003 survives, `problems=[]`). The JSON dialect refuses duplicate keys (NEG-07). Hides conflicting evidence | Build the maps with a duplicate check and raise `PT-KBC-SOURCE` ("ambiguous duplicate element"); XML twins of NEG-07 for every container | K1 (KB correlation) |
| RA-3 | `intelligence/csaf/transport.py:345`, `enrichment/intelligence.py:408`; sibling of C-01 (`acquisition/transport.py:193`, still open) | Medium | R3: loopback server sends 1 byte per 0.5 s. CSAF `_read` with a 2 s request deadline returns after 12.0 s; enrichment `_attempt` with a 2 s total deadline after 12.0 s. `response.read(65536)` blocks until the chunk fills, the 10 s per-recv timeout never fires and the deadline is only checked between chunks. Cancel still works (`interruptible`); headless runs (CI live jobs, scripts) have no bound | `read1` plus a remaining-time check per read, as `providers.py:114`; one shared bounded-read helper in `netutil` for all four transports; real-socket regression test | SPEC-28 CSAF, SPEC-07 enrichment, acquisition (C-01 owner) |
| RA-4 | `intelligence/csaf/transport.py:158-166,200-203` | Medium | R4: `urls.json` over `MAX_MAP_BYTES` (8 MiB, about 28-33k entries) reads back as `{}`; the next `put()` rewrites the index with one entry (40,000 to 1). Offline lookups of every earlier document then fail NOTFOUND while the bodies stay on disk. The read cap is not mirrored on write. New: C-22 covered only locking and raw OSError | Never rewrite from an unreadable map (raise `PT-INTEL-CONFIG`); rotate or shard the index before it crosses the cap | SPEC-28 CSAF |
| RA-5 | `kbcorrelation/sources/cvrf.py:594` | Low | R2: remediation `Type` of U+0662 (Arabic-Indic digit two), `" 2 "`, `"+2"`, `"0_2"` or U+FF12 (full-width two) all become type 2 and yield fix edges; the JSON dialect needs `type(kind) is int` (line 460) | `re.fullmatch(r'[0-9]{1,3}', value)` before `int()` | K1 |
| RA-6 | `cvrf.py:604-607,709`; `importer.py:117` | Low | R2: one row whose status `Type` has 5000 characters refuses the whole month (`PT-KBC-SOURCE`, "exceeds the kbcorrelation/1 bounds") instead of one row problem. JSON guards `len(name) > 200` (line 441); XML has no guard and `ProductStatus(...)` (709) sits outside the row-level `except ValidationError` (723) | Same guard in the XML path; build `ProductStatus` inside the `try` | K1 |
| RA-7 | `providers.py:39,88,140` | Low | R5: a key containing U+20AC (euro sign) passes `ProviderConfig`, `putheader` raises UnicodeEncodeError (a ValueError) before any socket opens and the user is told "malformed provider envelope". Latin-1-range characters are sent as one Latin-1 byte, not UTF-8 | Require printable ASCII in `__post_init__` ("invalid credential") | AI provider |
| RA-8 | `intelligence/tools/process.py:45`, `pe_overview/_common.py:19` | Low | R5: `sanitize` keeps U+009B (C1 CSI) and U+202E (RLO); PE `clean_text(b'a\x9b31mb')` keeps U+009B although `pe-overview.md:57` says control characters become `?`. The CLI sink `plain_text` escapes both, so exposure is stored/JSON fields and Qt labels | Drop `0x7f <= ord < 0xa0` and categories Cc/Cf like `kbcorrelation/products.py:50` and `display_text`; one shared hostile-character list | tools-core, SPEC-26 D |
| RA-9 | `pe_overview/entropy.py:34-35` | Low | R5: constant data returns entropy `-0.0` (`f'{x:.2f}'` is `-0.00`, JSON `-0.0`); `max(-0.0, 0.0)` keeps the first operand | `max(ent, 0.0) + 0.0` | SPEC-26 D |
| RA-10 | `tools/bench_enrichment.py:68-76` | Low | R6: without `resource` (Windows) the report prints `"peak_rss_mib": 0.0`; the E6 plan's "10 s, 512 MiB peak RSS, same" row for Windows would read as passing. `ru_maxrss` is bytes on macOS | Emit `null`/"unavailable" (or use `GetProcessMemoryInfo` as `binexport_limits.peak_memory_bytes`) | E6 performance |

## 3. Repro recipes (all ran; outputs quoted)

R1 `PYTHONPATH=src python r1.py`: honest vs overlapping layout, 8 MiB raw per section.
```python
import struct, time, tempfile, pathlib
from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import inspect_pe
def pe(n, rsize):
    opt = bytearray(240); struct.pack_into('<H', opt, 0, 0x20B); struct.pack_into('<I', opt, 60, 0x400); struct.pack_into('<I', opt, 108, 16)
    sec = b''.join(struct.pack('<8sIIIIIIHHI', b'.s%d' % i, 0x1000, 0x1000 * (i + 1), rsize, 0x400, 0, 0, 0, 0, 0x40000040) for i in range(n))
    head = b'MZ' + bytes(58) + struct.pack('<I', 0x40) + b'PE\0\0' + struct.pack('<HHIIIHH', 0x8664, n, 0, 0, 0, 240, 0x22) + bytes(opt) + sec
    return head.ljust(0x400, b'\0') + bytes(range(256)) * (rsize // 256)
for n in (1, 96):
    p = pathlib.Path(tempfile.mkdtemp()) / 'x.exe'; p.write_bytes(pe(n, 8 << 20))
    t = time.perf_counter()
    with VerifiedArtifactReader.open_path(p) as r: ov = inspect_pe(r)
    print(n, 'sections', p.stat().st_size, 'bytes', f'{time.perf_counter() - t:.1f}s', ov.status, [w.code for w in ov.warnings])
```
Output: `1 sections 8389632 bytes 0.5s ok []` and `96 sections 8392776 bytes 34.3s ok []`.

R2 `PYTHONPATH=src:tests python r2.py` (helpers `xml_doc`, `XML_VULN`, `NOW` come from `tests/test_kbc_cvrf.py`).
```python
from test_kbc_cvrf import xml_doc, XML_VULN, NOW
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.sources.cvrf import SourceError
def edges(raw): d = import_bytes(raw, now=NOW); return [(e.kb, e.cve[-5:], e.relation) for e in d.edges]
def st(kind): return f'<cvrf:ProductStatuses><cvrf:Status Type="{kind}"><cvrf:ProductID>PT-CLIENT</cvrf:ProductID></cvrf:Status></cvrf:ProductStatuses>'
def v(s): return xml_doc(XML_VULN.replace('</cvrf:Vulnerability>', s + '</cvrf:Vulnerability>'))
print(edges(v(st('Fixed') + st('Not affected'))))        # [Fixed, Not affected] -> disputed
print(edges(v(st('Not affected') + st('Fixed'))))        # same two statuses, other order -> vendor-remediation
dup = xml_doc(XML_VULN).replace(b'</cvrf:CvrfDoc>', b'<cvrf:Vulnerabilities>' + XML_VULN.replace('30002', '30003').encode()
                                + b'</cvrf:Vulnerabilities></cvrf:CvrfDoc>')
print(edges(dup))                                         # first container silently dropped, no problem raised
print(edges(xml_doc(XML_VULN.replace('Type="2"', 'Type="\N{ARABIC-INDIC DIGIT TWO}"'))))   # read as Type 2
try: edges(v(st('A' * 5000)))
except SourceError as e: print('whole document refused:', e.code, e.message)
```
Output: `[('KB5099001', '30002', 'disputed')]`, `[('KB5099001', '30002', 'vendor-remediation')]`, `[('KB5099001', '30003', 'vendor-remediation')]`,
`[('KB5099001', '30002', 'vendor-remediation')]`, `whole document refused: PT-KBC-SOURCE a value in the document exceeds the kbcorrelation/1 bounds`.

R3 `PYTHONPATH=src python r3.py`: a 2 s deadline against a server that drips one byte per 0.5 s for 12 s.
```python
import http.client, socket, threading, time
from datetime import UTC, datetime
from patchtrace.intelligence.csaf import transport as T
from patchtrace.enrichment import intelligence as E
def serve(sock):                                  # 200, no Content-Length, then one byte every 0.5 s for 12 s
    c, _ = sock.accept(); c.recv(4096); c.sendall(b'HTTP/1.0 200 OK\r\n\r\n'); end = time.monotonic() + 12
    while time.monotonic() < end:
        try: c.sendall(b' '); time.sleep(0.5)
        except OSError: break
    c.close()
def response():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(1); threading.Thread(target=serve, args=(s,), daemon=True).start()
    c = http.client.HTTPConnection('127.0.0.1', s.getsockname()[1], timeout=10); c.request('GET', '/'); return c.getresponse()
t = time.monotonic(); tr = T.CsafTransport(T.CsafConsent.for_hosts(['msrc.microsoft.com']), cancel=threading.Event())
try: tr._read(T._Response(response()), T.CAPS['document'], 'document', tr.clock() + 2.0)
except Exception as e: print('csaf      ', f'{time.monotonic() - t:.1f}s', e)
t = time.monotonic(); opener = lambda url, headers, timeout: E._UrllibResponse(response())
try: E._attempt('https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-0001', {}, opener, threading.Event(),
                time.monotonic, time.monotonic() + 2.0, lambda: datetime.now(UTC))
except Exception as e: print('enrichment', f'{time.monotonic() - t:.1f}s', e)
```
Output: `csaf       12.0s PT-INTEL-NETWORK: request deadline exceeded while reading`, `enrichment 12.0s PT-ENRICH-NETWORK: total timeout exceeded`.

R4 `PYTHONPATH=src python r4.py`: index larger than the read cap, then one `put()`.
```python
import hashlib, json, tempfile, pathlib
from patchtrace.intelligence.csaf.transport import Fetched, OfflineCache
root = pathlib.Path(tempfile.mkdtemp()); (root / 'bodies').mkdir(); cache = OfflineCache(root)
index = {f'https://msrc.microsoft.com/csaf/advisories/2026/{i:05d}.json': {'sha256': hashlib.sha256(b'%d' % i).hexdigest(),
         'retrieved_at': '2026-10-14T00:00:00Z', 'final_url': 'x' * 40} for i in range(40000)}
(root / 'urls.json').write_text(json.dumps(index, sort_keys=True, indent=1))
size = (root / 'urls.json').stat().st_size; print('entries', len(index), 'index bytes', size, 'over cap:', size > OfflineCache.MAX_MAP_BYTES)
body = b'doc'; cache.put(Fetched('https://msrc.microsoft.com/csaf/new.json', 'x', body, hashlib.sha256(body).hexdigest(), 't'))
print('entries after one more put():', len(json.loads((root / 'urls.json').read_text())))
```
Output: `entries 40000 index bytes 9960002 over cap: True`, `entries after one more put(): 1`.

R5 `PYTHONPATH=src python r5.py`.
```python
import threading, tempfile, pathlib
from patchtrace.providers import ProviderConfig, ProviderError, request_completion
cfg = ProviderConfig('openai', 'https://localhost.invalid/v1', 'm', api_key='sk-abc\N{EURO SIGN}def')    # accepted at construction
try: request_completion(cfg, 's', 'c', threading.Event())                                           # fails before any socket opens
except ProviderError as e: print(e)
from patchtrace.pe_overview._common import clean_text
from patchtrace.intelligence.tools.process import sanitize
from patchtrace.intelligence.reports import plain_text
bad = 'a\x9b31m \N{RIGHT-TO-LEFT OVERRIDE}b'      # non-ASCII code points that survive each sanitizer
print([hex(ord(c)) for c in clean_text(b'a\x9b31mb') if ord(c) > 127],
      [hex(ord(c)) for c in sanitize(bad) if ord(c) > 127], [hex(ord(c)) for c in plain_text(bad) if ord(c) > 127])
from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview._common import Ctx
from patchtrace.pe_overview.entropy import entropy_of_range
from patchtrace.pe_overview.models import Limits
p = pathlib.Path(tempfile.mkdtemp()) / 'z.bin'; p.write_bytes(bytes(4096))
with VerifiedArtifactReader.open_path(p) as r: print(entropy_of_range(Ctx(r, None, Limits()), 0, 4096))
```
Output: `PT-PROVIDER: malformed provider envelope`; `['0x9b'] ['0x9b', '0x202e'] []` (clean_text, sanitize, plain_text); `(-0.0, 4096, False)`.

R6 `PYTHONPATH=src python -c "import sys, runpy; sys.modules['resource'] = None; sys.argv = ['b', '--pairs', '40', '--lines', '2000', '--json']; runpy.run_path('tools/bench_enrichment.py', run_name='__main__')"`
prints `... "peak_rss_mib": 0.0, "status": "complete" ...`.

## 4. Missing tests

1. `test_pe_overview`: many sections over one raw range finish under a time bound or warn; total entropy bytes <= budget (RA-1).
2. `test_kbc_cvrf`: XML twins of NEG-07 (duplicate `Vulnerabilities`, `ProductStatuses`, `Remediations`, `ProductTree` raise `PT-KBC-SOURCE`);
   `Type` strictness (U+0662, `' 2 '`, `'+2'`, `'0_2'`); over-long status `Type` yields one problem and keeps the rest of the month.
3. A real-socket slow-drip fixture shared by acquisition, csaf and enrichment transports (C-01 already asks for it): wall time <= deadline + 1 s.
4. `test_intel_transport`: `OfflineCache.put` beyond `MAX_MAP_BYTES` keeps earlier entries; concurrent `put` lost update (C-22).
5. `test_providers`: `ProviderConfig` credential charset, parametrized (control, non-ASCII, non-Latin-1).
6. One hostile-character property test for `process.sanitize`, `pe_overview.clean_text`, `products.clean_text` and `display_text`: no Cc/Cf/Cs code point survives (RA-8).
7. Entropy of constant data is `0.0` with positive sign (`math.copysign`) (RA-9); `bench_enrichment` reports `null` RSS when `resource` is missing (RA-10).

## 5. Observed, not reproduced here (not counted)

- `pe_overview/authenticode.py`: WinVerifyTrust gets a path, not the verified handle (swap window after hash verification); `TRUST_E_NOSIGNATURE` is
  mapped to `unsigned` without `GetLastError`, which Microsoft documents as "unsigned or invalid signature". Windows only.
- `intelligence/tools/process._tree_entries`: `os.walk(followlinks=False)` and `Path.is_symlink()` do not see NTFS junctions (C-27 already notes it). Windows only.
- `backend_bundle._hash_files` maps every `OSError` (antivirus sharing violation, EACCES) to `PT-BUNDLE-MISSING`, whose remedy is "extract again";
  `_fast_walk` calls `entry.stat()` unguarded, so a file removed mid-scan raises out of `verify_bundle` (docstring: never raises). Race or Windows only.

## Appendix A. Draw script (`python -I draw.py <repo root>`)

```python
import pathlib, random, re, sys
root = pathlib.Path(sys.argv[1])
SKIP = r'(^|/)(ui[_a-z]*|tooltips|schema_data|__main__|desktop_entry|pins|__init__|render_screenshots|make_logo_assets|xmr_address|donate)\.py$'
CATS = [(5, 'parser', r'pe_overview/(headers|sections|imports_exports|authenticode|debug_info|certificates|inspect)|ir/(ingest|reader|records|pe_tables|schema|operands)|csaf/(validate|normalize|discovery)|sources/cvrf|binexport_(prescan|proto|check|run|worker|pipeline|descriptor|snapshot)|winbindex|tier_w/(msf|pe_tables|catalogue)|tier_r/(pe|debuginfo|csrc)|interpretation|normalization|/evidence\.py'),
 (5, 'subprocess/jobs', r'/jobs\.py|tools/(runner|process|diec|floss|capa)|bindiff_(run|probe)|rzdiff|scheduler|extract/runner|ghidriff|unified/worker|/backend\.py|runtime_discovery|engine_env'),
 (5, 'sqlite/persistence', r'storage|/store\.py|persistence|enrichment/cache|kbcorrelation/index|calibration/artifact'),
 (5, 'network', r'transport|netutil|net_plan|enrichment/cve|providers|tier_r/fetch'),
 (4, 'path/archive', r'quarantine|raw_cleanup|verified_backup|offline_bundle|backend_bundle|artifact_bytes|tier_w/paths|build_|provision_|release_gate|importer|exchange|/ingestion\.py'),
 (4, 'cli', r'cli|backend_cli'), (1, 'other', r'.*')]
ALREADY_AUDITED = r'acquisition/|csaf/|intelligence/tools/|enrichment/(cve|intelligence)|unified/(limits|contracts|keys|store)|/jobs\.py|secondary/(engine_env|scheduler|binexport)|/service\.py|/persistence\.py|/models\.py|/ingestion\.py|/artifact_bytes\.py'
files = sorted(p.relative_to(root).as_posix() for d in ('src/patchtrace', 'tools') for p in (root / d).rglob('*.py'))
cand = []
for f in files:
    if re.search(SKIP, f): continue
    w, cat = next((w, c) for w, c, rx in CATS if re.search(rx, f))
    cand.append((f, cat, w * 0.35 if re.search(ALREADY_AUDITED, f) else w))
random.seed(20261014)
for i, (k, f, c) in enumerate(sorted(((random.random() ** (1 / w), f, c) for f, c, w in cand), reverse=True)[:20], 1): print(i, f, c, round(k, 4))
```
