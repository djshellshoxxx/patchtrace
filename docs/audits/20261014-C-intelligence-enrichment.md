# Audit C: intelligence (CSAF, lexicon, tools) and enrichment CVE/transport (2026-10-14)

Scope: `src/patchtrace/intelligence/**` (contracts, csaf/{validate,normalize,identity,applicability,transport,
discovery}, lexicon, hypotheses, anchors, storage, tools/{common,process,normalize,capa,floss,diec,delta}),
`src/patchtrace/enrichment/{intelligence,cve}.py` and the `correlate` consumer in `cli.py`. Specs read:
`docs/specs/csaf-cve-interpretation-engine.md` (REGISTRY alias SPEC-35), `three-tool-evidence-adapters.md`
(SPEC-36), `enrichment.md` and `enrichment-hardening-backlog.md` (SPEC-07/07h), AGENTS.md invariants,
`docs/modules.md`. The checkout is the worktree at `1560531`.

Method: code reading, reproductions run with Python 3.13 in a worktree (nothing under `src/` modified; scratch
scripts live outside the repo), plus a structure-aware mutation fuzzer over the three CSAF fixtures (about
130k mutated documents through `load_document`, `normalize`, `lexicon.classify`, `anchors_for`). Baseline: the
215 existing tests of `test_intel_{applicability,validate,transport,discovery,storage}`, `test_enrichment_cve`
and `test_enrichment_intelligence` all pass. Nothing was run on Windows; Windows conclusions are marked
unverified. No network was used; the live MSRC/NVD checks remain blocked.

Counts: **0 High, 9 Medium, 15 Low, 3 Info.**

## Findings

| ID | Sev | Location | Summary (concrete failing input) |
|---|---|---|---|
| C-01 | Medium | csaf/validate.py:374 | `scores[0].cvss_v3.baseSeverity: ["HIGH"]` raises `TypeError: unhashable type: 'list'` out of `load_document`; `fetch_documents` only catches `IntelError`, so one hostile candidate aborts the whole fetch/batch |
| C-02 | Medium | csaf/validate.py:337, 492-494 | `vulnerabilities[0].product_status.x_extension: 5` (an additional property is only a 6.2.20 warning, then trusted as a list) raises `TypeError: 'int' object is not iterable` |
| C-03 | Medium | csaf/applicability.py:265-269 | A newer revision that drops the CVE leaves the older revision "current": supersession is computed only over documents that list the CVE |
| C-04 | Medium | enrichment/cve.py:491-502 | One BND signal is counted twice for an advisory listing CWE-787 and CWE-125 (+20 from one observation); `test_caps_identifier_cwe_and_total` locks this in |
| C-05 | Medium | enrichment/cve.py:162,289; cli.py:352 | A provider body with a lone surrogate (`"\ud800"`) passes strict JSON, then raises a raw pydantic `ValidationError` (not `EnrichmentError`); `correlate --fetch` ends in a traceback and the other provider's valid data is lost |
| C-06 | Medium | intelligence/anchors.py:39-42,75-78 | Vulnerability title `<i></i> Remote Code Execution Vulnerability` yields an empty component anchor, `Anchor(value='')` raises `ValidationError` from `anchors_for` |
| C-07 | Medium | intelligence/lexicon.py:178,228-233 | "Heap-based buffer overflow requires no user interaction." marks the real weakness as negated (trailing cue `no` within 3 tokens), so CWE-122 is dropped and the status becomes vague |
| C-08 | Medium | csaf/validate.py:127-175 | Limits are applied after a full parse: a 15 MB `[{},{},...]` takes 16 s and 758 MiB RSS before "more than 2000000 JSON values", with no cancel point |
| C-09 | Medium | cli.py:381-387 | `correlate --snapshot` reads files with plain `json.loads`: duplicate keys last-wins, `NaN` accepted, no size bound (AGENTS.md: import only strict JSON) |
| C-10 | Low | enrichment/cve.py:146-148 | `_CWE.match` is a prefix match: `CWE-1234567` becomes `CWE-123456`, `CWE-787-foo` becomes `CWE-787` (invented identifiers) |
| C-11 | Low | enrichment/cve.py:287 | `data[field][:MAX_LIST]` silently keeps 64 of 100 NVD references; status stays complete, no truncation marker |
| C-12 | Low | csaf/applicability.py:129-132 | Same-product-name detail embeds `origin.product_id` unclipped (CSAF ids are unbounded): a 600-char id makes `resolve` raise `ValidationError` (detail max 500) |
| C-13 | Low | csaf/normalize.py:182 | Lone surrogate in advisory text is reported as `PT-INTEL-LIMIT` ("exceeds the normalized contract bounds"), wrong code; the validator docstring claims strict UTF-8 JSON |
| C-14 | Low | tools/delta.py:139-156 | A rule matching in function A on both sides and newly in function B is `unchanged` (key `(kind, rule_id, scope)`); spec T6.2 asks for exactly this key, but it hides added locations |
| C-15 | Low | tools/floss.py:299,325-335 | FLOSS `metadata.imagebase` is used for RVAs without comparing to the header ImageBase; capa records `base-differs` (capa.py:411), FLOSS does not |
| C-16 | Low | tools/process.py:37-46 | `sanitize` leaks Windows user names containing a space and keeps bidi/zero-width/C1 characters in `ToolRun.error`; `display_text` is not used |
| C-17 | Low | tools/diec.py:233-241 | `toolchain`, `packer`, `protector` are unsanitized tool text (the other fields use `sanitize`); they flow into `QualityFlag.detail` |
| C-18 | Low | tools/common.py:360 | `load_json_strict` accepts `1e999` as `inf`; spec T5.1 rejects NaN/Infinity (validate.py handles this case) |
| C-19 | Low | tools/common.py:52,183 | `_FUNCTION_ID` with `$` and `.match` accepts `'rva:0x10\n'` |
| C-20 | Low | tools/delta.py:261 | `compute(None, None, None, None)` raises `AttributeError` instead of a not-comparable delta |
| C-21 | Low | intelligence/storage.py:137-149 | `_facts` never checks `facts.source_id == source.sha256` or the row's `facts_id` after the hash check; a row pointing at another valid facts file is served for the wrong source |
| C-22 | Low | csaf/transport.py:173-198,271 | `OfflineCache.put` raises raw `OSError` (not `IntelError`) and makes a successful fetch fail; `urls.json` read-modify-write has no lock; cached bodies are not capped per kind |
| C-23 | Low | enrichment/cve.py:165-168,241-245 | NVD Primary and Secondary CWEs are one provider list, so NVD `{787, 119}` vs MSRC `{787}` is reported as a cross-provider `cwe:` conflict (H12 exempts this for CVSS only) |
| C-24 | Low | enrichment/cve.py:124-129,187-195 | One over-long element (reference URL > 2000 chars) makes the whole provider response `PT-ENRICH-LIMIT` instead of dropping that element |
| C-25 | Info | src/** docstrings, docs/modules.md | 20 source files cite SPEC-28/SPEC-29, numbers REGISTRY re-assigned (CSAF = SPEC-35, tools = SPEC-36); REGISTRY says "none on main" for both |
| C-26 | Info | tasks/todo.md:108,117 | Not built: `intelligence/{cli,reports}.py`, `tools/{runner,store,cli}.py`; consent flags, exit codes and redaction are specified but untestable today |
| C-27 | Info | transport.py, process.py | Windows (unverified): environment/registry proxies are always ignored; sidecar paths of 90+ chars on top of the project root; junction handling in `_tree_entries` |

## Verified correct (no finding)

- Allow-lists: `check_url` (csaf) and `_check_url` (NVD/MSRC) reject userinfo, port, query/fragment, `%`, `\`, `..`, `//`,
  non-https, and are re-run on every redirect hop; the NVD key header is dropped on a cross-host hop; proxies are ignored;
  response caps are enforced while streaming, not only via `Content-Length`; retries obey the 60 s rule.
- Consent: `CsafConsent.for_hosts` accepts only `msrc.microsoft.com`; `CsafTransport` refuses to run online without consent;
  FLOSS emulation needs the consent digest; no data about the project is sent.
- Vendored schema patterns: no ReDoS on 1.6k to 6.4k character adversarial inputs for the CPE, PURL, language and version
  patterns (<= 6 ms).
- Mutation fuzzing found exactly two crash classes (C-01, C-02). `normalize`, `classify` and `anchors_for` produced only
  `IntelError` on everything the validator accepted, except C-06.
- "Missing is unknown" holds in applicability (an unmapped side abstains, a missing status is `unknown`), in
  `cve.normalize` (a missing score is `None`) and in tool evidence (`absent`/`failed` is never a negative vote).
- No code path averages engines or providers; scores are fixed integer points with a cap of 30.

## Details and reproductions

Run from the worktree root; each snippet needs `sys.path.insert(0, 'src')`.

### C-01 and C-02: validator crashes on schema-valid-looking input
```python
d = json.loads(Path('tests/fixtures/csaf/synthetic-advisory-rev1.json').read_text())
d['vulnerabilities'][0]['scores'][0]['cvss_v3']['baseSeverity'] = ['HIGH']
validate.load_document(json.dumps(d).encode())          # TypeError: unhashable type: 'list'
d = json.loads(...rev1...); d['vulnerabilities'][0]['product_status']['x_extension'] = 5
validate.load_document(json.dumps(d).encode())          # TypeError: 'int' object is not iterable
```
A string value (`'PT-100-1'`) iterates characters and fails 6.1.1 with misleading ids. Fix: use `isinstance(..., str)`
before the set lookup in `_cvss`; in `_references` and `t_6_1_6` skip product_status keys that are not in
`PRODUCT_STATUSES` or whose value is not a list of strings; add a hypothesis/mutation test asserting that
`load_document` raises only `IntelError`. `discovery.fetch_documents` should also treat an unexpected exception from one
candidate as a rejected candidate.

### C-03: superseded claims stay current
Repro: `rev2` with the CVE-2099-10001 item removed, stored beside `rev1`; `resolve('CVE-2099-10001', [f1, f2], ...)`
returns `older.resolution == 'affected'`, `superseded_sources == ()`, statuses `superseded=False`, while
`supersession([f1, f2])` over all documents is `[True, False]`. `storage.advisories()` computes it over all documents
(storage.py:180); `resolve` recomputes over `relevant` (applicability.py:265-269). Expected: pass the full supersession
map (or all documents) into `resolve`, and report a "revision withdrew this CVE" unknown. Also add a test.

### C-04: one signal counted under several CWE labels
```python
sets = [sset('x', [sig('BND', 'moderate', 'x', '1')])]; ranking = rank(sets, RankingConfig())
# MSRC cweList ['CWE-787']            -> adjustment 10, one cwe contribution
# MSRC cweList ['CWE-787','CWE-125']  -> adjustment 20, two contributions, both binary_ref == same signal
```
SPEC-35 step 6 says shared-origin observations must not be counted twice. `CWE_DETECTORS` maps 14 CWEs onto five
detector pairs, so any advisory with sibling CWEs (787 plus 122/120 is routine for Microsoft) double-counts the same
BND/SIZE signal. Fix: track consumed `signal_id`s across the CWE loop (one cwe contribution per signal) and invert the
test assertion `kinds.count('cwe') == 2`.

### C-05: lone surrogate in a provider body
`cve.normalize('CVE-2099-0001', {'nvd': body_with_"\ud800"}, ...)` gives
`ValidationError ... AttributedText.text unable to parse raw data as a unicode string`. `_normalize_available` and
`cmd_correlate` catch only `EnrichmentError`, so (by inspection of the call path; the CLI was not run end to end) the command ends in
a traceback instead of a `CliError`, and `--fetch` discards both providers. Fix: reject lone surrogates in `_strict_json`
(walk strings, `PT-ENRICH-PROVIDER`), or wrap model construction in `normalize`. The same input in CSAF is C-13.

### C-06: empty anchor
```python
t['vulnerabilities'][0]['title'] = '<i></i> Remote Code Execution Vulnerability'
anchors.anchors_for('CVE-2099-10001', [facts(t)])   # ValidationError: Anchor.value too_short
```
`_TAG.sub(' ', title)` creates leading whitespace, `_TITLE` matches `component=' '`, `_anchor` collapses it to `''`.
Fix: skip empty values in `_anchor` callers and `.strip()` the component before matching. One malformed title kills
`explain` for every document of that CVE.

### C-07: trailing negation cue
`lexicon._scan('Heap-based buffer overflow requires no user interaction.', '/x')` gives `heap-overflow, negated='no'`.
The after-window (AFTER=3) has no clause boundary for "requires". Common MSRC phrasing ("no user interaction",
"without authentication") therefore negates the weakness it describes. Fail-safe (the result degrades to `unknown`),
but wrong: the hit is listed as negated evidence. Suggest limiting after-cues to a small set (`not`, `cannot`,
`never`) and requiring adjacency, plus negative tests for "requires no", "without authentication".

### C-08: limits after parse
`parse_json` runs `json.loads` on the whole text and only then `_check_shape`. Measured with 5M `{}` in 15 MB:
16.1 s, peak RSS 758 MiB, then `PT-INTEL-LIMIT`. Cancellation is not observed. On a 16 MiB document cap that is a
realistic hang/oom for a hostile mirror or file. Mitigation: pre-scan bracket depth and element count on the bytes
(cheap, iterative) before `json.loads`; poll `cancel` in `_check_shape`; consider `max_nodes` 500k.

### C-09: non-strict snapshot import
`cmd_correlate` loads `--snapshot` with `json.loads(path.read_text())`, then `CveSnapshot.model_validate_json`.
`{"cve_id": "...", "cve_id": "..."}` is accepted (last wins), `NaN` parses, a 2 GB file is read whole, and
`snapshot_id`/`response_digests` are never recomputed. The CLI warns that such snapshots are unverified, but the
duplicate-key and size rules of the other importers are not applied. Reuse `cve._strict_json` plus a size cap.

### C-10, C-11, C-23, C-24: normalization fidelity
```python
cve._cwe_ids(['CWE-1234567', 'CWE-787-foo', 'CWE-20abc'])   # ['CWE-123456', 'CWE-787', 'CWE-20']
```
Use `fullmatch`. For C-11 the 100-reference NVD body returns `len(snap.advisories) == 64`, `conflicts == ()`; add a
`truncated` marker or raise `limit` rather than dropping silently. C-24: a 2500-character reference URL gives
`PT-ENRICH-LIMIT: reference url exceeds 2000 characters` for the entire NVD response.

### C-12 and C-13
`ap.resolve` with docs A, B (B renames PT-100-2 to a 600-character id) and `asserted_product_ids=[long_id]` raises
`ValidationError ... ProductMapping.detail should have at most 500 characters`. Clip with `[:500]` like line 102.
For C-13 `load_document` accepts `"\ud800"` and `normalize` reports `PT-INTEL-LIMIT`; reject in `parse_json` with
`PT-INTEL-FORMAT`.

### C-14 to C-20: tool adapters
- C-14: by design per T6.2; if the key stays, add a per-location pass (added matches in functions paired as added or
  modified) so the purpose of the delta is not defeated by a rule that already fires elsewhere.
- C-15: compare `doc.metadata.imagebase` with `ctx.pe.image_base` and add `base-differs`, as capa does.
- C-16: `sanitize('error opening C:\\Users\\John Smith\\AppData\\Local\\x.dll')` returns
  `'error opening John Smithx.dll'` (user name kept, path pieces glued), and
  `sanitize('failed \u202egnp.exe\u202c \u0085 end \u200b')` keeps U+202E and U+200B. Run the result through
  `display_text` and match paths with spaces (quote-aware or drive-anchored).
- C-17: pass `label` through `process.sanitize` before it is stored.
- C-18/C-19/C-20 reproduced as stated (`load_json_strict(b'{"a": 1e999}')` returns `{'a': inf}`;
  `EvidenceLink(function_id='rva:0x10\n', rva=16, attribution='function-start')` is accepted;
  `delta.compute(None, None, None, None)` raises `AttributeError`). Use `fullmatch`, `parse_float` with a finite check,
  and an early `not comparable` return.

### C-21, C-22: storage and cache
- `AdvisoryStore._facts` returns whatever `AdvisoryFacts` the hash-verified file contains. Check
  `facts.source_id == source.sha256 and facts.facts_id == facts_id` and fall back to recomputation otherwise
  (the fallback already exists).
- `OfflineCache.put` is called inside `CsafTransport.get` after a good response; a full disk, antivirus lock or
  read-only cache dir turns into `OSError` from `get`. Catch `OSError` in `put` (warn, continue) and lock the map update.

## Missing tests for stated invariants

| Invariant | State |
|---|---|
| Shared-origin observations count once (SPEC-35 step 6) | No test; `test_caps_identifier_cwe_and_total` asserts the opposite (C-04) |
| Never average / never merge engines | Holds by construction; no explicit test in `test_enrichment_cve.py` or `test_intel_applicability.py` |
| Missing is unknown | Covered for status and score; not for withdrawn CVE (C-03) or missing provider CWE |
| CSAF validator raises only `IntelError` | No property test; fuzzing found C-01, C-02. The mutation harness is about 70 lines and takes 25 s per 15k documents |
| Untrusted text escaped | `display_text` is tested; `process.sanitize` and diec labels are not tested with bidi/C1/surrogates (C-16, C-17) |
| Windows path sanitization | No test with spaces in a profile name |
| Hostile document in a batch fetch | `test_intel_discovery.py` covers schema rejects, not an unexpected exception from one candidate |

## Suggested order

1. C-01, C-02 (one `isinstance` fix each, plus catch-all per candidate in `fetch_documents`), C-05, C-06: crashes.
2. C-03, C-04, C-07: they change user-visible conclusions.
3. C-08, C-09: resource bounds and strict import (AGENTS.md).
4. Remaining Low items in one hardening commit with the red/green tests above; C-25 can ride with the next spec edit.
