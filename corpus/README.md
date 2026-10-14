# Corpus inputs: found open-source cases and our own synthetic suites

Purpose: material with EXACT, human-free answers ("this function is the same / changed / cosmetic / added ...") for testing
and calibrating PatchTrace's diff engines. The factory in `tools/calibration/tier_r/` (spec: `docs/specs/known-answer-corpus.md`)
builds these inputs into Windows x64 images and checks the declared truth against the built images. Nothing here is a binary.

Validate everything with `python tools/corpus_check.py all` (needs clang for the compile/function checks; exit 3 = BLOCKED,
never "passed"). One suite: `python tools/corpus_check.py suite corpus/ours/<suite>/<project>`; one catalog:
`python tools/corpus_check.py catalog corpus/catalog/<file>.json`.

## 1. `corpus/catalog/<category>.json`: found open-source cases (`case-card/1`)
A JSON array of cards. Every fact must be verified by running git (shallow clone into the scratchpad), not recalled.
```json
{"contract": "case-card/1", "id": "zlib-1.3-to-1.3.1", "project": "zlib",
 "upstream_git": "https://github.com/madler/zlib.git",
 "license_spdx": "Zlib", "license_evidence": "LICENSE at <commit>: 'This software is provided as-is ...'",
 "old": {"ref": "v1.3", "commit": "<40 hex>"}, "new": {"ref": "v1.3.1", "commit": "<40 hex>"},
 "kind": "release", "cve": [], "semantic_change": true,
 "changed_functions": [{"name": "inflateSync", "file": "inflate.c", "change": "shift direction fixed"}],
 "unchanged_controls": ["adler32", "crc32"],
 "build": {"system": "cmake", "recipe_notes": "cmake -DBUILD_SHARED_LIBS=ON; no deps", "mingw_ok": "unknown"},
 "verification": {"method": "git diff --stat v1.3..v1.3.1 -- '*.c' '*.h'", "files_changed": 12,
                  "functions_changed_count": 3, "verified_by_agent_run": true},
 "sources": ["https://github.com/madler/zlib/releases/tag/v1.3.1"], "risks": []}
```
`kind`: release | cve-fix | constant-only | bounds-only | refactor-control | large-rewrite | build-system-only | no-op.
Controls (`refactor-control`, `no-op`, `build-system-only`) set `"semantic_change": false` and list what did not change.
Licence must be one of the SPDX ids the checker allows; unknown or copyleft = do not use.

## 2. `corpus/ours/<suite>/<project>/`: our own synthetic code (`suite/1`)
MIT-licensed code written for this repo, FREESTANDING C11: no libc, no system headers (only stddef/stdint/stdbool/stdarg/
limits/float/iso646/stdalign/stdnoreturn), no inline assembly, no OS calls; it must compile with
`clang -std=c11 -ffreestanding -fsyntax-only -Wall -Wextra`. Every function has external linkage (no `static`, except a
deliberate `static inline` used to provoke inlining, tagged N4), unique names across the whole version, one definition per
name. Layout: `suite.json` plus one directory per version holding `.c`/`.h` files (<= 120 KB per file, <= 400 KB per version).
Make the code look like real code (parsers, allocators, checksums, state machines, small VMs), not toy one-liners.
```json
{"contract": "suite/1", "suite": "cwe-patterns", "project": "ringbuf", "license_spdx": "MIT",
 "summary": "...", "versions": ["v1", "v2", "v3"], "build": {"kind": "freestanding-dll", "defines": []},
 "pairs": [{"old": "v1", "new": "v2", "intent": "what changed and why",
   "truth": [{"function": "rb_push", "label": "changed", "kind": "bounds-check-added", "taxonomy": ["N6"], "notes": "..."}]}]}
```
Truth labels (EVERY function defined in either version appears exactly once per pair):
`same` (source text identical), `changed` (semantics differ; give `kind`), `cosmetic` (text differs, semantics identical),
`moved` (same function in another file), `added`, `removed`, `renamed` (`from`, `to`), `split` (`from`, `to`: list),
`merged` (`from`: list, `to`), `inlined` (`function` folded into `into`). The checker enforces text-identical for `same` and
text-different for `cosmetic`/`changed`.
`kind` for `changed`: bounds-check-added | bounds-check-removed | constant-change | comparison-change | call-added |
call-removed | arg-order-change | loop-bound-change | type-width-change | lock-added | lock-removed | null-check-added |
lifetime-fix | auth-check-added | path-normalization | format-string-fix | error-handling-change | algorithm-change |
large-rewrite | other.
Optional `taxonomy` tags (calibration spec 5.4): N1 near-duplicate/templated, N2 thunk/wrapper, N3 shared helper code,
N4 inlined/split/merged, N5 address-coincidence after layout shift (reorder definitions), N6 similar CFG but different
semantics, N7 added/removed that could be mis-paired, N8 unrelated control, N11 table/switch dominated, N12 large rewrite
that is still the same function. Add a `README.md` per suite explaining the design and which strata it covers.

## Rules
No binaries, no generated files, no network access inside suites. Deterministic text only. Do not copy third-party code into
`ours/` (write it yourself). Every fact in a case card must come from a primary source and a real command.
