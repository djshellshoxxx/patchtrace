# Corpus candidate verification audit, 2026-10-15

Scope: the 24 files `tools/calibration/catalogue/*-candidate.json` from `origin/chatgpt/corpus-1`, read-only. The candidate JSON files were not edited or committed. Plan file `docs/plans/chatgpt-corpus-1-continuation.md` was read only.

Method:
1. Extracted `upstream_url`, `source_pin.commit`, `license.license_file`, `license.spdx_election` and `license.observed_license_blob_sha` from each file. Searched every candidate for tag fields, fix-commit fields and 40-hex values.
2. Ran `git ls-remote --tags <upstream_url>` for each repo to confirm reachability and count upstream tags.
3. Fix-commit check: no candidate names a fix commit (no CVE, advisory or fix field exists), so no `git fetch --depth 1` was run.
4. Licence: recorded as CLAIMED only. The `observed_license_blob_sha` values are Git blob IDs, not commits and not licence SHA-256 values, and were not compared against any source tree.

Key finding: all 24 candidates have `source_pin.commit = null`, carry no release tag and name no fix commit. The only 40-hex value in the batch that is a commit is the plan's base commit `8af0e0effa7628f2bdf1ed8afc6d21f30e816924`, which exists locally (`git cat-file -t` returns `commit`). Because no tag or commit is claimed, no tag/commit match can be tested, and no candidate can be VERIFIED from these files.

Results of `git ls-remote --tags`: all 24 upstream URLs are reachable. Upstream tag counts: hiredis 38, http-parser 36, inih 33, jsmn 3, jsoncpp 65, libhydrogen 0, libogg 28, libspng 42, libtomcrypt 106, libtommath 126, libvterm 11, llhttp 178, monocypher 42, nanopb 148, nghttp2 269, parson 0, protobuf-c 18, pugixml 24, qoi 0, snappy 13, speex 50, tinycbor 37, tinyxml2 21, yyjson 30. The libhydrogen, parson and qoi repos have no tags (`--heads` lists branches only), so any future tag pin for them must be a commit pin.

## Table

| candidate | tag | claimed commit | actual commit | match | notes |
|---|---|---|---|---|---|
| hiredis | none claimed | null | n/a | n/a | URL reachable; 38 upstream tags; licence claimed BSD-3-Clause, COPYING |
| http-parser | none claimed | null | n/a | n/a | URL reachable; 36 tags; licence claimed MIT, LICENSE-MIT |
| inih | none claimed | null | n/a | n/a | URL reachable; 33 tags; licence claimed BSD-3-Clause, LICENSE.txt |
| jsmn | none claimed | null | n/a | n/a | URL reachable; 3 tags; licence claimed MIT, LICENSE |
| jsoncpp | none claimed | null | n/a | n/a | URL reachable; 65 tags; C++ (blocked for production per plan); licence claimed MIT, LICENSE |
| libhydrogen | none claimed | null | n/a | n/a | URL reachable; 0 tags (branches only); licence claimed ISC, LICENSE |
| libogg | none claimed | null | n/a | n/a | URL reachable; 28 tags; licence claimed BSD-3-Clause, COPYING |
| libspng | none claimed | null | n/a | n/a | URL reachable; 42 tags; licence claimed BSD-2-Clause, LICENSE; dependency pin also null |
| libtomcrypt | none claimed | null | n/a | n/a | URL reachable; 106 tags; licence claimed Unlicense, LICENSE; same licence blob ID as libtommath |
| libtommath | none claimed | null | n/a | n/a | URL reachable; 126 tags; licence claimed Unlicense, LICENSE |
| libvterm | none claimed | null | n/a | n/a | URL reachable; 11 tags; licence claimed MIT, LICENSE |
| llhttp | none claimed | null | n/a | n/a | URL reachable; 178 tags; licence claimed MIT, LICENSE |
| monocypher | none claimed | null | n/a | n/a | URL reachable; 42 tags; licence claimed BSD-2-Clause, LICENCE.md |
| nanopb | none claimed | null | n/a | n/a | URL reachable; 148 tags; licence claimed Zlib, LICENSE.txt |
| nghttp2 | none claimed | null | n/a | n/a | URL reachable; 269 tags; licence claimed MIT, COPYING; subset recipe only |
| parson | none claimed | null | n/a | n/a | URL reachable; 0 tags (branches only); licence claimed MIT, LICENSE |
| protobuf-c | none claimed | null | n/a | n/a | URL reachable; 18 tags; licence claimed BSD-2-Clause, LICENSE |
| pugixml | none claimed | null | n/a | n/a | URL reachable; 24 tags; licence claimed MIT, LICENSE.md |
| qoi | none claimed | null | n/a | n/a | URL reachable; 0 tags (branches only); licence claimed MIT, LICENSE |
| snappy | none claimed | null | n/a | n/a | URL reachable; 13 tags; licence claimed BSD-3-Clause, COPYING |
| speex | none claimed | null | n/a | n/a | URL reachable; 50 tags; licence claimed BSD-3-Clause, COPYING |
| tinycbor | none claimed | null | n/a | n/a | URL reachable; 37 tags; licence claimed MIT, LICENSE |
| tinyxml2 | none claimed | null | n/a | n/a | URL reachable; 21 tags; licence claimed Zlib, LICENSE.txt |
| yyjson | none claimed | null | n/a | n/a | URL reachable; 30 tags; licence claimed MIT, LICENSE |

## Verdicts

Counts: VERIFIED 0, REJECTED 0, NEEDS-OWNER 24.

VERIFIED: none.

REJECTED: none. No claimed tag or commit exists to contradict, and every upstream URL is reachable.

NEEDS-OWNER (all 24, each needs a tag or commit pin chosen and checked, plus licence verification at that pin, and a fix-commit source if the project needs CVE pairs):
- hiredis
- http-parser
- inih
- jsmn
- jsoncpp
- libhydrogen
- libogg
- libspng
- libtomcrypt
- libtommath
- libvterm
- llhttp
- monocypher
- nanopb
- nghttp2
- parson
- protobuf-c
- pugixml
- qoi
- snappy
- speex
- tinycbor
- tinyxml2
- yyjson
