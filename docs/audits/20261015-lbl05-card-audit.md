# LBL-05 card audit, 2026-10-15

Scope: `corpus/catalog/*.json` (52 found-case cards in 3 files), `tools/calibration/tier_r/catalogue/releases.d/*.json`
(15 files, 50 cards: the 38 in `releases.json` plus the 12 in `cves.json`, 27 CVE ids), `recipes.d/*.json` (16 recipes)
and `releases.json` / `recipes.json`, which the existing split test already covers. Offline only. Network re-verification
is marked [U]. Tests: `tests/test_corpus_cards_audit.py` (103 pass, 3 strict xfail). Existing `tests/test_tier_r_catalogue.py`
and `tests/test_corpus_check.py`: 100 pass.

Method: `tools/corpus_check.py catalog` on each file; scripted cross-check of every release card's old/new (ref, commit)
against its recipe's pins, plus licence and upstream; CVE regex; per-project licence and upstream consistency; grep for
`disagree` counts; reading the licence register (`docs/plans/calibration-licences.md`).

## Results

| card / scope | check | result | evidence |
|---|---|---|---|
| all 52 `corpus/catalog` cards | schema (`case-card/1`, kind, build, verification, sources, SPDX) | pass | `corpus_check.py catalog` on 3 files: 0 findings |
| 50 cards in `releases.d` (38 release + 12 CVE) | schema | pass | `corpus_check.py catalog` on 15 files: 0 findings |
| 12 cards in `cves.json` (inside `releases.d`) | schema | pass | `check_catalog` on each `releases.d` file; existing test `test_card_kind_matches_cve_ids` passes |
| 50 cards in `releases.d` | old/new (ref, commit) resolve to a recipe pin | pass | scripted: 0 missing pins, 0 commit mismatches |
| 16 recipes | pin commits 40-hex, licence SHA-256 64-hex, no duplicate ref or commit | pass | scripted; `test_recipe_pins_are_verified_shapes` |
| 50 cards in `releases.d` | licence and upstream equal to recipe | pass | scripted: 0 mismatches |
| 16 recipes | licence matches the register | pass for 13; pcre2 mismatched; brotli and zstd absent | register rows (below) |
| pin licence hashes | recorded SHA-256 equals the licence text at each pin | [U] | recorded hashes not re-fetched (network); `license_evidence` says the text was read at each pin |
| 52 found cards | `disagree` | pass: no card carries a disagree count; 3 release files (c-ares, libdeflate, stb) state "0 disagreements" | `grep disagree` over releases.d; no non-zero count anywhere |
| releases without a recorded disagree count | `run_card` re-run | [U] | `brotli, cJSON, expat, jansson, libpng, lua, lz4, mbedtls, miniz, pcre2, zlib, zstd` record no disagree count; re-run needs the factory and fetched pins |
| 33 CVE ids (corpus/catalog) | id format `CVE-YYYY-NNNN+` | pass; all 33 unique | `test_cve_ids_are_well_formed_unique_and_match_the_audited_count` |
| 27 CVE ids (cves.json) | id format | pass; unique | scripted |
| 33 CVE ids | exist in CVE List V5, vendor/product match | [U] | `corpus_check.py` has no `--cve-list` option (the plan names one; it is not implemented). NVD, MITRE, OSV and cve.org were unreachable from the collection sandbox (card risk notes); ids come from fixing commit messages. Ids from 2026 (CVE-2026-85091, -25646, -22695, -22801, -33416, -33636, -32776..32778) are the least checkable |
| 33 CVE ids | range the CVE claims | partly recorded | the card's old/new pair is the fix pair. Only the `risks` text states affected ranges (e.g. libssh2 CVE-2019-3861 "before 1.8.1"). No per-CVE affected-version field exists in `case-card/1` |
| CVE cards | Windows-scoped CVEs annotated | open, not done | no card has a Windows-scope field; the schema has no slot. Needs an owner decision on the field before annotation |
| CVE cards | same CVE in two places | acceptable | CVE-2018-12913 (corpus miniz card and cves.json miniz 3.0.2 to e680017) and CVE-2025-52497 (corpus mbedtls card and cves.json mbedtls 3.6.3 to 3.6.4) appear with different fix pairs |
| `pcre2` recipe licence | equals the register | **open** | `recipes.d/pcre2.json` `BSD-3-Clause`; register row says `BSD-3-Clause WITH PCRE2-exception` and "do not use until fixed". Fix is in `tools/calibration`, outside LBL-05 files. xfail `test_pcre2_recipe_licence_matches_the_register` |
| `postgresql-libpq` card (CVE-2024-10977) | licence allowed | **open** | register: PostgreSQL blocked (open item 7). Card `crypto-net-db-script.json` still lists it and the checker accepts `PostgreSQL`. Plan fallback is `excluded` with a reason. Not changed: that is a decision, not a typo. xfail `test_no_found_card_uses_a_blocked_licence` |
| `brotli`, `zstd` recipes | licence register row | **open** | neither is in `calibration-licences.md` (plan Q9). brotli LICENSE reads MIT per recipe evidence. zstd recipe records BSD-3-Clause with the GPL-2.0 option not elected (LICENSE vs COPYING); that election belongs in the register. xfail `test_brotli_and_zstd_are_in_the_licence_register` |
| `libyaml` recipe | release file | informational | recipe present, no `releases.d/libyaml.json`; its 2 cards are in `corpus/catalog/parsers-media.json` |
| `zlib-contrib-minizip` | project name | informational | 2 cards use a project name with no recipe of that name; zlib recipe covers the same pins |
| `mbedtls` card | dual-licence | pass | risk note says only Apache-2.0 may be used; register agrees |
| `libpng`, `libyaml`, `expat`, etc. | licence | pass | per-project licence is single-valued across all cards (scripted) |
| plain data or typo errors in `corpus/catalog` | fixed | none found | structure and cross-file checks found nothing to fix. A full prose typo sweep was not done |

## Changes made

- `tests/test_corpus_cards_audit.py` (new): regression tests for the rows above.
- No change to `corpus/catalog/*.json`. No plain data error was found. The three open licence items need a decision or a change outside this slice.

## Decisions needed

1. Windows-scope annotation: which field and which CVEs (no data exists today).
2. PostgreSQL card: mark `excluded` with reason, or keep pending the allow-list decision (register open item 7).
3. pcre2 recipe licence: apply the register value `BSD-3-Clause WITH PCRE2-exception` (recipe and monolithic `recipes.json`).
4. brotli and zstd: add register rows (zstd: record the BSD election over GPL-2.0).
5. Network re-verification of 33 CVE ids and pin licence hashes, with `run_card` for releases lacking a disagree count: [U], needs a network-enabled run.
