# Real-world patch candidates: evidence audit and bounded expansion

Research date: 2026-10-30 (UTC). Scope: R1 Tier E, reusing SPEC-32/Tier R and `case-card/1`. This is a read-only audit of catalogue data plus a bounded primary-source verification pass. It does not add cases, alter recipes, rebuild upstream targets, or claim a new real-engine benchmark. The integration owner's current run receipts and baseline report take precedence over historical run claims summarized here.

## Findings and acceptance boundary

The existing corpus has enough documented security candidates and project diversity to avoid collecting a new dataset. It does **not** establish a validated 14-project, three-consecutive-pair benchmark. The next useful action is to build a small, independently reviewed subset with the existing factory, preserve its source/build/label receipts, and evaluate the genuine Ghidriff baseline before enlarging it.

At the inspected checkout:

| Inventory | Count | What this establishes |
|---|---:|---|
| `corpus/catalog/*.json` | 51 cards, 24 project labels | Found source cases, including 22 `cve-fix` cards; these are not 51 built pairs |
| Tier R `releases.json` | 38 cards | Ordinary release comparisons; security fixes can still be present in a release marked `release` |
| Tier R `cves.json` | 13 cards | Factory-oriented security release comparisons across six projects |
| Union | 102 distinct IDs and 102 distinct repository/old/new commit edges | 35 `cve-fix` cards, 26 project labels, 25 distinct upstream repositories |
| Tier R recipes | 16 projects | Build configurations and exact source/license pins, not proof of current fetch/build success |
| Tier R split card files | 15 project files | Mirror of the 51 consolidated cards; **do not add these to the consolidated counts** |
| Tier R graph with at least three connected selected edges | 6 projects | c-ares, jansson, lz4, mbedtls, stb, zlib; this is weaker than three adjacent upstream releases |
| Real-world evaluation reproduced in this audit | 0 | This research worker did not execute any target or matching engine |

`zlib-contrib-minizip` shares the zlib upstream repository and must stay in the same project/lineage partition. Counting those names as two independent projects exaggerates diversity. The 25-repository inventory exceeds the 14-project discovery target, but only 16 have recipes, and several historical security pairs are outside the pins of the otherwise matching project recipe.

The 35 security cards document candidate comparisons, not 35 independently accepted vulnerability labels. Some cards bundle multiple CVEs and unrelated release changes. Counting every CVE identifier in a single release as a separate experimentally validated case would be misleading. Two particularly weak associations (Brotli and miniz) require quarantine from security-function scoring, discussed below.

## Evidence levels used in this audit

A case progresses through five distinct states. These are research status descriptions, not new serialized contracts.

1. **Catalogued:** strict card exists with source URLs, full old/new commits, license evidence and proposed changed functions.
2. **Fetched:** both exact commits have current verified fetch receipts, including the license-file SHA-256 expected by the recipe. A recipe pin or a card's `verified_by_agent_run` flag alone is insufficient.
3. **Built:** compiler identity, flags, dependency pins and both image hashes exist in build receipts; stripping and symbol-bearing counterparts are bound to the same build. A historical prose claim is identified as historical, not reproduced.
4. **Independently labelled:** source identity and patch intent are reviewed independently of the engine; debug ranges and binary body facts establish which source changes survive this configuration. Inlining, duplicate symbols, macros, missing source spans and architecture-specific code remain explicit uncertainties.
5. **Real-engine evaluated:** genuine engine output is hash-bound to both images and scored against accepted labels. Mock outputs, a successful build and a zero-disagreement comparison against declarations derived from the same factory are not evidence of engine accuracy or independent manual review.

The existing cards often preserve valuable previous source inspection and factory summaries. This audit retains that provenance while avoiding promotion of those summaries to new live observations. In particular, `docs/qa.md` `[LBL-02-04:tranche-recipes]` records 13 real MinGW GCC 13-win32 O2 builds (libdeflate 5, stb 4, c-ares 4) plus byte-identical A/A checks at libdeflate v1.19, stb_image-2.26 and cares-1_28_0 on 2026-10-15. It also says the c-ares security commit pair was not built and real MSVC was unverified. The declarations for those 13 cards were taken from the factory labels; that agreement is useful harness evidence but not a separate oracle. The exact old binaries, hashes and labels were not recovered or rechecked by this worker.

The Tier R security cards themselves record earlier factory runs with ambiguity counts. Those claims are reported below as inherited build/label evidence. They do not establish that the external store is available now, that another compiler gives the same labels, or that Ghidriff, BinDiff, rz-diff or the unified engine was run on those pairs.

## Fourteen-project coverage and three-pair interpretation

For a reproducible chain, three pairs means four exact source revisions, with the newer side of each edge equal to the older side of the next. For *consecutive releases*, also prove from upstream tag/release history that no intervening relevant release was skipped. Three disjoint adjacent release pairs do not form a longitudinal chain. Three arbitrary selected edges do not prove release adjacency.

The following matrix covers all 16 recipe projects; this is the cheapest expansion pool. Counts refer to consolidated Tier R cards, so `libyaml`'s two found cards appear separately. Full 40-hex revisions and license hashes are reproduced in the pin ledger below.

| Project | Existing Tier R pairs; longest connected chain | Concrete least-work expansion | Build scope and uncertainty |
|---|---|---|---|
| c-ares | 4; 4 | Reuse 1.27.0 → 1.28.0 → 1.28.1 → 1.29.0 (plus 1.30.0) | Historical O2 builds; Windows import libraries `ws2_32`, `iphlpapi`, `advapi32`; security parent/merge pins also exist but were not built in QA |
| jansson | 4; 3 | Reuse 2.13.1 → 2.14 → 2.14.1 → 2.15.0 | Explicit generated config headers; confirm release adjacency and config equivalence |
| lz4 | 3; 3 | Reuse 1.9.2 → 1.9.3 → 1.9.4 → 1.10.0 | Core library, not CLI; historical bounds/refactor commit pairs need additional recipe pins |
| mbedtls | 4; 3 | Reuse 3.6.2 → 3.6.3 → 3.6.4 → 3.6.5 | LTS source tree; network file excluded and entropy configuration modified for static-only fixtures; broad release diffs and many ambiguous labels |
| zlib | 3; 3 | Reuse 1.3 → 1.3.1 → 1.3.1.2 → 1.3.2; verify whether intermediate release convention meets the intended policy | Explicit C subset; dependency for libpng; gzip/minizip case coverage is a separate inclusion check |
| stb | 4; 4 | Existing snapshots form a selected chain; choose consecutive **component** versions if adjacency is required | No upstream tags; existing labels use image version bumps 2.23, 2.26, 2.27, 2.28, 2.30, which skip versions. Historical CVE pair is Vorbis, not those image bumps |
| expat | 4; 2 | Add 2.6.2 → 2.6.3 found card to existing 2.6.0 → 2.6.1 → 2.6.2 | Both endpoint pins already exist; zero new releases required; preserve CVE vs ordinary-change attribution |
| cJSON | 3; 2 | Add missing 1.7.15 → 1.7.16 edge; found 1.7.16 → 1.7.17 plus Tier R 1.7.17 → 1.7.18 → 1.7.19 form another chain | Six pins already exist. Single C file is the smallest security pilot; declarations still require binary survival review |
| pcre2 | 2; 2 | Include found security 10.45 → 10.46 with existing 10.46 → 10.47 → 10.48 | Both security pins already exist; 8-bit recipe, generated headers/chartables; JIT sources/config differ by version and later JIT-only case may not survive this recipe |
| libpng | 5; 1 | Existing found 1.6.41 → 1.6.42 → 1.6.43 plus Tier R 1.6.43 → 1.6.44 supplies a chain | zlib 1.3.1 dependency pinned; simplified API vs low-level API and ARM Neon fixes need separate applicability checks |
| libdeflate | 5; 2 | Add 1.17 → 1.18 between existing 1.15 → 1.16 → 1.17 and 1.18 → 1.19 → 1.20 | Eight pins already exist; historical O2 builds; nonsecurity compression tuning is valuable material-change control |
| lua | 3; 2 | Add a verified predecessor to 5.4.6 → 5.4.7 → 5.4.8, e.g. choose 5.4.5 after upstream pin/license verification | Existing separate 5.3.5 → 5.3.6 does not close the gap; security debug-function commit pair not in recipe pins |
| zstd | 3; 2 | Add the release immediately preceding 1.5.5 or following 1.5.7 after upstream pin/license verification | Existing 1.4.9 → 1.5.0 is disjoint; recipe disables assembly and omits dictBuilder, legacy, threading |
| brotli | 3; 2 | Add 1.0.8 → 1.0.9; all four 1.0.7–1.1.0 pins exist | First establish actual security-fix commit ancestry; current declared changed set is encoder-heavy despite decoder CVE |
| miniz | 1; 1 | Choose three adjacent official release edges from already pinned 2.1.0, 2.2.0, 3.0.0, 3.0.2, 3.1.0 only after adjacency review | Existing factory labels all ambiguous for security pair; file-level `extern "C"` source-span limitation; do not count as accepted security pilot |
| libyaml | 0 Tier R; 2 found pairs | Existing 0.2.3 → 0.2.4 → 0.2.5; obtain a fourth adjacent release pin if available | Recipe exists; its three pins support only two edges. Do not fabricate an additional release |

Six projects have selected Tier R chains of three or more edges. Combining already catalogued found edges yields chains for cJSON, expat, libpng and pcre2 too, without new source pins. This makes ten *selected-chain* projects, not proof of ten verified consecutive-release projects. libdeflate and Brotli need only missing edges over existing pins, while Lua/zstd need a fourth revision in one chosen series. A 14-project candidate expansion can therefore prioritize those projects and defer miniz/libyaml without changing their status or substituting synthetic cases. Whether each series is genuinely consecutive must be checked before marking the goal met.

## Security cases and exact provenance

The tables below preserve all 35 security cards so the existing 15-case goal can be audited without choosing convenient examples after seeing engine output. `F` denotes found cards in `corpus/catalog/`; `T` denotes factory-oriented cards in Tier R `cves.json`. Full pair pins are authoritative for identity; labels below are inherited proposed source/function sets, not a new adjudication.

In the build column, **both pins** means the existing recipe contains both commits; **project only** means a recipe exists but this exact pair is missing one or both pins; **no recipe** means a recipe is absent. These are availability checks, not execution results. `T` cards carry historical factory summaries; see the caveats after the table.

### Found security cases

| Case and CVEs | Exact old → new commit | Declared affected functions | Recipe coverage; evidence |
|---|---|---|---|
| [`libarchive-zip-mac-metadata-cve-2016-1541`](https://github.com/libarchive/libarchive/commit/d0331e8e5b05b475f20b1f3101fe1ad772d7e7e7); CVE-2016-1541 | `11855358b842491568afd3e37203e4879c351c47` → `d0331e8e5b05b475f20b1f3101fe1ad772d7e7e7` | `zip_read_mac_metadata` | no recipe; F inherited source inspection |
| [`libarchive-rar-run-filters-cve-2024-26256`](https://github.com/libarchive/libarchive/commit/b7b0c7c4379531206a53634a12a02a8d45b28a2f); CVE-2024-26256 | `13e8fc669bc53b563109e85515160d0a6f245e6c` → `b7b0c7c4379531206a53634a12a02a8d45b28a2f` | `run_filters` | no recipe; F inherited source inspection |
| [`libarchive-rar-lzss-copy-cve-2024-20696`](https://github.com/libarchive/libarchive/commit/eac15e252010c1189a5c0f461364dbe2cd2a68b1); CVE-2024-20696 | `576a24205050a0ce5f8209f13bc1d94912797883` → `eac15e252010c1189a5c0f461364dbe2cd2a68b1` | `copy_from_lzss_window_to_unp`, `read_data_compressed` | no recipe; F inherited source inspection |
| [`libarchive-tar-unzip-null-cve-2025-1632`](https://github.com/libarchive/libarchive/commit/c9bc934e7e91d302e0feca6e713ccc38d6d01532); CVE-2025-1632, CVE-2025-25724 | `52e0bfd750cb8ae7b7c7656c35020118efa28427` → `c9bc934e7e91d302e0feca6e713ccc38d6d01532` | `list_item_verbose`, `list` | no recipe; F inherited source inspection |
| [`zlib-minizip-miniunz-zip-slip-cve-2014-9485`](https://github.com/madler/zlib/commit/14a5f8f266c16c87ab6c086fc52b770b27701e01); CVE-2014-9485 | `44dc43ab047d65febed972a17b0e3bf7e994e8f2` → `14a5f8f266c16c87ab6c086fc52b770b27701e01` | `do_extract_currentfile` | no recipe; F inherited source inspection |
| [`zlib-gzwrite-nonblocking-overflow-cve-2026-85091`](https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148); CVE-2026-85091 | `bbc2ccf3d0de267576b524b875c769a724a513b0` → `df84af25dc1942490e1d1c899a07619152a46148` | `gz_write` | project only; F inherited source inspection |
| [`miniz-tinfl-code-len-cve-2018-12913`](https://github.com/richgel999/miniz/commit/384a12dea47068e712a52a4d516e8f013644a965); CVE-2018-12913 | `d10b03cc73475af673df40f06e5cefd1d5f940d9` → `384a12dea47068e712a52a4d516e8f013644a965` | `tinfl_decompress` | project only; F inherited source inspection |
| [`curl-socks5-long-hostname-cve-2023-38545`](https://www.cve.org/CVERecord?id=CVE-2023-38545); CVE-2023-38545 | `09e25b9d94f4106eac8ca3a43b221bdc66f405e4` → `fb4415d8aee6c1045be932a34fe6107c2f5ed147` | `do_SOCKS5` | no recipe; F inherited source inspection |
| [`libsodium-ed25519-main-subgroup-cve-2025-69277`](https://www.cve.org/CVERecord?id=CVE-2025-69277); CVE-2025-69277 | `ff06acd20dfc0cde134e73a78d03da4921989306` → `ad3004ec8731730e93fcfbbc824e67eadc1c1bae` | `ge25519_is_on_main_subgroup` | no recipe; F inherited source inspection |
| [`c-ares-read-line-embedded-nul-cve-2024-25629`](https://www.cve.org/CVERecord?id=CVE-2024-25629); CVE-2024-25629 | `035c4c3776ee0d04a9db97213891367b7998de55` → `a804c04ddc8245fc8adf0e92368709639125e183` | `ares__read_line` | both pins; F inherited source inspection |
| [`libssh2-transport-padding-length-cve-2019-3861`](https://www.cve.org/CVERecord?id=CVE-2019-3861); CVE-2019-3861 | `634444a34899b8353f1959d73cf3594569e53b97` → `8690f0e04166f7e8f1c881f4730facde0b17fbe1` | `_libssh2_transport_read` | no recipe; F inherited source inspection |
| [`openssl-punycode-off-by-one-cve-2022-3602`](https://www.cve.org/CVERecord?id=CVE-2022-3602); CVE-2022-3602 | `4bae06d47ae26b37a948d31f11884e1813f6d669` → `fe3b639dc19b325846f4f6801f2f4604f56e3de3` | `ossl_punycode_decode` | no recipe; F inherited source inspection |
| [`mbedtls-pem-padding-underflow-cve-2025-52497`](https://www.cve.org/CVERecord?id=CVE-2025-52497); CVE-2025-52497 | `9325883d9fb270cae63af5a254eb6a855813a189` → `6165e715899a9b370851e2868fe312d7e0a2cb83` | `pem_check_pkcs_padding` | project only; F inherited source inspection |
| [`nghttp2-continuation-limit-cve-2024-28182`](https://www.cve.org/CVERecord?id=CVE-2024-28182); CVE-2024-28182 | `605d9fdd6845e984ee2d1d39f14905d9b61ac04e` → `d71a4668c6bead55805d18810d633fbb98315af9` | `nghttp2_session_mem_recv2`, `session_new`, `nghttp2_strerror`, `nghttp2_option_set_max_continuations` | no recipe; F inherited source inspection |
| [`libuv-idna-zero-terminate-cve-2024-24806`](https://www.cve.org/CVERecord?id=CVE-2024-24806); CVE-2024-24806 | `bb6fbcf6e75201cebac30220366d4aff620b8765` → `c858a147643de38a09dd4164758ae5b685f2b488` | `uv__idna_toascii` | no recipe; F inherited source inspection |
| [`lua-getlocal-negation-overflow-cve-2020-24370`](https://www.cve.org/CVERecord?id=CVE-2020-24370); CVE-2020-24370 | `d2c2e32e8a0f649099de0e9d04b5a72037b7b138` → `a585eae6e7ada1ca9271607a4f48dfb17868ab7b` | `findvararg`, `luaG_findlocal` | project only; F inherited source inspection |
| [`cjson-1.7.16-to-1.7.17`](https://github.com/DaveGamble/cJSON/blob/v1.7.17/CHANGELOG.md); CVE-2023-50471, CVE-2023-50472 | `cb8693b058ba302f4829ec6d03f609ac6f848546` → `87d8f0961a01bf09bef98ff89bae9fdec42181ee` | `cJSON_SetValuestring`, `cJSON_InsertItemInArray` | both pins; F inherited source inspection |
| [`expat-2.6.2-to-2.6.3`](https://github.com/libexpat/libexpat/blob/R_2_6_3/expat/Changes); CVE-2024-45490, CVE-2024-45491, CVE-2024-45492 | `fa75b96546c069d17b8f80d91e0f4ef0cde3790d` → `88b3ed553d8ad335559254863a33360d55b9f1d6` | `XML_ParseBuffer`, `dtdCopy`, `nextScaffoldPart`, `processInternalEntity`, `internalEntityProcessor` | both pins; F inherited source inspection |
| [`libpng-1.6.54-to-1.6.55`](https://github.com/pnggroup/libpng/blob/v1.6.55/CHANGES); CVE-2026-25646 | `02f2b4f4699f0ef9111a6534f093b53732df4452` → `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` | `png_set_quantize`, `png_get_copyright` | both pins; F inherited source inspection |
| [`libwebp-1.3.1-to-1.3.2`](https://github.com/webmproject/libwebp/blob/v1.3.2/NEWS); CVE-2023-4863 | `fd7bb21c0cb56e8a82e9bfa376164b842f433f3b` → `ca332209cb5567c9b249c86788cb2dbf8847e760` | `BuildHuffmanTable`, `VP8LBuildHuffmanTable`, `VP8LHuffmanTablesAllocate`, `VP8LHuffmanTablesDeallocate`, `ReadHuffmanCodeLengths`, `ReadHuffmanCode`, `ReadHuffmanCodes`, `ClearMetadata`, `VP8LDecodeImage` | no recipe; F inherited source inspection |
| [`pcre2-10.45-to-10.46`](https://github.com/PCRE2Project/pcre2/blob/pcre2-10.46/ChangeLog); CVE-2025-58050 | `2dce7761b1831fd3f82a9c2bd5476259d945da4d` → `b2bd4254b379b9d7dc9a3dda060a7e27009ccdff` | `match` | both pins; F inherited source inspection |
| [`stb-vorbis-cve-2019-13217-to-13223`](https://github.com/nothings/stb/commit/98fdfc6df88b1e34a736d5e126e6c8139c8de1a6); CVE-2019-13217, CVE-2019-13218, CVE-2019-13219, CVE-2019-13220, CVE-2019-13221, CVE-2019-13222, CVE-2019-13223 | `c72a95d766b8cbf5514e68d3ddbf6437ac9425b1` → `98fdfc6df88b1e34a736d5e126e6c8139c8de1a6` | `lookup1_values`, `draw_line`, `get_window`, `vorbis_finish_frame`, `start_decoder` | project only; F inherited source inspection |

### Tier R security cases

| Case and CVEs | Exact old → new commit | Declared affected functions | Recipe coverage; evidence |
|---|---|---|---|
| [`libpng-v1.6.50-to-v1.6.51`](https://github.com/pnggroup/libpng/releases/tag/v1.6.51); CVE-2025-64505, CVE-2025-64506, CVE-2025-64720, CVE-2025-65018 | `2b978915d82377df13fcbb1fb56660195ded868a` → `49363adcfaf098748d7a4c8c624ad8c45a8c3a86` | `png_warning`, `png_image_read_direct`, `png_set_quantize`, `png_init_read_transformations`, `png_do_read_transformations`, `png_image_write_main` | both pins; T historical factory summary |
| [`libpng-v1.6.53-to-v1.6.54`](https://github.com/pnggroup/libpng/releases/tag/v1.6.54); CVE-2026-22695, CVE-2026-22801 | `4e3f57d50f552841550a36eabbb3fbcecacb7750` → `02f2b4f4699f0ef9111a6534f093b53732df4452` | `png_image_read_direct_scaled`, `png_write_image_8bit`, `png_write_image_16bit`, `png_image_write_main` | both pins; T historical factory summary |
| [`libpng-v1.6.55-to-v1.6.56`](https://github.com/pnggroup/libpng/releases/tag/v1.6.56); CVE-2026-33416, CVE-2026-33636 | `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` → `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33` | `png_image_read_colormap`, `png_image_read_and_map`, `png_image_finish_read`, `png_set_quantize`, `png_read_transform_info`, `png_set_eXIf_1`, `png_set_hIST`, `png_set_PLTE`, `png_set_tRNS`, `png_set_shift`, `png_image_write_main` | both pins; T historical factory summary |
| [`expat-r_2_4_8-to-r_2_4_9`](https://github.com/libexpat/libexpat/releases/tag/R_2_4_9); CVE-2022-40674 | `3bab6c09bbe8bf42d84b81563ddbcf4cca4be838` → `d77291a4824d78e697c5dc2b8024fd65ab31e209` | `processXmlDecl`, `internalEntityProcessor` | both pins; T historical factory summary |
| [`expat-r_2_6_1-to-r_2_6_2`](https://github.com/libexpat/libexpat/releases/tag/R_2_6_2); CVE-2024-28757 | `a590b2d5846865412182805b853dd91d18f38c8d` → `fa75b96546c069d17b8f80d91e0f4ef0cde3790d` | `storeEntityValue` | both pins; T historical factory summary |
| [`expat-r_2_7_4-to-r_2_7_5`](https://github.com/libexpat/libexpat/releases/tag/R_2_7_5); CVE-2026-32776, CVE-2026-32777, CVE-2026-32778 | `f5c2890d8ff91f88a018173d293a9bd02f76389e` → `f31adfd584b7f6c50bbf4d22eb928538ffc9145a` | `hashTableDestroy`, `lookup`, `processEntity`, `handleUnknownEncoding`, `parserInit`, `defineAttribute`, `nextScaffoldPart`, `addBinding`, `storeRawNames`, `poolGrow`, `setContext`, `XML_ParserReset`, `XML_SetEncoding`, `XML_ParserFree`, `parserCreate`, `XML_ExternalEntityParserCreate`, `XML_Parse`, `XML_StopParser`, `XML_GetParsingStatus`, `XML_ExpatVersionInfo`, `accountingDiffTolerated`, `processXmlDecl`, `doIgnoreSection`, `epilogProcessor`, `storeEntityValue` | both pins; T historical factory summary |
| [`cjson-v1.7.17-to-v1.7.18`](https://github.com/DaveGamble/cJSON/releases/tag/v1.7.18); CVE-2024-31755 | `87d8f0961a01bf09bef98ff89bae9fdec42181ee` → `acc76239bee01d8e9c858ae2cab296704e52d916` | `cJSON_Delete`, `cJSON_SetValuestring` | both pins; T historical factory summary |
| [`mbedtls-v3.6.0-to-v3.6.1`](https://github.com/Mbed-TLS/mbedtls/releases/tag/v3.6.1); CVE-2024-45157, CVE-2024-45158, CVE-2024-45159 | `2ca6c285a0dd3f33982dd57299012dacab1ff206` → `71c569d44bf3a8bd53d874c81ee8ac644dd6e9e3` | `mbedtls_mpi_exp_mod`, `mbedtls_mpi_core_exp_mod`, `get_pkcs_padding`, `mbedtls_entropy_free`, `mbedtls_lmots_public_free`, `mbedtls_lms_public_free`, `mbedtls_nist_kw_free`, `mbedtls_pem_free`, `copy_from_psa`, `psa_aead_update_ad`, `psa_cipher_decrypt`, `psa_generate_key`, `psa_generate_key_ext`, `psa_generate_key_internal`, `psa_key_derivation_output_key`, `psa_key_derivation_output_key_ext`, `psa_start_key_creation`, `psa_wipe_key_slot`, `mbedtls_cipher_info_from_psa`, `mbedtls_psa_rsa_export_public_key`, `mbedtls_psa_rsa_generate_key`, `mbedtls_psa_rsa_sign_hash`, `mbedtls_psa_get_stats`, `psa_get_and_lock_key_slot`, `psa_get_and_lock_key_slot_in_memory` | both pins; T historical factory summary |
| [`mbedtls-v3.6.2-to-v3.6.3`](https://github.com/Mbed-TLS/mbedtls/releases/tag/v3.6.3); CVE-2025-27809, CVE-2025-27810 | `107ea89daaefb9867ea9121002fbbdf926780e98` → `22098d41c6620ce07cf8a0134d37302355e1e5ef` | `mbedtls_aesni_crypt_ecb`, `mbedtls_mpi_core_exp_mod_optionally_safe`, `ccm_calculate_first_block_if_ready`, `mbedtls_ecp_check_privkey`, `mbedtls_high_level_strerr`, `psa_import_key`, `mbedtls_psa_sign_hash_start`, `mbedtls_psa_verify_hash_start`, `psa_key_derivation_input_internal`, `psa_generate_derived_key_internal`, `psa_generate_key_custom`, `psa_crypto_local_input_free`, `psa_crypto_local_output_free`, `mbedtls_psa_ecp_generate_key`, `mbedtls_ecdsa_raw_to_der`, `mbedtls_ecdsa_der_to_raw`, `mbedtls_ssl_update_in_pointers`, `mbedtls_ssl_prepare_handshake_record`, `mbedtls_ssl_handle_message_type`, `mbedtls_ssl_session_reset_msg_layer`, `mbedtls_ssl_set_hostname`, `mbedtls_ssl_free`, `mbedtls_ssl_setup`, `mbedtls_ssl_context_save`, `mbedtls_ssl_write_finished` | both pins; T historical factory summary |
| [`mbedtls-v3.6.3-to-v3.6.4`](https://github.com/Mbed-TLS/mbedtls/releases/tag/v3.6.4); CVE-2025-47917, CVE-2025-48965, CVE-2025-49087, CVE-2025-49600, CVE-2025-49601, CVE-2025-52496, CVE-2025-52497 | `22098d41c6620ce07cf8a0134d37302355e1e5ef` → `c765c831e5c2a0971410692f92f7a81d6ec65ec2` | `mbedtls_aesni_has_support`, `mbedtls_asn1_write_raw_buffer`, `mbedtls_asn1_store_named_data`, `mbedtls_base64_decode`, `mbedtls_lmots_import_public_key`, `mbedtls_lms_import_public_key`, `mbedtls_lms_verify`, `psa_key_derivation_start_hmac`, `psa_cipher_setup`, `psa_mac_setup`, `psa_aead_setup`, `psa_hash_clone`, `psa_key_derivation_tls12_prf_generate_next_block`, `psa_sign_hash_start`, `psa_verify_hash_start`, `psa_pake_setup`, `ssl_parse_record_header`, `mbedtls_ssl_write_change_cipher_spec`, `mbedtls_ssl_parse_change_cipher_spec`, `tls_prf_generic`, `tls_prf_sha256`, `tls_prf_sha384`, `ssl_tls12_populate_transform`, `mbedtls_ssl_handshake_step`, `mbedtls_ssl_session_reset_int` | both pins; T historical factory summary |
| [`mbedtls-v3.6.4-to-v3.6.5`](https://github.com/Mbed-TLS/mbedtls/releases/tag/v3.6.5); CVE-2025-54764, CVE-2025-59438 | `c765c831e5c2a0971410692f92f7a81d6ec65ec2` → `e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df` | `mbedtls_mpi_gcd`, `mbedtls_mpi_inv_mod`, `mbedtls_get_pkcs_padding`, `get_one_and_zeros_padding`, `get_zeros_and_len_padding`, `get_zeros_padding`, `get_no_padding`, `mbedtls_cipher_finish`, `mbedtls_cipher_crypt`, `mbedtls_ecdsa_sign_restartable`, `mbedtls_ecdsa_verify_restartable`, `ecp_mul_comb_after_precomp`, `psa_cipher_finish`, `psa_cipher_decrypt`, `mbedtls_psa_cipher_finish`, `mbedtls_psa_cipher_decrypt`, `mbedtls_rsa_gen_key`, `mbedtls_rsa_deduce_primes`, `mbedtls_rsa_deduce_private_exponent` | both pins; T historical factory summary |
| [`brotli-v1.0.7-to-v1.0.8`](https://github.com/google/brotli/releases/tag/v1.0.8); CVE-2020-8927 | `d6d98957ca8ccb1ef45922e978bb10efca0ea541` → `db361a0bb901d6a71c7cbf1370d97b3703482e3b` | `CreateBackwardReferencesNH65`, `PrepareH5`, `PrepareH6`, `PrepareH40`, `PrepareH41`, `PrepareH42`, `PrepareH65`, `PrepareH35`, `PrepareH55` | both pins; T historical factory summary |
| [`miniz-3.0.2-to-e680017`](https://github.com/richgel999/miniz/commit/e680017bae901240e8894062c0b0a3020eca42c1); CVE-2018-12913 | `293d4db1b7d0ffee9756d035b9ac6f7431ef8492` → `e680017bae901240e8894062c0b0a3020eca42c1` | `tinfl_decompress` | both pins; T historical factory summary |

## Primary-source verification performed on 2026-10-30

The following links were read through the available web retrieval service. Project advisories establish vulnerability identity and affected/fixed release boundaries; a full-SHA source diff is still required to establish the exact edge and per-function patch attribution. Retrieval success is deliberately distinguished from the inherited pin/source verification in the cards. The downloaded page is not a checked-out source tree or a license-hash receipt.

| Source | Independent observation in this audit | What remains unverified |
|---|---|---|
| [c-ares GHSA-mg26-v6qh-x48q](https://github.com/c-ares/c-ares/security/advisories/GHSA-mg26-v6qh-x48q) | CVE-2024-25629 concerns `ares__read_line`, embedded initial NUL and buffer under-read; fixed in 1.27.0 | Full parent/merge diff and compiled survival at the two untagged recipe pins |
| [curl project advisory](https://curl.se/docs/CVE-2023-38545.html) | CVE-2023-38545 is the SOCKS5 handshake hostname buffer overflow | Card's exact parent/fix commits and `do_SOCKS5` source spans were not re-fetched; no recipe |
| [libssh2 project advisory](https://libssh2.org/CVE-2019-3861.html) | Padding-length validation for crafted SSH packets; 0.15–1.8.0 affected, 1.8.1 fixed | Exact `_libssh2_transport_read` pair and dependency recipe need reproduction |
| [OpenSSL signed advisory archive](https://mta.openssl.org/pipermail/openssl-announce/2022-November/000243.html) | CVE-2022-3602 affects 3.0.0–3.0.6; fixed 3.0.7; name-constraint email processing | Exact `ossl_punycode_decode` patch edge not re-fetched; no recipe. Signature was displayed, not cryptographically verified |
| [libwebp 1.3.2 NEWS](https://chromium.googlesource.com/webm/libwebp/+/refs/tags/v1.3.2/NEWS) | Official versioned source says lossless decoder fix for CVE-2023-4863 | GitHub mirror SHA equivalence, changed helper list and CMake/library subset were not independently reconstructed |
| [PCRE2 GHSA-c2gv-xgf5-5cc2](https://github.com/PCRE2Project/pcre2/security/advisories/GHSA-c2gv-xgf5-5cc2) | Security-only 10.46 release fixes CVE-2025-58050 in 10.45; source report locates `src/pcre2_match.c` and the affected matching logic | Full tag/SHA peeling and body-level survival in the existing 8-bit recipe |
| [libuv GHSA-f74f-cvh7-c6q6](https://github.com/libuv/libuv/security/advisories/GHSA-f74f-cvh7-c6q6) | Domain lookup/IDNA vulnerability context confirmed by project advisory | Exact `uv__idna_toascii` source diff and Windows build remain inherited/no-recipe |
| [nghttp2 1.61.0 announcement](https://nghttp2.org/blog/2024/04/04/nghttp2-v1-61-0/) and [project advisory](https://github.com/nghttp2/nghttp2/security/advisories/GHSA-x6x3-gv8h-m57q) | CVE-2024-28182 is unbounded CONTINUATION-frame CPU consumption; official release warns generated GitHub archives are not usable release tarballs | Exact four-function attribution and library recipe absent. Do not blindly run upstream-generated host tools to work around source generation |
| [Lua bugs list](https://www.lua.org/bugs.html) and [linked fix](https://github.com/lua/lua/commit/a585eae6e7ada1ca9271607a4f48dfb17868ab7b) | Upstream names negation overflow in getlocal/setlocal, fixed in 5.4.1, and links the same fix SHA as the card | CVE-2020-24370 mapping and old full parent SHA were not independently re-fetched; exact historical pin recipe absent |
| [zlib fix df84af2](https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148) | Commit explicitly names CVE-2026-85091, displays parent bbc2ccf and one-file `gz_write` diff resetting stale input state | Full parent object identity, pinned license and gzip-inclusive build still need fetch receipt |
| [libarchive historical release notes](https://github.com/libarchive/libarchive/wiki/ReleaseNotes) | Upstream historical notes identify CVE-2016-1541 and compressed/uncompressed ZIP size handling | Wiki is mutable and deprecated; exact fix SHA/source diff was not retrieved in this audit |
| [Mbed TLS PEM advisory](https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2025-06-2/) | CVE-2025-52497, affected through 3.6.3 and fixed 3.6.4; PEM feature must be enabled | Source-level `pem_check_pkcs_padding` relationship and compiled implementation need independent review |
| [libsodium maintainer explanation](https://00f.net/2025/12/30/libsodium-vulnerability/) | Project maintainer explains the point-validation issue | Exact fix SHA/CVE linkage in the card was not independently recovered from this page; do not treat retrieval as commit verification |
| [stb maintained source history](https://github.com/nothings/stb/blob/master/stb_vorbis.c) | Primary source search result identifies Vorbis 1.17 as fixing CVE-2019-13217 through -13223 | Mutable source search result only; exact 2019 fix and five-function set remain inherited, not newly verified |
| [libpng GHSA-g8hp-mq4h-rqm3](https://github.com/pnggroup/libpng/security/advisories/GHSA-g8hp-mq4h-rqm3), [project homepage](https://www.libpng.org/pub/png/libpng.html) and [maintainer announcement](https://www.openwall.com/lists/oss-security/2026/02/09/7) | CVE-2026-25646 affects `png_set_quantize`; announcement identifies fix `01d03b8453eb30ade759cd45c707e5a1c7277d88` and release 1.6.55 | Card uses full release comparison 1.6.54→1.6.55; confirm fix ancestry and separate `png_get_copyright` from security intent |
| [Expat Changes at R_2_6_3](https://github.com/libexpat/libexpat/blob/R_2_6_3/expat/Changes) | Versioned upstream changelog contains the historical security entries including CVE-2024-45490/-45491/-45492 and CVE-2022-40674 | Tag/SHA object verification, architecture applicability and precise security-only changed set still need reproduction |
| [CVE Program cJSON -50471](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-50471) and [cJSON -50472](https://www.cve.org/CVERecord?id=CVE-2023-50472) | Primary record/search output names `cJSON_InsertItemInArray` and `cJSON_SetValuestring` in 1.7.16 | Project issues [802](https://github.com/DaveGamble/cJSON/issues/802) and [803](https://github.com/DaveGamble/cJSON/issues/803) and release page could not be fetched by the retrieval tool; exact fixed release/patch bodies remain inherited |
| [Brotli v1.0.9 release](https://github.com/google/brotli/releases/tag/v1.0.9) | Project release describes CVE-2020-8927 as decoder integer overflow on chunks larger than 2 GiB | Existing 1.0.7→1.0.8 CVE card's function set is not validated by this observation |
| [miniz issue 90](https://github.com/richgel999/miniz/issues/90) | Original 2018 report and later comment associate the `tinfl_decompress` infinite-loop report with CVE-2018-12913 | Neither existing candidate fix SHA was retrieved; issue alone does not identify the exact fixing commit |

Several full-commit pages, raw source/license URLs and cJSON issue/release pages returned `DisabledError` through web retrieval. Such failures establish only that this tool did not return the contents. They are not evidence that an upstream revision or license is missing. No proxy bypass, broad clone, dataset download or target execution was attempted. Pin-specific license checks remain inherited from repository receipts until the normal explicit `fetch` step succeeds. No new independent source-tree verification is asserted for a failed URL.

### Cases requiring special treatment before promotion

**Brotli CVE attribution.** The current `brotli-v1.0.7-to-v1.0.8` card lists `CreateBackwardReferencesNH65` and `PrepareH*` encoder helpers. The project release describes a decoder overflow, and the CNA record says versions before 1.0.8 are affected while the project 1.0.9 announcement carries the security note. This does not by itself prove the comparison is wrong: a release tag can be built from a tree containing a fix even if its release announcement is elsewhere, and optimization can make a decoder change ambiguous. It does mean the declared changed list is not an accepted CVE-specific function set. Recover the exact fix commit, prove it lies between the pins, inspect decoder body facts and retain unrelated encoder changes as ordinary release changes. Until then exclude this card from vulnerability-function recall and keep it as a quarantined release candidate.

**miniz CVE attribution and source spans.** The found card uses `d10b03cc73475af673df40f06e5cefd1d5f940d9` → `384a12dea47068e712a52a4d516e8f013644a965`; the Tier R card uses 3.0.2 (`293d4db1b7d0ffee9756d035b9ac6f7431ef8492`) → `e680017bae901240e8894062c0b0a3020eca42c1` (recipe date 2024-12-18). Both carry CVE-2018-12913. A later fix could address an old report, but issue 90 does not establish that association. The Tier R card additionally states all 140 labels are ambiguous because the source locator skips bodies within a file-level `extern "C"` block; its `tinfl_decompress` declaration comes from a diff hunk header, not accepted source/body label agreement. Do not count the later edge as an independently labelled CVE case, or use its absence of accepted changes as a true-negative result. Reproduce commit/issue linkage and repair source-span provenance before any label promotion.

**Mbed TLS artifact applicability.** The recipe omits `library/net_sockets.c` and changes entropy/platform options. It is appropriate only as a static-analysis fixture. It must never be represented as a usable cryptographic library. A release card's broad changed set is not a per-CVE fix set; the exact PEM fix card is outside current recipe pins even though the containing release pair is pinned. Check feature macros, inline wrappers and source spans at both revisions. A CVE not present under the chosen configuration belongs in not-applicable/unknown coverage, not in false negatives.

**Architecture-dependent libpng fixes.** CVE-2026-33636 is an ARM Neon palette-expansion issue according to the project homepage. A Windows x86-64 build cannot test detection of ARM-only machine code merely because its release pair contains that CVE. Record the CVE as source provenance and architecture-inapplicable for that fixture unless independently reviewed portable changes are also part of its fix. The related CVE-2026-33416 has a distinct lifetime/palette fix and must not be conflated with it.

**Library versus program targets.** libarchive's 2025 NULL cases modify `tar/util.c` and `unzip/bsdunzip.c`, not the core shared library. zlib's CVE-2014-9485 is in `contrib/minizip/miniunz.c`, not the ordinary zlib library recipe. curl control cards touch test server programs as well as library code; libsodium's comment-only card changes tests' `main` functions. Before declaring a binary change missing, verify the function's translation unit is linked into the selected artifact. Project name matching alone is inadequate.

## Nonsecurity controls and confounding

The found inventory already contains seven `no-op`, three `refactor-control`, one `build-system-only`, four `constant-only` and ten `bounds-only` cards. A bounds check without a CVE is still a material/security-relevant code change, not a safe negative security label. Likewise nonsecurity performance constants are material positives for change detection, even if no vulnerability is involved. Unknown CVE status is not evidence that a change is nonsecurity.

Useful controls include the following exact inherited pairs:

| Case | Old → new commit | Intended role | Caveat |
|---|---|---|---|
| `libdeflate-levels-11-12-optim-passes` | `84a60c514ab81d74ed809cb6c15317e91a87196a` → `ec03d361f2ece6058b7d1f594f4e7d3c78cfd80f` | constant-only; semantic_change=true | Compression tuning is ordinary material change, not cosmetic |
| `libdeflate-levels-5-6-search-depth` | `193dedc73fb1401be8835f4c37eff9603ea3052c` → `057cb92782b5107beb3f7738c4544ce84de653e1` | constant-only; semantic_change=true | Compression tuning is ordinary material change, not cosmetic |
| `zlib-typo-fixes-no-code-change-2022-08` | `1eb7682f845ac9e9bf9ae35bbfb3bad5dacbd91d` → `5752b171fd4cc96b8d1f9526ec1940199c6e9740` | no-op; semantic_change=false | Comment/token identity; debug line or build metadata can differ |
| `lz4-hc-optimal-reindent-whitespace-only` | `25ae65810f95eeca929b365fc1a3d06dc3e6998f` → `63b89affd09d0881944ec7dfb2a69c76f6327c9b` | refactor-control; semantic_change=false | Whitespace-only function body; source line count unchanged |
| `libsodium-test-comment-typos-no-op` | `c960b3b0c6e430ff2dfdb776bf1c990e62f3f18b` → `75c6d5520a3b99790696d98b554673697c71c5cc` | no-op; semantic_change=false | Test programs changed; no library source change |
| `libpng-1.6.41-to-1.6.42` | `ba980b8f0cfbc270ba1c4a663455e2fe8bad91d2` → `35d9f5ea523cb4f9d677af4705e00ddd185ed10e` | constant-only; semantic_change=true | Library copyright constant changes; public header macro regression affects external callers separately |
| `jansson-2.13-to-2.13.1` | `2882ead5bb90cf12a01b07b2c2361e24960fae02` → `e9ebfa7e77a6bee77df44e096b100e7131044059` | constant-only; semantic_change=true | Version macros induce real library constant changes despite identical function body text |
| `cjson-print-number-indent-8a334b0` | `acc76239bee01d8e9c858ae2cab296704e52d916` → `8a334b014038ef02065fcd41e6096c99102bcc36` | refactor-control; semantic_change=false | Whitespace-only `print_number`; new recipe pin needed |
| `cjson-spelling-tests-only-3249730` | `8a334b014038ef02065fcd41e6096c99102bcc36` → `324973008ced4ea03d1626a00915d0399ecbd9db` | no-op; semantic_change=false | Library sources unchanged; tests outside selected library |
| `cjson-readme-docs-a3f3d6c` | `5cc0e39f42dfe28cb8541f95fa2c513f0d550210` → `a3f3d6c7843f3021b648623d13bc4fbca0084838` | no-op; semantic_change=false | README-only; compare stripped library bodies |
| `cjson-cmake-minimum-a29814f` | `c859b25da02955fef659d658b8f324b5cde87be3` → `a29814f285cc531c00223743ad3c55cd38c0dc56` | build-system-only; semantic_change=false | No source change; factory explicit source recipe may bypass upstream CMake difference |

`factory.IdenticalImages` deliberately refuses byte-identical old/new engine images as an ordinary pair. Preserve such outcomes as successful image-equality controls, rather than modifying labels, enabling nondeterminism or inventing a semantic difference to force the card through a release-pair path. A separate A/A identity comparison is the correct way to measure matching behavior on identical images. For comment-only pairs whose debug binaries differ, compare stripped engine images and per-function bodies before accepting cosmetic/no-change labels.

Unchanged function controls listed in each security card provide local correspondence negatives/positives but are not sufficient to prove unchanged machine code: a header, macro, type layout, inline helper, constant table or compiler transformation may affect an unchanged source body. Record at least one affected function and several binary-confirmed unchanged controls per pilot pair, and explicitly retain unresolved effects as ambiguous.

## Smallest feasible real pilot and expansion order

The smallest useful Tier E pilot is one security release pair with exact recipe coverage, accompanied by a same-revision A/A control and a stripped/unstripped artifact check. Start with `cjson-1.7.16-to-1.7.17` (`cb8693b058ba302f4829ec6d03f609ac6f848546` → `87d8f0961a01bf09bef98ff89bae9fdec42181ee`). It has a small source surface, MIT license evidence and both existing recipe pins. Independently review its two named function changes, confirm emitted code differs for each accepted changed label, bind symbol-derived RVAs to the stripped images, then evaluate genuine Ghidriff output. Do not claim the pilot succeeded unless those run receipts actually exist. The integration owner selects runnable compilers/tools and records any currently blocked dependency.

A second small candidate is `pcre2-10.45-to-10.46`: the maintainer explicitly calls 10.46 a security-only release, reducing release-level confounding, and the existing recipe contains both pins. It is larger than cJSON but provides stronger publicly accessible project advisory evidence for a narrowly located fix. Expat 2.6.2→2.6.3 then adds multiple integer/bounds fixes and 32-bit applicability questions. Keep compiler family/optimization combinations separate; MinGW GCC O0/O2 is an initial stratum, not evidence for MSVC or Clang.

The first 15 **candidate** comparisons with current exact recipe coverage can be drawn from cJSON (2), Expat (4), libpng (4), Mbed TLS (4) and PCRE2 (1), excluding the weak Brotli/miniz associations. This reaches the numerical comparison count with only five source families; it does not meet the project-diversity goal, does not isolate 15 independent vulnerabilities, and still needs source/binary applicability review. The goal is better served by promoting a few narrow fix edges in new projects than by reporting a large number of bundled CVEs from these same libraries.

Expansion should proceed in this order:

1. Recover or rebuild the already documented 13 libdeflate/stb/c-ares O2 pairs and the current cJSON/Expat/PCRE2/libpng exact-pin pairs. Preserve source receipts, toolchain identity, binary SHA-256s, label digests and raw engine output. Add compiler/optimization variants only after the base pair's independent label review.
2. Close existing-source chain gaps: cJSON, Expat, PCRE2 and libpng need reuse of found cards; libdeflate and Brotli need additional edge cards over already pinned commits. Verify actual release adjacency. Keep Brotli security attribution quarantined meanwhile.
3. Add a fourth verified Lua/zstd series pin and adjacent edge to bring the selected-chain pool toward 14 projects. Keep all versions and compiler variants of a project together for partitioning, including shared zlib/minizip lineage and third-party reused code.
4. Add exact fix recipes for c-ares and zlib gzip, then one narrowly scoped new family such as libwebp or libuv. Review explicit source lists and feature macros; no generated host programs are executed. Libssh2/OpenSSL introduce dependency/build complexity and can follow once a pinned subset is reviewed.
5. Defer libarchive until its configuration/header and format subset are explicit. Preserve its five found cards as provenance. Defer miniz's label promotion until its source-span and CVE-edge questions are resolved. Keep libyaml's two real edges, with the third edge honestly unavailable until a fourth release is verified.

An accepted run must list catalogued, fetched, built, independently labelled and engine-evaluated counts separately. It must report unavailable functions/configurations, not silently suppress them. Use project/lineage grouping for split assignment before tuning. A subset repeatedly inspected to choose fixes and recipes is development/validation material; it cannot simultaneously serve as a locked unseen test set.

## PostgreSQL exclusion verified and preserved

`corpus/excluded/postgresql-libpq-untrusted-error-cve-2024-10977.json` explicitly records an owner-accepted exclusion on 2026-10-15 because SPDX `PostgreSQL` is outside the repository permissive allow-list. `docs/plans/calibration-licences.md` preserves the same decision and open item 7. The research did **not** restore this card, relabel it MIT/BSD, change the allow-list or count it toward candidate acceptance.

The exclusion is a repository policy decision, not a claim that PostgreSQL lacks a permissive license or that the CVE is unverified. The official [PostgreSQL license page](https://www.postgresql.org/about/licence/) describes the PostgreSQL License and requires preservation of its notice and disclaimer. The official [CVE-2024-10977 advisory](https://www.postgresql.org/support/security/CVE-2024-10977/) confirms libpq can retain an unauthenticated server error under SSL/GSS negotiation and identifies fixed releases 17.1, 16.5, 15.9, 14.14, 13.17 and 12.21 (2024-11-14).

The excluded card pins `5d4298e75f252b162008ad0475f29349023573cb` → `bf8835ea9717df50230c12133cff1b486dcc57be` and proposes `PQconnectPoll` in `src/interfaces/libpq/fe-connect.c`; [upstream commit](https://github.com/postgres/postgres/commit/bf8835ea9717df50230c12133cff1b486dcc57be). This is a master-branch fix, not necessarily the same commit as stable-branch backports. Its exact source diff/license blob verification is inherited; the current web check verified the advisory and license policy, not a new git checkout. Reconsider only under the repository's recorded owner/integrator policy process, and preserve the excluded record either way.

## License and artifact redistribution assessment

Source-license elections below are inherited from the exact pinned recipe/card evidence, except the current Lua and PostgreSQL project license pages were independently read. Pin-specific raw license retrieval failed for several projects; no independent license SHA-256 revalidation is claimed. The normal `fetch.py` verifies the license file against its expected hash before use. A grant for source does not automatically settle the notices needed for a linked artifact and its runtime dependencies.

Publish this research, cards, recipes and digests. Follow repository policy: no compiled upstream images, PDBs or downloaded datasets committed to git; generated open-source fixture outputs are only eligible for the project's CI artifact policy after notices and dependencies are reviewed. Do not redistribute compiler toolchains, Windows SDK files, import-library payloads or Microsoft's symbol-server artifacts as part of these cases. A DLL assembled with altered crypto/entropy options is analysis-only and must carry that limitation in its manifest.

| License/election | Projects and constraints |
|---|---|
| MIT | cJSON, c-ares, Expat, Jansson, libdeflate, libuv, libyaml, Lua, nghttp2, Brotli, miniz; preserve copyright and license notice for substantial copies. Confirm file-level exceptions and dependency notices at each pin |
| BSD-2-Clause | libarchive and lz4 library portions; reproduce copyright/license/disclaimer in binary documentation. libarchive `COPYING` has file-specific exceptions; target source list determines coverage |
| BSD-3-Clause | libwebp, libssh2, libevent and elected zstd option; retain notices/disclaimer and endorsement restriction; zstd GPL alternative is not elected |
| BSD-3-Clause WITH PCRE2-exception | PCRE2 recipe election; found card abbreviates to BSD-3-Clause. Preserve actual `LICENCE.md` and binary-linking exception; do not flatten elections across pins/components |
| Apache-2.0 | OpenSSL 3.x and Mbed TLS elected option; preserve license/notices, mark source modifications where required and inspect NOTICE/patent provisions. Mbed TLS GPL alternative is not elected |
| Libpng-2.0 | libpng; preserve the actual versioned license and disclaimers; recipe has multiple license hashes across history |
| Zlib | zlib and historical contrib/minizip; preserve origin and altered-source marking conditions; ensure minizip file headers match the selected historical license |
| ISC | libsodium; retain copyright and permission notice |
| curl | curl's project license; retain its permission/copyright text and disclaimers rather than substituting a generic MIT label |
| MIT election from dual license | stb is MIT OR Unlicense; use MIT consistently and preserve its notice |
| PostgreSQL | Excluded by current policy; current upstream license is permissive, but that does not authorize bypassing the allow-list |

Do not confuse a license Git blob ID with a license-file SHA-256, a source commit or an artifact digest. `docs/audits/20261015-corpus-candidates-verified.md` found 24 older candidate files with null source commits and no fix pins; none qualified as verified. Those names are discovery leads only and are not silently added to this audit's accepted inventory.

## Exact source and license pin ledger (inherited)

These are the existing recipe pins copied mechanically from `recipes.json`, grouped by source project. They are **not** new resolutions of mutable tags. Dates in recipes are historical metadata; full commits bind the source. Each link uses the pinned commit for the source/license file, while SHA-256 is the expected file-byte hash. A future fetch must compare it against actual bytes. The build recipe itself is a source transformation when it writes configuration headers or wrappers; preserve its digest and generated-file bytes in build provenance.

### brotli

Upstream: https://github.com/google/brotli.git. Election: `MIT`. License file: `LICENSE`. Output: `brotli.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `v1.0.7` | [`d6d98957ca8ccb1ef45922e978bb10efca0ea541`](https://github.com/google/brotli/commit/d6d98957ca8ccb1ef45922e978bb10efca0ea541) | [`3d180008e36922a4e8daec11c34c7af264fed5962d07924aea928c38e8663c94`](https://github.com/google/brotli/blob/d6d98957ca8ccb1ef45922e978bb10efca0ea541/LICENSE) |
| `v1.0.8` | [`db361a0bb901d6a71c7cbf1370d97b3703482e3b`](https://github.com/google/brotli/commit/db361a0bb901d6a71c7cbf1370d97b3703482e3b) | [`3d180008e36922a4e8daec11c34c7af264fed5962d07924aea928c38e8663c94`](https://github.com/google/brotli/blob/db361a0bb901d6a71c7cbf1370d97b3703482e3b/LICENSE) |
| `v1.0.9` | [`e61745a6b7add50d380cfd7d3883dd6c62fc2c71`](https://github.com/google/brotli/commit/e61745a6b7add50d380cfd7d3883dd6c62fc2c71) | [`3d180008e36922a4e8daec11c34c7af264fed5962d07924aea928c38e8663c94`](https://github.com/google/brotli/blob/e61745a6b7add50d380cfd7d3883dd6c62fc2c71/LICENSE) |
| `v1.1.0` | [`ed738e842d2fbdf2d6459e39267a633c4a9b2f5d`](https://github.com/google/brotli/commit/ed738e842d2fbdf2d6459e39267a633c4a9b2f5d) | [`3d180008e36922a4e8daec11c34c7af264fed5962d07924aea928c38e8663c94`](https://github.com/google/brotli/blob/ed738e842d2fbdf2d6459e39267a633c4a9b2f5d/LICENSE) |
| `v1.2.0` | [`028fb5a23661f123017c060daa546b55cf4bde29`](https://github.com/google/brotli/commit/028fb5a23661f123017c060daa546b55cf4bde29) | [`3d180008e36922a4e8daec11c34c7af264fed5962d07924aea928c38e8663c94`](https://github.com/google/brotli/blob/028fb5a23661f123017c060daa546b55cf4bde29/LICENSE) |

Recipe note: Common, decoder and encoder C sources; the command-line tool is not built.

### c-ares

Upstream: https://github.com/c-ares/c-ares.git. Election: `MIT`. License file: `LICENSE.md`. Output: `libcares.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `cares-1_26_0` | [`0ad09d251bf01cc2b7860950527e33e22cd64256`](https://github.com/c-ares/c-ares/commit/0ad09d251bf01cc2b7860950527e33e22cd64256) | [`80fff25340df53b0cf0c3cddbca9050b559b9cbed2ad71830327cfef54959aef`](https://github.com/c-ares/c-ares/blob/0ad09d251bf01cc2b7860950527e33e22cd64256/LICENSE.md) |
| `cares-1_27_0` | [`9eb57f2c8beb4e8af590992e56182c0788b9ce0b`](https://github.com/c-ares/c-ares/commit/9eb57f2c8beb4e8af590992e56182c0788b9ce0b) | [`80fff25340df53b0cf0c3cddbca9050b559b9cbed2ad71830327cfef54959aef`](https://github.com/c-ares/c-ares/blob/9eb57f2c8beb4e8af590992e56182c0788b9ce0b/LICENSE.md) |
| `cares-1_28_0` | [`458c93721387d2974fe125c0a4efec2eab30e6be`](https://github.com/c-ares/c-ares/commit/458c93721387d2974fe125c0a4efec2eab30e6be) | [`80fff25340df53b0cf0c3cddbca9050b559b9cbed2ad71830327cfef54959aef`](https://github.com/c-ares/c-ares/blob/458c93721387d2974fe125c0a4efec2eab30e6be/LICENSE.md) |
| `cares-1_28_1` | [`3a26df136a76b0bcb893fce2787527efbec80fa4`](https://github.com/c-ares/c-ares/commit/3a26df136a76b0bcb893fce2787527efbec80fa4) | [`80fff25340df53b0cf0c3cddbca9050b559b9cbed2ad71830327cfef54959aef`](https://github.com/c-ares/c-ares/blob/3a26df136a76b0bcb893fce2787527efbec80fa4/LICENSE.md) |
| `cares-1_29_0` | [`bf4c5fd223e71776e3d0c5a6a8d5598ffb82597c`](https://github.com/c-ares/c-ares/commit/bf4c5fd223e71776e3d0c5a6a8d5598ffb82597c) | [`80fff25340df53b0cf0c3cddbca9050b559b9cbed2ad71830327cfef54959aef`](https://github.com/c-ares/c-ares/blob/bf4c5fd223e71776e3d0c5a6a8d5598ffb82597c/LICENSE.md) |
| `v1.30.0` | [`f90e73304a2d9f5c56d2255c19f9efaaa5b2c16c`](https://github.com/c-ares/c-ares/commit/f90e73304a2d9f5c56d2255c19f9efaaa5b2c16c) | [`8a9994f85a8e531e1a3217ab7ba509787c6b93056aabe702137ce662db8321c2`](https://github.com/c-ares/c-ares/blob/f90e73304a2d9f5c56d2255c19f9efaaa5b2c16c/LICENSE.md) |
| `cares-1_27_0-pre-ghsa-mg26` | [`035c4c3776ee0d04a9db97213891367b7998de55`](https://github.com/c-ares/c-ares/commit/035c4c3776ee0d04a9db97213891367b7998de55) | [`80fff25340df53b0cf0c3cddbca9050b559b9cbed2ad71830327cfef54959aef`](https://github.com/c-ares/c-ares/blob/035c4c3776ee0d04a9db97213891367b7998de55/LICENSE.md) |
| `cares-1_27_0-ghsa-mg26-merge` | [`a804c04ddc8245fc8adf0e92368709639125e183`](https://github.com/c-ares/c-ares/commit/a804c04ddc8245fc8adf0e92368709639125e183) | [`80fff25340df53b0cf0c3cddbca9050b559b9cbed2ad71830327cfef54959aef`](https://github.com/c-ares/c-ares/blob/a804c04ddc8245fc8adf0e92368709639125e183/LICENSE.md) |

Recipe note: No cmake, autoconf or generated config: src/lib/config-win32.h is selected by ares_setup.h when WIN32 is defined and HAVE_CONFIG_H is not, and include/ares_build.h is authored (the mingw branch of ares_build.h.dist, whose __int64 ssize_t line precedes any mingw header; socklen_t is int, ssize_t is long long). All src/lib/*.c are compiled (the POSIX event backends compile out). Tags cares-1_26_0 to v1.30.0 share the flat src/lib layout; the two trailing pins are the first-parent pair of the CVE-2024-25629 merge (found card c-ares-read-line-embedded-nul-cve-2024-25629 in corpus/catalog), both between cares-1_26_0 and cares-1_27_0. Releases from v1.33.0 move sources into subdirectories and are not pinned.

### cJSON

Upstream: https://github.com/DaveGamble/cJSON.git. Election: `MIT`. License file: `LICENSE`. Output: `cjson.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `v1.7.14` | [`d2735278ed1c2e4556f53a7a782063b31331dbf7`](https://github.com/DaveGamble/cJSON/commit/d2735278ed1c2e4556f53a7a782063b31331dbf7) | [`a36dda207c36db5818729c54e7ad4e8b0c6fba847491ba64f372c1a2037b6d5c`](https://github.com/DaveGamble/cJSON/blob/d2735278ed1c2e4556f53a7a782063b31331dbf7/LICENSE) |
| `v1.7.15` | [`d348621ca93571343a56862df7de4ff3bc9b5667`](https://github.com/DaveGamble/cJSON/commit/d348621ca93571343a56862df7de4ff3bc9b5667) | [`a36dda207c36db5818729c54e7ad4e8b0c6fba847491ba64f372c1a2037b6d5c`](https://github.com/DaveGamble/cJSON/blob/d348621ca93571343a56862df7de4ff3bc9b5667/LICENSE) |
| `v1.7.16` | [`cb8693b058ba302f4829ec6d03f609ac6f848546`](https://github.com/DaveGamble/cJSON/commit/cb8693b058ba302f4829ec6d03f609ac6f848546) | [`a36dda207c36db5818729c54e7ad4e8b0c6fba847491ba64f372c1a2037b6d5c`](https://github.com/DaveGamble/cJSON/blob/cb8693b058ba302f4829ec6d03f609ac6f848546/LICENSE) |
| `v1.7.17` | [`87d8f0961a01bf09bef98ff89bae9fdec42181ee`](https://github.com/DaveGamble/cJSON/commit/87d8f0961a01bf09bef98ff89bae9fdec42181ee) | [`a36dda207c36db5818729c54e7ad4e8b0c6fba847491ba64f372c1a2037b6d5c`](https://github.com/DaveGamble/cJSON/blob/87d8f0961a01bf09bef98ff89bae9fdec42181ee/LICENSE) |
| `v1.7.18` | [`acc76239bee01d8e9c858ae2cab296704e52d916`](https://github.com/DaveGamble/cJSON/commit/acc76239bee01d8e9c858ae2cab296704e52d916) | [`a36dda207c36db5818729c54e7ad4e8b0c6fba847491ba64f372c1a2037b6d5c`](https://github.com/DaveGamble/cJSON/blob/acc76239bee01d8e9c858ae2cab296704e52d916/LICENSE) |
| `v1.7.19` | [`c859b25da02955fef659d658b8f324b5cde87be3`](https://github.com/DaveGamble/cJSON/commit/c859b25da02955fef659d658b8f324b5cde87be3) | [`a36dda207c36db5818729c54e7ad4e8b0c6fba847491ba64f372c1a2037b6d5c`](https://github.com/DaveGamble/cJSON/blob/c859b25da02955fef659d658b8f324b5cde87be3/LICENSE) |

Recipe note: Two source files; no build system used.

### expat

Upstream: https://github.com/libexpat/libexpat.git. Election: `MIT`. License file: `expat/COPYING`. Output: `libexpat.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `R_2_4_8` | [`3bab6c09bbe8bf42d84b81563ddbcf4cca4be838`](https://github.com/libexpat/libexpat/commit/3bab6c09bbe8bf42d84b81563ddbcf4cca4be838) | [`8c6b5b6de8fae20b317f4992729abc0e520bfba4c7606cd1e9eeb87418eebdec`](https://github.com/libexpat/libexpat/blob/3bab6c09bbe8bf42d84b81563ddbcf4cca4be838/expat/COPYING) |
| `R_2_4_9` | [`d77291a4824d78e697c5dc2b8024fd65ab31e209`](https://github.com/libexpat/libexpat/commit/d77291a4824d78e697c5dc2b8024fd65ab31e209) | [`122f2c27000472a201d337b9b31f7eb2b52d091b02857061a8880371612d9534`](https://github.com/libexpat/libexpat/blob/d77291a4824d78e697c5dc2b8024fd65ab31e209/expat/COPYING) |
| `R_2_6_0` | [`849da3e3fe727fccef5e96ef35482d66447f06a2`](https://github.com/libexpat/libexpat/commit/849da3e3fe727fccef5e96ef35482d66447f06a2) | [`122f2c27000472a201d337b9b31f7eb2b52d091b02857061a8880371612d9534`](https://github.com/libexpat/libexpat/blob/849da3e3fe727fccef5e96ef35482d66447f06a2/expat/COPYING) |
| `R_2_6_1` | [`a590b2d5846865412182805b853dd91d18f38c8d`](https://github.com/libexpat/libexpat/commit/a590b2d5846865412182805b853dd91d18f38c8d) | [`122f2c27000472a201d337b9b31f7eb2b52d091b02857061a8880371612d9534`](https://github.com/libexpat/libexpat/blob/a590b2d5846865412182805b853dd91d18f38c8d/expat/COPYING) |
| `R_2_6_2` | [`fa75b96546c069d17b8f80d91e0f4ef0cde3790d`](https://github.com/libexpat/libexpat/commit/fa75b96546c069d17b8f80d91e0f4ef0cde3790d) | [`122f2c27000472a201d337b9b31f7eb2b52d091b02857061a8880371612d9534`](https://github.com/libexpat/libexpat/blob/fa75b96546c069d17b8f80d91e0f4ef0cde3790d/expat/COPYING) |
| `R_2_6_3` | [`88b3ed553d8ad335559254863a33360d55b9f1d6`](https://github.com/libexpat/libexpat/commit/88b3ed553d8ad335559254863a33360d55b9f1d6) | [`122f2c27000472a201d337b9b31f7eb2b52d091b02857061a8880371612d9534`](https://github.com/libexpat/libexpat/blob/88b3ed553d8ad335559254863a33360d55b9f1d6/expat/COPYING) |
| `R_2_7_4` | [`f5c2890d8ff91f88a018173d293a9bd02f76389e`](https://github.com/libexpat/libexpat/commit/f5c2890d8ff91f88a018173d293a9bd02f76389e) | [`31b15de82aa19a845156169a17a5488bf597e561b2c318d159ed583139b25e87`](https://github.com/libexpat/libexpat/blob/f5c2890d8ff91f88a018173d293a9bd02f76389e/expat/COPYING) |
| `R_2_7_5` | [`f31adfd584b7f6c50bbf4d22eb928538ffc9145a`](https://github.com/libexpat/libexpat/commit/f31adfd584b7f6c50bbf4d22eb928538ffc9145a) | [`31b15de82aa19a845156169a17a5488bf597e561b2c318d159ed583139b25e87`](https://github.com/libexpat/libexpat/blob/f31adfd584b7f6c50bbf4d22eb928538ffc9145a/expat/COPYING) |

Recipe note: xmltok_impl.c and xmltok_ns.c are #included by xmltok.c. expat_config.h is authored here (little-endian, XML_DTD, XML_GE, XML_NS; the Windows entropy path is used).

### jansson

Upstream: https://github.com/akheron/jansson.git. Election: `MIT`. License file: `LICENSE`. Output: `jansson.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `v2.12` | [`71c4e8ec215afa225ac20eed269a14963cd37b50`](https://github.com/akheron/jansson/commit/71c4e8ec215afa225ac20eed269a14963cd37b50) | [`f0a0c95c64e9f49ec4cbfac8e7fee06823c85ee8ba4af5d57aaabb372347adc2`](https://github.com/akheron/jansson/blob/71c4e8ec215afa225ac20eed269a14963cd37b50/LICENSE) |
| `v2.13` | [`2882ead5bb90cf12a01b07b2c2361e24960fae02`](https://github.com/akheron/jansson/commit/2882ead5bb90cf12a01b07b2c2361e24960fae02) | [`1fff7d37d22157bcd81ab53b6c54da755d7c2f868f15807d9bde920f10730da0`](https://github.com/akheron/jansson/blob/2882ead5bb90cf12a01b07b2c2361e24960fae02/LICENSE) |
| `v2.13.1` | [`e9ebfa7e77a6bee77df44e096b100e7131044059`](https://github.com/akheron/jansson/commit/e9ebfa7e77a6bee77df44e096b100e7131044059) | [`1fff7d37d22157bcd81ab53b6c54da755d7c2f868f15807d9bde920f10730da0`](https://github.com/akheron/jansson/blob/e9ebfa7e77a6bee77df44e096b100e7131044059/LICENSE) |
| `v2.14` | [`684e18c927e89615c2d501737e90018f4930d6c5`](https://github.com/akheron/jansson/commit/684e18c927e89615c2d501737e90018f4930d6c5) | [`1fff7d37d22157bcd81ab53b6c54da755d7c2f868f15807d9bde920f10730da0`](https://github.com/akheron/jansson/blob/684e18c927e89615c2d501737e90018f4930d6c5/LICENSE) |
| `v2.14.1` | [`ed5cae4ed0621ef409510f94270c9f8f263736d0`](https://github.com/akheron/jansson/commit/ed5cae4ed0621ef409510f94270c9f8f263736d0) | [`150d90904cd8de73609bb177b42edd3867b07b4b7b786dbba319f30de39fcda2`](https://github.com/akheron/jansson/blob/ed5cae4ed0621ef409510f94270c9f8f263736d0/LICENSE) |
| `v2.15.0` | [`4a9a6db73d5dc553164992e87426502ab2d54512`](https://github.com/akheron/jansson/commit/4a9a6db73d5dc553164992e87426502ab2d54512) | [`150d90904cd8de73609bb177b42edd3867b07b4b7b786dbba319f30de39fcda2`](https://github.com/akheron/jansson/blob/4a9a6db73d5dc553164992e87426502ab2d54512/LICENSE) |

Recipe note: jansson_config.h and jansson_private_config.h (autoconf/cmake output upstream) are authored here with the mingw-w64 feature set.

### libdeflate

Upstream: https://github.com/ebiggers/libdeflate.git. Election: `MIT`. License file: `COPYING`. Output: `libdeflate.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `v1.15` | [`020133854ff73b8506fe59f92a9b5b622d360716`](https://github.com/ebiggers/libdeflate/commit/020133854ff73b8506fe59f92a9b5b622d360716) | [`5d246dd2537307b80fed9ba5fdddf5d0fe7a8f023393a071182b9daed56b40fe`](https://github.com/ebiggers/libdeflate/blob/020133854ff73b8506fe59f92a9b5b622d360716/COPYING) |
| `v1.16` | [`7e11d509789df468151b52f7ed64ca4e566996c4`](https://github.com/ebiggers/libdeflate/commit/7e11d509789df468151b52f7ed64ca4e566996c4) | [`5d246dd2537307b80fed9ba5fdddf5d0fe7a8f023393a071182b9daed56b40fe`](https://github.com/ebiggers/libdeflate/blob/7e11d509789df468151b52f7ed64ca4e566996c4/COPYING) |
| `v1.17` | [`bd925ae68e99f65d69f20181cb845aaba5c8f098`](https://github.com/ebiggers/libdeflate/commit/bd925ae68e99f65d69f20181cb845aaba5c8f098) | [`5d246dd2537307b80fed9ba5fdddf5d0fe7a8f023393a071182b9daed56b40fe`](https://github.com/ebiggers/libdeflate/blob/bd925ae68e99f65d69f20181cb845aaba5c8f098/COPYING) |
| `v1.18` | [`495fee110ebb48a5eb63b75fd67e42b2955871e2`](https://github.com/ebiggers/libdeflate/commit/495fee110ebb48a5eb63b75fd67e42b2955871e2) | [`5d246dd2537307b80fed9ba5fdddf5d0fe7a8f023393a071182b9daed56b40fe`](https://github.com/ebiggers/libdeflate/blob/495fee110ebb48a5eb63b75fd67e42b2955871e2/COPYING) |
| `v1.19` | [`dd12ff2b36d603dbb7fa8838fe7e7176fcbd4f6f`](https://github.com/ebiggers/libdeflate/commit/dd12ff2b36d603dbb7fa8838fe7e7176fcbd4f6f) | [`5d246dd2537307b80fed9ba5fdddf5d0fe7a8f023393a071182b9daed56b40fe`](https://github.com/ebiggers/libdeflate/blob/dd12ff2b36d603dbb7fa8838fe7e7176fcbd4f6f/COPYING) |
| `v1.20` | [`275aa5141db6eda3587214e0f1d3a134768f557d`](https://github.com/ebiggers/libdeflate/commit/275aa5141db6eda3587214e0f1d3a134768f557d) | [`5d246dd2537307b80fed9ba5fdddf5d0fe7a8f023393a071182b9daed56b40fe`](https://github.com/ebiggers/libdeflate/blob/275aa5141db6eda3587214e0f1d3a134768f557d/COPYING) |
| `v1.23` | [`78051988f96dc8d8916310d8b24021f01bd9e102`](https://github.com/ebiggers/libdeflate/commit/78051988f96dc8d8916310d8b24021f01bd9e102) | [`4ad69099cb4374836fd27583d9991e2838cd86b6e4666ab26b2d32582c91e73a`](https://github.com/ebiggers/libdeflate/blob/78051988f96dc8d8916310d8b24021f01bd9e102/COPYING) |
| `v1.24` | [`96836d7d9d10e3e0d53e6edb54eb908514e336c4`](https://github.com/ebiggers/libdeflate/commit/96836d7d9d10e3e0d53e6edb54eb908514e336c4) | [`4ad69099cb4374836fd27583d9991e2838cd86b6e4666ab26b2d32582c91e73a`](https://github.com/ebiggers/libdeflate/blob/96836d7d9d10e3e0d53e6edb54eb908514e336c4/COPYING) |

Recipe note: Library sources only (programs/, scripts/ and tests are not compiled); no cmake or make: lib/*.c plus the per-arch cpu_features.c files, whose bodies compile out on the other architecture. Each pin passes native gcc -std=gnu11 -fsyntax-only -I. on all 11 sources; built with mingw-w64 gcc 13-win32 -O2 -g at every card pin. Upstream uses no dllexport without LIBDEFLATE_DLL, so the DLL exports every global symbol.

### libpng

Upstream: https://github.com/pnggroup/libpng.git. Election: `Libpng-2.0`. License file: `LICENSE`. Output: `libpng16.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `v1.6.37` | [`a40189cf881e9f0db80511c382292a5604c3c3d1`](https://github.com/pnggroup/libpng/commit/a40189cf881e9f0db80511c382292a5604c3c3d1) | [`bf5e22b9dce8464064ae17a48ea1133c3369ac9e1d80ef9e320e5219aa14ea9b`](https://github.com/pnggroup/libpng/blob/a40189cf881e9f0db80511c382292a5604c3c3d1/LICENSE) |
| `v1.6.38` | [`0a158f3506502dfa23edfc42790dfaed82efba17`](https://github.com/pnggroup/libpng/commit/0a158f3506502dfa23edfc42790dfaed82efba17) | [`dfe5a536b0e5a531f844fb9c101a3089aca60772a503893b8e15f9457e369960`](https://github.com/pnggroup/libpng/blob/0a158f3506502dfa23edfc42790dfaed82efba17/LICENSE) |
| `v1.6.41` | [`ba980b8f0cfbc270ba1c4a663455e2fe8bad91d2`](https://github.com/pnggroup/libpng/commit/ba980b8f0cfbc270ba1c4a663455e2fe8bad91d2) | [`7317e078e2d3b5d7ba5a6159e650945153262b44b76f6700f8e9edb261c5143e`](https://github.com/pnggroup/libpng/blob/ba980b8f0cfbc270ba1c4a663455e2fe8bad91d2/LICENSE) |
| `v1.6.42` | [`35d9f5ea523cb4f9d677af4705e00ddd185ed10e`](https://github.com/pnggroup/libpng/commit/35d9f5ea523cb4f9d677af4705e00ddd185ed10e) | [`7317e078e2d3b5d7ba5a6159e650945153262b44b76f6700f8e9edb261c5143e`](https://github.com/pnggroup/libpng/blob/35d9f5ea523cb4f9d677af4705e00ddd185ed10e/LICENSE) |
| `v1.6.43` | [`ed217e3e601d8e462f7fd1e04bed43ac42212429`](https://github.com/pnggroup/libpng/commit/ed217e3e601d8e462f7fd1e04bed43ac42212429) | [`7317e078e2d3b5d7ba5a6159e650945153262b44b76f6700f8e9edb261c5143e`](https://github.com/pnggroup/libpng/blob/ed217e3e601d8e462f7fd1e04bed43ac42212429/LICENSE) |
| `v1.6.44` | [`f5e92d76973a7a53f517579bc95d61483bf108c0`](https://github.com/pnggroup/libpng/commit/f5e92d76973a7a53f517579bc95d61483bf108c0) | [`7317e078e2d3b5d7ba5a6159e650945153262b44b76f6700f8e9edb261c5143e`](https://github.com/pnggroup/libpng/blob/f5e92d76973a7a53f517579bc95d61483bf108c0/LICENSE) |
| `v1.6.46` | [`0024abd279d3a06435c0309a3f4172eed7c7a19a`](https://github.com/pnggroup/libpng/commit/0024abd279d3a06435c0309a3f4172eed7c7a19a) | [`16d9daaafbf63a31a5bdc91d4600972548fef5aaa1244202393288dbd079c49a`](https://github.com/pnggroup/libpng/blob/0024abd279d3a06435c0309a3f4172eed7c7a19a/LICENSE) |
| `v1.6.47` | [`872555f4ba910252783af1507f9e7fe1653be252`](https://github.com/pnggroup/libpng/commit/872555f4ba910252783af1507f9e7fe1653be252) | [`16d9daaafbf63a31a5bdc91d4600972548fef5aaa1244202393288dbd079c49a`](https://github.com/pnggroup/libpng/blob/872555f4ba910252783af1507f9e7fe1653be252/LICENSE) |
| `v1.6.50` | [`2b978915d82377df13fcbb1fb56660195ded868a`](https://github.com/pnggroup/libpng/commit/2b978915d82377df13fcbb1fb56660195ded868a) | [`16d9daaafbf63a31a5bdc91d4600972548fef5aaa1244202393288dbd079c49a`](https://github.com/pnggroup/libpng/blob/2b978915d82377df13fcbb1fb56660195ded868a/LICENSE) |
| `v1.6.51` | [`49363adcfaf098748d7a4c8c624ad8c45a8c3a86`](https://github.com/pnggroup/libpng/commit/49363adcfaf098748d7a4c8c624ad8c45a8c3a86) | [`16d9daaafbf63a31a5bdc91d4600972548fef5aaa1244202393288dbd079c49a`](https://github.com/pnggroup/libpng/blob/49363adcfaf098748d7a4c8c624ad8c45a8c3a86/LICENSE) |
| `v1.6.53` | [`4e3f57d50f552841550a36eabbb3fbcecacb7750`](https://github.com/pnggroup/libpng/commit/4e3f57d50f552841550a36eabbb3fbcecacb7750) | [`16d9daaafbf63a31a5bdc91d4600972548fef5aaa1244202393288dbd079c49a`](https://github.com/pnggroup/libpng/blob/4e3f57d50f552841550a36eabbb3fbcecacb7750/LICENSE) |
| `v1.6.54` | [`02f2b4f4699f0ef9111a6534f093b53732df4452`](https://github.com/pnggroup/libpng/commit/02f2b4f4699f0ef9111a6534f093b53732df4452) | [`bdb0a645ea18c60507d0368379b1ac5474b92255fcc2d115e07486a7672ba526`](https://github.com/pnggroup/libpng/blob/02f2b4f4699f0ef9111a6534f093b53732df4452/LICENSE) |
| `v1.6.55` | [`c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`](https://github.com/pnggroup/libpng/commit/c3e304954a9cfd154bc0dfbfea2b01cd61d6546d) | [`bdb0a645ea18c60507d0368379b1ac5474b92255fcc2d115e07486a7672ba526`](https://github.com/pnggroup/libpng/blob/c3e304954a9cfd154bc0dfbfea2b01cd61d6546d/LICENSE) |
| `v1.6.56` | [`d5515b5b8be3901aac04e5bd8bd5c89f287bcd33`](https://github.com/pnggroup/libpng/commit/d5515b5b8be3901aac04e5bd8bd5c89f287bcd33) | [`bdb0a645ea18c60507d0368379b1ac5474b92255fcc2d115e07486a7672ba526`](https://github.com/pnggroup/libpng/blob/d5515b5b8be3901aac04e5bd8bd5c89f287bcd33/LICENSE) |

Pinned dependencies: zlib `v1.3.1` / `51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf`.

Recipe note: Fifteen explicit libpng sources (pngtest.c and example.c excluded); scripts/pnglibconf.h.prebuilt is copied to pnglibconf.h (no configure/cmake); zlib v1.3.1 is compiled into the same image as a dependency; no arch-specific SIMD files.

### libyaml

Upstream: https://github.com/yaml/libyaml.git. Election: `MIT`. License file: `License`. Output: `yaml.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `0.2.3` | [`bf5290289996338dcba9471b839013068d9e9ae8`](https://github.com/yaml/libyaml/commit/bf5290289996338dcba9471b839013068d9e9ae8) | [`c40112449f254b9753045925248313e9270efa36d226b22d82d4cc6c43c57f29`](https://github.com/yaml/libyaml/blob/bf5290289996338dcba9471b839013068d9e9ae8/License) |
| `0.2.4` | [`72e2f75277ff88ad1fb8a81cf422df06bf371578`](https://github.com/yaml/libyaml/commit/72e2f75277ff88ad1fb8a81cf422df06bf371578) | [`c40112449f254b9753045925248313e9270efa36d226b22d82d4cc6c43c57f29`](https://github.com/yaml/libyaml/blob/72e2f75277ff88ad1fb8a81cf422df06bf371578/License) |
| `0.2.5` | [`2c891fc7a770e8ba2fec34fc6b545c672beb37e6`](https://github.com/yaml/libyaml/commit/2c891fc7a770e8ba2fec34fc6b545c672beb37e6) | [`c40112449f254b9753045925248313e9270efa36d226b22d82d4cc6c43c57f29`](https://github.com/yaml/libyaml/blob/2c891fc7a770e8ba2fec34fc6b545c672beb37e6/License) |

Recipe note: Eight src files; src/config.h (cmake output upstream) is authored per version with YAML_VERSION_* and YAML_DECLARE_STATIC. The licence file is named License only from 0.2.3 on (LICENSE before), so earlier tags are not pinned.

### lua

Upstream: https://github.com/lua/lua.git. Election: `MIT`. License file: `lua.h`. Output: `lua54.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `v5.3.5` | [`063d4e4543088e7a21965bda8ee5a0f952a9029e`](https://github.com/lua/lua/commit/063d4e4543088e7a21965bda8ee5a0f952a9029e) | [`ad0c88137d59e93f88c416f1f24661fd5d529d2658b10ffa9c283a94a507af82`](https://github.com/lua/lua/blob/063d4e4543088e7a21965bda8ee5a0f952a9029e/lua.h) |
| `v5.3.6` | [`75ea9ccbea7c4886f30da147fb67b693b2624c26`](https://github.com/lua/lua/commit/75ea9ccbea7c4886f30da147fb67b693b2624c26) | [`d05e8e3b199aa51fec7c3d40f058a1e4f9aa76bb0587a9fe211f00c800f71a9d`](https://github.com/lua/lua/blob/75ea9ccbea7c4886f30da147fb67b693b2624c26/lua.h) |
| `v5.4.6` | [`6443185167c77adcc8552a3fee7edab7895db1a9`](https://github.com/lua/lua/commit/6443185167c77adcc8552a3fee7edab7895db1a9) | [`245ec29da577aefefebdb728c32a7d7407e4ff43889e038d2ab6e6349f5153f0`](https://github.com/lua/lua/blob/6443185167c77adcc8552a3fee7edab7895db1a9/lua.h) |
| `v5.4.7` | [`1ab3208a1fceb12fca8f24ba57d6e13c5bff15e3`](https://github.com/lua/lua/commit/1ab3208a1fceb12fca8f24ba57d6e13c5bff15e3) | [`341014ee8b49570fc01c1fb2afc6a7decc853525636c74e7a6a9507a933aa62e`](https://github.com/lua/lua/blob/1ab3208a1fceb12fca8f24ba57d6e13c5bff15e3/lua.h) |
| `v5.4.8` | [`6e22fedb74cf0c9b6656e9fce8b7331db847c605`](https://github.com/lua/lua/commit/6e22fedb74cf0c9b6656e9fce8b7331db847c605) | [`3b77329f9deed929a5cbe7a7d5fc81ebbb63fd869a49e0a9302fe9240caf1930`](https://github.com/lua/lua/blob/6e22fedb74cf0c9b6656e9fce8b7331db847c605/lua.h) |

Recipe note: The licence notice is the MIT block at the end of lua.h (no LICENSE file in the development repository). Core + standard libraries; the lua.c/luac.c front ends, onelua.c amalgam and ltests.c are excluded.

### lz4

Upstream: https://github.com/lz4/lz4.git. Election: `BSD-2-Clause`. License file: `lib/LICENSE`. Output: `liblz4.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `v1.9.2` | [`fdf2ef5809ca875c454510610764d9125ef2ebbd`](https://github.com/lz4/lz4/commit/fdf2ef5809ca875c454510610764d9125ef2ebbd) | [`d15d99c8dc6b0ec22174c0e563a95bc40f9363ca7f9d9d793bb5c5a8e8d0af71`](https://github.com/lz4/lz4/blob/fdf2ef5809ca875c454510610764d9125ef2ebbd/lib/LICENSE) |
| `v1.9.3` | [`d44371841a2f1728a3f36839fd4b7e872d0927d3`](https://github.com/lz4/lz4/commit/d44371841a2f1728a3f36839fd4b7e872d0927d3) | [`d15d99c8dc6b0ec22174c0e563a95bc40f9363ca7f9d9d793bb5c5a8e8d0af71`](https://github.com/lz4/lz4/blob/d44371841a2f1728a3f36839fd4b7e872d0927d3/lib/LICENSE) |
| `v1.9.4` | [`5ff839680134437dbf4678f3d0c7b371d84f4964`](https://github.com/lz4/lz4/commit/5ff839680134437dbf4678f3d0c7b371d84f4964) | [`8b58c446121a109ccf32edc094bba3010a3d85e4ee3702950db55e4d3e87736c`](https://github.com/lz4/lz4/blob/5ff839680134437dbf4678f3d0c7b371d84f4964/lib/LICENSE) |
| `v1.10.0` | [`ebb370ca83af193212df4dcbadcc5d87bc0de2f0`](https://github.com/lz4/lz4/commit/ebb370ca83af193212df4dcbadcc5d87bc0de2f0) | [`8b58c446121a109ccf32edc094bba3010a3d85e4ee3702950db55e4d3e87736c`](https://github.com/lz4/lz4/blob/ebb370ca83af193212df4dcbadcc5d87bc0de2f0/lib/LICENSE) |

Recipe note: The BSD-2-Clause library directory only (lib/LICENSE; the repository root LICENSE also covers the GPL programs/ tools, which are not compiled). lz4file.c exists from v1.9.4 on and is ignored where absent.

### mbedtls

Upstream: https://github.com/Mbed-TLS/mbedtls.git. Election: `Apache-2.0`. License file: `LICENSE`. Output: `mbedtls.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `v3.6.0` | [`2ca6c285a0dd3f33982dd57299012dacab1ff206`](https://github.com/Mbed-TLS/mbedtls/commit/2ca6c285a0dd3f33982dd57299012dacab1ff206) | [`9b405ef4c89342f5eae1dd828882f931747f71001cfba7d114801039b52ad09b`](https://github.com/Mbed-TLS/mbedtls/blob/2ca6c285a0dd3f33982dd57299012dacab1ff206/LICENSE) |
| `v3.6.1` | [`71c569d44bf3a8bd53d874c81ee8ac644dd6e9e3`](https://github.com/Mbed-TLS/mbedtls/commit/71c569d44bf3a8bd53d874c81ee8ac644dd6e9e3) | [`9b405ef4c89342f5eae1dd828882f931747f71001cfba7d114801039b52ad09b`](https://github.com/Mbed-TLS/mbedtls/blob/71c569d44bf3a8bd53d874c81ee8ac644dd6e9e3/LICENSE) |
| `v3.6.2` | [`107ea89daaefb9867ea9121002fbbdf926780e98`](https://github.com/Mbed-TLS/mbedtls/commit/107ea89daaefb9867ea9121002fbbdf926780e98) | [`9b405ef4c89342f5eae1dd828882f931747f71001cfba7d114801039b52ad09b`](https://github.com/Mbed-TLS/mbedtls/blob/107ea89daaefb9867ea9121002fbbdf926780e98/LICENSE) |
| `v3.6.3` | [`22098d41c6620ce07cf8a0134d37302355e1e5ef`](https://github.com/Mbed-TLS/mbedtls/commit/22098d41c6620ce07cf8a0134d37302355e1e5ef) | [`9b405ef4c89342f5eae1dd828882f931747f71001cfba7d114801039b52ad09b`](https://github.com/Mbed-TLS/mbedtls/blob/22098d41c6620ce07cf8a0134d37302355e1e5ef/LICENSE) |
| `v3.6.4` | [`c765c831e5c2a0971410692f92f7a81d6ec65ec2`](https://github.com/Mbed-TLS/mbedtls/commit/c765c831e5c2a0971410692f92f7a81d6ec65ec2) | [`9b405ef4c89342f5eae1dd828882f931747f71001cfba7d114801039b52ad09b`](https://github.com/Mbed-TLS/mbedtls/blob/c765c831e5c2a0971410692f92f7a81d6ec65ec2/LICENSE) |
| `v3.6.5` | [`e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df`](https://github.com/Mbed-TLS/mbedtls/commit/e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df) | [`9b405ef4c89342f5eae1dd828882f931747f71001cfba7d114801039b52ad09b`](https://github.com/Mbed-TLS/mbedtls/blob/e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df/LICENSE) |

Recipe note: The 3.6 LTS single-tree layout only (4.x moved crypto to the tf-psa-crypto submodule). Dual-licensed: the Apache-2.0 option is recorded. library/net_sockets.c is excluded (winsock) and three -D switches avoid the bcrypt/ws2_32 import libraries the fixed link line cannot name: the software inet_pton and no platform entropy source (image is never executed). Otherwise the default mbedtls_config.h.

### miniz

Upstream: https://github.com/richgel999/miniz.git. Election: `MIT`. License file: `LICENSE`. Output: `miniz.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `2.1.0` | [`a4264837ae37384b1d7a205a6732db322f0f3769`](https://github.com/richgel999/miniz/commit/a4264837ae37384b1d7a205a6732db322f0f3769) | [`0115478d567121238cf6cc1c0c361926cf07a49d9e4c9e66da97fac6a01646b3`](https://github.com/richgel999/miniz/blob/a4264837ae37384b1d7a205a6732db322f0f3769/LICENSE) |
| `2.2.0` | [`cb97387d20909c0a4728972fd0f19bfacd083c42`](https://github.com/richgel999/miniz/commit/cb97387d20909c0a4728972fd0f19bfacd083c42) | [`0115478d567121238cf6cc1c0c361926cf07a49d9e4c9e66da97fac6a01646b3`](https://github.com/richgel999/miniz/blob/cb97387d20909c0a4728972fd0f19bfacd083c42/LICENSE) |
| `3.0.0` | [`39f65158c7e5a830e390f3aece08de654c763981`](https://github.com/richgel999/miniz/commit/39f65158c7e5a830e390f3aece08de654c763981) | [`0115478d567121238cf6cc1c0c361926cf07a49d9e4c9e66da97fac6a01646b3`](https://github.com/richgel999/miniz/blob/39f65158c7e5a830e390f3aece08de654c763981/LICENSE) |
| `3.0.2` | [`293d4db1b7d0ffee9756d035b9ac6f7431ef8492`](https://github.com/richgel999/miniz/commit/293d4db1b7d0ffee9756d035b9ac6f7431ef8492) | [`0115478d567121238cf6cc1c0c361926cf07a49d9e4c9e66da97fac6a01646b3`](https://github.com/richgel999/miniz/blob/293d4db1b7d0ffee9756d035b9ac6f7431ef8492/LICENSE) |
| `3.1.0` | [`174573d60290f447c13a2b1b3405de2b96e27d6c`](https://github.com/richgel999/miniz/commit/174573d60290f447c13a2b1b3405de2b96e27d6c) | [`0115478d567121238cf6cc1c0c361926cf07a49d9e4c9e66da97fac6a01646b3`](https://github.com/richgel999/miniz/blob/174573d60290f447c13a2b1b3405de2b96e27d6c/LICENSE) |
| `e680017` | [`e680017bae901240e8894062c0b0a3020eca42c1`](https://github.com/richgel999/miniz/commit/e680017bae901240e8894062c0b0a3020eca42c1) | [`0115478d567121238cf6cc1c0c361926cf07a49d9e4c9e66da97fac6a01646b3`](https://github.com/richgel999/miniz/blob/e680017bae901240e8894062c0b0a3020eca42c1/LICENSE) |

Recipe note: miniz_export.h (generated by cmake upstream) is authored as an empty export macro. Source files that do not exist at a pin are ignored.

### pcre2

Upstream: https://github.com/PCRE2Project/pcre2.git. Election: `BSD-3-Clause WITH PCRE2-exception`. License file: `LICENCE.md`. Output: `pcre2-8.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `pcre2-10.45` | [`2dce7761b1831fd3f82a9c2bd5476259d945da4d`](https://github.com/PCRE2Project/pcre2/commit/2dce7761b1831fd3f82a9c2bd5476259d945da4d) | [`9cf7ac6976099a1d856826d3ef1b093bd6b84489dc6100628ac79e740cf9885a`](https://github.com/PCRE2Project/pcre2/blob/2dce7761b1831fd3f82a9c2bd5476259d945da4d/LICENCE.md) |
| `pcre2-10.46` | [`b2bd4254b379b9d7dc9a3dda060a7e27009ccdff`](https://github.com/PCRE2Project/pcre2/commit/b2bd4254b379b9d7dc9a3dda060a7e27009ccdff) | [`9cf7ac6976099a1d856826d3ef1b093bd6b84489dc6100628ac79e740cf9885a`](https://github.com/PCRE2Project/pcre2/blob/b2bd4254b379b9d7dc9a3dda060a7e27009ccdff/LICENCE.md) |
| `pcre2-10.47` | [`f454e231fe5006dd7ff8f4693fd2b8eb94333429`](https://github.com/PCRE2Project/pcre2/commit/f454e231fe5006dd7ff8f4693fd2b8eb94333429) | [`197d8a73ffee0d6b09adba2f9c677b5f5aede24edf89258a68e48248d010d811`](https://github.com/PCRE2Project/pcre2/blob/f454e231fe5006dd7ff8f4693fd2b8eb94333429/LICENCE.md) |
| `pcre2-10.48` | [`7978954dbd2efc6f2196869290553cf1871b4ce6`](https://github.com/PCRE2Project/pcre2/commit/7978954dbd2efc6f2196869290553cf1871b4ce6) | [`197d8a73ffee0d6b09adba2f9c677b5f5aede24edf89258a68e48248d010d811`](https://github.com/PCRE2Project/pcre2/blob/7978954dbd2efc6f2196869290553cf1871b4ce6/LICENCE.md) |
| `pcre2-10.49` | [`6f9d7c1373262c541324a16a358785b33ef116cf`](https://github.com/PCRE2Project/pcre2/commit/6f9d7c1373262c541324a16a358785b33ef116cf) | [`197d8a73ffee0d6b09adba2f9c677b5f5aede24edf89258a68e48248d010d811`](https://github.com/PCRE2Project/pcre2/blob/6f9d7c1373262c541324a16a358785b33ef116cf/LICENCE.md) |

Recipe note: 8-bit library without JIT (stub pcre2_jit_*). config.h, pcre2.h and pcre2_chartables.c come from the pinned *.generic/.dist templates (copy rules); pcre2_ucd.c/pcre2_ucptables.c are #included by other units; in 10.45/10.46 pcre2_jit_match.c and pcre2_jit_misc.c are #included by pcre2_jit_compile.c and excluded as separate units.

### stb

Upstream: https://github.com/nothings/stb.git. Election: `MIT`. License file: `LICENSE`. Output: `stb.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `stb_image-2.23-2020-02-02` | [`5e4a0617b72fd4db2e1fc4d5c2d8b483d948d573`](https://github.com/nothings/stb/commit/5e4a0617b72fd4db2e1fc4d5c2d8b483d948d573) | [`bebfe904b14301657e4e5d655c811d51fd31b97c455b9cc2d8600d6bac6cff63`](https://github.com/nothings/stb/blob/5e4a0617b72fd4db2e1fc4d5c2d8b483d948d573/LICENSE) |
| `stb_image-2.26` | [`314d0a6f9af5af27e585336eecea333e95c5a2d8`](https://github.com/nothings/stb/commit/314d0a6f9af5af27e585336eecea333e95c5a2d8) | [`bebfe904b14301657e4e5d655c811d51fd31b97c455b9cc2d8600d6bac6cff63`](https://github.com/nothings/stb/blob/314d0a6f9af5af27e585336eecea333e95c5a2d8/LICENSE) |
| `stb_image-2.27` | [`1ee679ca2ef753a528db5ba6801e1067b40481b8`](https://github.com/nothings/stb/commit/1ee679ca2ef753a528db5ba6801e1067b40481b8) | [`bebfe904b14301657e4e5d655c811d51fd31b97c455b9cc2d8600d6bac6cff63`](https://github.com/nothings/stb/blob/1ee679ca2ef753a528db5ba6801e1067b40481b8/LICENSE) |
| `stb_image-2.28` | [`6199bf77130da41fd424722eeb7a8db4d766c4c6`](https://github.com/nothings/stb/commit/6199bf77130da41fd424722eeb7a8db4d766c4c6) | [`bebfe904b14301657e4e5d655c811d51fd31b97c455b9cc2d8600d6bac6cff63`](https://github.com/nothings/stb/blob/6199bf77130da41fd424722eeb7a8db4d766c4c6/LICENSE) |
| `stb_image-2.30` | [`013ac3beddff3dbffafd5177e7972067cd2b5083`](https://github.com/nothings/stb/commit/013ac3beddff3dbffafd5177e7972067cd2b5083) | [`bebfe904b14301657e4e5d655c811d51fd31b97c455b9cc2d8600d6bac6cff63`](https://github.com/nothings/stb/blob/013ac3beddff3dbffafd5177e7972067cd2b5083/LICENSE) |

Recipe note: stb has no tags: pins are commit pairs, each the upstream 'update version numbers' commit (stb_image 2.23, 2.26, 2.27, 2.28) plus 013ac3b (2.30). The single-header libraries are compiled through five authored one-line translation-unit wrappers (the *_IMPLEMENTATION define then the header) and stb_vorbis.c, which is an ordinary C file; changed-function files are therefore the headers. LICENSE exists only from 2020-02-02, so the 2019 stb_vorbis CVE cards stay no-recipe. Each pin passes native gcc -fsyntax-only on all six units and links as a shared object; built with mingw-w64 gcc 13-win32 -O2 -g at every card pin. MIT is chosen from the dual MIT / Unlicense LICENSE (alternative A).

### zlib

Upstream: https://github.com/madler/zlib.git. Election: `Zlib`. License file: `LICENSE`. Output: `zlib1.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `v1.3` | [`09155eaa2f9270dc4ed1fa13e2b4b2613e6e4851`](https://github.com/madler/zlib/commit/09155eaa2f9270dc4ed1fa13e2b4b2613e6e4851) | [`845efc77857d485d91fb3e0b884aaa929368c717ae8186b66fe1ed2495753243`](https://github.com/madler/zlib/blob/09155eaa2f9270dc4ed1fa13e2b4b2613e6e4851/LICENSE) |
| `v1.3.1` | [`51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf`](https://github.com/madler/zlib/commit/51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf) | [`845efc77857d485d91fb3e0b884aaa929368c717ae8186b66fe1ed2495753243`](https://github.com/madler/zlib/blob/51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf/LICENSE) |
| `v1.3.1.2` | [`570720b0c24f9686c33f35a1b3165c1f568b96be`](https://github.com/madler/zlib/commit/570720b0c24f9686c33f35a1b3165c1f568b96be) | [`db87e85464166fab6bc644092392fd6cfedf0abd8a16c63f419139ea57c33628`](https://github.com/madler/zlib/blob/570720b0c24f9686c33f35a1b3165c1f568b96be/LICENSE) |
| `v1.3.2` | [`da607da739fa6047df13e66a2af6b8bec7c2a498`](https://github.com/madler/zlib/commit/da607da739fa6047df13e66a2af6b8bec7c2a498) | [`e32ff4e00d9d94930537635291da39e7e612703334bf6fde8c7f1686fe8a45a2`](https://github.com/madler/zlib/blob/da607da739fa6047df13e66a2af6b8bec7c2a498/LICENSE) |

Recipe note: Top-level *.c only (subdirectories excluded by the POSIX glob). Commits are the peeled tag objects from git ls-remote; each verified by the fetch receipt (git rev-parse HEAD).

### zstd

Upstream: https://github.com/facebook/zstd.git. Election: `BSD-3-Clause`. License file: `LICENSE`. Output: `libzstd.dll`.

| Existing ref | Exact commit | Expected license SHA-256 |
|---|---|---|
| `v1.4.9` | [`e4558ffd1dc49399faf4ee5d85abed4386b4dcf5`](https://github.com/facebook/zstd/commit/e4558ffd1dc49399faf4ee5d85abed4386b4dcf5) | [`2c1a7fa704df8f3a606f6fc010b8b5aaebf403f3aeec339a12048f1ba7331a0b`](https://github.com/facebook/zstd/blob/e4558ffd1dc49399faf4ee5d85abed4386b4dcf5/LICENSE) |
| `v1.5.0` | [`a488ba114ec17ea1054b9057c26a046fc122b3b6`](https://github.com/facebook/zstd/commit/a488ba114ec17ea1054b9057c26a046fc122b3b6) | [`2c1a7fa704df8f3a606f6fc010b8b5aaebf403f3aeec339a12048f1ba7331a0b`](https://github.com/facebook/zstd/blob/a488ba114ec17ea1054b9057c26a046fc122b3b6/LICENSE) |
| `v1.5.5` | [`63779c798237346c2b245c546c40b72a5a5913fe`](https://github.com/facebook/zstd/commit/63779c798237346c2b245c546c40b72a5a5913fe) | [`7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8`](https://github.com/facebook/zstd/blob/63779c798237346c2b245c546c40b72a5a5913fe/LICENSE) |
| `v1.5.6` | [`794ea1b0afca0f020f4e57b6732332231fb23c70`](https://github.com/facebook/zstd/commit/794ea1b0afca0f020f4e57b6732332231fb23c70) | [`7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8`](https://github.com/facebook/zstd/blob/794ea1b0afca0f020f4e57b6732332231fb23c70/LICENSE) |
| `v1.5.7` | [`f8745da6ff1ad1e7bab384bd1f9d742439278e99`](https://github.com/facebook/zstd/commit/f8745da6ff1ad1e7bab384bd1f9d742439278e99) | [`7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8`](https://github.com/facebook/zstd/blob/f8745da6ff1ad1e7bab384bd1f9d742439278e99/LICENSE) |

Recipe note: zstd is dual BSD-3-Clause / GPL-2.0; the BSD option (LICENSE, not COPYING) is the one recorded. common+compress+decompress only (no dictBuilder/legacy/threading); the amd64 assembly Huffman decoder is disabled with ZSTD_DISABLE_ASM.

## Reproduction record and unresolved gates

This worker parsed local JSON, counted unique IDs/commit edges/upstreams, compared exact recipe-pin membership, inspected Tier R CLI/factory/fetch code and historical QA, and retrieved the listed primary sources. It did not execute target binaries, fetch an external corpus, compile targets, generate new labels or run a matching engine. No upstream binary artifact hash is invented: no new upstream binary artifacts were generated. Recover historical build receipts or produce fresh current receipts before citing a built/evaluated count.

To reproduce the inventory without target execution, read the three found catalogue arrays plus `releases.json` and `cves.json`; deduplicate by `(upstream_git, old.commit, new.commit)`, and compare each endpoint against `recipes.json` pins. Do not count the mirrored `releases.d` arrays again. For chain counts, use full commits rather than tag names; verify release adjacency separately against upstream history. Existing `tests/test_tier_r_catalogue.py::test_per_project_split_mirrors_the_monolithic_files` encodes the mirror invariant, but this documentation audit did not run the full test suite. The integration owner's test log is the source for new pass/fail claims.

The following catalogue byte digests anchor this inventory. They are input-file hashes, **not** target artifact hashes or proof of their prior source inspections:

| Local input | SHA-256 observed in this audit |
|---|---|
| `corpus/catalog/compression-archive.json` | `02dcad9f2edc7696d8c7ae152483b8a620ae03d53b9c64690e8dca9d425d0de7` |
| `corpus/catalog/crypto-net-db-script.json` | `4037672c915de9b6a141419105c01e0fca40b60773ea6bbb00327a87a0c471f9` |
| `corpus/catalog/parsers-media.json` | `e667a189cafed9cab62a6dc56f121a5292bea98c7e3405be5eacee0b1219de9c` |
| `tools/calibration/tier_r/catalogue/recipes.json` | `76c4f8feb875dd3171d33eca83dc3f6fa71cbd796347f1e347f7a0e7f9fab54b` |
| `tools/calibration/tier_r/catalogue/releases.json` | `9f563e8f980ff7c3415d1c422e0a2237e7a46f9c5fa887847049cdeccd8a235d` |
| `tools/calibration/tier_r/catalogue/cves.json` | `b563c7a9a2d9573bc8d16625ad711c945c3504cb042014d3ada002cccd7ef821` |
| `corpus/excluded/postgresql-libpq-untrusted-error-cve-2024-10977.json` | `86403105a091c5ca8432a8dd9bbf30f69055a4ccb5def9b9342ea6d6728ed7e6` |

Open gates for Tier E acceptance:

- Re-fetch selected exact pins and revalidate per-pin license hashes; preserve failed fetches as blocked with reasons.
- Rebuild selected reviewed source subsets under exact compiler/flags/dependencies; retain image/debug/source/configuration hashes and repeat-build evidence.
- Independently review security intent and function identity; distinguish unrelated release edits, architecture/configuration-inapplicable fixes, compiler-induced changes and unresolved structural relationships.
- Resolve miniz source spans and CVE-edge linkage and Brotli decoder attribution before security scoring.
- Obtain at least three accepted control categories without forcing identical-image cases into changed-release comparisons.
- Run genuine engines against stripped images with ground truth hidden; report coverage, abstention and engine availability separately. No prediction becomes a label.
- Complete real MSVC/Windows and additional compiler/optimization strata when available; fake toolchain tests are not compatibility evidence.
- Verify adjacent-release chains for the 14-project target; current card count alone cannot close this gate.
- Keep project, lineage and shared dependency variants grouped for partitioning; freeze a held-out subset before calibration and do not tune against it repeatedly.

The report preserves a useful, already pinned research pool and its limitations. It deliberately leaves acceptance to reproducible receipts and independent review rather than treating catalogue volume as experimental completion.
