# PR349 daee337c hosted evidence — sealed native results, QA pending

Sealed snapshot: **2026-11-21 07:01:13 UTC**. This package is specific to head `daee337c48c63dda8aeac149c407e900c79dcc86`, complete tree `6c2a8d018ccc00bf65ef074579604b40627f7658`. It is **not merge qualification**: both full QA suites and packaging remain pending. Subsequent QA observations stay outside this sealed archive.

## Exact source identity

The [published head](https://github.com/djshellshoxxx/PatchTrace/commit/daee337c48c63dda8aeac149c407e900c79dcc86) and local publication `0a270822935fb372fc181f3e2573fe60d9a16a53` have the same complete tree. The actual PR checkout is synthetic merge `ba98225bc27e3bb4e8106948f32d6ab44e8c4eb0`, whose API-confirmed parents are main `fdc2696c23bdbfe7668348f25e3b336ce33039f7` and this head; its tree is identical. Every retained complete native job log reports that checkout. All five completed non-QA workflows are pull-request runs, attempt 1, with `head_sha=daee337c`.

## Completed workflows and actual acceptance

| Workflow | Hosted conclusion | Actual evidence and limits |
|---|---|---|
| [Ghidriff 44876415864](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44876415864) | Success; five jobs | Three positive authored-PE analyses each print `Known patch accepted: 1 change records`. One expected negative control reproduces plain Ghidriff's cached-PDB FileExistsError. One raw-cache check passes. This is not five general accuracy tests. |
| [Rizin 44876415848](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44876415848) | Success; Linux and Windows | Verified artifact JSON: `mocked=false`, status `passed`, engine run `ok`. Observed match counts are 30/322, respectively; counts are not accuracy. |
| [BinDiff 44876415845](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44876415845) | Success; Linux and Windows | Linux **7 passed / 0 blocked** native checks. Windows **6 passed / 1 blocked**: `no_network` requires Linux `unshare -rn`; Windows network behavior remains manual. Each pytest wrapper reports one pass. Synthetic 20/21-function inputs are not real-driver evidence. Existing pinned TOFU asset-trust limits remain. |
| [Optional dependencies 44876415859](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44876415859) | Success; Linux and Windows | Both probes find rapidfuzz 3.14.6, yara-x 1.21.0, iced-x86 1.21.0; `missing=none`. Availability probe only. |
| [Tier R 44876415888](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44876415888) | Success | Actual aggregate is **warning**: 11 attempted engine pairs, **5 completed / 6 failed / 0 blocked**, 45.45% completion. Corpus-case outcomes are 11 ok/1 skipped; these are a different count. Windows advisory has 11 `findings`, each reason `exit 1`, and no substantive native report. MSVC advisory is skipped. |

Ghidriff raw-cache artifact [14696463366](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44876415864/artifacts/14696463366) reports both runs completed, one match each, second-run cache reuse, and identical raw SHA-256 `ed494c80a4a6aee562cff0d1850f709f45015571bc3d3f7233e6a31c920d9261`. Its acceptance record is `passed`. Known-patch analyses use authored compiled fixtures; no analyzed target is executed.

## Tier R gap and original-archive cache evidence

Both current Linux shards ([0](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44876415888/job/136764698670), [1](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44876415888/job/136764698668)) record a real hit on `rizin-archive-v1-9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf`. Both then rehash **the original** `rizin-archive/rizin-v0.9.1-static-x86_64.tar.xz` and print `OK` before use. Java, Ghidra cache restore, and Ghidra/Ghidriff install steps explicitly skip because `ENGINES=rz-diff`; this provides no Ghidra archive-cache acceptance.

All six failed engine pairs are tiny-fixture A/A, mutation, authored, or noise cases, with the same `no functions in the older file` reason. Five zlib pairs complete. The skipped typo-only zlib case produces byte-identical engine images, so no discriminating pair is fabricated. Two merges of the same shards have identical report digest `364c87d3a16c6cca92c325eb2f4d593c5e9562561e39b787004c1d6248642b4a`.

A read-only historical comparison downloaded and verified original PR349 head `11f51c105bf63946f59373ae605b937c4fee607a`, [run 44870397157](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44870397157), aggregate artifact 14694390478. Its artifact SHA-256 is `fd76df4149a9af8f9298f37dcef2664aff06f3571844d158afa567561e69ed23`. It has the **same per-pair status/reason mapping, same 5/11 completion, and same canonical report digest**. These are already-observed coverage gaps, not a newly demonstrated daee regression. The old run is retained only for attribution; its results do not qualify this source. `prior-comparison/comparison.json` records the exact comparison.

## QA state at sealing

[QA run 44876416755](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44876416755) remains in progress. Linux job 136761991347 and Windows job 136761991553 are executing full pytest; no final counts are available. Ubuntu Qt shard 4/4 reports success, while the other three Ubuntu shards and Windows Qt repeat job remain running. Windows build/frozen smoke/portable extraction/install/uninstall and Linux package plus Ubuntu 22.04/24.04 frozen CLI checks are not qualified. Release gate is intentionally skipped. Earlier original PR349 full-suite registry failures remain separately retained and are not converted into passes here.

## Contents and boundaries

`summary.json` is the compact machine-readable disposition. `source-identity.json` and `native-rest.json` retain API evidence. `logs/` contains complete decoded native job logs with original decoded text preserved, not original GitHub ZIP bytes. `artifacts/` contains original downloaded artifact ZIPs verified against GitHub metadata plus selected readable JSON. `manifest.json` hashes every included file; the archive receipt outside the ZIP hashes the sealed ZIP itself. Intel run 44876415860 is reported separately by its assigned reviewer.

No source change, workflow retry/dispatch, ref write, merge, local native engine execution, or analyzed-target execution was performed by this observer. A replacement head requires fresh native qualification; these results must not be transferred.

