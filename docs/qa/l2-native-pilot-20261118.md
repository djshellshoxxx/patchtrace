# First native L2 pilot — preserved MISS, 2026-11-18

## Result and scope

One independent source pair was analyzed once through the supported production scheduler and Rizin adapter. Native execution returned 0; the production status was `ok`. Rizin emitted **five matches, all similarity 1.0**, and omitted the frozen expected function `http_parser_execute`. The existing research ranking correctly returned `[]`; the unchanged per-case comparator returned **MISS**. The research receipt records **FAIL**. The original oracle, settings and result are sealed unchanged.

This is one ELF/GCC source-backed matching pilot, one case and one project. No percentage or confidence bound was computed. It is **not** formal Windows/MSVC L2 acceptance, desktop acquisition qualification, vulnerability attribution accuracy, or L3. No target binary was executed and no Windows target was acquired.

## Source, oracle and build

- Component: Node's vendored `http-parser`, MIT-licensed; absent from the existing calibration/research/unified fixture catalogue search.
- Primary fix: https://github.com/nodejs/node/commit/fc70ce08f5818a286fb5899a1bc3aff5965a745e
- Sole parent: `323a6f114a93a534da70f61dd5a1f5e600c11406`.
- Fix: `fc70ce08f5818a286fb5899a1bc3aff5965a745e`.
- Primary advisory: https://nodejs.org/en/blog/vulnerability/january-2021-security-releases
- CVE-2020-8287: the sole production hunk adds `parser->flags &= ~F_CHUNKED` inside `http_parser_execute` when a new Transfer-Encoding header is recognized. The other changed upstream file is `test.c`.
- Source-oracle proposal SHA-256: `bbd619b791a64d39ec48740eebe8aeed84b0bff3dbd561b61bc0ce9aaed941d1`.
- Root independently reviewed the primary commit, immediate parent, source diff, advisory and all six source SHA-256/Git blob identities before analysis. That approval is a separate record; the proposal was not edited.
- Pilot manifest canonical SHA-256: `6167e3d3ff06f0d67ba1ceef4468dbecaeeab20556d75336459dd0bcc3d4471f`.

| Input | SHA-256 |
|---|---|
| Older `http_parser.c` | `35115393aa0e716b7bc80c1dfb8836b9921161eb47c5052f7a5fc8c282cb63a4` |
| Newer `http_parser.c` | `983ae49a427094430f65c00adc6a6af4bd16651a6cec627a9813aa0b0374409d` |
| Identical header on both sides | `68d5fc4bbf8148393b27aba99333a298d2c7d9d10d4e058d236afd1ff7880b1d` |
| Identical MIT licence on both sides | `79e6ba8b687cb54786207342b9b6fcee0ac10218453ed9009b84d949b2233cc0` |
| Older ELF, 40,680 bytes | `c3914b7f5f70b88dbfc25677211347ffa86ab38a833e065a5e51a0445c26133b` |
| Newer ELF, 40,680 bytes | `96bcb8a0b8f9201d12c81e30090d933e13e7679125c26d5d604ebb0f02028df0` |

Compiler: Debian GCC 14.2.0-19. `/usr/bin/x86_64-linux-gnu-gcc-14` SHA-256: `a23ecab8ff08f09ad8c80602c2c5df7f49e09c25905cb8975902e101bf72635f`. Each build ran in its corresponding `source-candidate/older` or `source-candidate/newer` directory:

```sh
/usr/bin/cc -O2 -DNDEBUG -fPIC -shared -Wl,--build-id=none -Wl,-soname,libhttp_parser.so -o ../../build/older/libhttp_parser.so http_parser.c
/usr/bin/cc -O2 -DNDEBUG -fPIC -shared -Wl,--build-id=none -Wl,-soname,libhttp_parser.so -o ../../build/newer/libhttp_parser.so http_parser.c
```

## Tool and production source

- Download URL: https://github.com/rizinorg/rizin/releases/download/v0.9.1/rizin-v0.9.1-static-x86_64.tar.xz
- Archive: 137,626,404 bytes; SHA-256 `9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf`.
- Native version: Rizin/rz-diff 0.9.1, source commit `c3a90e9226d977f58f4e9c75f78fa6b07afe13c7`.
- `rz-diff` executable SHA-256: `536987d5d0e5d2a35689f653502dc10f8be8751a46ef2ffd888e8d514ed9712e`.
- Pinned source/licence provenance: https://github.com/rizinorg/rizin/tree/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7 ; upstream `COPYING` and `COPYING.LESSER` are included in the reproducibility bundle. These are the tool's upstream terms; the candidate sources use their own MIT licence.
- This is the stock pinned tool; the historical corrected native-API experiment was not applied to it.
- PatchTrace commit: `9ac9cbeb8ba1947b5e0889e03dccad769a6d155b`; tree: `eba3ca64508f9989c63dcbe0f42a90cd668ffebd`. Tracked source was clean; relevant module hashes were checked before and after the run.

The linked-worktree receipt helper at that commit independently passed 141 focused/adjacent tests and 25 temporary controls; no blocking review findings. The receipt contains the actual source SHA.

## Native operation and raw result

Production argv: `rz-diff -C -j -t functions VERIFIED_OLDER_COPY VERIFIED_NEWER_COPY`. The scheduler made private copies and verified both recorded input hashes. The supported runner observer delegated unchanged arguments/settings to the real `jobs.run_process` and returned its unchanged result.

- Deadline: 120 seconds. Stdout cap: 64 MiB. Stderr cap: 2 MiB. Cache disabled.
- Native duration: 1.9091231989987136 seconds; complete pilot: 2.12 seconds.
- Complete stdout: 834 bytes; SHA-256 `52a42e2045d1c4d3368ed319eaf8be4ad40b5c1087806ed643a3be1e4ae7dbb2`.
- Complete stderr: 108 bytes; SHA-256 `545d5ce5a474fbd397e64832256bccdea1e1e7d238fc68def7e2d4720788c0fc`.
- Stderr reports `Cannot determine entrypoint, using 0x00002080.` for each shared library. This is a diagnostic clue, not an established cause.
- Both pre-existing static ELF symbol reports contain `http_parser_execute` at `0x25d0`, size 12,754. It is present in the compiled inputs but absent from native output.

Exact invocation, from the pilot directory:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/workspace/scratch/e83fbf4505c3/repair-receipt-identity/src:/workspace/scratch/e83fbf4505c3/repair-receipt-identity QT_QPA_PLATFORM=offscreen /workspace/scratch/3a6632a6e5ff/venv/bin/python run_pilot.py
```

The wrapper exited 1 for the recorded MISS. It did not call aggregate scoring functions or change the expected function/name aliases.

## Exact artifacts

- Preparation: `/workspace/scratch/e83fbf4505c3/l2-tool-preparation/20261118T080830Z-rizin091`.
- Sealed first pilot: `/workspace/scratch/e83fbf4505c3/l2-native-pilot/20261118T082742Z-http-parser`.
- First-pilot manifest SHA-256: `eac35dcc23d09ee59d9190986f8414560f6f19e4f4ac61225526cf24f3897f04`.
- Result SHA-256: `6d95d0b857d2a2cdb61ceecf6a69d05133dd852677aa6889b10fbd4544de339e`.
- Research receipt: `rq-l2-native-pilot-11dab64f1a054d61-20261118T082952699329Z.json` in the pilot directory.
- Small commit candidates: this handoff, `approval.json`, `pilot-plan.json`, `pilot-case-manifest.json`, `pilot-result.json`, `engine-run.json`, `secondary-match-set.json`, `receipts/01-analysis.json`, both analysis raw streams, and the research receipt. Source/build metadata and exact scripts remain in the reproducibility archive.

## Next bounded diagnosis

Read pinned Rizin 0.9.1 source/help, then use independently authored ELF shared-library/executable and existing authored PE controls to separate native discovery/flag limitations from an adapter defect. Keep that evidence explicitly post-measurement and separate. Do not change the scorer/oracle or rerun this candidate to seek PASS; a repair informed by this case cannot later claim it as held-out evidence. Diagnosis is read-only; any production repair needs a separate specification, regression proof and independent review.

## Reproducibility archive

`l2-http-parser-reproducibility-20261118.zip`, 305,209 bytes, SHA-256
`bd6af6cd486ec38802417828a94c4f208be7a9ffadb7b6f17b42d70d1f6faec8`,
retains MIT source/header/licence snapshots, both compiled ELF files, primary
commit metadata, tool pins and all pilot evidence. Its 97 indexed members were
hash-verified. The reconstructible tool payload and full advisory HTML are
excluded. The original baseline and first-pilot records remain immutable.
