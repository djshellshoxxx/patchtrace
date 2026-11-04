# R2 native cJSON development observation

Date: 2026-10-30. Production source: `6d1e8be450d8018576cff5176d5a92c606c8de85`, matching policy `matching/2`, unchanged `ude/1` wire contract. Machine receipt: [native-cjson.json](results/native-cjson.json). Reproducible research runner: [r2_cjson_probe.py](../../../tools/research/r2_cjson_probe.py).

**Outcome:** fresh native Ghidra extraction and the production unified ladder/fusion/facts path found both of the independently reviewed cJSON security-guard correspondences and classified each as `matched` / `material`. Each was accepted by P03 trusted name matching, with exported symbols visible. Native rz-diff 0.9.1 completed through the production scheduler/parser but did not propose either reviewed endpoint pair. Its weak evidence created nine contested rows elsewhere when fused with the ladder. Those other predictions have not been adjudicated.

This is one real-source **development** pair and two selected reviewed positives. It is not a held-out evaluation, an accuracy estimate, an independent-lineage sample, a calibration result, or evidence that the remaining predictions are correct or incorrect.

## Population and review boundary

The R1 pilot protocol declares all pilot cases development observations and consumes no locked test. The cJSON 1.7.16 → 1.7.17 O2 selection accepts exactly two source-lineage pairs with surviving compiled security guards; it leaves 111 other label records unaccepted. The review was unblinded: its author had previously seen the primary engine's two modified RVA pairs, then used independent source, DWARF and static binary mechanisms to establish the accepted claims. This run uses that limited selection as supplied and does not enlarge it.

The protocol and original review live in R1's `docs/research/ground-truth-corpus/04-pilot-protocol.md` and `results/cjson-review.md`. Acceptance document SHA-256 is `266e5d2176b34aef9d489094c8e6e2625a9b991456b25af5c51553af1876dae6`; it binds original label content digest `3e33941f984951fde5ee28870da9aaad8a7b3e6560a974e6d691ee908e3debe3`. The original label file SHA-256 recorded by that review is `5084235aeaa865266539b3fae608c3ccc09394cbad734c540a517da3933fe6e9`.

The runner reads the acceptance identities only after all matching executions. No source labels, oracle names, function correspondence, manual anchors or debug-image symbols are passed to the matcher. The engine DLLs retain **92 PE exports**, including both reviewed functions. Their inherent names are visible to Ghidra and P03 and can materially improve correspondence yield. P02 export-key wiring remains inactive, as separately inventoried; this run's target acceptance is P03, not P02.

The reviewed recipe uses MinGW GCC 13-win32, O2 and fixed image base `0x180000000`; cJSON.c and cJSON_Utils.c are linked into a DLL. The source/debug review and source hashes below are R1 provenance, copied into the machine receipt; this probe independently rehashed the engine DLLs, not all original source inputs. No target DLL was loaded or executed.

| Identity | Older | Newer |
|---|---|---|
| cJSON source revision | `cb8693b058ba302f4829ec6d03f609ac6f848546` | `87d8f0961a01bf09bef98ff89bae9fdec42181ee` |
| cJSON.c SHA-256 | `fdfd427d82fadb395076567edf470c80cebee319e38fd417198508fe11ae56e7` | `de63e951ce3bc9b6938c7635575a6c90c3b364595b0b0f4c5ae8f9c83a43c17d` |
| Engine DLL SHA-256, independently verified | `bed3ef087fd07161a14154d38c683b3f648611114bf9794bf91fba123d6f2d48` | `d3837c837ffff4eb90342b2b9d5d29cd023f72d3858c3a405a015cc180e963b4` |
| DLL bytes | 96,256 | 96,256 |
| Native extracted IR content digest | `f53b4f19da7aef48ae6e8eb42429842b4571c4a871750d54d336ad47b7045b66` | `42e77dd326bd69dce6461f0e642a7c5b152206061329edbd06f8fe79dbb1de38` |
| Native raw extractor JSONL SHA-256 | `f445d3bffaf79916c296c304fecf6aad5b28fc7d74ae43724fd2b6ec771fa152` | `0ca3d1b494a3759f478d74ec2050516f7ae13ca0109d999dacb5ac6e973ade91` |

## Executed paths and tool provenance

Each R1 engine image was opened read-only, its declared SHA-256 checked, copied to a private work directory and rehashed. Both native Ghidra analyses were fresh. The runner selected production `root/src` explicitly; `tools/live_unified_check.Side` supplied the existing extraction/ingestion path over verified bytes. The production ladder, arbiter, L2 facts, result writer and deep verifier then produced a persisted result. A second derived result added the actual rz-diff set through `SecondaryAdapter`. The optional primary Ghidriff run was neither repeated nor imported; no fabricated primary result was supplied.

The absent-primary identity slot uses the explicitly marked missing source with the empty-byte digest, and the ladder-only invocation selects no external atom sources. This is an IR-derived run, not an operational Ghidriff comparison. C6 is unavailable because neither primary decompiled text nor on-demand S3b decompilation was supplied. No thresholds, calibration artifacts, release flags or production code changed for this experiment.

| Component | Observed version/status |
|---|---|
| Ghidra | 12.0.4; both native analyses/extractions succeeded |
| Java reported by extractor | 21.0.12 |
| Python reported by extractor | 3.12.14 |
| pyghidra | 3.0.2 |
| JPype1 | 1.5.2 |
| ghidriff package | 1.0.0 installed; primary engine not run here |
| rz-diff | 0.9.1; production capability probe supported; native run return code 0, status `ok` |
| rz-diff executable SHA-256 | `536987d5d0e5d2a35689f653502dc10f8be8751a46ef2ffd888e8d514ed9712e` |
| Extractor script SHA-256 | `7676f631fb825551569f04f6b32828b771694a8d49d86e8d15a0a120f6f26fd9` |

All temporary programs, packed GZFs, native IR JSONL, sidecars, worker input copies, configuration and cache paths belong to `/tmp/patchtrace-r2-cjson-native-20261030`. No R1 store, source, result or label was modified. The JSON receipt retains raw extractor paths/digests and complete bounded rz-diff stdout, parsed sets, engine-run record and derived rows/facts. Native rz-diff stdout was 30,123 bytes; its recorded total equals the retained stream length, and SHA-256 `cc8044de06f7067d69974d5955879ffe474b6f98c8125e574332be8d1adcc059` equals the production engine output digest.

## Observations on the two accepted positives

| Reviewed function | Old RVA → new RVA | Ladder-only L1 / L2 | Ladder + rz-diff L1 / L2 | Native rz-diff exact proposal |
|---|---|---|---|---|
| cJSON_SetValuestring | `0x2b80 → 0x2b80` | `matched` / `material` | `matched` / `material` | Absent |
| cJSON_InsertItemInArray | `0x3ab0 → 0x3ac0` | `matched` / `material` | `matched` / `material` | Absent |

Both exact reviewed relations have the source atom `pt-ladder`, step `P03-name-exact`, tier A, E-NAME. Both remain uncontested in the combined run. This demonstrates preservation of these two selected correspondences with visible names; it does not test hidden-symbol matching or estimate the frequency of false tier-A name anchors.

The L2 facts of both rows use differing C0/C1/C2/C3 with **C3 as the second channel** for materiality. C6/C7/C8 are unavailable. The selected source review establishes actual validation changes: entry NULL checks in both functions, an existing valuestring-pointer check in SetValuestring, and a predecessor-pointer check in InsertItemInArray. The engine facts also contain many unmatched instructions, register substitutions, block/CFG deltas and, for SetValuestring, call-related deltas. The binary alignment is noisy; this experiment does not independently certify each individual reported delta or prove that every materiality anchor describes precisely the reviewed source guard. R3 should inspect the anchored explanation quality before making semantic-specificity claims.

Native rz-diff produced 169 parsed records but no exact proposal for either reviewed pair. This is a missing proposal, not a negative correspondence vote and not a semantic unchanged verdict. Its behavior on this pair does not justify generalizing to all changed cJSON functions or to its previously documented singleton-orientation failure.

## Output counts and measured time

These counts describe engine output only. Outside the two accepted endpoint pairs, predictions remain unreviewed—including runtime/import/thunk functions beyond the 113 source-label records.

| Output decision | Ladder only | Ladder + rz-diff |
|---|---:|---:|
| matched | 249 | 242 |
| tentative | 1 | 1 |
| candidate | 5 | 7 |
| contested | 0 | 9 |
| older-only | 7 | 3 |
| newer-only | 7 | 3 |
| ambiguous | 0 | 0 |

| L2 output | Ladder only | Ladder + rz-diff |
|---|---:|---:|
| unchanged | 102 | 102 |
| cosmetic | 139 | 139 |
| material | 2 | 2 |
| review | 12 | 16 |
| not-applicable | 14 | 6 |

The nine contests added outside the reviewed positives show that weak secondary disagreement remains visible. Their correctness is unresolved; a reduction in matched rows is not automatically a regression, and additional candidate coverage is not automatically an improvement.

Ghidra extracted 262 functions per side: 37 imports and 38 thunks, with 224 pdata-confirmed extents. The older side has 19,801 instructions and newer 19,804; both report one unlocated operand mask. The final manifests are `complete`, with no listed result limitations. A complete execution status is not a comprehensive truth certificate. No N:M label is scored; no ladder group count was reported for this pair, but that does not prove the absence of compiler boundary transformations. The general overlapping-group persistence gap remains open.

| Stage | Wall seconds |
|---|---:|
| Older native extraction + ingest | 33.250 |
| Newer native extraction + ingest | 33.141 |
| Ladder-only compute, write and deep verification | 0.937 |
| Native rz-diff process | 2.567 |
| Combined compute, write and deep verification | 1.146 |
| Whole probe | 71.373 |

Peak process-tree RSS is **unavailable**: the probe did not instrument it. There was one fresh analysis per side and one invocation per compute variant; this is not a repeated cold/warm cache study. The existing tool installation was reused read-only while analysis/configuration/cache work was private.

## Reproduction and verification

```bash
PYTHONDONTWRITEBYTECODE=1 /workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python \
  tools/research/r2_cjson_probe.py \
  --production-root /workspace/scratch/9b177a4979cd/patchtrace-r2 \
  --pilot-store /workspace/scratch/a55b59b3e326/r1-pilot-store \
  --ghidra-dir /workspace/scratch/a55b59b3e326/research-tools/ghidra_12.0.4_PUBLIC \
  --rz-diff /workspace/scratch/a55b59b3e326/research-tools/rizin/bin/rz-diff \
  --acceptance /workspace/scratch/a55b59b3e326/patchtrace/docs/research/ground-truth-corpus/results/cjson-acceptance.json \
  --work /tmp/patchtrace-r2-cjson-reproduction-20261030 \
  --output docs/research/unified-matching-r2/results/reproduction/native-cjson.json
```

Both `--work` and `--output` must be fresh for each reproduction. The runner refuses reused work roots or existing reports, and confines reports to this script checkout's R2 results subtree; select another fresh filename if the example has already been run. The original committed receipt remains unchanged. Selected DLL/executable inputs must resolve to regular files of at most 256 MiB, and the review JSON to a regular file of at most 4 MiB. SHA-256 verification streams the selected files. Raw extractor JSONL uses exclusive creation under the fresh private work root, refusing unexpected existing leaves or symlinks. These checks assume stable caller-selected inputs; they do not claim a concurrent-filesystem sandbox.

The recorded run completed successfully, both derived results passed deep verification, and Ruff passed for the research script. Later selected-input/publication hardening was tested without rerunning native analysis, so it does not rewrite the historical native timing or evidence. A full test suite was not repeated for this research-only addition; root owns integration validation. No source labels, production algorithms, target binaries or R1 artifacts were edited.

Precision, F1, false-positive rate, broad correspondence recall, specificity, calibration and independent-lineage confidence intervals remain **unestimated**. A defensible conclusion is limited to two reviewed positive correspondences and their materiality outputs on this exact exported-symbol build. Additional accepted negative/unchanged labels, more project lineages, hidden-symbol controls, native MSVC/Windows work and semantic explanation review remain necessary for broader acceptance.
