# Ghidra original-archive acceptance: bounded read-only assessment

**No unchanged Tier R dispatch satisfies the complete request. Keep the archive/native gate open on PR351.** Exact inspected source: remote `d6679abc6dfddbadce0391c8d18289f7f96338d6`, local `2ae1bbad2ad9cc78c29541872381750e347c670e`, complete tree `6001ef506c38930fd590bd827f428b997c3b2797`.

## Concrete blockers

1. **The Tier R Ghidriff evaluator does not run the engine.** `tools/calibration/tier_r/evaluate.py:default_providers` selects `GhidriffImportProvider`. That provider explicitly reads `<imports>/<pair_id>.ghidriff.json` and never launches Ghidra, Java or Ghidriff. `run_shard` creates a fresh temporary store; no workflow step produces these imports. Installing Java/Ghidra/Ghidriff is therefore provisioning evidence only.
2. **A cold run cannot be expected to seed the cache.** Missing imports produce BLOCKED in evaluation (exit3); `run-shard` preserves that exit unless a harder failure takes precedence. The shard job has no `continue-on-error`. The exact pinned `actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830` metadata declares `post-if: success()`, so its save hook does not run after a blocked/failed shard. Adding rz-diff does not remove the separately evaluated Ghidriff failure. Repeating the same cold dispatch is not a reliable cold/warm plan.
3. **No whole-workflow dispatch is authored-fixtures-only.** Linux `subset=noise` is authored-only, but the unconditional Windows advisory ignores the requested subset and independently plans `smoke`, including six external zlib cards. No dispatch input disables it. The default smoke set itself is not authored-only.
4. **Current archive-cache existence is unknown.** The read-only cache metadata GET was rejected by the available connector with HTTP400: the endpoint is not supported. This is not evidence that the cache is absent. No cache was created, deleted or inspected through another access path.

The first two findings follow the actual source call chain, not guessed engine names or package-install success. `tests/test_evalcore_engines.py` also checks the provider selection. The existing CODEX6 tests validate source structure and positive/corrupt tiny archive shell fixtures; they deliberately do not download or launch Ghidra. Their evidence does not close hosted archive behavior.

## Existing supported input scope

Pure source-bound planning, with no build or engine execution, enumerated:

| Subset | Planned case IDs | Linux inputs authored-only? |
|---|---:|---|
| smoke | 10 | No: four tiny authored cases and six zlib cards |
| noise | 25 | Yes |
| suites | 50 | Yes |
| cards | 83 | No |
| mutations | 750 | Yes |
| full | 908 | No |

The smallest Linux authored-only set **by case count**, for diagnostic planning only, is:

```json
{"engines":"ghidriff","shards":"1","subset":"noise","seed":"1"}
```

Use the released feature branch only after checking it still resolves to the qualified intended source. This is **not a recommendation to dispatch the current workflow**: the blockers above still apply. Noise spans all25 suites and four default optimization pairs per suite, plus available cross-compiler comparisons;25 case IDs do not mean25 builds or a small runtime guarantee. No single-suite/case selector exists. More shards distribute the same total work and repeat tool provisioning.

The existing limits are plan10minutes, each Linux shard120minutes, each case/evaluation subprocess1800seconds, merge15minutes, unconditional Windows advisory45minutes, and an additional45minute MSVC advisory if repository variable `TIER_R_MSVC` is1. The variable's value was not independently queried. Same workflow/event/ref runs cancel earlier runs, so any future cold/warm pair must be sequential through completion of the first cache-save hook.

## What archive acceptance must prove

The current installation block is correctly guarded and pinned:

- Ghidra12.0.4 original release ZIP, SHA256 `c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120`.
- Cache key `ghidra-archive-v1-` plus that digest, cache path `ghidra-archive`, archive `ghidra.zip`, no restore-key fallback.
- On every applicable hit or miss, `sha256sum -c` runs before removing/recreating `ghidra-runtime` and extracting. A present corrupt ZIP is rejected; it is not silently redownloaded.
- JavaTemurin25, Python3.12, Ghidriff commit `4f5d895fcbb1eacd65efd81145922c15bb7e741d`, compilers and shell utilities are required. Rizin provisioning remains unconditional. The archive pin does not cover Java/Ghidriff Python dependencies or close CODEX5.

If an exact visible archive cache already exists, **one** independently authorized run could prove a restore hit plus checksum and fresh extraction. It would not prove a new cold save or real engine execution through the current import-only evaluator.

If the cache is missing, the normal plan is **two sequential successful runs on the same ref**: first a cache miss, pinned download/checksum/extraction and successful post-save; then an exact-key restore hit with repeated checksum before fresh extraction. The current blocked shard prevents reliable completion of that sequence. Cache scope includes key, internal version and branch; a same-name sibling-branch cache cannot simply be assumed accessible. The pinned action README states default-branch caches are available to other branches.

Retain exact checkout/source, dispatch inputs, plan digest, restore/save logs, checksum `OK` for the original ZIP, extraction success and per-engine/per-pair status. An embedded digest in a key is not byte verification. A green warning-level merge summary is not native acceptance; BLOCKED/failed shard results remain visible and must not be relabeled.

## Native execution and prior cache evidence

Tier R compiles authored source using explicit tool argv and reads the generated PE images; built target images are not executed. No heavy engine, compiler, archive download or target was executed during this assessment. Pure `make_plan` enumeration was the only project operation run locally.

The existing `live-backend.yml` raw-cache-hit variant runs `python tools/live_cache_check.py --diagnostics-dir live-cache-diagnostics` after fresh pinned Ghidra provisioning. That is application raw-analysis cache evidence. It is distinct from restoring the original Ghidra ZIP from GitHub Actions cache and cannot substitute for CODEX6 archive-cache proof.

**Next action:** leave PR351 frozen and this gate open. Root can separately authorize a minimal, specified and independently reviewed archive-acceptance path with an actual native invocation, or explicitly limit the claim to archive restore/checksum only. Do not mask the blocked evaluator, broaden the fixture scope implicitly, dispatch Pages, or assume two unchanged Tier R runs will solve the gap.

## Sources and retained evidence

Exact source snapshots and blob/digest identities are in `source/` and `review.json`; pure planning output is `pure-plan-enumeration.json`. The unsupported cache metadata response is retained. Official pinned action metadata and README were independently fetched:

- https://github.com/actions/cache/blob/0057852bfaa89a56745cba8c7296529d2fc39830/action.yml
- https://github.com/actions/cache/blob/0057852bfaa89a56745cba8c7296529d2fc39830/README.md

No source/ref/PR changes, dispatch, install, native execution or product tests were performed. The inspected worktree remains clean.
