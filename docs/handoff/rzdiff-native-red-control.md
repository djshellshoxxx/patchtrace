# Native red-control continuation (not production acceptance)

Parent: PR #166, edab7d916970144b33c98384834369773e5b0e62.
PR #165 remains 4d66af5577e6f6ad8f6e21440f6fe4187e0c8fe5.
Neither source branch nor #163/#164 was modified.

## Implemented
- Separate stock/corrected native builds, fail-fast disabled.
- Checkout immutable PR head, record it separately from workflow merge SHA.
- Strict 32-row native API matrix validation, including duplicate multiplicity.
  Stock must fail every singleton scenario and no ordinary scenario.
  Corrected must pass the identical oracle. A crash, missing executable,
  timeout, truncated output or arbitrary nonzero exit cannot qualify stock red.
- Retain compilation diagnostics and binary/library hashes before execution.
- Retain raw stdout/stderr, process status, hashes and run/head metadata on
  native execution failure. No continue-on-error or quarantine changes.

## Executed here
- New regression initially failed collection because evidence runner was absent.
- 25 new synthetic/process-runner tests plus existing unverified-source
  rejection: **26 passed**, 0 skipped (0.09s).
- Python compileall, YAML parsing and bash -n of all five workflow shell blocks.
- Ruff unavailable: No module named ruff. actionlint unavailable.
- pkg-config cannot locate rz_core. NO native Rizin execution claimed.
- Hosted Shell clone failed once: Could not resolve host: github.com.
  No DNS retry. Mounted MCP has no Actions log/artifact download methods.
  get_file_contents returns download acknowledgements without readable bytes;
  bounded source was recovered from added-file commit patches instead.

## Refreshed state and constraints
At session start #165 producer job 125717089321 failed.
#166 producer job 125720018315 was still reported in progress; Sonar passed.
Neither status is native acceptance evidence. The one-line #166 size_t fix is
retained by ancestry. No draft PR merged. #167 is unrelated and deferred.
Credit balance/cost is unavailable; the owner's 50% limit is NOT enforced here.
No parallel persistent workers are exposed.

## Resume
1. Refresh this PR head and both stock/corrected producer jobs. Download actual
   artifacts from a network-enabled authorized runner. Inspect native-compile,
   native-result.json, raw matrix/stderr and source/binary hashes. Distinguish
   stock expected red from build/runtime/environment failure.
2. Correct native errors, not the oracle thresholds. Independent review required.
3. Add distinct-byte/IO-context fixtures, production rz-diff JSON plus independently
   recovered inventory witnesses in both orientations and ambiguous controls.
4. Rerun application ownership/provenance/cache refusal regressions. Only after
   complete producer review/validation integrate; then rerun BOTH Tier R shards
   and dependent gates. Existing equal-NOP API fixture is NOT sufficient.
5. Consolidation heads: #163 6e82fd70f315b99c6798a42c9061a1424a02933e;
   #164 b58bb53debcb3323e5d8d634e09397cb7e02965f.
   Preserve their unresolved Sonar/native/package/Linux/Windows gate obligations.

## Second implementation checkpoint
Initial published implementation: 4013cdd5d491b5d662105a24c63761ee7c787480,
PR #168 stacked on #166.

Found and reproduced an oracle gap: covered() accepted a function simultaneously
matched and unmatched, and accepted duplicate unmatched pointers. The compiled
oracle regression failed with two violations against the old check.
The repaired coverage check requires a partition while retaining legitimate
singleton all-candidate matches. Pointer-membership checks remain unchanged.
Matching/serialization/production code is not changed.

Final bounded selection: **27 passed, no skips** (26 evidence/oracle tests plus
existing source-refusal regression). The oracle C compiled with C99,
Wall/Wextra/Werror and list doubles. This is NOT native Rizin acceptance.
Additional signature-only compilation control using the actual #166 callback:
old int compile exit 1 with incompatible-pointer-types; size_t compile exit 0.
This confirms the bounded signature correction, not complete API compilation.
git diff --check passed. Native logs remain inaccessible in this environment.

A NULL native API result now emits diagnostics without a matrix row, ensuring
strict completeness validation refuses it even in the stock red job.

## 2026-11-05 isolated rz-diff research-controls consolidation

- Integrated only PR #174 producer-control commits c2107f57, 0b5c5087, 5175ccbe, e8cd27d1, d22853d3: original #165 source patch/boundary control (51e5b4b1, 4d66af55), #166 callback size_t repair (edab7d91), #168 red-matrix and partition-oracle repairs (4013cdd5, b304034e). No #163/#164 application, GT-01, normalizer, workflow or tracker-restoration changes are included. Existing historical evidence files retain their original scope/date.
- Confirmed an additional evidence-loss defect: rerunning the native evidence runner in an existing output directory overwrote receipts/logs even when the executable was absent. Five regression cases failed before the correction. Exclusive run reservation and exclusive evidence-file creation now refuse reuse and preserve prior output; other build diagnostic files are allowed.
- PASSED: 33 focused tests, no skips, with PATCHTRACE_RIZIN_SIMILARITY pointing to the exact pinned source downloaded from raw.githubusercontent.com/rizinorg/rizin/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/arch/similarity.c. Test verifies Git blob8544259e17a692bcb3c1d8858f104745cd0cba4c and byte-identical patch/application. Compiled wrapper-double stock-red/corrected-green checks and compiled partition oracle are synthetic boundary evidence only.
- PASSED: python -m ruff check src tests tools. No schemas changed.
- BLOCKED/NOT RUN: complete pinned-native API/CLI JSON acceptance, independent recovered inventories, distinct-byte/IO-context controls, Windows acceptance and downstream Tier R requalification. No target binaries executed; no quarantine, runtime parser, approved pin, cache acceptance, or automation changes. This is a research-tool checkpoint, not a qualified producer.
