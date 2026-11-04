# Rz-diff producer implementation checkpoint — not accepted

Based on #164 b58bb53debcb3323e5d8d634e09397cb7e02965f; isolated
repair/rzdiff-producer-ownership. #163/#164 branches remain untouched.

## Exact source and correction

Complete upstream similarity.c recovered via GitHub MCP commit patches from its
initial addition fbad0b4859802a62dcc96002c2710e696809a0c3 through the path's
v0.9.1 history. Every context/deletion was checked while reconstructing.
Reconstructed 19,485 bytes hash to the independently fetched v0.9.1 blob
8544259e17a692bcb3c1d8858f104745cd0cba4c.
Tag resolves to c3a90e9226d977f58f4e9c75f78fa6b07afe13c7.

- Original SHA256: a0b196dbc39e4fb3df4f850e156482ba9668838ccf5bb99a25563fd7a8c7ee5a
- Corrected SHA256: 5b11e8ce3cce7ca30c59472b3a0e2ade876ef120ba0f767253840c26b5c4078f

Singleton callback deliberately receives queue=B/list_b=A. Its alloc_a reads the
singleton from analysis A and alloc_b reads queued functions from analysis B.
Do not simply change caller list order or swap IO contexts. The common helper
clones its second list into unmatch_b, then removes matched pair_b pointers.
Swapping only match_pair_new arguments would therefore corrupt unmatched
bookkeeping. The bounded correction restores pair_a/pair_b and exchanges the two
unmatched list handles AFTER helper completion, inside the singleton branch.
Normal branch, similarity values and callback cardinality remain unchanged.
Null helper result stays null. No serializer or parser global swap.

tools/rzdiff/singleton-ownership.patch is the actual C source correction.
patch_producer.py applies it only to the exact full upstream blob and refuses
drift/double application. This is research build tooling, NOT runtime attestation.

## Executed evidence

Local compiled-boundary suite: 2 passed in 0.10 seconds, no skips.
The same extracted public C wrapper and pointer-ownership oracle produce:
stock exit 1, six ownership failures; corrected exit 0, zero ownership/helper
failures across 12 constructed scenarios. Both C builds used C99, Wall/Wextra/
Werror. Matrix covers singleton/ordinary/reversed/empty input cardinalities,
unmatched handle ownership, unchanged score, helper failure and invalid options.
Helper is a deterministic DOUBLE. This does not exercise native matching, threads,
IO, recovered inventories, serializer or application cache. First successful
pre-fixture-cleanup run was 2 passed in 0.15 seconds and is not native evidence.
Ruff invocation failed because module ruff is absent; no lint pass claimed.

Native public API matrix is authored but NOT compiled/run here. It uses
independently owned function pointers including overlapping-address controls,
both input orders, complete inventory coverage and empty-side unmatched controls.
GitHub Actions workflow builds the pinned corrected Rizin and runs that matrix,
retaining build logs, source hashes, JUnit and executable/library hashes even on
failure. It does not install the tool in PatchTrace or modify approved native pins.
Build/API/platform failures must remain failures, not skips.

## Unresolved gates and continuation

No successful repair, native JSON acceptance, independent review or merge claim.
Existing quarantine, matching/3 cache policy and all provenance consumers are
byte-unchanged. A patched version suffix cannot unlock them. No runtime witness,
cache allowlist or producer-acceptance path was introduced.

Still required:
1. Inspect exact-head Actions check runs AND download actual job logs/artifacts.
   Mounted MCP tools provide PR check summaries but no Actions dispatch/log/
   artifact-download API. Hosted Shell raw HTTP failed once with DNS failure;
   no cloning/retries were attempted. If workflow publication/CI is blocked, use
   an authorized runner with GitHub network access; never invent receipts.
2. Compile/run native_control.c; add stock-native red control and production
   rz-diff -C -j -t functions old/new JSON acceptance using independently verified
   recovered inventories, 1:1/1:2/2:1/2:2, reversed, unmatched and overlapping
   controls. Current API fixture uses equal NOP bytes; this alone is insufficient.
3. Missing/stale/wrong-tool/wrong-input witness rejection, ambiguous JSON refusal,
   pre-cache probe rejection and downstream no-vote/no-link/no-calibration tests
   must be rerun on complete application source before any adoption. Existing
   recorded quarantine tests are not newly executed evidence in this session.
4. Independently review C ownership and native provenance. Integrate corrected
   producer only after qualification, then rerun BOTH Corpus Tier R shards and
   dependent aggregation/training plus relevant Linux/Windows native acceptance.
   No Tier R run was requested here because no corrected producer is integrated.
5. Only separately reviewed native evidence may justify a later quarantine change.

Stop at this reviewable implementation checkpoint. Do not overwrite consolidation
refs, change thresholds or equate a compiled helper-double test with native repair.
