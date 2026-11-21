# CODEX-6 independent standards review

## Reviewed source and scope

Date: 2026-11-21. Worktree: `/workspace/scratch/patchtrace-95fe-c3/cache-review`.

- HEAD: `53e02a478235498563a092d7943c7feaf40adda6`.
- Tree: `34acedca0fc524a20a8def6be4b18e909ea2f772`.
- Baseline: `6b6fcd3597a604212032ffc453477aeb6edc69ff`.
- Diff: `git diff 6b6fcd3597a604212032ffc453477aeb6edc69ff...HEAD`.
- Scope: 16 changed files, 649 insertions and 20 deletions, including archive candidate `658cc814`, fixture successor through `d2507b14`, and root test repair `53e02a47`.

The source was clean at the reviewed head. This review was read-only: no tests, builds, native tools, network probes/downloads, source mutations, or ref changes. Only this report was written. Root owns actual pytest and whole-tree Ruff verification. The separate Linux CODEX-14 review remains a different receipt.

Standards: `AGENTS.md:5` (specification before contracts, ownership, no target execution), `AGENTS.md:7` (meaningful tests, evidence limits, failure preservation), `AGENTS.md:9` and `AGENTS.md:11` (unverified acceptance and all-green merge gates); relevant module ownership at `docs/modules.md:558` and `docs/modules.md:1132`; normative cache amendment at `docs/specs/known-answer-corpus.md:394`. The code-review skill's smell baseline was applied as judgment only, with repository rules taking precedence. No separate CONTRIBUTING, CODING, or issue-tracker file was found; the originating specification is explicitly available.

## Findings

**Hard implementation violations / blocking source defects: none found.** Hosted qualification remains an acceptance blocker, as required by the specification; this is not a newly introduced source defect.

**P3 — reconcile or version the historical control counts.** `docs/engineering-handoffs/codex6-corpus-cache-archive-20261121.md:22` and `docs/engineering/task-ledger.json:920` report 12 source invariants, while `docs/engineering/evidence/codex6-archive-cache-controls-20261121.json:14` and `docs/engineering/codex6-corpus-cache-archive-20261121.md:39` report 14. `docs/qa.md:2320` reports 10 negative mutations, while the receipt at line 18 and its enumerated list report 14. Under `AGENTS.md:7`, preserve actual prior results and distinguish each stage explicitly, or align current summaries with the current receipt. These inconsistencies do not establish a workflow/runtime failure and do not justify replacing historical observations with newly inferred results. No claim of actual repository pytest or native acceptance should be inferred from the author JS controls.

**Optional test improvement, not a blocker:** `tests/test_corpus_cache_archive_integrity_20261121.py:12` and `tests/test_corpus_archive_cache_hit_shell_20261121.py:29` select named steps using text delimiters. Current headings are selected correctly, but neither helper interprets full YAML conditions or failure-suppression semantics. The actual fixture test executes only the selected `run` block. Semantic YAML assertions could protect later structural edits; the currently reviewed YAML has no disabling or failure-suppression condition. The repeated small named-step selection is a possible Duplicated Code heuristic, but its two consumers have different responsibilities and this limited duplication does not warrant a mandatory abstraction.

No other actionable naming, ownership, data-clump, primitive, repeated-dispatch, scattered-change, mixed-responsibility, speculative-abstraction, navigation, delegation, or inheritance smell was identified. Formatting/import enforcement is left to Ruff as instructed.

## Source evidence supporting the implementation verdict

- **Archive-only storage and identity:** `.github/workflows/corpus-tier-r.yml:96` and line 125 cache only the archive directories, with new digest-suffixed `-archive-v1-` keys at lines 97 and 126 and no restore-key fallback. rizin's download, digest, and extraction use the same `archive` variable (lines 104, 106, 108, 111); Ghidra's operations use `ghidra-archive/ghidra.zip` consistently (lines 134, 135, 137, 140).
- **Fail closed before cleanup or use:** both install steps retain `set -euo pipefail` and validate the pin syntax (lines 101, 102, 131, 132). Archive download is conditional only on its absence. Digest verification precedes `rm -rf`, fresh directory creation, and extraction (rizin at lines 108-111, Ghidra at lines 137-140). Corrupt cached bytes stop the step; no silent redownload, replacement pin, cache-hit bypass, or continue-on-error is introduced. `RZ_DIFF` publication follows extraction at line 113; shard execution follows both applicable installations at line 143.
- **Conditional and unchanged responsibilities:** Ghidra and Java remain conditional on requested Ghidriff (lines 115, 122, 128). Existing Ghidriff pip installation remains outside the archive integrity claim (line 142; specification line 408). Event filters, permissions, source checkout, plan/shard ownership, summary retention, and merge handling are unchanged. No product runtime, analyzed target execution, or schema change is introduced.
- **Real source selection in hermetic fixtures:** `tests/test_corpus_archive_cache_hit_shell_20261121.py:60` reads the checked-out workflow, line 66 selects its actual Bash body, and lines 68-70 replace exactly one external pip install only inside the test. Lines 38-52 author tiny tar.xz/ZIP fixtures, lines 79-84 route accidental curl invocation to a refusal, and line 92 executes Bash in `tmp_path` with a 30-second timeout. The assertions at lines 101-113 distinguish checksum refusal preserving the stale tree from successful clean extraction. They do not execute fixture payloads, real native tools, or the cache service.
- **Root repair eliminates vacuous mutation success:** `53e02a47` fixes the full rizin/Ghidra install-step names at `tests/test_corpus_cache_archive_integrity_20261121.py:25` and line 27. Each mutation now first requires `admission_errors(original) == []` at line 100, so an already-broken positive baseline cannot make every negative test appear successful. This is a source inspection conclusion; this reviewer did not replay the tests.
- **Original audit boundary preserved:** only CODEX-6's expected-failure marker is removed in `tests/test_codex_pkg_workflows.py:121`; CODEX-1 and CODEX-5 remain. The new structural checks and fixture executions support a bounded archive-admission claim, not native matching or complete Actions acceptance.

## Evidence identities and limitations

The workflow blob is `c15784337596d03de29a144980312872830b8aa4`, matching the author's receipt at `docs/engineering/evidence/codex6-archive-cache-controls-20261121.json:7`. Current structural test blob: `d32d234bc6a2bbe62bdd5295447f14da9c0edce2`; fixture test: `bff4a96c992bc1caae666846c5d1ce9216326b13`; maintained audit test: `379bcc5daff743446976ec6874a107970b5e53a8`. Workflow blob identity does not verify execution of the author's JS or shell controls and does not qualify the later Python tests.

The cache-namespace narrative at `docs/engineering/evidence/codex6-archive-cache-controls-20261121.json:83` is author rationale, not a reproduced Actions service result. This review verifies explicit new-key isolation and conformity to the specification; it does not establish the service's historical cache-version/migration behavior.

`docs/specs/known-answer-corpus.md:416` requires matching-source hosted Tier R qualification with Ghidriff separately verified where available. The fixture handoff at `docs/engineering-handoffs/codex6-cache-hit-fixture-20261121.md:13` additionally calls for a repeated same-key cache hit. Those are still open here, along with actual root-owned checks and applicable full QA/Qt/native/package gates. The Windows skip in the Bash fixture (`tests/test_corpus_archive_cache_hit_shell_20261121.py:23`) provides no Windows acceptance; absent prerequisite tools likewise give no fixture result. No archive availability, native accuracy, manual Windows/trust/accessibility, raw provenance, L1/L2/L3, merge, or release qualification is claimed.

The original CODEX-6 audited failure and PR345 NSIS feed failure remain historical evidence. Older SIGKILL/native/Qt failures are not reclassified. Earlier ancestor workflow results do not qualify this candidate, and the CODEX-14 branch remains separate.

## Exact retained commit list

Newest first:

```text
53e02a478235498563a092d7943c7feaf40adda6 test(ci): repair archive-cache controls and verify mutation baselines
d2507b1415fd0917fcda6b9f26565d0467d7b9ba docs: record isolated CODEX-6 fixture controls in authoritative ledger [no release]
211911d6a6bee0e1fdb7d638da44827a840fd2d8 docs: retain executable cache-hit fixture handoff and acceptance limits [no release]
22532f7fe68af4215fce90abb9bfd492ed14638e test: execute pinned archive cache-hit steps using authored fixture archives [no release]
658cc814aa74d1eaebf0d7e6dd4553d06aaef0eb docs(evidence): reconcile fourteen source integrity invariants [no release]
bb2e8706cb0b7f236db8eaa85c3c3447b0601d3f docs(ci): record archive-cache namespace collision review correction [no release]
40c3cef25917d45044deb992162d4a5c62a92fd4 docs(ci): record archive-cache namespace collision review correction [no release]
2b33441d1cf1e6dafce3d3833a10c9e5584e4f1d docs(ci): record archive-cache namespace collision review correction [no release]
2db010e8137a94c5907cca421214bbc42f675e51 docs(ci): record archive-cache namespace collision review correction [no release]
8ffc36dded4bbac6be654ee6136856c92ab3bc3f docs(ci): record archive-cache namespace collision review correction [no release]
be5862752201402d4f1090267fe14846f107088f docs(ci): record archive-cache namespace collision review correction [no release]
e4bf6bf4f37bd683df7158fc14ac7ac129679515 docs(evidence): capture fresh archive-only cache-key migration red/green [no release]
6cf0b2f8b7e5d1231fc00d6f985dfa36a8554cc7 fix(ci): version archive cache keys to exclude old extracted-tree entries [no release]
351c2488336b16603db8211834766ca5171d45ba test(ci): refuse legacy extracted-cache key namespace and fallbacks [no release]
23e6d6541a0546dd03f89bf12150ad4cc045efc2 docs(spec): isolate verified archive cache keys from pre-fix extracted caches [no release]
cbc272f77912e69ca0d688c038dff52cf0b21a5b docs(ci): reconcile 12 verified archive-integrity mutations [no release]
59f96b5201c8ba3015bf759e720dc08c8256f183 docs(ci): reconcile 12 verified archive-integrity mutations [no release]
bbafc8c3daf98a4aa5a377f376cfb974021e20df docs(ci): reconcile 12 verified archive-integrity mutations [no release]
370b4089ad87d2f9cf0045b8b1f98b48702bfca5 docs(ci): reconcile 12 verified archive-integrity mutations [no release]
f145d2b6a54b074de4c68e90ebfcc3a1ae8a77a3 docs(ci): reconcile 12 verified archive-integrity mutations [no release]
83bce856974724a1a3d9013b1ca104ebf0a660b6 docs(ci): reconcile 12 verified archive-integrity mutations [no release]
b7fea69c7054d8d217bf78a8256f6358be56ba4e test(ci): enforce same archived rizin bytes through digest and extraction [no release]
9dff1ba0109260ac21aba7cc98494a1d193570e1 docs(evidence): bind CODEX-6 baseline defect and repaired source blobs [no release]
ef698cf1602e70f3fb2754d9a32826c775b209de docs(qa): retain CODEX-6 actual evidence and outstanding hosted gates [no release]
81c134809d20249028845a28376ac2e7743d1b95 docs(qa): retain CODEX-6 actual evidence and outstanding hosted gates [no release]
0590f9fcf07b09502e8b75b61e519c887c17de7c docs(ci): disclose candidate-only CODEX-6 verification and remaining gates [no release]
298115cd307fb656bf16da3eb27c2e890c3d361e docs(ci): disclose candidate-only CODEX-6 verification and remaining gates [no release]
ea65ece57b4dfd4047c8b719a45756a4a51d03ec docs(ci): disclose candidate-only CODEX-6 verification and remaining gates [no release]
c4f2ecf7d396877c32ba6ec58e9492cd2261387c docs(ci): disclose candidate-only CODEX-6 verification and remaining gates [no release]
0e398d4699970f151c3f2f06848f4af2bbb7ac22 docs(handoff): continue isolated CODEX-6 verification without overlapping worker scopes [no release]
dcbe142897597efea085112bb5088316b360c570 docs(ledger): own and gate CODEX-6 cache-hit integrity successor [no release]
e209c447d6c3274848b37bebfbe505cfc908869b docs(ci): record cache-hit corruption controls and exact source-bounded limitations [no release]
8de4943ef079fe3903a40512258239005306102f docs(ci): preserve CODEX-6 source repair, real boundaries and verification limits [no release]
1d7eced915ff31c2c62b5922c24b2c91a7909860 test(ci): bind Ghidra download, verification and extraction to same archived bytes [no release]
716635000a82f935c036b686f58947ebd31ec0da test(ci): graduate CODEX-6 from strict xfail with archive verification assertions [no release]
c32449278d0712fa9e653f4b7c51eb5f679a693c fix(ci): cache only pinned native archives and verify before every extraction [no release]
0aaabfc2e85cd9e98eacc1e74fd8c60a0a0e31f5 test(ci): make negative integrity checks fail closed without raising [no release]
ef4bcc7704bd914cb4a53ba467810ac0817f86b3 test(ci): reproduce unverified Tier R cache-hit admission with negative mutations [no release]
0e5c94e96802cc1630ea3583468d38484247ff33 docs(spec): require verified original tool archives on every Tier R cache hit [no release]
```

