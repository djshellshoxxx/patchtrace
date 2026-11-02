# Receipt lineage disposition: #128 → #145 → #150

Read-only audit, session 2026-11-02. **Keep all three PRs and their original refs. None is fully represented in current main or published draft #163.** The remainder is a substantial separate R1 research/integrity lane, not just a small receipt-writer follow-up.

## Exact scope and lineage

| Snapshot | Commit | Tree |
|---|---|---|
| Current-main comparison baseline | `ce8c65bf41541cf6adb52289d2a530ce2817a53a` | `0f90e002704d93e8343568acf0bde443dcc4b2eb` |
| Published #163 | `6e82fd70f315b99c6798a42c9061a1424a02933e` | `2e7cd8e258821f50d776ca3b3a4caef594e2a417` |
| #128 | `04bd023df566f43939296f7df1766e46186e7fff` | `21027e900e88c1656adf4790239f55ac44c276a6` |
| #145 | `8c9eafc79b007a963453d8edf6cb40c804c9bc3d` | `d79b1e7df0a52b9b91928d1c1e4a4e6d2da04844` |
| #150 | `2fdac2ea9042985ac3c98545d38ac3461d00f4cc` | `501569e0d817d449a84a81eb391ee029e4087e23` |

Live connector metadata confirms the three PRs remain open at these heads. Git Commit API records confirm that #145 has #128 as its sole parent and #150 has #145 as its sole parent. These heads are not ancestors of #163's actual five integration parents, as established in the separate consolidation disposition.

The complete GitHub changed-file lists, complete main/#163 recursive trees, immutable local tree objects, and exact fetched #128 source blobs were compared. Counts below are **exact files / different files / absent paths**; they are not feature-completion percentages.

| PR-specific delta | Changed paths | Main | #163 |
|---|---:|---:|---:|
| [#128](https://github.com/djshellshoxxx/patchtrace/pull/128) | 154 | 0 / 10 / 144 | 1 / 10 / 143 |
| [#145](https://github.com/djshellshoxxx/patchtrace/pull/145) | 3 | 0 / 0 / 3 | 0 / 0 / 3 |
| [#150](https://github.com/djshellshoxxx/patchtrace/pull/150) | 7 | 0 / 2 / 5 | 0 / 2 / 5 |

Taking the union of all three deltas at the latest #150 versions gives **156 paths: 1 exact, 10 different, 145 absent in #163**. Main has 0 exact, 10 different, 146 absent. The full path/blob manifest is in the companion JSON.

## What #163 already represents

- **`.github/workflows/unified-live-gates.yml` is byte-identical to #128**, blob `81b6bc76d8d0a89bb459edc27d4935bd797f5edf`. This is a workflow preservation fact, not evidence that its acceptance jobs passed.
- **`tools/unified/live_pairs.py` retains #128's completed-primary persistence and configuration retention.** Comparing the full files shows that #163 adds the later forced identical-input native-control settings, bounded/redacted failure diagnostics, and per-comparison extraction staging. Those later protections must survive a future receipt-lane merge.
- **`tests/test_unified_live_pairs_r1.py` retains the corresponding R1 orchestration tests**, extended with the failed-extraction-first control. It is a stronger successor at this specific overlap, not an exact blob copy.

This selective integration does not absorb #128's research tools, corpus evidence, or the #145/#150 receipt publication behavior.

## What remains unique

### #128: substantial parent functionality and evidence

Of its 143 absent paths in #163, **128 are under `docs/research/ground-truth-corpus/`**, **4 are the authored pilot fixture**, **7 are tests**, and **4 are research tools**. The absent tools are `research_audit.py`, `research_build.py`, `research_observers.py`, and `research_pilot.py` under `tools/calibration/tier_r/`. The entire research report/receipt/label archive is absent at its original paths.

Direct review of the shared source files establishes three specific R1 changes that are **still absent** from both main and #163; the three current files have identical blobs in those two baselines:

| Shared file | Unique #128 behavior absent from #163 |
|---|---|
| `tools/calibration/tier_r/build.py` | `persist_build_record` retains a full content-addressed build receipt using exclusive staged publication, checks existing receipt integrity, and then updates the compatibility view. The current file writes only the mutable `build.json` view. |
| `tools/calibration/tier_r/factory.py` | `Session.side` binds cached SideData to build specification, debug hash, recipe digest, source digest, and resolved source root. The current cache key is only the debug hash. |
| `tools/calibration/tier_r/labeler.py` | A declared-unchanged control with an ambiguous label stays `unchecked`. The current expression treats every label other than `changed` as `ok`. |

The related R1 regression files are absent, including build-receipt, session-provenance, and label-promotion tests. A separate one-line test delta also remains: #128 uses `Path(sys.executable).absolute()` in `tests/test_binexport_isolation.py`; #163 still uses `.resolve()`. This audit does not claim that difference causes a current test failure.

Shared `docs/modules.md`, `docs/qa.md`, `docs/specs/known-answer-corpus.md`, and `tasks/todo.md` differ and are not whole-file substitutes for the absent R1 archive.

### #145: completed matrix receipt recovery

All three changed paths are absent in #163: the research-build CLI, its test file, and the research handoff.

The unique behavior is to retain the complete completed matrix receipt in error JSON when publication fails after work completes, while returning exit 2 and preserving a competing output file. Pre-work failures must not invent a receipt. Its two regressions and 11-line handoff continuation are therefore also unrepresented.

### #150: shared anchored publication and pilot recovery

The shared `tools/calibration/tier_r/receipts.py`, both research CLI callers, `tests/test_tier_r_receipt_parent_race.py`, and `tests/test_tier_r_research_build.py` are all absent in #163.

The PR's unique delta supplies the retained-directory publisher, connects both CLIs to it, and retains a completed pilot receipt in error JSON as well as its stderr diagnostic. Its dedicated tests cover late destination collisions, failed writes and descriptor setup, unavailable anchoring, and native Windows directory/reparse/path controls.

The two existing documentation paths differ. Their R1 additions are absent: the published corpus specification contains neither the R1-20261030 nor R1-20261101 amendments, nor the named research CLI/publisher references. Copying the #150 specification amendment into the active spec alone would incorrectly describe an implementation that is not installed.

## Safe documentation preservation now

A small **historical lineage index** can safely preserve discoverability without importing the research implementation. It should retain these immutable links, record the heads above, and state that #163 contains only the selective orchestration overlap:

- [#128 research index](https://github.com/djshellshoxxx/patchtrace/blob/04bd023df566f43939296f7df1766e46186e7fff/docs/research/ground-truth-corpus/README.md).
- [#145 handoff with the receipt-recovery continuation](https://github.com/djshellshoxxx/patchtrace/blob/8c9eafc79b007a963453d8edf6cb40c804c9bc3d/docs/research/ground-truth-corpus/07-handoff-and-reproduction.md).
- [#150 historical anchored-publication amendment](https://github.com/djshellshoxxx/patchtrace/blob/2fdac2ea9042985ac3c98545d38ac3461d00f4cc/docs/specs/known-answer-corpus.md).

This report and its path manifest provide that bounded preservation material. A full copy of the research archive would require its own link/provenance and scope review; no archive import is certified here. Neither an index nor a documentation copy would justify closing the three implementation PRs.

## Next integration decision and closure conditions

The next decision is whether to integrate the R1 parent feature as a dedicated lane. Cherry-picking #145 or #150 directly onto #163 is insufficient because their callers, parent research tools, tests, and evidence are missing.

A dedicated reconciliation must preserve #163's later `live_pairs.py` recovery/diagnostic safeguards while deliberately deciding the three remaining shared data-integrity changes, the missing tools/tests/fixtures, and the historical research evidence. This audit stops before that broader domain work.

- **#128:** retire only after all retained-scope implementation, tests, and evidence have an explicit landed disposition, with review of the shared-file decisions. Selective orchestration adoption alone is insufficient.
- **#145:** retire when the matrix receipt recovery, its pre-work distinction, both regressions, and the handoff are landed through the accepted parent lane or a verified equivalent.
- **#150:** retire when the publisher and both callers, complete error receipts, native-platform regression obligations, and documentation are landed and verified on the actual integration head. Its historical Windows result must not be transferred to an untested merged tree.

The #150 PR body reports prior native Windows successes and unresolved Sonar path findings; this bounded audit did not independently recertify those historical claims or resolve those findings. Parent research/corpus acceptance remains separate from a child receipt-writer check.

No production/source edits, remote mutations, extra tests, native programs, compilers, or analysis tools were run. All original refs remain preserved.

Companion evidence: `/tmp/patchtrace-receipts-lane-disposition-20261102.json`.
