# Bounded semantic recovery batch 2

Date: 2026-11-19. Integration base:
`ef9167d20bc6f6296148a6f5dad1c637184344f4`. Reviewed PR #319 head:
`a56ab13aaf9916fc12bea70ba1494075991b7f09`.

This batch inspected two retained branch contributions and repaired one adjacent
accuracy admission defect. It does not declare the retained branch backlog
recovered. The frozen branch census and its dispositions are unchanged; each
entry below describes only the identified contribution.

## Candidate dispositions and source attribution

| Candidate | Pinned source | Observed disposition |
| --- | --- | --- |
| Hide the internal BinExport worker from CLI help | `haiku/cli-help-suppress-20261027`, `37940b706f117f9786109433aed7751eca4e52a6` | The current command registration already omits the worker from public help without the old `argparse.SUPPRESS` placeholder. Both existing help regressions pass. `src/patchtrace/secondary/cli_binexport.py` and `tests/test_secondary_help.py` are byte-identical between the integration base and PR #319. No duplicate implementation was copied. |
| Accept renamed or alternative expected function names in the research scorer | `fix/remediation-a58defa8-139db0`, `6d9c06c2d82cb778712cf2e3c963b63c6363f7c9` | The current scorer already implements the accept-list behavior from `0a734a02ef373b83a35fb61dd3546b21c96cf600`, and its existing positive assertions remain. The baseline scorer is byte-identical to PR #319. Reviewing this contribution exposed a separate missing facts admission guard. |

The original rank scorer is attributable to
`131d47e67e75c5a6923dc61071f6bb66c3e99a92`. The facts guard in this batch is a
new correction discovered during that source review, not a claim that the
retained source already contained the correction.

## Confirmed defect and repair

The repository prohibits scoring cases whose facts are unverified. Before this
change, the shared `score_case` function could return `HIT` for such a case,
including an accepted alternative name or an empty no-change result. The public
`score` and `parity` commands inherited that behavior. Native `scorerun` already
had a facts guard; that separate guard did not protect these entry points.

`score_case` now admits ranking only when `facts` is exactly `verified`. Other
facts values, including an absent field, return `BLOCKED`, a null rank and
`reason: facts_not_verified`. Candidate shape validation still runs, so malformed
results are not silently accepted. Existing aggregate handling excludes blocked
rows from hit, miss, top-one, false-positive and confidence counts, and from
parity comparisons, disagreements and overlap/Jaccard averages. The existing
aggregate algorithms are unchanged.

The accuracy plan records this boundary. Eleven new controls reproduce the
defect and exercise direct scoring, aggregate denominators, parity accounting
and both public CLI commands. The existing synthetic positive fixtures now
explicitly identify themselves as authored verified mechanics. Their original
positive scoring assertions remain unchanged. No real case manifest or facts
status was altered; this batch establishes no L1, L2, L3, CVE or native Windows
accuracy result.

## Verification

| Check | Observed result |
| --- | --- |
| New facts-gate controls against the baseline | 11 failed, 0 errors, proving the missing boundary. Two cache-write warnings were incidental to constrained disk space; subsequent runs disabled the cache provider. |
| Facts-gate, scoring and parity tests after the repair | 33 passed. |
| Initial caller sweep | 106 passed, 1 failed. The failing adapter plumbing fixture lacked facts metadata despite asserting a positive hit. Its authored fixture metadata was corrected; the assertion was preserved. |
| Final combined scoped suite | 140 passed in 4.59 seconds, 0 failed, 0 skipped. |
| Ruff on the modified scorer and four test modules | Passed. |
| `git diff --check` | Passed. |

The final suite included:

- `tests/test_research_qualification_facts_gate.py`
- `tests/test_research_qualification_scoring.py`
- `tests/test_research_qualification_parity.py`
- `tests/test_research_qualification_scorerun.py`
- `tests/test_research_qualification_cases.py`
- `tests/test_research_qualification_adapters.py`
- `tests/test_secondary_help.py`

Tests used `QT_QPA_PLATFORM=offscreen`, `PYTHONPATH=src`, `-p no:cacheprovider`
and an explicit `/tmp/pt-81e4-rq-final` fixture directory. An isolated Python
import check confirmed that the dedicated environment resolves `patchtrace`
from this batch's worktree. Full repository and platform gates remain the
responsibility of the combined integration candidate.

Durable raw receipts are retained under the task workspace's `verification/`
directory. The final log and JUnit report identify the same successful run;
the earlier receipts preserve the red/green progression.

| Receipt | SHA-256 |
| --- | --- |
| `facts-gate-red.log` | `625601a14b918f023d7a8b118bda56db126ed7b12a57934b36904e8a959f5c34` |
| `facts-gate-red.xml` | `bdd2cbc21be05284f0da536b3ab655806420209f174d51e5ef3ecfe91fc27f21` |
| `facts-gate-green.log` | `e7f5fbbcba377b4a45752d66d1f404ba19ce037e28020b1797e3990abecf5f52` |
| `facts-gate-callers.log` | `5cfd86930345becc170b744c13c453f0fd38424d52ef6c43524c295f796432d8` |
| `facts-gate-final.log` | `84e006b9f3bb3fe0b5d94c90cc6fd50ffa43aa47a24a54d3d9744c2a2f5eae54` |
| `facts-gate-final.xml` | `118cedca26b205868be73a48ab988494d01bd6a2a0afb0fd09f089a75046e88a` |

All source branches and refs are preserved. This batch changes only the shared
research scorer, its authored tests, the accuracy plan and this report. It does
not change UI, acquisition, pairing, BinDiff, cache or PE metadata code.
