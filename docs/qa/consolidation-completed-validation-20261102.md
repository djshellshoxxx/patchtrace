# Consolidation validation results — 2026-11-02

## Candidate identity and conclusion

The published consolidation candidate is [PR #163](https://github.com/djshellshoxxx/patchtrace/pull/163), commit `6e82fd70f315b99c6798a42c9061a1424a02933e`, tree `2e7cd8e258821f50d776ca3b3a4caef594e2a417`. It remains a draft and is not release-qualified.

The immutable full-suite input was local commit `f2b7d981008dea25ac09ea82734da64a1dccb96d`, tree `985078aed0feb4f909690d6082ec4940540cda17`. The published candidate adds five QA documents; all pre-existing file paths, modes and blob hashes are identical. Followups used an editable installation of an archive of this same source. These evidence documents are a later, documentation-only branch; they do not silently replace the tested input or restart candidate checks.

**All 68 original nonpassing test outcomes have passing targeted followups on unchanged product source. The original full run still failed.** This closes the identified local environment/setup failures; it does not establish a fresh all-green full run, Windows package acceptance, resolution of the Sonar findings, or qualification of blocked native engines.

## Full run, preserved without relabeling

Command, run from the immutable source checkout:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python3 -m pytest -q --junitxml=/tmp/patchtrace-consolidation-full-20261102.xml
```

Result: **19,154 passed; 59 failed; 9 errors; 402 skipped; 7 xfailed; 18 warnings in 2,101.09 seconds**. Exit status was 1.

[Full-run receipt](consolidation-full-run-20261102.json) records source identity and SHA-256 values. [Original log, JUnit, failure and skip archive](consolidation-full-run-20261102.tar.gz) preserves the observed results. Counts from separate runs must not be summed into an invented full-suite result.

## Targeted reconciliation

| Original nonpassing group | Cause established from the original traces | Followup and result |
|---|---|---|
| 46 failures + 9 setup errors | Runner restricted socket creation/binding before the assertions could execute. | The exact 55 affected nodes passed in 30.10 seconds in a fresh network namespace containing only loopback and no default route. The existing network-consent tests and assertions were unchanged. |
| 4 import failures + 2 missing-suggestion failures | RapidFuzz was not installed in the initial runtime. | All six failed nodes, plus 15 previously skipped search nodes, passed after installing the pinned cached wheel in an isolated environment. |
| 7 import-isolation failures | `python -I` could not import an uninstalled PatchTrace package; execution stopped before the no-Qt assertion. | All seven passed in 3.55 seconds after editable installation of the unchanged source archive. The parent/isolated-child dependency differences are recorded, not hidden. |

The three groups contain 55 + 6 + 7 = **68** unique original nonpassing nodes. No product/test assertion was changed to obtain these passes.

### Additional dependency-dependent coverage

An offline installation of pinned cached RapidFuzz 3.14.6, YARA-X 1.21.0 and iced-x86 1.21.0 enabled a 335-test selection. Cached wheel SHA-256 and wheel RECORD payloads were verified and retained in the receipts. This verifies the supplied cached bytes; it is not a new upstream signature audit.

That selection produced **334 passed, 1 failed, 0 skipped in 42.58 seconds**. It included all 21 search nodes, 261 formerly skipped YARA nodes, 42 tests in a previously collection-skipped YARA module, and 11 decoder nodes.

The remaining rule-export failure was a correct refusal: the runner has a Git ancestor marker above its ordinary `/tmp` output directory. The test attempted to export beneath that marker and received `PT-RULE-EXPORT [git-tree]`; no export was written. A separate rerun of the same test using a fresh, owned `/dev/shm` directory outside every Git ancestor **passed in 1.12 seconds**. The Git marker, export guard and consent requirements were not removed or weakened.

[Targeted-run receipt](consolidation-targeted-reruns-20261102.json) records the separate outcomes and artifact hashes. [Targeted raw evidence](consolidation-targeted-reruns-20261102.tar.gz) contains the logs, JUnit results, exact selection, environment probes, cached dependency receipts and bounded rerun script. The original 402 skips and 7 xfails remain historical results; this work did not qualify every skipped platform/native case.

## Hosted checks and release limits

The candidate's native Windows Ghidriff and live unified-extraction workflows have successful runs at the published source SHA. These are useful source-integration evidence, but do not qualify the distinct full offline bundle profile or a human desktop acceptance pass.

As of the recorded followup checkpoint, Linux/Windows QA and Qt/package gates were still running. The following independent failures remained:

- **Sonar:** C Security Rating on New Code where A is required, with ten annotations. The connector returned the summary, not the issue paths, rules or dataflows. Ten annotations must not be represented as ten proven vulnerabilities. No finding was resolved, suppressed or declared a false positive. See the [diagnostic access receipt](consolidation-sonar-diagnostic-20261102.md).
- **Rizin and dependent corpus acceptance:** the existing `rz-diff-orientation-unverified` quarantine still blocks the pinned engine. Failure/refusal evidence and quarantine were preserved. No native acceptance or default-corpus success is inferred from parser tests.
- **Packaging and remaining scope:** exact Windows artifact checks, advertised native workflows, clean desktop acceptance, receipt-lineage reconciliation and the unfinished rules evidence loader remain separately tracked in the [release critical path](consolidation-release-critical-path-20261102.md).

The [research agenda](../research/patchtrace-improvement-research-20261102.md) proposes evaluations of ground truth, matching robustness, confidence, rule utility, persistence and usability. It contains no completed benchmark or new accuracy claim. Research should improve measurable correctness while the existing release gates are closed.
