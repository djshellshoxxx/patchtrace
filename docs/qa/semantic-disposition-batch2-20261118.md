# Semantic branch disposition batch 2 — QA receipt (2026-11-18)

Comparison source: `3be3af166897fc2376dc64850edc66485273dea1`. Tree: `7ef690a25be236eb7c28e3ea92228dca348d2697`.
Evidence-only branch: `codex/semantic-disposition-batch2-20261118`.

The [semantic ledger](../plans/autonomous-consolidation-20261118/semantic-disposition-batch2.md)
and [complete JSON](../plans/autonomous-consolidation-20261118/semantic-disposition-batch2.json)
record all 20 exact tips, source projections, merge bases, ahead/behind counts,
patch-equivalence output, scoped decisions and the 91 unselected original tips.
The source/tests/tools tree is unchanged from the comparison source.

## Reproducible evidence

[Raw archive](semantic-disposition-batch2-20261118.zip): **121 members**,
**1,420,869 bytes**. SHA-256:
`aa5e5bf561abb60a80f0a7422e9475cf91b872500f1cc98f863d58b62075d2ca`.

Every retained file has a size and SHA-256 in `manifest.json`; the builder
reopened the archive, checked its ZIP integrity and verified every manifest hash.
The archive contains complete source/test/tools patches, mechanical snapshots,
per-symbol AST evidence, replacement ancestry, scripts, exact command records,
stdout/stderr, JUnit XML and authored temporary-store inputs. It excludes transient
locks and Python caches. The original inventory observation is unchanged; no REST
refresh or remote mutation occurred.

## Results and scope

| Invocation | Result | Scope |
|---|---|---|
| `current_gate.py` | 955 passed, 2 skipped, 32.63 s | 39 selected current replacement files |
| `current-audit-boundaries-command.json` | 139 passed, 15.31 s | 4 additional current audit files |
| `historical-rules-command.json` | 15 passed, 0.81 s | Unchanged original rules/callgraph file |
| `historical-acquisition-command.json` | 7 passed, 1 failed, 0.19 s | Old direct strict-JSON helper contract differs |
| `historical-kbc-command.json` | 28 passed, 2 failed, 0.45 s | Missing selected-file warning and an obsolete fixture shape |
| `named-superseded-red-command.json` | 1 failed, 0.50 s | Initial warning reproduction, overlapping the previous row |
| `named-superseded-cli-final/receipt.json` | 5 actual headless calls; exits 0/4/4/0/4 | JSON/text observation plus active/cached controls |

All pytest invocations use the shared venv with absolute `PYTHONPATH` pointing to
this exact worktree. Qt uses `QT_QPA_PLATFORM=offscreen`. The actual CLI children
assert no PySide6 module was imported. The two native skips are
`test_native_unsigned_file_does_not_raise` (WinVerifyTrust) and
`test_apply_synthetic_delta_created_with_createdeltab` (`msdelta.dll`).

The counts are separate invocations with overlapping behavior, not additive
product completeness or accuracy. No historical full tree, native engine,
target execution, live provider, manual GUI or packaged acceptance is claimed.
Table durations reproduce pytest's terminal summaries; the JSON also retains
the separately labelled JUnit suite durations.

## Preserved failures and corrections

`failure-disposition.json` records each failure without changing its original
input or relabelling it as a passing test. The old acquisition helper test expects
document-wide surrogate rejection; current public entry parsers intentionally
validate each record so valid siblings survive. The old KB prefix test constructs
a SimpleNamespace without current `ambiguous`/`truncated` fields; the current
production-shaped prefix control passes. The missing `NAMED_SUPERSEDED` warning
is the one confirmed behavior omission, shared by two historical tips.

The first gate preflight selected a nonexistent `test_rules_window.py`; it stopped
before pytest. Its exact script is retained as `current_gate_preflight.py`, with
an explicitly labelled posthoc preflight record. The corrected selection uses
the existing original rules diff-cap controls. The initial CLI observation script
used raw hashes as document IDs; it selected absent scopes and failed its result
assertion. `named_superseded_cli_initial.py`, its failure log and all five output
pairs remain unchanged. The corrected script uses the production importer ID and
retains subprocess exits before assertions.

The final CLI output confirms correct withholding but misleading selected-source
explanation. JSON includes only the generic superseded warning; plain output omits
warnings and says the checked documents do not list the old hit. The proposed
follow-on must cover both index warning and presentation without changing source
admission, status, applicability, ambiguity or conflict behavior.

## Gate limits

This docs-only batch receives no new source implementation credit. Eighteen
examined focal scopes are retained, two tips share one omission, and 91 original
tips have not been selected by either semantic batch. No entire branch is closed
or authorized for deletion/wholesale merging. Current platform, package, native,
security and empirical research gates remain owned by their separate workflows.
