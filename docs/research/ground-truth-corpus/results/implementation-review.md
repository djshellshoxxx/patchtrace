# R1 pilot implementation review and isolated-suite failure diagnosis

Reviewer: `/root/truth_audit`, automated agent independent of the pilot runner author. Date: 2026-10-30 UTC. This is an independent code review, not human approval or live-engine acceptance. Review scope is `tools/calibration/tier_r/research_pilot.py`, its focused tests, the observer/metric interfaces it consumes, and one isolated preexisting test failure. No target binary was executed by this reviewer.

## Verified design properties

The runner retains existing persisted contracts and invokes existing primary, secondary and unified APIs. `select_truth` binds the pair ID and exact validated label content digest; requires nonempty reviewer metadata; rejects missing, overlapping, duplicate or unknown record keys; requires a complete accepted/ambiguous partition; and produces a separately digested transient label view. It does not mutate the input label object or rewrite the original label file. Ambiguous records remain present with ambiguous identity/change and an unchecked review state, so missing truth is not silently reclassified as a negative.

Explicit unified observations are reduced from actual stored results. Only unique `matched` decisions grant committed correspondence evidence. Tentative, candidate, contested and grouped rows abstain. `review`, unknown and not-applicable materiality preserve matched identity with a `None` change verdict. An unknown materiality does not become unchanged. Explicit one-sided decisions retain endpoint observations. The supplemental metric helper receives selected truth and performs no Ghidriff omission credit.

A successful new primary result passes through `ProjectService.apply_analysis` before derived unified work. Raw bytes are retained by the existing service; the runner verifies the stored raw SHA-256 before parsing, validates the imported diff's image identity against labels, and projects external namespaces only into a separate observer view. The projection preserves the original raw mapping. Failures do not replace primary JSON with a truth-derived substitute. Backend identical-hash shortcut is recorded as blocked engine execution rather than a native A/A pass.

Engine failure isolation is reasonable for this pilot: primary preparation/observation failure prevents unified execution, while an independently selected rz-diff run can still proceed. Unified exceptions are recorded separately and do not overwrite successful primary evidence. BinDiff is explicitly blocked; omitted engines are explicitly not-run. Performance scope explicitly says clocks are sequential local observations and process-tree peak memory is unavailable.

## Findings at initial review

These are bounded code-inspection findings in the version initially supplied for review. The integration owner's later fixes and tests supersede the corresponding initial observations; they should be recorded in the final checkpoint rather than treated as unresolved automatically.

1. **Resume provenance needs explicit classification (medium).** `primary_project` initially selected any latest completed run after validating project artifact metadata. A completed analyst import (`backend='ghidriff-import'`) or sample project could therefore enter the Ghidriff branch. `resumed_primary=true` correctly says no new run was executed, but the initial receipt did not expose `run.backend` or `run.backend_version`, making genuine native provenance difficult to assess. Record run ID/backend/version and either reject known imported/sample runs for native acceptance or classify them as imported evidence. Content binding alone does not prove tool execution.
2. **Bind the review receipt itself (medium).** The initial `truth_scope` retained the original and selected label digests plus reviewer strings, but not a digest of the acceptance review and its evidence. The selected digest identifies the chosen function partition, not the exact reviewer/evidence assertion. Record the canonical review digest (and, when needed, exact file-byte digest at the CLI boundary) so a result can identify which review authorized acceptance.
3. **Original versus selected truth annotations (low).** The initial `_unified` called `outcome_of(service, doc, 'forward')` using the original labels. Its stored row `truth`/`edited` annotations can therefore call a source-lineage record right/edited even when strict review selected it as ambiguous. Supplemental arithmetic already uses selected truth and is correct. Pass selected truth to this annotation step or label those embedded annotations explicitly as original candidate truth. This affects interpretation, not engine decisions.

Additional interpretation limits: the tuple observer cannot represent native materiality classes beyond True/False/unknown, so native coverage counters remain necessary for `review` versus `material`. Missing dependencies can reach existing backend errors and be recorded as failed unless separately preflighted; installation failure is never an engine pass. A successful status with zero discovered functions is observable through coverage/metrics and must not be promoted to corpus acceptance merely from status. A failed/cancelled unified stage must not be described as a completed accuracy measurement even if an earlier stored result can be read.

### Resolution inspection

The reviewer inspected the integration owner's subsequent changes. The receipt now includes `run_id`, `backend`, `backend_version`, and `execution_provenance` (`persisted-primary` or `executed-now`). The exact canonical acceptance review is hashed into `truth_scope.review_sha256`. Both cold and warm unified outcome reductions now receive the selected `truth` document. Findings 2 and 3 are resolved by those inspected changes. Finding 1's traceability issue is resolved; imported/sample provenance must still be interpreted from the recorded backend and must not be described as a genuine newly executed Ghidriff result. Explicit classification of non-Ghidriff backends was identified by the integration owner as follow-up work when this resolution note was written. No matching-engine outputs were consulted for this inspection.

## Isolated protobuf test failure: demonstrated environment cause

The full-suite failure reported to the reviewer was reproduced with the installed development venv, using only:

```text
QT_QPA_PLATFORM=offscreen <venv>/bin/python -m pytest -q \
  tests/test_binexport_isolation.py::test_pure_python_runtime_is_refused_in_a_fresh_interpreter
```

Before the correction, it failed because stdout was `protobuf_missing`; the expected value was `protobuf_not_upb`. The test module set `PY = str(Path(sys.executable).resolve())`. In this environment the venv interpreter is a symlink. Resolving it selects the base runtime interpreter instead of the venv interpreter, losing the venv's installed protobuf package.

An independent subprocess comparison used the same code, source path and `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python` in both cases:

| Interpreter | Observed refusal reason | Interpretation |
|---|---|---|
| `/workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python` | `protobuf_not_upb` | Protobuf is installed and the expected pure-Python-runtime refusal occurs. |
| `/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3.12` | `protobuf_missing` | The resolved base interpreter does not have that venv-installed package. |

`git diff 95e09548a82202ae4cfd9380522f36513da87a66 -- tests/test_binexport_isolation.py src/patchtrace/secondary/binexport_proto.py` showed neither file differed before the correction. This is a preexisting test harness assumption exposed by a symlinked venv, not an R1 production-code regression. It is unrelated to loopback networking and required no sandbox escalation.

After the integration owner explicitly authorized a test-only correction, the reviewer changed only `Path(sys.executable).resolve()` to `.absolute()` in the test module. Absolute interpreter paths remain available while the venv entry point is preserved. The entire file then passed: **28 passed in 18.77 seconds**. Production BinExport/protobuf behavior was unchanged. The original failing test provides the regression evidence; no mirrored extra test was added.
