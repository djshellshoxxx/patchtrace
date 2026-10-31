# R1 pilot receipt-output safety review

Reviewer: `/root/truth_audit`, independent automated agent, 2026-10-30 UTC. Scope: read-only review of the current `research_pilot.py` output-path repair and its focused tests, plus the accompanying execution-provenance helper. No production or test files were changed by this reviewer. No target binary or real engine was executed during this review.

## Finding and repair boundary

The preserved Sonar annotation for checkpoint `0271f1869ccba0697c5bf6f797432bb7c6ec54d4` identifies an arbitrary output overwrite at the old `args.output.write_bytes(...)` call. Its exact annotation is retained in `sonar-checkpoint-0271-annotation.json`. The protocol was amended before the repair to require a new `.json` receipt directly inside the explicitly selected absolute private work directory, outside the repository. Historical receipts are not relocated or overwritten by this change.

The reviewed repair implements that boundary:

* `_receipt_path` rejects relative work/output paths and explicit `..` components.
* It checks both paths and all their parent components for symlinks, including a dangling destination symlink.
* It resolves the work root and rejects a root within the repository.
* It requires the output's parent to resolve exactly to that root, with a `.json` suffix and a direct-child filename. It reuses `ingestion.safe_path`, which also rejects separators/colon-based escapes, invalid components and contained-path symlinks.
* It rejects an existing destination before engine work.
* `main` performs this validation before loading labels or invoking `run_pilot`, then validates again immediately before publication.
* Publication uses `open('xb')`. If another file appears at the final destination after a check, exclusive creation refuses to overwrite it. The preexisting file's contents are preserved.

No blocking defect was identified in this output-safety repair **within the stated mistaken-CLI-argument threat model**. The design prevents an incorrect output argument from replacing an existing source file, snapshot or receipt, and binds new receipt creation to the explicitly chosen work directory. It does not purport to isolate the command from a hostile local process that can replace the directory itself between operations. The amended protocol states that limit explicitly; this review makes no stronger claim.

The CLI also preserves useful execution-status semantics: a failed engine results in exit 1, input/output validation errors return 2, and an all-unavailable/not-run receipt returns 3 rather than successful engine acceptance. JSON receipt creation does not establish native compatibility.

## Regression evidence

The author reported that the original implementation genuinely failed the ten new negative cases while passing the positive case before the repair. This reviewer read those tests and independently ran the complete current focused file:

```text
QT_QPA_PLATFORM=offscreen <venv>/bin/python -m pytest -q tests/test_tier_r_research_pilot.py
29 passed in 0.95 seconds
```

The tests exercise actual CLI file handling while substituting only the expensive native runner. They verify that invalid destinations prevent engine invocation; outside/traversal/relative/nested/non-JSON/repository destinations are refused; existing receipts and symlink targets retain their original contents; a normal contained receipt is published; and a receipt created during analysis remains untouched. The substitutes are correctly described as unit/orchestration evidence, not real engine evidence. The exclusive-create standard-library behavior additionally addresses the final check/open window without claiming protection against directory replacement by another process.

This local review and green test run do not constitute a new Sonar server result. The integration owner's final checkpoint must report the actual remote annotation/check status separately.

## Execution provenance inspection

The six supplied metadata cases confirm that cached, resumed and imported observations do not receive fresh native-execution credit. Cache detection uses presence of `cache_origin`, including empty/None metadata, so a cache-served completed run is no longer mislabeled as freshly executed merely because it was not explicitly resumed.

A low-priority corner remains in the initially reviewed condition order: an explicitly non-native backend that also carries cache-origin metadata is labeled `persisted-native-cache` before the non-native-backend branch is considered. The reviewer reproduced:

```text
backend='ghidriff-import', settings={'cache_origin': {'run_id': 'native-prior'}}, resumed=True
→ execution_provenance='persisted-native-cache', native_execution_in_this_invocation=False
```

Fresh execution credit remains false, so this does not reopen the overwrite issue or claim a new engine invocation. The integration owner subsequently corrected the condition order: non-native backend classification now takes precedence over cache-origin metadata. The new import-plus-cache parameter first failed (1 failed, 6 passed, 23 deselected), then the full focused file passed **30 tests**, as confirmed by the final test log. The reviewer inspected the reordered implementation. This corner is resolved; the original observation and red/green history are retained here for traceability. No additional finding is raised by this final bounded review.
