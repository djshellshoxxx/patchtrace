# Independent review: aggregate credit and output completion

No blocking findings within the aggregate credit and output-completion slice.

- Source: `a14255715b051b0e5500786049669f77789943d9`
- Tree: `9fa4779bf8031878ded162ebc64328db01ab3a1d`
- Parent: `692e9b009c9f4bba5edceb2a97c207713152d4cb`
- QA-only descendant: `e6e6aa5b8ea52d256fd3ddc70cbc9e5bed01aac9`

## Scope and reasoning

- Dedicated aggregate credit budget remains 64 MiB. Pure preflight and finalization share the exact bounded manifest builder; successful wire shapes and MANAGED_FILES remain unchanged.
- An exclusively published sentinel blocks readers before credits appear. All byte, ownership, diagnostic-presence and sentinel checks occur before owned removal; no fallible validation follows the success transition.
- Any completion or failure diagnostic filename blocks managed and legacy loading, including malformed content and broken links. Parent collections remain refused.
- Started stores cannot retry or append; completed stores refuse later failure retention without modifying prior output. Diagnostics publish without overwrite and remain outside ordinary report discovery.
- EvaluationRetentionError preserves the full assembled report and original completion error even when bounded diagnostic writes fail. CLI returns FINDINGS 1 with failed/uncredited status and in-memory report when retention fails.

## Independent validation

- 140 passed, 3 expected LegacyOutputWarning warnings in 2.60 seconds
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q --tb=short tests/test_tier_r_credit_completion.py tests/test_tier_r_output_persistence.py tests/test_tier_r_credited_replay.py tests/test_tier_r_output_stat_compat.py tests/test_tier_r_eval_report.py`
- Independent child processes terminated after sentinel publication and after credit publication remain refused by both output and training readers, with no diagnostic exception handler running. Termination after successful completion remains readable.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python /workspace/scratch/142cb233d750/reviews-resume/output_completion_controls.py`
- 7,882-byte aggregate accepted at its exact bound; 7,881-byte cap refused by preflight and finalization; preflight created no files; attempted-store retry refused. Two independent engine reports retain two outputs.
  Command: `Same independent control script; exact two-report manifest boundary`
- All generated report schemas exactly match checked-in bytes. Changed-file Ruff and diff checks passed.
  Command: `RS.render comparison; changed Python-file Ruff; git diff --check base..source`

## Limits

- Constructed providers and injected filesystem failures only; no native engine, real corpus acceptance, full suite, performance, or native Windows claim.
- Abrupt process-exit controls do not establish power-loss durability. The contract explicitly excludes an OS-wide or hostile same-user lock; identity checks detect observed replacement, not all possible concurrent filesystem mutation.
- Corpus transfer adoption of the pure preflight remains a separate reviewed integration.
- Only author QA artifacts changed from a142557 to observed e6e6aa5; source and test bytes were independently checked equal.
- No repository source edits, remote mutations, or GitHub approval were performed.

The JSON sibling binds all changed source paths and retained control artifacts by SHA-256.
