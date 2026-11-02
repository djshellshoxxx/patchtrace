# Independent review: verified-transfer preflight adoption

No blocking findings in narrow verified-transfer preflight adoption.

- Source: `d696be1aaa516d33a417d18cb1b74ab942e4a60b`
- Tree: `1e9617f85a4d5306c30a5986f4a2ce1a68ef385d`
- Parent: `b899baca33ee1c69e55b29c3398170a483f0ba55`

## Scope and reasoning

- The shared bundle writer derives exact output metadata from already verified output tuples and calls preflight_credit_manifest after report/label/output/case checks but before _fresh creates the destination.
- The extraction of pair ID matches the immediately preceding filename and ownership validation, including pair IDs containing dots. Metadata fields match OutputStore.write_raw records; report_sha256 remains the shared builder responsibility.
- Both shard export and merge use this common path. Known aggregate overflow cannot create a transfer destination; later IO failure preservation and source records remain unchanged.
- Only five production lines, one focused regression, and a specification clarification change. The output-store/evaluator/schema API equals reviewed a142557; MANAGED_FILES and credit schemas are untouched.

## Independent validation

- 102 passed in 5.57 seconds. Includes actual constructed-provider shard evaluation, merge, credit reading, exact-byte ownership, and the new known aggregate overflow rejection before destination creation.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q --tb=short tests/test_tier_r_training_artifacts.py tests/test_tier_r_shard.py`
- Independent complementary shard-export control passed: one preflight call; insufficient batch budget yields failed transfer diagnostic and no training destination; original completed evaluator report and credited exact output remain readable and hash-consistent. Expected injected [FAILED] diagnostic is evidence of refusal, not a test failure.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python /workspace/scratch/142cb233d750/reviews-resume/transfer_preflight_control.py`
- Passed; shared reviewed API files are unchanged; three changed paths and clean worktree.
  Command: `Changed-file Ruff; git diff --check HEAD^ HEAD; diff of output_store/evaluate/report_schemas against a142557`

## Limits

- Root should adopt only d696be1 after the shared output-completion API, not the branch parents containing integration copies.
- Constructed local transfer checks only; no hosted artifact roundtrip, native engine, training fit, full suite, performance run, or final-evaluation acceptance.
- No repository source edits, target execution, remote mutation, or GitHub approval performed.

The JSON sibling binds every changed file and retained control artifact by SHA-256.
