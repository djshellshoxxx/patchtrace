# Retain the static scanner's bootstrap input

The focused workflow repair adds **one upload glob**:
`build/security-static/*.txt`. The scanner already writes and validates
`bootstrap-pip.txt`, but the static upload selected only JSON/stdout/stderr.
Dependency-profile uploads already selected text files. The spec now explicitly
requires these raw input receipts on successful and failed runs.

## Exact source and scope

| Item | Identity |
| --- | --- |
| Branch | `codex/static-scan-receipt-20261118` |
| Baseline | `740869debb111f8edbef33899316e4c75e6fdf7a` |
| Baseline tree | `b93fb18a7412fb31aab5516903bc300a9ad797e4`, identical to published PR316 `14efc52369146f4a638b7d688208736a05321bc0` |
| Spec-first commit | `8455a2ec` (full SHA in source-provenance.json) |
| Source commit | `7adcecd72e7476746819e30937dfc3ca09c01f1e` |
| Source tree | `d897f965039ff99280d1f988a5ff6def2907acd1` |

The complete pre-QA diff is one workflow line and six specification lines.
`source-provenance.json` proves all other workflow bytes are identical. No
scanner command, validator, acceptance condition, mandatory job, action pin,
permissions, timeout, continue-on-error behavior, suppression, or release gate
changed. The scanner Git blob is `298160671271c86d4739f43306ad048d9a45a5c4`
at both this baseline and the original published55 source.

## Original missing-input evidence stays unchanged

The original PR316 static artifact **14459695622** has 38 members and omits
`bootstrap-pip.txt`. Its bytes are retained as `original-static-14459695622.zip`,
SHA-256 `75edfdea10a0e71dbf252d69e3aab967398b00499222611d0b2d8fcdda4c921c`.
It records the actual PR preview
`872947fd8edead1f3269700375c05149fa71e9ef` for published head
`55f3d0742f7d4cf32357a42b8b1cc76d85875e71`: Ruff exited 1 with 81 unsuppressed
diagnostics. Those historical findings are not changed, reclassified, or counted
as findings on the repaired workflow source.

The shared producer writes the same required bootstrap text for every profile.
An actual 89-byte copy from runtime artifact 14458535146 is retained separately
as `observed-runtime-bootstrap-pip.txt`; its SHA-256 is
`321898f94f26b2e9bcddb2b214e5e7c73ab240555ccb17fb9038a2445d50391a`.
`input-provenance.json` preserves the runtime ZIP hash and member ownership.
This is evidence of the required input's exact format, not a replacement member
inserted into the old static archive. The historical static artifact remains
incomplete and failed.

## Direct before/after control

The unchanged `check_upload.py` reads the actual workflow and retained original
ZIP. It restricts its comparison to the exact flat-file wildcard forms used by
this action, checks the original archive hash/CRC/failure, and asks whether the
required prospective static input is included. It does not simulate scanner
success or claim to have executed actions/upload-artifact.

| Check | Before | After |
| --- | --- | --- |
| Required `build/security-static/bootstrap-pip.txt` matched | No | Yes |
| Original 38 artifact members still matched | 38/38 | 38/38 |
| Direct control exit | 1 | 0 |
| Original scanner status | Exit 1 / 81 findings | Same unchanged evidence |

The failed control ran before the spec/source edits. `before.json/log`,
`after.json/log`, and exact before/after workflow bytes are retained. No new
implementation-mirroring repository test was added for this one-line change.

## Focused verification

On exact committed source `7adcecd7`, five existing controls passed in 0.46s:

- dependency workflow mandatory OS/profile jobs, steps, pins and unsuppressed behavior;
- required dependency/static names in release policy;
- critical release-policy names against actual source workflows;
- shared guard before mutation in both publishing paths (two parameter cases).

`run_controls.py` proves the selected source/test bytes before collection, sets
the exact worktree Python source, and denies socket and subprocess operations
through a process-local audit hook. There were **zero denied attempts**. The
original full test assertions remain unchanged. See `controls.log`,
`controls.xml`, and `controls-provenance.json`.

Normal repository Ruff also passed:

```sh
/workspace/scratch/3a6632a6e5ff/venv/bin/python -B -m ruff check src tests tools
```

The direct check was run against the baseline and repaired working trees using:

```sh
/workspace/scratch/3a6632a6e5ff/venv/bin/python -B qa/static-scan-receipt/check_upload.py --root /workspace/scratch/c7a9e8d98848/static-scan-receipt --receipt RECEIPT.json
```

This verifies retention configuration only. No scanner, installer, full test
suite, native tool, hosted action, workflow dispatch, release, tag or deployment
was executed. Future hosted artifacts must demonstrate the added member on
their own exact source/run/attempt; this local check grants no hosted/native or
clean-scan credit. Publication remains subject to all existing qualification
requirements and the literal commit hold.
