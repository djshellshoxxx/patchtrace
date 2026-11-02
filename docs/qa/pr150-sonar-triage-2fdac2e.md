# PR #150 Sonar security triage — 2026-11-01

## Source and gate

- PR head: `2fdac2ea9042985ac3c98545d38ac3461d00f4cc`.
- Git tree: `501569e0d817d449a84a81eb391ee029e4087e23` (confirmed from GitHub Git commit API).
- Local tested commit: `df17b22089d8db2153aed7a399e1c5fb15bc7715`; its complete tree is identical to the PR head. No source edits were made for this triage.
- Check `124841431988`, SonarCloud Code Analysis: **failure**, C Security Rating on New Code; required A.
- [Check](https://github.com/djshellshoxxx/patchtrace/pull/150/checks?check_run_id=124841431988).
- [Sonar analysis](https://sonarcloud.io/dashboard?id=djshellshoxxx_patchtrace&pullRequest=150).

## Actual findings retrieved

All seven GitHub annotations have failure level and title prefix **Path Traversal via faulty LLM-supplied CLI arguments**. They point to the same new receipt helper. No annotations were omitted (reported annotations_count=7; retrieved 7 on one page).

| Sonar issue | receipts.py line | Reported function |
|---|---:|---|
| `AaGW-kiENBQiGCnb-aMe` | 139 | write_new_receipt() |
| `AaGW-kiENBQiGCnb-aMc` | 59 | _posix_parent() |
| `AaGW-kiENBQiGCnb-aMb` | 113 | _windows_parent() |
| `AaGW-kiENBQiGCnb-aMa` | 62 | _posix_parent() |
| `AaGW-kiENBQiGCnb-aMd` | 146 | write_new_receipt() |
| `AaGW-kiENBQiGCnb-aMY` | 49 | _posix_parent() |
| `AaGW-kiENBQiGCnb-aMZ` | 54 | _posix_parent() |

GitHub annotation `raw_details` is null for every finding. Fetching Sonar `/api/issues/search` for the exact seven IDs returned HTTP 403. Opening the issue page through the web retrieval service also failed. Thus the exact Sonar rule ID, source-to-sink trace, and detailed explanation were **not available**; do not treat the title alone as a proven exploit or mark these issues false-positive merely from this triage.

## Observed source-to-sink paths

There are exactly two non-test `write_new_receipt` callers in the repository; both are development command-line tools. Searching `src`, `tools`, and `.github` finds no product UI, model response, tool-response parser, or automatic LLM command-execution caller of these research functions.

1. `research_build.main`: explicit argparse `--output` at line 135 → `_new_receipt_path` at lines 142 and 146 → `write_new_receipt(args.output, ..., create_parents=True)` at line 147. `_new_receipt_path` validates the original spelling, rejects repository-contained paths, symlink components and existing destinations, and checks resolved outside-repository status. This CLI intentionally permits a new absolute `.json` output anywhere outside the repository that the invoking OS account can write. The accepted spec supplies no fixed output-root allowlist for this matrix tool.
2. `research_pilot.main`: explicit argparse `--work` and `--output` at lines 274–275 → `_receipt_path` at lines 287 and 295 → `write_new_receipt(args.output, data)` at line 296. `_receipt_path` requires absolute non-traversing paths outside the repository, rejects link components/existing destinations, and requires the receipt directly inside the explicitly selected work directory. It preserves the original argument spelling for the anchored publisher.
3. `write_new_receipt` itself repeats absolute/`.json`/no-`..` validation before platform dispatch. It is a reusable filesystem helper: outside-repository and pilot work-root policy belongs to its two inspected callers, as its module documentation states.

### Sink-specific controls

- POSIX line 49 opens only `path.anchor`, the absolute filesystem root. Lines 54/62 open each single `Path.parts` component relative to the retained parent descriptor, using `O_DIRECTORY|O_NOFOLLOW`. Line 59 creates a missing parent component relative to that descriptor, then reopens it with the same no-follow directory flags. `..` never reaches this path; it is rejected by `validate_spelling`.
- POSIX line 146 exclusively creates only `path.name` relative to the retained final parent descriptor using `O_CREAT|O_EXCL|O_NOFOLLOW`, with mode 0600. Ancestor descriptors remain retained through the write; observed rename/replacement prevents a success report and retains the complete receipt on stdout.
- Windows line 113 creates a missing directory only after its preceding ancestors are held. Every directory is opened with `LIST_DIRECTORY|READ_ATTRIBUTES` and `FILE_SHARE_READ` only (no write/delete sharing), plus `OPEN_REPARSE_POINT`; reparse/non-directory attributes are refused. Line 139 then uses exclusive `xb` leaf creation while those handles remain open. Device namespaces, reserved names, streams and trailing-dot/space aliases are rejected beforehand. The native Windows tests, including in-place reparse mutation, are separate acceptance evidence and were not executed in this Linux triage.

## Authority boundary and disposition

An explicit `--output` destination supplied to a local CLI is an output capability granted by its invoker. Creating a new JSON file at that explicitly selected permitted absolute path is the existing contract; the matrix tool is not a sandbox limited to `--store`. Restricting it to a newly invented root merely to satisfy the scanner would change that contract. Likewise, saying an LLM could supply a wrong argument does not establish an application path that executes untrusted model-proposed commands; no such caller was found, and AGENTS.md expressly prohibits executing model-suggested commands.

This is a **source-based rationale, not a Sonar disposition**. No traversal, link-redirection, destination-overwrite, or work-root escape was reproduced in the tested paths. No issue was suppressed, resolved, marked safe, or reclassified remotely. The seven findings and failed quality gate remain **OPEN / REVIEW REQUIRED** until the full issue trace can be reviewed through authorized access and/or a concrete violating input is supplied and exercised. A native Windows test result is still needed to qualify the Windows filesystem implementation.

The original parent-replacement bug was real (baseline 5 failed/1 passed) and was repaired; this triage does not withdraw that historical defect or turn the new helper's successful Linux controls into full project/native acceptance.

## Verification for this triage

Command, from `/workspace/scratch/142cb233d750/wt-receipt` with that worktree's installed environment:

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q tests/test_tier_r_receipt_parent_race.py tests/test_tier_r_research_build.py tests/test_tier_r_research_pilot.py
```

Result: **73 passed, 14 skipped**. The skipped cases are all native Windows cases. Existing focused tests exercise relative/traversal/repository/outside-work-root rejection, destination/link collisions, late parent/ancestor replacement, exclusive creation, missing-parent races, FIFO/hardlink/symlink refusal, retained full receipts, descriptor cleanup and unsupported-primitive failure. Substitute build/engine results are not native engine evidence.

Raw evidence in this directory:

- `pr150-sonar-check-124841431988.json`
- `pr150-sonar-annotations-124841431988.json`
- `pr150-sonar-source-2fdac2e.json`
- `pr150-sonar-regressions-2fdac2e.txt`

Next executable action: inspect the exact Sonar issue traces with an authorized service connection; reconcile the Windows QA child results at the exact PR SHA. Keep the gate open and preserve the current output contract meanwhile.
