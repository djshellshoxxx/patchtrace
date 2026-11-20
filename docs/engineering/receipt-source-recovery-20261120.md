# Recovered worktree-aware receipt identity

## Problem and uniqueness

Generation 29 (`6c8b33b851a22fb16d39b31693922359cd34ad12`) reads
`.git/HEAD` as though every checkout has a `.git` directory. Its shared research
receipt helper returned `None` in the actual linked integration worktree.
`tasks/todo.md` already retained this unfinished item.

The archaeologist inspected the helper at all 341 retained remote branch tips:
251 lacked the file, 79 held original blob
`55aa8899b597cdd100530ab2e3bcead4aae610a1`, and 11 held repaired blob
`6b826bd41bec664506b10217b867a1bc7cb8bb02`. Original repair commit:
`0f63e0dcb6b53ef4b57550b183b42f80f376eaa8`. This is a missing implementation
with a reusable donor, not a reason to adopt a whole donor branch.

## Recovery

The three-file donor was recovered as
`648e508961b4e38cc3a2a005808f6bf819ce0823`, preserving its author and source
commit. Production and maintained test blobs remain donor-identical. The only
conflict was an appended plan section; both the current Windows publication
contract and the donor's receipt identity amendment were retained.

The existing helper now observes the requested worktree's HEAD, declared common
refs, detached state, and loose/packed refs without invoking Git. Bounded reads
admit regular metadata files. Invalid or ambiguous metadata returns unknown.
The receipt schema, callers and historical receipts remain unchanged. SHA-1
file-backed refs are the documented scope; this is not clean-source attestation
or alternate-ref-backend support.

## Verification

| Execution | Source | Result |
| --- | --- | --- |
| Donor's maintained controls before recovery | `6c8b33b8` | 18 failed, 11 passed |
| Receipt identity, receipt, CLI, performance harness, scorerun and L1-run mechanics | `648e5089` | 140 passed, 1 skipped in 7.19 s |
| Previously skipped resource control after installing optional `psutil` | `9fdb518f`, unchanged helper/test blobs | 1 passed in 1.13 s |
| Fresh peer's additional ordinary Git-layout controls | `648e5089`, unchanged helper at later direct observation | 6 passed in 0.18 s |

The first skip explicitly reported missing `psutil`; its original receipt
remains unchanged. The later one-case result is separate. Peer controls use
authored empty Git commits and temporary metadata, covering real linked,
detached and separate-gitdir layouts, packed refs, private namespaces, invalid
UTF-8, and no subprocess execution inside the helper.

The peer's final direct check initially used a stale expected commit after
unrelated integration advanced HEAD. The helper returned the new correct HEAD.
A contemporaneous observation bracketed by identical Git HEAD reads passed;
both observations are retained. See the [independent review](receipt-source-independent-review-20261120.md)
and [evidence](evidence/generation30/). Combined, hosted and native Windows
qualification remain separate gates.

## Reproduction

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_research_qualification_git_identity.py \
  tests/test_research_qualification_receipt.py \
  tests/test_research_qualification_cli.py \
  tests/test_research_qualification_perf_harness.py \
  tests/test_research_qualification_scorerun.py \
  tests/test_research_qualification_l1_run.py
python -m ruff check tools/research_qualification/receipt.py \
  tests/test_research_qualification_git_identity.py
```
