# Held parent stdin for Windows native acceptance — portable candidate

This packet qualifies authored stdin control flow and owned-reference cleanup
using **scripted Win32 APIs**, plus unchanged receipt/registry controls. It does
not qualify the Windows SDK/ABI, AppContainer permissions, actual handle
inheritance, effective network denial or native BinDiff. All earlier native
failed/blocked receipts remain unchanged.

## Source chain and ownership

The reused checkout is `/workspace/scratch/c7a9e8d98848/pw02-local-packages`, on
`codex/windows-stdin-handoff-20261118`. The prior diagnostic branch remains at
`dfdf1c488e242adc6b3a38eb6975e6503f1eb2b2`. No new worktree or remote ref was
created. A transient zero-free-space reading delayed checkout; after root's
space recovery, a fresh reading showed 1,482,665,984 bytes free before the
explicit branch transition. No failed write or evidence deletion occurred.

| Role | Exact commit |
| --- | --- |
| Root-approved baseline | `c1685bca780de6702d8c3d1932136f75f760de35` |
| Specification, module row and authored controls before C edits | `56a7766bed47dcb30dc8b9d4ccb72123d2bff786` |
| Three-file C implementation | `3d0831025d50d231171aa69c32be4021b18fe7f6` |
| Test import-order/blank-line correction; assertions and C unchanged | `49e2bf908b76e0296f645afb7450e634b6036b8a` |

Owned production changes are only `tools/windows_network/common.h`, `probe.c`
and `launcher.c`. Supporting changes are `tests/test_windows_network_stdin.py`,
the fixed-stage expectation in `tests/test_windows_network_diagnostics.py`,
`docs/specs/windows-bindiff-network-acceptance.md` and the existing row in
`docs/modules.md`. No supervisor, Python adapter, workflow, release policy,
capability, ACL, firewall, dependency or successful stdout schema was changed.

The reviewed external design is preserved **byte for byte** under
`approved-design/`: its 27,706-byte ZIP, original manifest and seal. The ZIP has
11 members / 10 payloads and SHA-256
`1369f6b5ef62a9a937aecbb38a268a757ac1480b59a05357befe54f50e5aba6e`.
Its manifest SHA-256 is
`73b4c7ee5c75235e378144429b2ab7d1454d89b2790ab324a31427d8933dd947`.
It includes the original interface/trust/ABI limits and thirteen Microsoft
primary references. An initial unsealed design suggestion and its withdrawal
remain recorded there; no approved/frozen design payload was rewritten.

## Observed native failure, still failed

At published head `771e5a775f5bf60a8d9094232b51dcdbb47d6389`, preview
`ac6632ad6de486ba16343f0eeb4a2b5a446e4ac1`, tree
`ddf151c6ff8fb3f70b74378525fe1d8d5c9050e3`, run `44409973491` / job
`135175184142` retained artifact `14475538670`. Its ZIP is 207,921 bytes,
SHA-256 `cc5927dd12b64ed6599a906d584bfe6961f8bd29215651b78b94a00ad158f251`.
The three baseline C files are the same reviewed diagnostic bytes used there.

The restricted depth-zero probe emitted `nul-open` / Win32 error 5, followed
by `child-spawn` / error 5 and exit 125. The failing open precedes descendant
`CreateProcessW` in the exact source. The original stderr is retained unchanged
in `observed-native/`; its provenance and full original ZIP reference are in
`native-red-reference.json`. No original image was extracted or executed here.

The four loopback timeouts remain a separate unresolved acceptance result.
Only Winsock 10013 qualifies as denial. Neither timeouts nor the UDP sent-byte
counters prove delivery or effective denial. Restricted descendants, lifecycle
controls and the real restricted adapter run were not completed in that
receipt. A successful advisory job conclusion did not qualify it.

## What changed

The parent still creates read-only NUL. A probe captures a non-inheritable,
same-access reference to its inherited stdin and retains it throughout its
existing body. Startup/current/held references must have the required type,
flags and same kernel-object identity. Each descendant receives a fresh
inheritable duplicate in the existing stdin slot. It does not reopen NUL or
fall back to a weaker mode when the held reference is unavailable.

The small private selection helper enforces the two existing caller roles:
non-null AppContainer SID plus no lease creates fresh parent NUL; no SID plus
a valid lease forwards the held input. Invalid combinations fail before input
creation. The later existing capability/token comparison is unchanged.
DuplicateHandle always uses the current process on both sides, desired access
zero, `DUPLICATE_SAME_ACCESS`, and the explicit required inheritance boolean.
It never uses `DUPLICATE_CLOSE_SOURCE` or grants parent-process access.

NUL origin remains a controlled-entry claim. Character type alone is not NUL
proof, startup values do not authenticate a caller, and a duplicate is not an
independent pathname reopen. The ordinary Python supervisor still has its
existing inheritable-stdio/spawn-lock implementation; this change adds no
general explicit-handle-list guarantee to it. The restricted native launcher
keeps its existing exact three-entry list.

The exact `CompareObjectHandles` export is resolved from one owned System32
loader reference and called through `BOOL (WINAPI *)(HANDLE, HANDLE)`. Missing
APIs and unsupported SDK/ABI behavior refuse; current target macro, warnings,
link inputs and installation policy remain unchanged. Windows 10 / Server 2016
is the API's documented support floor. Actual native availability and calling
convention remain hosted requirements, not facts proved by the surrogates.

The parent-owned outbound stdin reference closes while the child is suspended,
after token/Job checks and before startup success. Separate ownership tracking
keeps the attribute-array storage alive and prevents a stale retry. Close
failure takes the existing failed-start termination path and never authorizes
resume. This strict handling is scoped to stdin; no broad final-close-loop
refactor was made.

Each new validation returns deterministic `ERROR_INVALID_DATA`. A failed API's
error is retained before secondary cleanup. The keeper/module cleanup attempts
both owned releases, consumes ownership once, and returns the first cleanup
failure. Capture/forward callers restore their primary operation error; the
probe wrapper preserves a failing body's primary error and returns 125 if an
otherwise successful body cannot confirm release. Borrowed standard handles
are never closed. New fixed stderr stages share the original per-process
16-record / less-than-512-byte-per-record limit and unchanged eight kinds.

## Preserved red and green evidence

| Receipt | Exact source | Result | Meaning |
| --- | --- | --- | --- |
| `red.*` | `56a7766b` | 4 failures, 8 positives, 45 setup errors | The first runner retained only the old formatter filename in its compiler allowlist and refused the authored stdin compile before execution. Not a behavioral/native red. |
| `red-v2.*` | `56a7766b` | **47 failed, 10 passed**, 0.75 s | Six old-selector behavior failures, 37 missing-lease-contract failures, three static integration failures and one missing-vocabulary failure. C was unchanged. |
| `source.*` | `3d083102` | **57 passed, 0 skipped**, 0.65 s | Focused authored helper/formatter/receipt refusal controls. |
| `final.*` | `3d083102` | **379 passed, 0 skipped**, 1.38 s | Focused controls plus existing Windows receipt and registry neighbors. |
| `ruff.*` | `3d083102` | One I001 finding | New test import order/extra blank line only; original output retained. |
| `final-v2.*` | `49e2bf90` | **379 passed, 0 skipped**, 1.41 s | Exact final test tip after import ordering; C and every test assertion unchanged. |
| `ruff-v2.*` | `49e2bf90` | **Passed** | Full normal Ruff on `src tests tools`, without cache. |

The behavioral forward red executed the actual old stdin-selection fragment
with a valid modeled lease and a scripted NUL access denial: it returned false,
error 5, one NUL open and zero duplicates. After the change the same control
returns success with no NUL open and one same-object inheritable duplicate.
Fresh-parent creation and actual NUL-error preservation remained positive.

The portable harness executes the exact authored helper block from `common.h`.
Scripted cases exercise loader/export failure, invalid/missing startup handles,
wrong types/flags, same-object handles with different numeric values, object
replacement after capture, wrong duplicate identity/rights arguments, occupied
output ownership, first-error preservation, both cleanup attempts, and no
stale or borrowed close. The scripts are explicit models, not Windows API
implementations. They cannot qualify SDK types, ABI, OS permissions, native
inheritance, AppContainer containment or actual process-resume ordering.

The 379-case final gate consists of 48 new stdin controls, nine diagnostic
controls, 209 existing Windows network receipt controls and 113 registry cases.
The final source pin checked 68 imported project/tool modules with no location
or blob drift. It recorded 66 approved child invocations: the existing local
C compiler, authored Linux C fixtures, and the inspected pre-existing local
Git/Python/fake-BinDiff fixtures. No denied socket/child attempt occurred in
the corrected runs. The initial denied compiler call remains in `red.exit.json`.

## Exact command and verification limits

The final runner invocation is:

```text
/workspace/scratch/3a6632a6e5ff/venv/bin/python /workspace/scratch/c7a9e8d98848/qa/windows-stdin-handoff/runner-v2.py 49e2bf908b76e0296f645afb7450e634b6036b8a final-v2
```

The pytest file set is:

```text
tests/test_windows_network_stdin.py
tests/test_windows_network_diagnostics.py
tests/test_windows_bindiff_network.py
tests/test_spec_registry.py
```

`final-v2.command.json` retains the literal argv, owned `/tmp` basetemp, Python
version, environment, compiler identity and source snapshots. Absolute root/src
pins avoid the shared venv's editable-checkout drift. The audit denies network
and unapproved child calls in the Python parent. Compiler descendants are not
audit-instrumented; only inspected authored standard-C/scripted-API sources are
compiled. Fixture/build scratch was removed only after each bounded run ended.

The runner retained raw stdout/stderr and generated C for each applicable
phase. Its inherited metadata names `formatter_runs` and
`local_formatter_sha256` contain both portable formatter and scripted-stdin
fixtures; their exact argv/basenames identify which was run. Neither field is
a Windows executable identity. Original records were not renamed or rewritten.

`source-boundaries.json` records ten static equalities: unchanged socket
implementation, diagnostic functions/kinds/budget, identity/parent/command
helpers, finish/lifecycle code, launcher aside from its explicit mode argument,
probe body aside from the stdin parameter, native build wrapper and workflow.
It also verifies that all three production C files at `49e2bf90` equal
`3d083102`. These are review aids, not execution-path or native proofs.

Root independent source review precedes integration. Later exact-source hosted
MSVC compilation, actual comparison/duplication inside the zero-capability
process, full depth 0/1/2 socket controls, lifecycle termination and real
BinDiff semantic equivalence remain mandatory. No workflow dispatch, native
image execution, package install, release, tag or remote mutation occurred.
