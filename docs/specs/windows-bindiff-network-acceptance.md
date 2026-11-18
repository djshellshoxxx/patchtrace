# Windows BinDiff network acceptance

Status: implementation candidate, 2026-11-18. Native Windows qualification is
pending. This extends SPEC-29 sections 7, 9.4 and 10; it does not change the
product's process-launch contract or the release qualification policy.

## 1. Observed gap and boundary

At source `d8c02caea407f6d323eecd636735849c1eb31a2d`, workflow run
44319417801, job 134854104769 produced artifact 14438536883. Its ZIP is 6,490
bytes, SHA-256
`01a48208cb6f024f65ad76d35134d6b76623d6c966141baec2fb92212b64816e`.
Six subchecks passed; `checks.no_network` and overall acceptance were `blocked`.
That original observation remains blocked. A successful job was not complete
native qualification. The relevant harness remained unchanged at candidate
`7023c3ad0ce727eb9c8b94c082b55ca9779bd6bb`.

The new check covers the native BinDiff probe/diff process tree launched through
the real `BinDiffAdapter` and `run_engines` runner seams. C3 input acceptance and
the Python result importer remain outside the AppContainer. Inputs are authored
synthetic PEs and BinExport2 data and are never executed. This is not a claim
about arbitrary Windows brokers, a general product sandbox, or real-driver
accuracy. The existing bundle acceptance program-list firewall rules do not
prove this boundary and cannot substitute for its controls.

## 2. Mechanism and ownership

An authored Windows SDK helper creates a fresh, uniquely named AppContainer
profile with no capabilities. A collision is a refusal, not permission to reuse
or delete another profile. The launcher uses
`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` with `CapabilityCount=0` and starts
the child suspended. Before resuming it, the helper verifies the actual child's
AppContainer token, exact profile SID and empty capability list, and assigns it
to a Job Object with kill-on-close and no breakaway. A separate handle-list
attribute permits only dedicated NUL stdin and stdout/stderr pipe handles; no
socket or arbitrary inherited handle is passed.

The helper and an alternate-named copy are built from the checked source with
the hosted runner's existing Windows SDK/compiler. Missing build tools or APIs
remain blocked; the harness does not install a compiler. Build source hashes,
compiler/SDK information, executable hash and source commit/tree are retained.
The pinned BinDiff executable and adjacent runtime files are copied into a
fresh, bounded, non-reparse test tree and verified before use. Only this new tree
and new work directories receive the profile's ACL entries. Write directories
receive a low integrity label. Existing checkout, interpreter, tool installation
and host policy ACLs are not changed. No firewall policy, local account, service
configuration or loopback exemption is changed.

A dedicated ordinary Python harness process sets its temporary-directory root
to its own work tree before invoking production code. It passes the same native
launcher to both `BinDiffAdapter(probe_runner=...)` and `run_engines(runner=...)`.
Every native probe and diff launch must have a corresponding verified launch
receipt. C3 acceptance and the importer use their original production code.

## 3. Effective-denial controls

The same authored native probe runs before restriction, under the AppContainer,
and after cleanup. It also starts a differently named child and grandchild.
Each process records its actual PID/parent PID, token, SID, capability count and
per-attempt nonce. The complete depth 0/1/2 chain and distinct process identities
must be present; launch failure cannot masquerade as a denied socket.

Required socket cases are TCP/UDP over IPv4 and IPv6 loopback, using bounded
nonce echo listeners, and one bounded TCP connection to `1.1.1.1:443`. No HTTP
request or target data is transmitted. All cases must succeed before and after
restriction. Under restriction all cases must report Winsock access denied
(`WSAEACCES`, 10013). Refused connections, absent IPv6, network timeouts or an
unreachable public control are inconclusive and cannot count as effective
denial. No network capability is added to rescue a failing control.

The actual pinned BinDiff probe and synthetic diff must then succeed inside the
same profile, with C3 acceptance, import validation and raw result preservation.
The real launch receipts must prove token verification and job assignment before
resume, exact executable bytes, and bounded termination of remaining children.
Authored cancellation/timeout and abrupt-parent-exit controls must demonstrate
that descendants stop. A missing lifecycle control is not a pass.

## 4. Result equivalence

Keep the existing match-count comparison on both Linux and Windows. Also compare
a shared domain-separated SHA-256 over the complete imported semantic match set:
contract, engine/version, ordered artifact hashes, image-base interpretation,
all match fields, all alternative-match fields and limitations. Canonicalize
dictionary keys and order-insensitive row/flag/limitation collections. Exclude
only the raw file SHA-256 and run ID, which identify separate executions rather
than match semantics. Preserve each raw file and its own hash separately.
Equal counts with different addresses, names, scores, flags, algorithms,
alternatives or limitations fail. Reordering identical rows is permitted.

## 5. Evidence and cleanup

The bounded strict `bindiff-network/1` receipt binds the exact source commit/tree,
helper build/source hashes, pinned native executable hash, unique nonce/profile,
all three probe chains, every native launch, the adapter result and cleanup.
Duplicate keys, nonfinite numbers (including exponent overflow), missing fields,
unknown states, bool-as-integer identities, reused PIDs within a chain, wrong
SID/source/build ownership, incomplete control sets and contradictory cleanup
are refused. Raw command output and individual native receipts are retained in
the artifact's `network/` subdirectory; a failed or partial attempt is retained.

Stop and reap owned process trees before removing the owned profile and staging
tree. Cleanup runs after ordinary failures and cancellation. Recheck directory
identity before removal; do not follow a replacement link/junction or delete an
unrelated path. A profile-delete error, remaining process, unverified owner death
or missing cleanup receipt fails qualification. Process/runner termination can
leave incomplete evidence; it must never create a successful receipt. Cleanup
may address only objects whose creation and ownership were recorded by this
attempt, never a pre-existing profile or an arbitrary path from an input file.

Missing native capability or an unavailable positive control is `blocked`.
Ineffective denial, bad token/handle/job identity, inconsistent semantic output,
malformed evidence or failed cleanup is `failed`. `passed` requires every
mandatory control and the real native adapter run. Mocks prove orchestration
only. Neither Linux unit tests nor a green advisory job establish Windows
qualification. The original blocked artifact is never rewritten.

## 6. Budgets and workflow

Per socket attempt: at most 5 seconds. Three processes per control chain, depth
at most two. No unbounded child recursion. At most 512 MiB and 4,096 files in the
private tool copy; no links/reparse entries. Per native launch at most 120 seconds,
complete Windows network check at most 600 seconds, cleanup waits at most 10
seconds per owned object. JSON receipts are at most 2 MiB and log captures are
bounded. The existing 45-minute workflow timeout remains unchanged.

The workflow builds the helper on Windows before the existing live test, retains
build/probe/launch/cleanup evidence even on failure, and includes the new owned
paths in its pull-request filter. Advisory policy and release policy are not
changed. A canonical exact-source native run is still required by publication
qualification; a PR preview alone is insufficient.

## 7. Test plan and primary references

Hermetic controls cover complete positive evidence, every missing phase/field,
wrong token/source/build/nonce, child/grandchild omission, duplicate identities,
count-equal semantic differences, incomplete socket cases, non-access-denied
errors, cleanup failure and refusal to remove a replaced work tree. Workflow
controls ensure both probe and diff seams are wired and failed evidence retained.
Native controls additionally exercise actual AppContainer token inheritance,
socket denial, handle restriction, Job Object lifetime and real BinDiff output.

Microsoft primary documentation (reviewed 2026-11-18):

- [AppContainer for legacy apps](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-for-legacy-applications-): ordinary `CreateProcess` children inherit the token/AppContainer.
- [AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation): network resources require allocation.
- [SECURITY_CAPABILITIES](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_capabilities).
- [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute): security capabilities and explicit inherited handle list.
- [CreateAppContainerProfile](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile): unique profile creation and collision results.
- [DeleteAppContainerProfile](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-deleteappcontainerprofile): close handles before deletion; failure leaves status uncertain.

These describe the mechanism. Native SDK/runtime/BinDiff compatibility remains
an empirical hosted gate until its exact-source receipts pass.
