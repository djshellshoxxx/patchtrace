# Windows BinDiff network acceptance

Status: implementation candidate, 2026-11-18. Native Windows qualification is
pending. This extends SPEC-29 sections 7, 9.4 and 10; it does not change the
product's process-launch contract or the release qualification policy.

## 1. Observed gap and boundary

### Portable harness correction — 2026-11-19

The exact Windows QA run 44433724017 at source `f2b6827f` recorded 45 stdin
fixture setup errors because its scripted `GetLastError` collided with the
MinGW CRT's imported symbol. The authored surrogate functions now have private
test names through preprocessor aliases. The extracted production block and
every ownership, cleanup, refusal and error assertion remain unchanged. This
repairs the portable test harness, not the Windows ABI qualification.

The same run recorded formatter `attempted=16` and `stream_error=0` after
`freopen(..., "r", stderr)`. A read-only stdio mode does not supply the intended
cross-CRT write-error fixture. The harness instead attaches a real read-only
file descriptor to a writable stdio stream before the first formatter call.
Its writes therefore reach an OS-backed refusal. The unchanged success
predicate still requires 16 consumed attempts and a nonzero stdio error flag.
No formatter code, diagnostic budget, failure expectation or native acceptance
requirement changes. The inert source bytes are checked after the invocation.
Windows execution of this corrected fixture remains required.

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
helper/probe build/source hashes, repository-pinned native executable size/hash/version, unique nonce/profile,
all three probe chains, their actual launch identities, every native launch, the
adapter result and cleanup. Lifecycle entries retain the observed process
creation identities, actual launch owner, interruption reason/exit and bounded
post-stop liveness-query result; success booleans alone are insufficient.
Every process creation time is the canonical ASCII decimal string emitted by
the native helper: one to twenty characters, first character `1` through `9`,
remaining characters `0` through `9`, and numerical value at most `2^64 - 1`.
Zero, leading zeroes, Unicode decimal spellings, signs, whitespace, absent or
non-string values, and oversized values are refused before a launch identity
is admitted or a liveness query is invoked. The same rule covers positive and
denied probe chains, lifecycle chains and their launch records, serial native
launches, and cleanup liveness identities. A `(PID, creation time)` pair cannot
be credited twice through a different spelling; genuine PID reuse with a
different canonical creation time remains valid. Profile `created: true` is a
separate ownership flag and is not a process creation timestamp.
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

### 5.1 Bounded native failure diagnostics

At head `f3f4492981f2c76c8d461d6a6d3eb1ac682fb996`, preview
`a94495abb6117400c138eaaa0127d260c3010094`, run 44395588057 / job
135124463954 retains artifact 14470410950. The restricted probe records only
depth 0, four loopback timeouts and external TCP access denial, then exits 125.
Socket errors alone do not cause that exit in the authored probe; descendant
launch/resume/wait or an early child failure is unresolved. This original
receipt remains failed. No specific Windows API cause is inferred from 125.

Diagnostic-only records go to the already bounded stderr capture. They never
extend successful stdout cases, replace required receipts, change an exit/
qualification decision, or turn a timeout into access denial. The fixed
`windows-network-diagnostic/1` record contains sequence, stage, kind, owner PID,
subject PID, error, socket index, sent bytes and received bytes. These are
bounded unsigned 32-bit fields and fixed vocabulary strings; absent socket
index is `UINT32_MAX`, other unavailable numeric values are zero. No raw argv,
path, environment, nonce, SID or token information is emitted. Diagnostic PIDs
are context for an existing captured launch, not an independent identity proof.

The shared C formatter permits at most 16 attempted records per process, each
strictly below 512 bytes. The sixteenth record is a fixed `diagnostic-limit` /
truncated marker and further calls emit nothing, even if writes fail. Thus one
helper/probe process attempts fewer than 8 KiB of diagnostic output. The bounded
three-process probe chain plus its launcher permits fewer than 32 KiB; existing
per-command capture limits and whole-check time/process bounds remain. No
polling loop emits a record per iteration. Missing/truncated diagnostics cannot
create successful acceptance or prove cleanup.

Win32/WSA failure values are captured at the failing boundary before cleanup or
logging can replace them. Native precondition/token mismatch is explicitly
distinct from an OS error. Socket diagnostics retain the connect/send/receive
or wait phase and known byte counts; application-authored timeout is labeled
as such. Native launch, identity, resume, child exit, wait and cleanup failures
retain fixed stage context. Logging preserves the caller's Win32 last-error
value. Existing OS calls, flags, capabilities, handle lists, Job decisions,
cleanup attempts, cancellation behavior and return values remain unchanged.

Portable tests compile and run only the extracted authored standard-C formatter,
without Windows API stubs or downloaded native images. They exercise actual
formatted JSON, finite vocabulary, maximum numeric values, and the total
record/byte bound, including actual stdio write failure against a valid read-only
stream. Source-order checks are explicitly static; existing evidence
controls continue to refuse incomplete chains, code 125 and non-access-denied
socket results even when diagnostic text is present. Windows compilation and
actual error-path/runtime behavior remain a separate hosted requirement.

#### Portable failed-write predicate observations

The original Windows full-QA result at head `771e5a77`, job `135175350823`,
retains a formatter-harness exit 4 with empty output. Its predicate combines
the 16-attempt count with `ferror(stderr)`; neither constituent was recorded.
That result remains unresolved and is not proof that either constituent alone
failed or that the production formatter violated its budget.

When that same predicate fails, the authored standalone formatter harness must
retain the observed attempt count and stdio error indicator separately in one
fixed JSON line on its own stdout, strictly below 128 bytes. The record has
`probe="formatter-failed-write/1"`, `attempted` and `stream_error`; it contains
no path, source bytes, environment or native identity. It still exits 4. A
passing harness still emits no stdout. The original count/error conjunction
and all pytest success/refusal assertions remain unchanged. This observation
must not perform an extra write to the failed stream, substitute a fake sink,
clear its error indicator, or modify the actual extracted formatter code.

Pytest must retain a bounded failure message containing the return code and
at most 512 bytes of each captured stream. This test-harness observation is
separate from the native helpers' stderr-only protocol; it does not change
their stdout, stderr, return values, 16-attempt cap or acceptance. Portable
success does not resolve the original Windows CRT observation; an actual
subsequent Windows run must supply the missing values.

### 5.2 Parent-created stdin and descendant identity

At head `771e5a775f5bf60a8d9094232b51dcdbb47d6389`, preview
`ac6632ad6de486ba16343f0eeb4a2b5a446e4ac1`, run `44409973491` / job
`135175184142`, artifact `14475538670` records `nul-open` Win32 error 5 followed
by `child-spawn` error 5 and exit 125. The failing NUL open occurs in the
restricted depth-zero process before `CreateProcessW`. That original result
remains failed. Its loopback timeouts remain separate inconclusive socket
evidence and never qualify as access denial.

The controlled ordinary parent creates read-only NUL stdin. The restricted
launcher passes it through the existing three-entry explicit handle list.
Each probe owns a non-inheritable duplicate of its inherited stdin for its
complete lifetime. Descendant launch uses a fresh same-access inheritable
duplicate of that held object in the existing stdin slot. A missing or invalid
held reference is refusal; no descendant pathname reopen or other fallback is
permitted. No cross-process duplicate authority is granted to the child.

Native checks require valid startup/current stdin handles, the startup standard
handle flag, character-device type, correct inheritance flags, and positive
same-object comparisons of the startup/current/held/outbound references. A
numeric handle value is not an object identity. A type classification is not
NUL-origin proof. NUL origin depends on the inspected creator paths and exact
controlled invocation; arbitrary external invocations are outside that claim.
Retaining an owned reference detects post-capture object replacement but does
not authenticate a pre-capture caller or independently reopen a device name.

The comparison mechanism requires the documented `CompareObjectHandles`
Windows API and its actual ABI. The acceptance runtime floor for this mechanism
is Windows 10 / Server 2016. Resolve the exact export through an owned,
System32-constrained loader reference and the exact `BOOL (WINAPI *)(HANDLE,
HANDLE)` function type. Keep the current compiler warnings, target macro and
link flags. Missing SDK/runtime functionality, failed lookup or comparison,
unsupported ABI or unverified cleanup causes refusal. There is no type-only,
numeric-identity, API-substitution or privilege-expansion fallback.

The private keeper is never inherited. Only the same-access outbound stdin
duplicate and the existing stdout/stderr pipe duplicates enter the existing
handle list. The image lock, zero capabilities, suspended start, token checks,
Job containment, cancellation and resume rules remain required. The ordinary
Python supervisor's existing inheritable-stdio behavior is not broadened or
claimed to acquire a new explicit-list guarantee in this change.

Close the parent's owned outbound stdin reference while the child is still
suspended and before returning successful startup. If that close fails, refuse
and follow existing termination/wait handling; do not resume. Attribute-list
storage remains alive until its documented destruction point. Consume
ownership before each close and never retry a possibly stale handle value.
Borrowed standard/startup handles are not closed. The private keeper and one
owned module reference are released on every ordinary probe return; both
cleanup attempts occur even if one fails. A successful body cannot remain
successful after uncertain release. A failed operation keeps its first failure
as primary and records later cleanup errors separately.

Fixed stderr-only stages report new API, validation and cleanup failures under
the existing per-process total record/byte budget. Capture OS errors before
logging/cleanup. Object/type mismatch is validation, not an invented API error.
No raw handles, paths, argv, nonce or token values enter diagnostics. The
successful stdout schema and 10013-only denial policy are unchanged.

Portable scripted API controls qualify only helper decisions, bounded resource
ownership and error precedence. Static integration checks are not native
execution. Actual SDK compilation, runtime export availability, handle
inheritance and object identity inside the zero-capability process, full
descendant controls, lifecycle cleanup and real BinDiff output require a new
exact-source hosted receipt. The earlier failed artifact is never rewritten.


The private selection helper has two explicit modes: a non-null AppContainer
SID with no inherited lease creates the fresh parent NUL; no SID with a valid
lease forwards the held object. Both-present and both-absent combinations are
invalid. This does not change the subsequent existing SID/token comparison.
Owned keeper flags must be zero; outbound stdin flags must be exactly
`HANDLE_FLAG_INHERIT`. No close-protection or unknown bits are accepted, and no
borrowed flags are modified. New validation refusals set `ERROR_INVALID_DATA`
as a deterministic primary error. API errors are captured before cleanup;
secondary cleanup errors cannot replace the failed operation's first error.

The portable stdin controls execute extracted authored helper code with
scripted Win32 API behavior. They also retain a baseline behavioral control
that executes the original stdin-selection fragment with a valid held input
and a denied NUL open. These controls do not execute Windows APIs or qualify
native inheritance/permissions/ABI. The earlier formatter controls retain their
separate standard-C/no-Windows-stub scope.

Primary references for this addition (reviewed 2026-11-18):

- [DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle).
- [GetFileType](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfiletype).
- [GetHandleInformation](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-gethandleinformation).
- [CompareObjectHandles](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-compareobjecthandles): Windows 10 / Server 2016; Kernelbase DLL/import library.
- [GetStartupInfoW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getstartupinfow) and [GetStdHandle](https://learn.microsoft.com/en-us/windows/console/getstdhandle).
- [LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw), [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress), and [FreeLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary).

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
noncanonical creation-time spellings and bounded liveness-query admission,
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
